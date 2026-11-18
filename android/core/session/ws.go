// WebSocket carrier transport (spec §2): the Go counterpart of
// cli/src/ws-client.js, over gorilla/websocket.
//
// protect() discipline (plan §2/D10, red-team register): EVERY egress
// socket this process dials goes through the protected dialer —
//  1. this WS carrier (below): net.Dialer.Control calls
//     Protector.Protect(fd) on the raw socket before connect;
//  2. DNS / core-direct streams: they ride INSIDE this carrier as core
//     streams and own no socket at all (pump.DialFlow -> core streams);
//  3. /meta fetches: session.FetchMeta uses this same dialer.
//
// The carrier hostname is resolved by the OS resolver (Android netd),
// never through the tunnel — the Windows "never resolve the underlay
// through the tunnel" discipline, carried over.
package session

import (
	"context"
	"net"
	"sync/atomic"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"

	"hollow/androidcore/core"
)

// ClientUA is the spec §2-2 carrier User-Agent (no proxy/vpn/tunnel words).
const ClientUA = "HollowClient/0.1"

// Protector is implemented on the Kotlin side (VpnService.protect).
type Protector interface {
	Protect(fd int) bool
}

// protectedDialContext dials with VpnService.protect applied to the
// socket before connect — the load-bearing anti-loop step (D10).
func protectedDialContext(p Protector) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if p == nil {
				return nil
			}
			var perr error
			cerr := c.Control(func(fd uintptr) {
				if !p.Protect(int(fd)) {
					perr = errProtectFailed
				}
			})
			if cerr != nil {
				return cerr
			}
			return perr
		},
	}
	return d.DialContext
}

var errProtectFailed = &net.OpError{Op: "protect", Err: errString("VpnService.protect refused the socket")}

type errString string

func (e errString) Error() string { return string(e) }

// byteCounters accumulates wire bytes at the transport boundary
// (NP-1118-03, the Windows core-bridge traffic counters' Go twin):
// display-only, shared across rotations by pointer.
type byteCounters struct {
	up   atomic.Int64
	down atomic.Int64
}

// wsTransport implements core.Transport over one gorilla connection.
type wsTransport struct {
	conn     *websocket.Conn
	client   *core.HollowClient
	writeMu  sync.Mutex
	done     chan struct{}
	once     sync.Once
	counters *byteCounters // may be nil (tests)
}

func dialCarrier(ctx context.Context, wsURL string, p Protector, counters *byteCounters) (*wsTransport, error) {
	dialer := websocket.Dialer{
		NetDialContext:   protectedDialContext(p),
		HandshakeTimeout: 15 * time.Second,
	}
	header := http.Header{}
	header.Set("User-Agent", ClientUA)
	conn, _, err := dialer.DialContext(ctx, wsURL, header)
	if err != nil {
		return nil, err
	}
	return &wsTransport{conn: conn, done: make(chan struct{}), counters: counters}, nil
}

// attach binds the core client and starts the read loop + WS ping ticker
// (transport-level keepalive, as in the JS transport).
func (t *wsTransport) attach(client *core.HollowClient) {
	t.client = client
	go t.readLoop()
	go t.pingLoop()
}

func (t *wsTransport) readLoop() {
	for {
		_, msg, err := t.conn.ReadMessage()
		if err != nil {
			t.shutdown()
			return
		}
		if t.counters != nil {
			t.counters.down.Add(int64(len(msg)))
		}
		t.client.HandleMessage(msg)
	}
}

func (t *wsTransport) pingLoop() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			t.writeMu.Lock()
			_ = t.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
			t.writeMu.Unlock()
		}
	}
}

func (t *wsTransport) shutdown() {
	t.once.Do(func() {
		close(t.done)
		t.conn.Close()
		if t.client != nil {
			t.client.HandleClose()
		}
	})
}

func (t *wsTransport) Send(b []byte) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_ = t.conn.WriteMessage(websocket.BinaryMessage, b)
	if t.counters != nil {
		t.counters.up.Add(int64(len(b)))
	}
}

func (t *wsTransport) Close() { t.shutdown() }

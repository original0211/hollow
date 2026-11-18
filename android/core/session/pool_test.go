package session

// NP-1118-05 pool evidence: aggregate opens spread across lineages
// with per-carrier caps intact, one carrier's death leaves the other
// lineages' streams untouched, rotation stays inside the serving
// lineage, and an auth-fatal handshake failure stops the whole pool.
import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"hollow/androidcore/core"
)

// dialHold opens a stream through the pool and keeps it open after
// one verified echo round.
func dialHold(t *testing.T, s *Session) net.Conn {
	t.Helper()
	conn, err := s.dialFlow(net.ParseIP("203.0.113.7"), 443)
	if err != nil {
		t.Fatalf("dialHold: %v", err)
	}
	if err := echoOnce(conn); err != nil {
		t.Fatalf("dialHold echo: %v", err)
	}
	return conn
}

func echoOnce(conn net.Conn) error {
	msg := []byte("pool-probe")
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != string(msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// Aggregate: 300 streams over a 4-lineage pool against a 50/conn cap.
func TestPoolAggregateCaps(t *testing.T) {
	psk := testPSK()
	cs := newCapServer(t, psk, 50, core.ErrOutboundFailed, -1)
	wsURL := "ws" + strings.TrimPrefix(cs.srv.URL, "http")
	s := newTestPoolSession(wsURL, psk, 4)
	establishAll(t, s)
	startWatchdogs(s)
	defer s.Stop()
	for i := 0; i < 300; i++ {
		dialEcho(t, s, i)
	}
	st := s.State()
	if st.PoolSize != 4 || st.LiveCarriers != 4 {
		t.Fatalf("state pool = %d/%d, want 4/4", st.LiveCarriers, st.PoolSize)
	}
	if st.Carriers < 8 {
		t.Fatalf("carriers = %d, want >= 8 (per-lineage rotations at 40 opens)", st.Carriers)
	}
	if cs.maxAccepted.Load() > 50 {
		t.Fatalf("a carrier established %d streams, above the 50 cap", cs.maxAccepted.Load())
	}
	if cs.totalAccepts.Load() != 300 {
		t.Fatalf("accepted = %d, want 300", cs.totalAccepts.Load())
	}
	t.Logf("carriers=%d serverConns=%d maxAccepted=%d streamsOK=%d", st.Carriers, cs.conns.Load(), cs.maxAccepted.Load(), st.StreamsOK)
}

// Death isolation: kill one carrier; the other lineage's held stream
// keeps echoing and the pool never leaves "connected".
func TestPoolKillOneCarrier(t *testing.T) {
	psk := testPSK()
	cs := newCapServer(t, psk, 0, 0, -1)
	wsURL := "ws" + strings.TrimPrefix(cs.srv.URL, "http")
	s := newTestPoolSession(wsURL, psk, 2)
	establishAll(t, s)
	startWatchdogs(s)
	defer s.Stop()
	c1 := dialHold(t, s)
	c2 := dialHold(t, s)
	defer c1.Close()
	defer c2.Close()
	if !cs.killOneConn() {
		t.Fatal("no server conn to kill")
	}
	// Exactly one held stream is dead; the other must still echo.
	err1 := echoOnce(c1)
	err2 := echoOnce(c2)
	if (err1 == nil) == (err2 == nil) {
		t.Fatalf("held streams after kill: err1=%v err2=%v — want exactly one dead", err1, err2)
	}
	if st := s.State(); st.State != "connected" || st.LiveCarriers < 1 {
		t.Fatalf("pool state after kill = %+v, want connected with >=1 live", st)
	}
	// Fresh dials still land (survivor now, healed lineage shortly).
	dialEcho(t, s, 999)
}

// Rotation isolation: with only lineage 0 established, its reactive
// rotation must not touch lineage 1 at all.
func TestPoolRotationStaysPerLineage(t *testing.T) {
	psk := testPSK()
	cs := newCapServer(t, psk, 40, core.ErrOutboundFailed, -1)
	wsURL := "ws" + strings.TrimPrefix(cs.srv.URL, "http")
	s := newTestPoolSession(wsURL, psk, 2)
	l0 := s.lineages()[0]
	if err := l0.rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	defer s.Stop()
	for i := 0; i < 45; i++ {
		dialEcho(t, s, i)
	}
	l1 := s.lineages()[1]
	l1.mu.Lock()
	c1, n1 := l1.client, l1.carriers
	l1.mu.Unlock()
	if c1 != nil || n1 != 0 {
		t.Fatalf("lineage 1 was touched: client=%v carriers=%d", c1 != nil, n1)
	}
	if got := s.State().Carriers; got != 2 {
		t.Fatalf("carriers = %d, want 2 (lineage 0 rotated once)", got)
	}
	_ = cs
}

// echoHandlerOn serves the minimal Hollow echo handshake on a
// caller-provided listener (for the same-port server swap below).
var echoConns sync.Map // *websocket.Conn registry for echoServerOn

func killEchoConns() {
	echoConns.Range(func(k, _ any) bool {
		_ = k.(*websocket.Conn).Close()
		return true
	})
}

func echoServerOn(t *testing.T, psk []byte, ln net.Listener) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		echoConns.Store(ws, struct{}{})
		defer echoConns.Delete(ws)
		defer ws.Close()
		_, helloRaw, err := ws.ReadMessage()
		if err != nil {
			return
		}
		ch := core.ParseClientHello(helloRaw)
		if ch == nil {
			return
		}
		eph, err := core.GenerateEphemeral()
		if err != nil {
			return
		}
		serverRandom := make([]byte, 32)
		rand.Read(serverRandom)
		shRaw := core.BuildServerHello(core.ProtoVersion, eph.PubRaw, serverRandom, []byte{1, 2, 3})
		if err := ws.WriteMessage(websocket.BinaryMessage, shRaw); err != nil {
			return
		}
		peerPub, err := ecdh.X25519().NewPublicKey(ch.PublicRaw)
		if err != nil {
			return
		}
		dh, err := eph.Priv.ECDH(peerPub)
		if err != nil {
			return
		}
		keys := core.DeriveSession(dh, core.DeriveVerifier(psk), ch.Random, serverRandom, helloRaw, shRaw)
		var writeMu = make(chan struct{}, 1)
		writeMu <- struct{}{}
		send := func(b []byte) {
			<-writeMu
			_ = ws.WriteMessage(websocket.BinaryMessage, b)
			writeMu <- struct{}{}
		}
		sender := core.NewRecordSender(keys.KS2c, keys.IvS2c, send)
		receiver := core.NewRecordReceiver(keys.KC2s, keys.IvC2s)
		sender.Push(core.BuildFrame(core.FTFinish, 0, core.FinishedMAC(keys.FS, keys.TH, "server")), true)
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		blob := receiver.Open(msg)
		if blob == nil {
			return
		}
		frames, recErr, _ := core.ParseFrames(blob)
		if recErr || len(frames) != 1 || frames[0].Type != core.FTFinish {
			return
		}
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			blob := receiver.Open(msg)
			if blob == nil {
				return
			}
			frames, _, _ := core.ParseFrames(blob)
			for _, f := range frames {
				switch f.Type {
				case core.FTOpen:
					sender.Push(core.BuildFrame(core.FTOpenOK, f.StreamID, []byte{core.GateConnect}), true)
				case core.FTData:
					sender.Push(core.BuildFrame(core.FTData, f.StreamID, f.Payload), true)
				case core.FTClose:
					sender.Push(core.BuildFrame(core.FTClose, f.StreamID, []byte{0}), true)
				}
			}
		}
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// Auth fatal: the server is swapped (same port) for one with a wrong
// PSK; the watchdog's redial handshake is rejected and the whole
// pool must land in "error" instead of redialing forever.
func TestPoolAuthFatalStopsPool(t *testing.T) {
	psk := testPSK()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	good := echoServerOn(t, psk, ln)
	wsURL := "ws://" + ln.Addr().String()
	s := newTestPoolSession(wsURL, psk, 1)
	establishAll(t, s)
	startWatchdogs(s)
	defer s.Stop()
	dialEcho(t, s, 0)

	// Swap the server for a wrong-PSK one on the same port and kill
	// the live carrier to force a redial into the bad handshake.
	good.Close()
	ln2, err := net.Listen("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	badPSK := make([]byte, 32)
	for i := range badPSK {
		badPSK[i] = byte(0x50 + i)
	}
	_ = echoServerOn(t, badPSK, ln2)
	killEchoConns()

	waitState(t, s, "error after auth-fatal redial", 15*time.Second, func(st StateSnapshot) bool {
		return st.State == "error"
	})
	if st := s.State(); st.LiveCarriers != 0 {
		t.Fatalf("live carriers after fatal = %d, want 0", st.LiveCarriers)
	}
}

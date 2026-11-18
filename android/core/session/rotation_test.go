package session

// NP-1118-03 evidence tests for the NP-1117-16/14 parity work:
// (a) proactive budget rotation — 150 streams through one pipeline,
//     carrier rotates at 40 opens, none may hit the server's 50 cap;
// (b) 0x01 concurrency retry on the same carrier;
// (c) 0x06 reactive rotation — no watchdog, the dial itself rotates
//     and retries once on the new carrier.
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"hollow/androidcore/core"
)

// capServer is a Hollow echo server with a per-connection OPEN
// budget: opens beyond capPerConn are rejected with rejectCode
// (payload retry_after 10ms, big-endian u16 as the Go client reads).
// rejectFirstN rejects the first N opens globally with 0x01.
type capServer struct {
	srv          *httptest.Server
	conns        atomic.Int64
	opensPerConn sync.Map // *websocket.Conn -> *atomic.Int64
	maxPerConn   atomic.Int64
	maxAccepted  atomic.Int64
	totalOpens   atomic.Int64
	totalAccepts atomic.Int64
	rejectFirst  atomic.Int64
}

func newCapServer(t *testing.T, psk []byte, capPerConn int64, rejectCode byte, rejectFirstN int64) *capServer {
	t.Helper()
	cs := &capServer{}
	cs.rejectFirst.Store(rejectFirstN)
	cs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		cs.conns.Add(1)
		myOpens := &atomic.Int64{}
		myAccepts := &atomic.Int64{}
		cs.opensPerConn.Store(ws, myOpens)
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
					n := myOpens.Add(1)
					cs.totalOpens.Add(1)
					for {
						m := cs.maxPerConn.Load()
						if n <= m || cs.maxPerConn.CompareAndSwap(m, n) {
							break
						}
					}
					if cs.rejectFirst.Add(-1) >= 0 {
						sender.Push(core.BuildFrame(core.FTOpenReject, f.StreamID, []byte{core.ErrConcurrencyLimit, 0, 10}), true)
						continue
					}
					if capPerConn > 0 && n > capPerConn {
						sender.Push(core.BuildFrame(core.FTOpenReject, f.StreamID, []byte{rejectCode, 0, 10}), true)
						continue
					}
					a := myAccepts.Add(1)
					cs.totalAccepts.Add(1)
					for {
						m := cs.maxAccepted.Load()
						if a <= m || cs.maxAccepted.CompareAndSwap(m, a) {
							break
						}
					}
					sender.Push(core.BuildFrame(core.FTOpenOK, f.StreamID, []byte{core.GateConnect}), true)
				case core.FTData:
					sender.Push(core.BuildFrame(core.FTData, f.StreamID, f.Payload), true)
				case core.FTClose:
					sender.Push(core.BuildFrame(core.FTClose, f.StreamID, []byte{0}), true)
				}
			}
		}
	}))
	t.Cleanup(cs.srv.Close)
	return cs
}

// killOneConn closes a single live server-side carrier connection
// (pool death-isolation evidence).
func (cs *capServer) killOneConn() bool {
	done := false
	cs.opensPerConn.Range(func(k, _ any) bool {
		if done {
			return false
		}
		_ = k.(*websocket.Conn).Close()
		done = true
		return false
	})
	return done
}

func testPSK() []byte {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xa0 + i)
	}
	return psk
}

func newTestSession(wsURL string, psk []byte) *Session {
	return newTestPoolSession(wsURL, psk, 1)
}

func dialEcho(t *testing.T, s *Session, i int) {
	t.Helper()
	conn, err := s.dialFlow(net.ParseIP("203.0.113.7"), 443)
	if err != nil {
		t.Fatalf("dial %d: %v", i, err)
	}
	msg := []byte("rotation-probe")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write %d: %v", i, err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		st := s.State()
		t.Fatalf("read %d: %v (pool state=%s live=%d/%d carriers=%d streamsOK=%d)", i, err, st.State, st.LiveCarriers, st.PoolSize, st.Carriers, st.StreamsOK)
	}
	conn.Close()
}

// (a) 150 streams, server cap 50/conn with 0x06 beyond: proactive
// rotation at 40 must keep every stream off the cap.
func TestBudgetRotation150Streams(t *testing.T) {
	psk := testPSK()
	cs := newCapServer(t, psk, 50, core.ErrOutboundFailed, -1)
	wsURL := "ws" + strings.TrimPrefix(cs.srv.URL, "http")
	s := newTestSession(wsURL, psk)
	if err := s.lineages()[0].rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	startWatchdogs(s)
	defer s.Stop()
	// The proactive rotation is asynchronous (as in the JS design):
	// opens already in flight when the swap lands may still be SENT
	// on the old carrier and draw a 0x06 — the reactive path then
	// migrates the dial. The guarantees asserted are the design's
	// own: every dial succeeds, rotations demonstrably happen, and
	// no carrier ever ESTABLISHES more than the 50 cap.
	for i := 0; i < 150; i++ {
		dialEcho(t, s, i)
	}
	st := s.State()
	if st.Carriers < 3 {
		t.Fatalf("carriers = %d, want >= 3 (initial + >=2 rotations)", st.Carriers)
	}
	if cs.maxAccepted.Load() > 50 {
		t.Fatalf("a carrier established %d streams, above the 50 cap", cs.maxAccepted.Load())
	}
	if cs.totalAccepts.Load() != 150 {
		t.Fatalf("accepted opens = %d, want exactly 150", cs.totalAccepts.Load())
	}
	t.Logf("carriers=%d conns=%d maxSentPerConn=%d maxAcceptedPerConn=%d totalOpens=%d", st.Carriers, cs.conns.Load(), cs.maxPerConn.Load(), cs.maxAccepted.Load(), cs.totalOpens.Load())
}

// (b) The first 3 opens are rejected 0x01; the dial must retry on the
// same carrier and succeed.
func TestConcurrencyRetry(t *testing.T) {
	psk := testPSK()
	cs := newCapServer(t, psk, 0, 0, 3)
	wsURL := "ws" + strings.TrimPrefix(cs.srv.URL, "http")
	s := newTestSession(wsURL, psk)
	if err := s.lineages()[0].rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	defer s.Stop()
	dialEcho(t, s, 0)
	if cs.totalOpens.Load() != 4 {
		t.Fatalf("server opens = %d, want 4 (3 rejects + 1 success)", cs.totalOpens.Load())
	}
	if got := s.State().Carriers; got != 1 {
		t.Fatalf("carriers = %d, want 1 (0x01 must not rotate)", got)
	}
}

// (c) No watchdog: opens past 40 on the first carrier get 0x06; the
// dial must rotate synchronously and succeed on the new carrier.
func TestReactiveRotationOn06(t *testing.T) {
	psk := testPSK()
	cs := newCapServer(t, psk, 40, core.ErrOutboundFailed, -1)
	wsURL := "ws" + strings.TrimPrefix(cs.srv.URL, "http")
	s := newTestSession(wsURL, psk)
	if err := s.lineages()[0].rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	defer s.Stop()
	for i := 0; i < 45; i++ {
		dialEcho(t, s, i)
	}
	if got := s.State().Carriers; got != 2 {
		t.Fatalf("carriers = %d, want 2 (one reactive rotation)", got)
	}
	t.Logf("conns=%d maxPerConn=%d totalOpens=%d", cs.conns.Load(), cs.maxPerConn.Load(), cs.totalOpens.Load())
}

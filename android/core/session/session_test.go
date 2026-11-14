package session

// Live loopback test of the session layer: a minimal Hollow server
// built from the core package's own primitives (the same derivation the
// JS server performs) answers a real gorilla WebSocket, and the session
// must handshake, open a stream through dialFlow, and echo bytes
// through the streamConn adapter.
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

var upgrader = websocket.Upgrader{}

// carrierConns tracks live server-side carrier connections so a test
// can kill the carrier mid-session (NP-1114-42 follow-up).
var carrierConns sync.Map // *websocket.Conn -> struct{}{}

func killCarriers() int {
	n := 0
	carrierConns.Range(func(k, _ any) bool {
		_ = k.(*websocket.Conn).Close()
		n++
		return true
	})
	return n
}

func testServer(t *testing.T, psk []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		carrierConns.Store(ws, struct{}{})
		defer carrierConns.Delete(ws)
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
		// Client Finished record.
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
		// Echo server loop.
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
}

func TestSessionLiveLoopback(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xa0 + i)
	}
	srv := testServer(t, psk)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	s := &Session{
		cfg:     Config{WSURL: wsURL, PSK: psk, KeyID: 1},
		stopCh:  make(chan struct{}),
		deathCh: make(chan struct{}, 1),
		tunFD:   -1,
	}
	if err := s.rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	defer s.Stop()

	conn, err := s.dialFlow(net.ParseIP("203.0.113.7"), 443)
	if err != nil {
		t.Fatalf("dialFlow: %v", err)
	}
	msg := []byte("hello through the session layer")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch: %q", got)
	}
	conn.Close()
}

// TestSessionStateMachine (M3-4): the presentation state follows the
// session lifecycle — connected with counters after the live loopback
// attach, a stream success counted, disconnected after Stop.
func TestSessionStateMachine(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xa0 + i)
	}
	srv := testServer(t, psk)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	s := &Session{
		cfg:     Config{WSURL: wsURL, PSK: psk, KeyID: 1},
		stopCh:  make(chan struct{}),
		deathCh: make(chan struct{}, 1),
		tunFD:   -1,
		state:   "connecting",
	}
	if err := s.rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	st := s.State()
	if st.State != "connected" || st.Carriers != 1 || st.SinceMs == 0 {
		t.Fatalf("state after attach: %+v", st)
	}
	conn, err := s.dialFlow(net.ParseIP("203.0.113.7"), 443)
	if err != nil {
		t.Fatalf("dialFlow: %v", err)
	}
	msg := []byte("state-probe")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if st := s.State(); st.StreamsOK != 1 {
		t.Fatalf("streamsOK = %d, want 1", st.StreamsOK)
	}
	conn.Close()
	s.Stop()
	if got := s.State().State; got != "disconnected" {
		t.Fatalf("state after Stop = %s, want disconnected", got)
	}
}

// waitState polls the presentation state until pred holds or the
// deadline passes; the failure message carries the last snapshot.
func waitState(t *testing.T, s *Session, what string, deadline time.Duration, pred func(StateSnapshot) bool) StateSnapshot {
	t.Helper()
	end := time.Now().Add(deadline)
	for {
		st := s.State()
		if pred(st) {
			return st
		}
		if time.Now().After(end) {
			t.Fatalf("state never reached %s; last = %+v", what, st)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSessionCarrierDeathRecovery (NP-1114-42 follow-up; red-team
// NP-1114-43 gap): with the watchdog running, killing the live carrier
// must move the state machine to connecting WITH the reason on the
// detail face, and the §8.4 watchdog rotation must bring it back to
// connected on a SECOND carrier that actually carries traffic again.
// This is the migration the M3-4 receipt's "full lifecycle" wording
// claimed before test evidence existed.
func TestSessionCarrierDeathRecovery(t *testing.T) {
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(0xa0 + i)
	}
	srv := testServer(t, psk)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	s := &Session{
		cfg:     Config{WSURL: wsURL, PSK: psk, KeyID: 1},
		stopCh:  make(chan struct{}),
		deathCh: make(chan struct{}, 1),
		tunFD:   -1,
		state:   "connecting",
	}
	if err := s.rotateCarrier(context.Background()); err != nil {
		t.Fatalf("rotateCarrier: %v", err)
	}
	defer s.Stop()
	go s.watchdog()

	if st := s.State(); st.State != "connected" || st.Carriers != 1 {
		t.Fatalf("pre-kill state: %+v", st)
	}
	if n := killCarriers(); n == 0 {
		t.Fatal("no live carrier connection to kill")
	}
	// Death migration: connecting, with the reason on the face.
	st := waitState(t, s, "connecting after carrier death", 5*time.Second, func(st StateSnapshot) bool {
		return st.State == "connecting"
	})
	if st.Detail != "承载中断，正在重连" {
		t.Fatalf("detail after death = %q, want the reconnecting reason", st.Detail)
	}
	// Recovery: the watchdog re-dials (backoff ~1s); second carrier.
	st = waitState(t, s, "connected on carrier #2", 15*time.Second, func(st StateSnapshot) bool {
		return st.State == "connected" && st.Carriers == 2
	})
	if st.Detail != "" {
		t.Fatalf("detail after recovery = %q, want empty", st.Detail)
	}
	// The recovered carrier really carries: one more echo round.
	conn, err := s.dialFlow(net.ParseIP("203.0.113.7"), 443)
	if err != nil {
		t.Fatalf("dialFlow after recovery: %v", err)
	}
	msg := []byte("after-recovery")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo after recovery: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo mismatch after recovery: %q", got)
	}
	conn.Close()
	if st := s.State(); st.StreamsOK != 1 {
		t.Fatalf("streamsOK after recovery = %d, want 1", st.StreamsOK)
	}
}

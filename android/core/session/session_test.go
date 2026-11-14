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
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"hollow/androidcore/core"
)

var upgrader = websocket.Upgrader{}

func testServer(t *testing.T, psk []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
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

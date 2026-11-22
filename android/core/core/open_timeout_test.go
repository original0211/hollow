package core

// NP-1118-54: local OPEN-answer bound — the Go mirror of the
// tests/open-timeout.test.mjs cells. A minimal loopback server
// built from this package's own primitives (the session package's
// testServer pattern, over an in-memory pipe) never answers OPENs
// for "hang.test" and answers "slow.test" after 600 ms.

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

type otPipe struct {
	inbox chan []byte
}

func (t *otPipe) Send(b []byte) { t.inbox <- append([]byte(nil), b...) }
func (t *otPipe) Close()        {}

type otServer struct {
	mu     sync.Mutex
	resets []uint32
	// NP-1118-66 (S3 grid): when set, the server answers an OPEN
	// and immediately sends GOAWAY.
	goAwayOnOpen bool
}

func (s *otServer) gotReset(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.resets {
		if r == id {
			return true
		}
	}
	return false
}

func runOTServer(psk []byte, pipe *otPipe, client *HollowClient, srv *otServer) {
	helloRaw := <-pipe.inbox
	ch := ParseClientHello(helloRaw)
	if ch == nil {
		return
	}
	eph, err := GenerateEphemeral()
	if err != nil {
		return
	}
	serverRandom := make([]byte, 32)
	_, _ = crand.Read(serverRandom)
	shRaw := BuildServerHello(ProtoVersion, eph.PubRaw, serverRandom, []byte{1, 2, 3})
	send := func(b []byte) { client.HandleMessage(b) }
	send(shRaw)
	peerPub, err := ecdh.X25519().NewPublicKey(ch.PublicRaw)
	if err != nil {
		return
	}
	dh, err := eph.Priv.ECDH(peerPub)
	if err != nil {
		return
	}
	keys := DeriveSession(dh, DeriveVerifier(psk), ch.Random, serverRandom, helloRaw, shRaw)
	sender := NewRecordSender(keys.KS2c, keys.IvS2c, send)
	receiver := NewRecordReceiver(keys.KC2s, keys.IvC2s)
	sender.Push(BuildFrame(FTFinish, 0, FinishedMAC(keys.FS, keys.TH, "server")), true)
	msg := <-pipe.inbox
	blob := receiver.Open(msg)
	if blob == nil {
		return
	}
	frames, recErr, _ := ParseFrames(blob)
	if recErr || len(frames) != 1 || frames[0].Type != FTFinish {
		return
	}
	for msg := range pipe.inbox {
		blob := receiver.Open(msg)
		if blob == nil {
			return
		}
		frames, recErr, _ := ParseFrames(blob)
		if recErr {
			return
		}
		for _, f := range frames {
			switch f.Type {
			case FTOpen:
				op := ParseOpenPayload(f.Payload)
				if op == nil {
					continue
				}
				switch op.Host {
				case "hang.test":
					// never answered — the NP-1118-54 bound is the only resolution
				case "slow.test":
					time.Sleep(600 * time.Millisecond)
					sender.Push(BuildFrame(FTOpenOK, f.StreamID, []byte{GateConnect}), true)
				default:
					sender.Push(BuildFrame(FTOpenOK, f.StreamID, []byte{GateConnect}), true)
					if srv.goAwayOnOpen {
						sender.Push(BuildFrame(FTGoAway, 0, []byte{0x03}), true)
					}
				}
			case FTData:
				sender.Push(BuildFrame(FTData, f.StreamID, f.Payload), true)
			case FTReset:
				srv.mu.Lock()
				srv.resets = append(srv.resets, f.StreamID)
				srv.mu.Unlock()
			case FTClose:
				sender.Push(BuildFrame(FTClose, f.StreamID, []byte{0}), true)
			}
		}
	}
}

func otClient(t *testing.T, openTimeoutMs int) (*HollowClient, *otServer) {
	t.Helper()
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = byte(i + 1)
	}
	pipe := &otPipe{inbox: make(chan []byte, 64)}
	srv := &otServer{}
	client := NewClient(pipe, ClientOptions{PSK: psk, KeyID: 1, OpenTimeoutMs: openTimeoutMs})
	go runOTServer(psk, pipe, client, srv)
	<-client.Handshake()
	if err := client.Err(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return client, srv
}

func TestOpenTimeoutNeverAnswered(t *testing.T) {
	client, srv := otClient(t, 300)

	sHang, err := client.OpenStream("hang.test", 443, SchemeUnknown, 0)
	if err != nil {
		t.Fatalf("open hang stream: %v", err)
	}
	type res struct {
		err error
		dur time.Duration
	}
	hangRes := make(chan res, 1)
	go func() {
		t0 := time.Now()
		_, err := sHang.WaitOpen()
		hangRes <- res{err, time.Since(t0)}
	}()

	// A sibling stream on the same carrier opens and echoes while
	// the hang stream is still pending.
	echoCh := make(chan []byte, 1)
	sOk, err := client.OpenStreamWithCallbacks("echo.test", 80, SchemeUnknown, 0, &StreamCallbacks{
		OnData: func(b []byte) { echoCh <- append([]byte(nil), b...) },
	})
	if err != nil {
		t.Fatalf("open echo stream: %v", err)
	}
	if _, err := sOk.WaitOpen(); err != nil {
		t.Fatalf("echo stream WaitOpen: %v", err)
	}
	sOk.Write([]byte("ping"))
	select {
	case got := <-echoCh:
		if string(got) != "ping" {
			t.Fatalf("echo = %q, want ping", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("echo timed out")
	}

	r := <-hangRes
	var ote *OpenTimeoutError
	if !errors.As(r.err, &ote) {
		t.Fatalf("hang WaitOpen err = %v, want OpenTimeoutError", r.err)
	}
	if r.dur < 250*time.Millisecond || r.dur > 3*time.Second {
		t.Fatalf("bound fired at %v, want ~300ms", r.dur)
	}
	if got := client.ActiveStreams(); got != 1 {
		t.Fatalf("ActiveStreams = %d, want 1 (only the echo stream)", got)
	}
	// The client RESET the timed-out stream (frees the server side).
	deadline := time.Now().Add(2 * time.Second)
	for !srv.gotReset(sHang.ID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !srv.gotReset(sHang.ID) {
		t.Fatal("server never received the timeout RESET")
	}
	sOk.Reset(0)
	client.Close()
}

func TestOpenTimeoutSlowButLegitimate(t *testing.T) {
	client, _ := otClient(t, 5000)
	s, err := client.OpenStream("slow.test", 443, SchemeUnknown, 0)
	if err != nil {
		t.Fatalf("open slow stream: %v", err)
	}
	if _, err := s.WaitOpen(); err != nil {
		t.Fatalf("slow stream WaitOpen: %v (600 ms answer, 5 s bound)", err)
	}
	client.Close()
}

func TestOpenTimeoutDisabled(t *testing.T) {
	client, _ := otClient(t, -1)
	s, err := client.OpenStream("hang.test", 443, SchemeUnknown, 0)
	if err != nil {
		t.Fatalf("open hang stream: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.WaitOpen()
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("WaitOpen returned with the bound disabled: %v", err)
	case <-time.After(500 * time.Millisecond):
		// still pending — exactly the pre-NP-1118-54 behavior
	}
	client.Close()
	select {
	case err := <-done:
		var ote *OpenTimeoutError
		if errors.As(err, &ote) {
			t.Fatal("WaitOpen returned OpenTimeoutError with the bound disabled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitOpen did not return after Close")
	}
}

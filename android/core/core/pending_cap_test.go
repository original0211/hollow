package core

// NP-1118-66 grids for audit NP-1118-63 S4 (Go side): a stream's
// pending queue is capped. Overflow fails the stream (OnFail +
// RESET to the server) instead of write() silently accepting
// data into unbounded memory.

import (
	"testing"
	"time"
)

func TestPendingCapFailsStreamOnOverflow(t *testing.T) {
	client, srv := otClient(t, 0)
	// Rebuild with a small cap: otClient has no options slot, so
	// set the resolved field directly (same-package white box).
	client.streamPendingMax = 1024

	s, err := client.OpenStream("example.test", 443, 0, 0)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := s.WaitOpen(); err != nil {
		t.Fatalf("WaitOpen: %v", err)
	}
	failed := make(chan string, 1)
	s.OnFail = func(reason string) { failed <- reason }

	// White-box stall (event loop): the peer grants no window.
	client.enqueue(func() {
		s.sendWindow = 0
		client.connSendWindow = 0
	})
	s.Write(make([]byte, 600))
	s.Write(make([]byte, 600)) // 1200 > 1024 cap: overflow

	select {
	case reason := <-failed:
		if reason != "send queue overflow" {
			t.Fatalf("OnFail reason = %q, want send queue overflow", reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnFail never fired on pending overflow")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !srv.gotReset(s.ID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.gotReset(s.ID) {
		t.Fatal("server never received the RESET for the overflowed stream")
	}
}

func TestPendingUnderCapFlows(t *testing.T) {
	client, _ := otClient(t, 0)
	client.streamPendingMax = 1024
	s, err := client.OpenStream("example.test", 443, 0, 0)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := s.WaitOpen(); err != nil {
		t.Fatalf("WaitOpen: %v", err)
	}
	got := make(chan []byte, 1)
	s.OnData = func(b []byte) { got <- append([]byte(nil), b...) }
	s.Write([]byte("hello"))
	select {
	case b := <-got:
		if string(b) != "hello" {
			t.Fatalf("echo = %q, want hello", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("echo never came back under the cap")
	}
}

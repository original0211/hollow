package core

// NP-1118-66 grids for audit NP-1118-63 S3 (Go side): GOAWAY is
// consumed — OnGoAway fires once, and OpenStream refuses new
// streams locally once the session is going away.

import (
	"strings"
	"testing"
	"time"
)

func TestGoAwayConsumedAndGatesOpenStream(t *testing.T) {
	client, srv := otClient(t, 0)
	srv.goAwayOnOpen = true

	fired := make(chan byte, 2)
	client.OnGoAway = func(code byte) { fired <- code }

	s, err := client.OpenStream("example.test", 443, 0, 0)
	if err != nil {
		t.Fatalf("first OpenStream: %v", err)
	}
	if _, err := s.WaitOpen(); err != nil {
		t.Fatalf("first stream should open before GOAWAY lands: %v", err)
	}
	select {
	case code := <-fired:
		if code != 0x03 {
			t.Fatalf("OnGoAway code = %d, want 3", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnGoAway never fired")
	}
	if client.GoAwayCode == nil || *client.GoAwayCode != 0x03 {
		t.Fatalf("GoAwayCode = %v, want 3", client.GoAwayCode)
	}

	// New streams are refused locally once going away: the
	// OpenStream call itself surfaces the refusal.
	if _, err := client.OpenStream("example.test", 443, 0, 0); err == nil {
		t.Fatal("stream opened on a going-away session; want refusal")
	} else if !strings.Contains(err.Error(), "going away") {
		t.Fatalf("refusal error = %v, want the going-away refusal", err)
	}
	// OnGoAway fires once only.
	select {
	case code := <-fired:
		t.Fatalf("OnGoAway fired twice (code %d)", code)
	case <-time.After(300 * time.Millisecond):
	}
}

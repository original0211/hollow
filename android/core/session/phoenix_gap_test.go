package session

// NP-1118-66 grids for audit NP-1118-63 S5 (Go side): a write
// landing in the redial gap after replay protection ended must
// surface as an error, never as success for discarded bytes.

import (
	"errors"
	"testing"
)

func TestPhoenixGapWriteAfterProtectionEnds(t *testing.T) {
	c := &phoenixConn{protected: false, cur: nil}
	n, err := c.Write([]byte("lost?"))
	if n != 0 || !errors.Is(err, errPhoenixGapWrite) {
		t.Fatalf("gap write = (%d, %v), want (0, errPhoenixGapWrite)", n, err)
	}
}

func TestPhoenixGapWriteWhileProtectedBuffers(t *testing.T) {
	c := &phoenixConn{protected: true, cur: nil}
	payload := []byte("held")
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("protected gap write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if string(c.buf) != "held" {
		t.Fatalf("buffer = %q, want the chunk held for replay", c.buf)
	}
}

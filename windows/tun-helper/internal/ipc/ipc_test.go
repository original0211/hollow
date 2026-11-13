package ipc

import (
	"bufio"
	"strings"
	"testing"
)

func TestClosedVerbSet(t *testing.T) {
	for _, v := range []Verb{VerbEnableTun, VerbDisableTun, VerbNoteMode, VerbStatus, VerbRestore, VerbPing} {
		f := &Frame{Verb: v}
		if v == VerbNoteMode {
			f.Params = []byte(`{"mode":"off"}`)
		}
		if v == VerbEnableTun {
			f.Params = []byte(`{"socksPort":1080}`)
		}
		if err := f.ValidateRequest(); err != nil {
			t.Fatalf("verb %s should validate: %v", v, err)
		}
	}
	for _, bad := range []string{"exec", "run", "shell", "set_config", "enable", ""} {
		f := &Frame{Verb: Verb(bad)}
		if err := f.ValidateRequest(); err == nil {
			t.Fatalf("verb %q must be rejected (closed set)", bad)
		}
	}
}

func TestFrameRoundtripAndCap(t *testing.T) {
	var sb strings.Builder
	yes := true
	if err := WriteFrame(&sb, &Frame{ID: 7, Verb: VerbPing, OK: &yes}); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(bufio.NewReader(strings.NewReader(sb.String())))
	if err != nil {
		t.Fatal(err)
	}
	if f.ID != 7 || f.Verb != VerbPing {
		t.Fatalf("roundtrip mismatch: %+v", f)
	}
	big := strings.NewReader(strings.Repeat("x", MaxFrameBytes+10) + "\n")
	if _, err := ReadFrame(bufio.NewReader(big)); err == nil {
		t.Fatal("oversize frame must be rejected")
	}
}

func TestEnableTunParamsValidated(t *testing.T) {
	f := &Frame{Verb: VerbEnableTun, Params: []byte(`{"socksPort":70000}`)}
	if err := f.ValidateRequest(); err == nil {
		t.Fatal("out-of-range socks port must be rejected")
	}
	f2 := &Frame{Verb: VerbNoteMode, Params: []byte(`{"mode":"everything"}`)}
	if err := f2.ValidateRequest(); err == nil {
		t.Fatal("invalid mode must be rejected")
	}
}

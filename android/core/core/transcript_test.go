package core

// Tier B: full session transcript replay (VECTORS.md). The vector holds
// one real JS client <-> JS server session, wire byte for wire byte.
// The Go client — driven with the recorded ephemeral/random/padding —
// must emit byte-identical client messages and consume the recorded
// server messages to the same end state.
import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

type transcriptDoc struct {
	Transcript struct {
		PSK           string `json:"psk"`
		ClientPrivRaw string `json:"clientPrivRaw"`
		ClientRandom  string `json:"clientRandom"`
		ClientPadding string `json:"clientPadding"`
		Messages      []struct {
			Dir string `json:"dir"`
			Hex string `json:"hex"`
		} `json:"messages"`
	} `json:"transcript"`
}

type fakeTransport struct {
	sent   [][]byte
	closed bool
}

func (f *fakeTransport) Send(b []byte) { f.sent = append(f.sent, append([]byte(nil), b...)) }
func (f *fakeTransport) Close()        { f.closed = true }

func TestTranscriptReplay(t *testing.T) {
	raw, err := os.ReadFile("../testvectors/vectors-v0.1.2.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc transcriptDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	tr := doc.Transcript
	msgs := tr.Messages
	if len(msgs) < 10 {
		t.Fatalf("transcript too short: %d", len(msgs))
	}

	eph, err := EphemeralFromRaw(un(t, tr.ClientPrivRaw))
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTransport{}
	client := NewClient(ft, ClientOptions{
		PSK:               un(t, tr.PSK),
		KeyID:             1,
		EphemeralOverride: eph,
		RandomOverride:    un(t, tr.ClientRandom),
		PaddingOverride:   un(t, tr.ClientPadding),
	})

	sentIdx := 0 // consumed prefix of ft.sent
	expectC2S := func(wantHex string) {
		t.Helper()
		client.Sync()
		if sentIdx >= len(ft.sent) {
			t.Fatalf("client sent nothing; want c2s %s…", wantHex[:32])
		}
		got := ft.sent[sentIdx]
		sentIdx++
		if !bytes.Equal(got, un(t, wantHex)) {
			t.Fatalf("c2s mismatch at sent #%d:\n got %x…\nwant %s…", sentIdx, got[:min(32, len(got))], wantHex[:64])
		}
	}
	feedS2C := func(hexMsg string) {
		client.HandleMessage(un(t, hexMsg))
		client.Sync()
	}

	// --- handshake phase: msgs[0]=c2s hello, [1]=s2c hello,
	// [2]=s2c finished record, [3]=c2s finished record ---
	if msgs[0].Dir != "c2s" || msgs[1].Dir != "s2c" || msgs[2].Dir != "s2c" || msgs[3].Dir != "c2s" {
		t.Fatal("transcript handshake shape unexpected")
	}
	done := client.Handshake()
	expectC2S(msgs[0].Hex)
	feedS2C(msgs[1].Hex)
	feedS2C(msgs[2].Hex)
	<-done
	if client.Err() != nil {
		t.Fatalf("handshake failed: %v", client.Err())
	}
	expectC2S(msgs[3].Hex)
	if client.State != "open" {
		t.Fatalf("state = %s, want open", client.State)
	}

	// --- session phase: walk the rest; run scripted client actions
	// when the next expected c2s message has not been produced ---
	var stream *ClientStream
	var gotData [][]byte
	actions := []func(){
		func() { // open the stream (matches the OPEN record)
			var err error
			stream, err = client.OpenStream("example.com", 443, SchemeHTTPS, 0)
			if err != nil {
				t.Fatalf("open stream: %v", err)
			}
			stream.OnData = func(d []byte) { gotData = append(gotData, append([]byte(nil), d...)) }
		},
		func() { // 100 KiB up (matches the DATA records)
			stream.Write(bytes.Repeat([]byte{0x75}, 100*1024))
			client.FlushSender()
		},
		func() { // close (matches the CLOSE record)
			stream.CloseWrite()
			client.Sync()
		},
	}
	ai := 0
	for i := 4; i < len(msgs); i++ {
		m := msgs[i]
		if m.Dir == "s2c" {
			feedS2C(m.Hex)
			continue
		}
		// c2s expectation: if the client hasn't produced it yet, run
		// the next scripted action (PONG/WINDOW_UPDATE reactions are
		// produced by feeds and never consume an action).
		client.Sync()
		if sentIdx >= len(ft.sent) {
			if ai >= len(actions) {
				t.Fatalf("no action left to produce expected c2s at transcript #%d", i)
			}
			actions[ai]()
			ai++
		}
		expectC2S(m.Hex)
	}
	if ai != len(actions) {
		t.Fatalf("only %d/%d scripted actions ran", ai, len(actions))
	}
	client.Sync()
	if sentIdx != len(ft.sent) {
		t.Fatalf("client sent %d extra message(s)", len(ft.sent)-sentIdx)
	}
	total := 0
	for _, d := range gotData {
		total += len(d)
		for _, b := range d {
			if b != 0x64 {
				t.Fatal("downstream payload corrupted")
			}
		}
	}
	if total != 300*1024 {
		t.Fatalf("downstream total = %d, want %d", total, 300*1024)
	}
	if len(client.streams) != 0 {
		t.Fatalf("streams not freed: %d remain", len(client.streams))
	}
	if client.State != "open" {
		t.Fatalf("final state = %s, want open", client.State)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

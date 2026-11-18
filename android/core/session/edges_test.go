package session

// NP-1118-09 loopback evidence for entry dispersion: pin placement
// grids, demotion memory, concurrent pick race, pinned dialing
// against a fictional hostname, measurement over loopback, and the
// pool-aware redial cap.
import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"hollow/androidcore/core"
)

func TestParseEdgesJSON(t *testing.T) {
	got, err := parseEdgesJSON([]byte(`{"edges":["104.16.85.20","104.17.164.30","104.16.85.20","2001:db8::1","junk"]}`))
	if err != nil || len(got) != 2 || got[0] != "104.16.85.20" {
		t.Fatalf("v2 parse = %v, %v", got, err)
	}
	got, err = parseEdgesJSON([]byte(`{"edges":[{"ip":"172.64.80.100","note":"x"}]}`))
	if err != nil || len(got) != 1 || got[0] != "172.64.80.100" {
		t.Fatalf("v1 parse = %v, %v", got, err)
	}
	if _, err := parseEdgesJSON([]byte(`{"edges":[]}`)); err == nil {
		t.Fatal("empty payload must error")
	}
	if _, err := parseEdgesJSON([]byte(`not json`)); err == nil {
		t.Fatal("malformed payload must error")
	}
}

func rankedFixture() []EdgeCandidate {
	return []EdgeCandidate{
		{IP: "10.0.0.1", RTTMs: 100},
		{IP: "10.0.0.2", RTTMs: 200},
		{IP: "10.0.0.3", RTTMs: 300},
		{IP: "10.0.0.4", RTTMs: 400},
	}
}

func TestPickSlotEdgeGrids(t *testing.T) {
	psk := testPSK()
	s := newTestPoolSession("ws://127.0.0.1:1", psk, 4)
	// No candidates: every slot dials by domain.
	if got := s.pickSlotEdge(0); got != "" {
		t.Fatalf("no candidates: pick = %q, want domain", got)
	}
	s.setEdgeCandidates(rankedFixture())
	// Primaries land one per slot, in rank order.
	for i, want := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		if got := s.pickSlotEdge(i); got != want {
			t.Fatalf("slot %d pick = %q, want %q", i, got, want)
		}
	}
	// A slot past the end of the list dials by domain, no substitute.
	s2 := newTestPoolSession("ws://127.0.0.1:1", psk, 6)
	s2.setEdgeCandidates(rankedFixture()[:2])
	if got := s2.pickSlotEdge(2); got != "" {
		t.Fatalf("past-end slot pick = %q, want domain", got)
	}
	// Primary demoted: fall through to the best free candidate.
	s3 := newTestPoolSession("ws://127.0.0.1:1", psk, 2)
	s3.setEdgeCandidates(rankedFixture())
	for i := 0; i < 3; i++ {
		s3.noteEdgeFailure("10.0.0.1", errors.New("dial refused"))
	}
	if got := s3.pickSlotEdge(0); got != "10.0.0.2" {
		t.Fatalf("demoted primary pick = %q, want substitute 10.0.0.2", got)
	}
	// Primary taken by another slot: substitute, never a duplicate.
	s4 := newTestPoolSession("ws://127.0.0.1:1", psk, 2)
	s4.setEdgeCandidates(rankedFixture())
	_ = s4.pickSlotEdge(0) // takes 10.0.0.1
	s4.mu.Lock()
	s4.slotEdges[1] = "10.0.0.2" // slot 1 already holds the #2 candidate
	s4.mu.Unlock()
	if got := s4.pickSlotEdge(1); got != "10.0.0.2" {
		t.Fatalf("own reservation re-pick = %q, want 10.0.0.2", got)
	}
	// Everything demoted: domain.
	s5 := newTestPoolSession("ws://127.0.0.1:1", psk, 2)
	s5.setEdgeCandidates(rankedFixture()[:1])
	for i := 0; i < 3; i++ {
		s5.noteEdgeFailure("10.0.0.1", errors.New("dial refused"))
	}
	if got := s5.pickSlotEdge(0); got != "" {
		t.Fatalf("all demoted pick = %q, want domain", got)
	}
}

func TestEdgeFailureMemory(t *testing.T) {
	s := newTestPoolSession("ws://127.0.0.1:1", testPSK(), 1)
	s.setEdgeCandidates(rankedFixture())
	s.noteEdgeFailure("10.0.0.1", errors.New("x"))
	s.noteEdgeFailure("10.0.0.1", errors.New("x"))
	s.mu.Lock()
	demoted := s.edgeDisfavored["10.0.0.1"]
	s.mu.Unlock()
	if demoted {
		t.Fatal("demoted after only 2 failures")
	}
	// A success resets the consecutive count.
	s.noteEdgeSuccess("10.0.0.1")
	s.noteEdgeFailure("10.0.0.1", errors.New("x"))
	s.noteEdgeFailure("10.0.0.1", errors.New("x"))
	s.mu.Lock()
	demoted = s.edgeDisfavored["10.0.0.1"]
	s.mu.Unlock()
	if demoted {
		t.Fatal("demoted after reset + 2 failures")
	}
	s.noteEdgeFailure("10.0.0.1", errors.New("x"))
	s.mu.Lock()
	demoted = s.edgeDisfavored["10.0.0.1"]
	s.mu.Unlock()
	if !demoted {
		t.Fatal("not demoted after 3 consecutive failures")
	}
	// Auth-fatal failures never count (they stop the pool instead).
	s.noteEdgeFailure("10.0.0.2", errors.New("session: handshake: server finished mismatch"))
	s.mu.Lock()
	n := s.edgeFailCounts["10.0.0.2"]
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("auth-fatal counted %d times", n)
	}
	// A refresh clears demotions (new health evidence).
	s.setEdgeCandidates(rankedFixture())
	s.mu.Lock()
	demoted = s.edgeDisfavored["10.0.0.1"]
	s.mu.Unlock()
	if demoted {
		t.Fatal("refresh did not clear the demotion")
	}
}

func TestPickSlotEdgeConcurrentDistinct(t *testing.T) {
	s := newTestPoolSession("ws://127.0.0.1:1", testPSK(), 4)
	s.setEdgeCandidates(rankedFixture())
	var wg sync.WaitGroup
	results := make([]string, 4)
	for slot := 0; slot < 4; slot++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			results[slot] = s.pickSlotEdge(slot)
		}(slot)
	}
	wg.Wait()
	seen := map[string]bool{}
	for slot, ip := range results {
		if ip == "" {
			t.Fatalf("slot %d got domain under concurrency, want a pin", slot)
		}
		if seen[ip] {
			t.Fatalf("two slots pinned the same IP %s", ip)
		}
		seen[ip] = true
	}
}

// Pinned dialing: the WS URL names a fictional host; only the pin
// can carry the connection (to the loopback server at 127.0.0.1).
func TestPinnedDialCarrier(t *testing.T) {
	psk := testPSK()
	srv := testServer(t, psk)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	wsURL := "ws://unresolvable.invalid:" + u.Port()

	// Without a pin the fictional host cannot be dialed at all.
	if _, err := dialCarrier(context.Background(), wsURL, protectedDialContext(nil), nil, ""); err == nil {
		t.Fatal("unpinned dial to a fictional host unexpectedly succeeded")
	}
	// With the pin, the full Hollow handshake completes.
	tport, err := dialCarrier(context.Background(), wsURL, protectedDialContext(nil), nil, "127.0.0.1")
	if err != nil {
		t.Fatalf("pinned dial: %v", err)
	}
	client := core.NewClient(tport, core.ClientOptions{PSK: psk, KeyID: 1})
	tport.attach(client)
	done := client.Handshake()
	select {
	case <-done:
		if err := client.Err(); err != nil {
			t.Fatalf("pinned handshake: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pinned handshake timeout")
	}
	client.Close()
}

// Measurement over loopback: the real server IP ranks; a dead IP is
// disqualified (not ranked, never dialed by rank).
func TestMeasureEdgesLoopback(t *testing.T) {
	psk := testPSK()
	srv := testServer(t, psk)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	wsURL := "ws://unresolvable.invalid:" + u.Port()
	s := newTestPoolSession(wsURL, psk, 1)
	ranked := s.measureEdges(context.Background(), []string{"127.0.0.1", "127.0.0.2"})
	if len(ranked) != 1 || ranked[0].IP != "127.0.0.1" {
		t.Fatalf("ranked = %+v, want only 127.0.0.1", ranked)
	}
	if ranked[0].RTTMs < 0 {
		t.Fatalf("rtt = %d", ranked[0].RTTMs)
	}
}

func TestRedialCapPoolAware(t *testing.T) {
	psk := testPSK()
	srv := testServer(t, psk)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	s := newTestPoolSession(wsURL, psk, 2)
	// Nobody live: degraded -> eager cap.
	if got := s.redialCap(); got != 5*time.Second {
		t.Fatalf("cap with 0/2 live = %v, want 5s", got)
	}
	if err := s.lineages()[0].rotateCarrier(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if got := s.redialCap(); got != 5*time.Second {
		t.Fatalf("cap with 1/2 live = %v, want 5s", got)
	}
	if err := s.lineages()[1].rotateCarrier(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := s.redialCap(); got != 60*time.Second {
		t.Fatalf("cap with 2/2 live = %v, want 60s", got)
	}
}

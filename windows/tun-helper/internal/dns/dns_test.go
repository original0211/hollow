package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildQuery crafts a minimal DNS query (one A question).
func buildQuery(id uint16, name string) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	out[2] = 0x01 // RD
	binary.BigEndian.PutUint16(out[4:6], 1)
	// labels
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	out = append(out, 0)
	out = append(out, 0, 1, 0, 1) // A IN
	return out
}

func questionName(msg []byte) string {
	off := 12
	name := ""
	for {
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if name != "" {
			name += "."
		}
		name += string(msg[off : off+l])
		off += l
	}
	return name
}

// fakeUpstream is a DNS-over-TCP server that answers every query by
// echoing it back with QR set (enough to verify routing/mapping).
type fakeUpstream struct {
	ln    net.Listener
	delay time.Duration
	sink  bool // accept and never answer
}

func startUpstream(t *testing.T, delay time.Duration, sink bool) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{ln: ln, delay: delay, sink: sink}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return u
}

func (u *fakeUpstream) serve(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr))
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		if u.sink {
			continue
		}
		if u.delay > 0 {
			time.Sleep(u.delay)
		}
		msg[2] |= 0x80 // QR
		out := append([]byte{byte(n >> 8), byte(n)}, msg...)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func dialerTo(addr string, counter *uint64) DialFunc {
	return func() (net.Conn, error) {
		if counter != nil {
			atomic.AddUint64(counter, 1)
		}
		return net.DialTimeout("tcp", addr, 2*time.Second)
	}
}

// Reuse proof (mandatory change E): N queries, exactly ONE connection.
func TestPersistentConnectionReuse(t *testing.T) {
	up := startUpstream(t, 0, false)
	var dials uint64
	r := NewResolver(dialerTo(up.ln.Addr().String(), &dials), 2*time.Second)
	defer r.Close()
	for i := 0; i < 5; i++ {
		q := buildQuery(uint16(100+i), fmt.Sprintf("host%d.example", i))
		resp := r.Exchange(q)
		if resp[2]&0x80 == 0 {
			t.Fatalf("response %d not a reply", i)
		}
		if got := binary.BigEndian.Uint16(resp[0:2]); got != uint16(100+i) {
			t.Fatalf("response id = %d, want %d", got, 100+i)
		}
	}
	st := r.Stats()
	if st.UpstreamConns != 1 || dials != 1 {
		t.Fatalf("conns = %d (dials %d), want exactly 1", st.UpstreamConns, dials)
	}
	if st.Resolved != 5 || st.Servfail != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

// Same original ID used concurrently: upstream IDs are rewritten and
// each caller gets ITS OWN answer back.
func TestIDCollisionRemapped(t *testing.T) {
	up := startUpstream(t, 20*time.Millisecond, false)
	r := NewResolver(dialerTo(up.ln.Addr().String(), nil), 2*time.Second)
	defer r.Close()
	results := make([][]byte, 2)
	done := make(chan struct{}, 2)
	for i, name := range []string{"alpha.example", "beta.example"} {
		go func(i int, name string) {
			results[i] = r.Exchange(buildQuery(0xBEEF, name)) // same original ID
			done <- struct{}{}
		}(i, name)
	}
	<-done
	<-done
	for i, want := range []string{"alpha.example", "beta.example"} {
		if got := questionName(results[i]); got != want {
			t.Fatalf("caller %d got answer for %q, want %q", i, got, want)
		}
		if binary.BigEndian.Uint16(results[i][0:2]) != 0xBEEF {
			t.Fatalf("caller %d: original id not restored", i)
		}
	}
}

// Timeout -> SERVFAIL with the question echoed, within a sane bound.
func TestTimeoutServfail(t *testing.T) {
	up := startUpstream(t, 0, true) // sink
	r := NewResolver(dialerTo(up.ln.Addr().String(), nil), 300*time.Millisecond)
	defer r.Close()
	start := time.Now()
	resp := r.Exchange(buildQuery(42, "slow.example"))
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("servfail took %v", elapsed)
	}
	if resp[3]&0x0F != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL(2)", resp[3]&0x0F)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 42 || questionName(resp) != "slow.example" {
		t.Fatal("servfail does not echo id+question")
	}
	if r.Stats().Servfail != 1 {
		t.Fatalf("stats = %+v", r.Stats())
	}
}

// Upstream unreachable -> SERVFAIL (fail-closed); when it recovers, the
// next query redials and succeeds (connection rebuilt after failure).
func TestUpstreamDownThenRecovery(t *testing.T) {
	r := NewResolver(func() (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	}, time.Second)
	resp := r.Exchange(buildQuery(7, "down.example"))
	if resp[3]&0x0F != 2 {
		t.Fatal("expected SERVFAIL while upstream down")
	}
	up := startUpstream(t, 0, false)
	r2 := NewResolver(dialerTo(up.ln.Addr().String(), nil), time.Second)
	defer r2.Close()
	resp = r2.Exchange(buildQuery(7, "down.example"))
	if resp[2]&0x80 == 0 || resp[3]&0x0F == 2 {
		t.Fatal("expected a real answer after recovery")
	}
}

// NP-1118-14: the first upstream accepts the connection and then
// EOFs on the first exchange (the production 1.1.1.1 failure
// shape). The query must fail over to the second upstream and be
// answered — not SERVFAILed — and later queries must keep working.
func TestFailoverAfterUpstreamEOF(t *testing.T) {
	good := startUpstream(t, 0, false)
	defer good.ln.Close()
	var deadDials uint64
	dead := func() (net.Conn, error) {
		atomic.AddUint64(&deadDials, 1)
		c1, c2 := net.Pipe()
		go func() {
			buf := make([]byte, 4096)
			_, _ = c2.Read(buf) // swallow the framed query
			c2.Close()          // then die mid-exchange
		}()
		return c1, nil
	}
	var goodDials uint64
	r := NewResolverMulti([]DialFunc{dead, dialerTo(good.ln.Addr().String(), &goodDials)}, 3*time.Second)
	q := buildQuery(0x2222, "failover.example")
	resp := r.Exchange(q)
	if len(resp) < 12 || resp[2]&0x0F == 2 {
		t.Fatalf("expected a real answer after failover, got rcode/err: %v", resp)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x2222 {
		t.Fatalf("response id = %#x, want the original 0x2222", binary.BigEndian.Uint16(resp[0:2]))
	}
	st := r.Stats()
	if st.Resolved != 1 || st.Servfail != 0 {
		t.Fatalf("stats = %+v, want 1 resolved / 0 servfail", st)
	}
	// A follow-up query rides the surviving upstream.
	resp = r.Exchange(buildQuery(0x2223, "failover.example"))
	if len(resp) < 12 || resp[2]&0x0F == 2 {
		t.Fatalf("follow-up query failed: %v", resp)
	}
	if got := r.Stats().Resolved; got != 2 {
		t.Fatalf("resolved = %d, want 2", got)
	}
}

// NP-1118-19: budget derivation table. base = 5s (the ctor
// default in production); perAttempt = clamp(2·rtt+1s, base,
// 12s); total = clamp(3·rtt+base, 8s, 20s).
func TestBudgetsTable(t *testing.T) {
	cases := []struct {
		rttMs           int64
		perAttempt, tot time.Duration
	}{
		{0, 5 * time.Second, 8 * time.Second},
		{300, 5 * time.Second, 8 * time.Second},
		{1000, 5 * time.Second, 8 * time.Second},
		{2000, 5 * time.Second, 11 * time.Second},
		{3000, 7 * time.Second, 14 * time.Second},
		{4654, 10308 * time.Millisecond, 18962 * time.Millisecond},
		{10000, 12 * time.Second, 20 * time.Second},
	}
	for _, c := range cases {
		r := NewResolverMulti([]DialFunc{func() (net.Conn, error) { return nil, fmt.Errorf("x") }}, 5*time.Second)
		r.SetRTTHint(func() (int64, bool) { return c.rttMs, true })
		pa, tot := r.budgets()
		if pa != c.perAttempt || tot != c.tot {
			t.Fatalf("rtt %dms: budgets = (%v, %v), want (%v, %v)", c.rttMs, pa, tot, c.perAttempt, c.tot)
		}
	}
}

// NP-1118-19 high-latency grid: a 6-second answer on a path
// whose measured RTT is 3s succeeds under the adaptive budget —
// and fails under the pre-NP-1118-19 fixed budget (no hint),
// proving the grid discriminates.
func TestAdaptiveBudgetSlowUpstream(t *testing.T) {
	slow := startUpstream(t, 6*time.Second, false)
	defer slow.ln.Close()
	r := NewResolverMulti([]DialFunc{dialerTo(slow.ln.Addr().String(), nil)}, 5*time.Second)
	r.SetRTTHint(func() (int64, bool) { return 3000, true })
	defer r.Close()
	resp := r.Exchange(buildQuery(0x4444, "slow.example"))
	if len(resp) < 12 || resp[3]&0x0F == 2 {
		t.Fatalf("slow-but-alive upstream SERVFAILed under adaptive budget: %v", resp)
	}
	r2 := NewResolverMulti([]DialFunc{dialerTo(slow.ln.Addr().String(), nil)}, 5*time.Second)
	defer r2.Close()
	resp = r2.Exchange(buildQuery(0x4445, "slow.example"))
	if len(resp) < 12 || resp[3]&0x0F != 2 {
		t.Fatalf("control (no hint) should SERVFAIL the 6s answer, got %v", resp)
	}
}

// NP-1118-19: an attempt timeout must not demote the winner.
// A answers in 2s (over the ~1.2s per-attempt wait at the small
// test budgets), B instantly: the first exchange fails over to
// B; once A is fast, the next exchange must try A FIRST again.
func serveDelayed(c net.Conn, delayFn func() time.Duration) {
	defer c.Close()
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr))
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		if d := delayFn(); d > 0 {
			time.Sleep(d)
		}
		msg[2] |= 0x80 // QR
		out := append([]byte{byte(n >> 8), byte(n)}, msg...)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

func TestTimeoutDoesNotDemote(t *testing.T) {
	var aDelay atomic.Int64
	aDelay.Store(int64(2 * time.Second))
	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()
	go func() {
		for {
			c, err := lnA.Accept()
			if err != nil {
				return
			}
			go serveDelayed(c, func() time.Duration { return time.Duration(aDelay.Load()) })
		}
	}()
	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var bMu sync.Mutex
	var bConns []net.Conn
	go func() {
		for {
			c, err := lnB.Accept()
			if err != nil {
				return
			}
			bMu.Lock()
			bConns = append(bConns, c)
			bMu.Unlock()
			go serveDelayed(c, func() time.Duration { return 0 })
		}
	}()
	defer lnB.Close()
	var order []string
	var mu sync.Mutex
	mk := func(name, addr string) DialFunc {
		return func() (net.Conn, error) {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return net.Dial("tcp", addr)
		}
	}
	r := NewResolverMulti([]DialFunc{mk("A", lnA.Addr().String()), mk("B", lnB.Addr().String())}, 300*time.Millisecond)
	r.SetRTTHint(func() (int64, bool) { return 100, true })
	defer r.Close()
	resp := r.Exchange(buildQuery(0x5555, "demote.example"))
	if len(resp) < 12 || resp[3]&0x0F == 2 {
		t.Fatalf("failover exchange failed: %v", resp)
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if len(got) < 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("dial order = %v, want [A B ...]", got)
	}
	// The precise claim: A's timeout left the cross-query winner
	// pointing at A (a demote-on-timeout would have moved it to B).
	r.mu.Lock()
	nt := r.nextTry
	r.mu.Unlock()
	if nt != 0 {
		t.Fatalf("nextTry = %d after A's timeout, want 0 (A keeps its ranking)", nt)
	}
	// Behavioral half: kill B's live connection; the forced
	// re-establishment must dial A (fast now) and be answered.
	bMu.Lock()
	for _, c := range bConns {
		c.Close()
	}
	bMu.Unlock()
	lnB.Close()
	aDelay.Store(0)
	resp = r.Exchange(buildQuery(0x5556, "demote.example"))
	if len(resp) < 12 || resp[3]&0x0F == 2 {
		t.Fatalf("second exchange failed: %v", resp)
	}
	mu.Lock()
	got = append([]string(nil), order...)
	mu.Unlock()
	if len(got) != 3 || got[2] != "A" {
		t.Fatalf("dial order after recovery = %v, want third dial to be A", got)
	}
}

// NP-1118-23 cold-start trap, inverted: the exact sequence that
// failed forever under NP-1118-19 (hint 700ms, every upstream
// answering in 5.5s, budgets frozen at the 5s/8s floor, EWMA
// pinned at 0) must now succeed — the first exchange escalates
// within itself via the timeout lower bound, and the second
// starts from the learned cost.
func TestColdStartTrapEscapes(t *testing.T) {
	var dialers []DialFunc
	for i := 0; i < 3; i++ {
		up := startUpstream(t, 5500*time.Millisecond, false)
		defer up.ln.Close()
		dialers = append(dialers, dialerTo(up.ln.Addr().String(), nil))
	}
	r := NewResolverMulti(dialers, 5*time.Second)
	r.SetRTTHint(func() (int64, bool) { return 700, true })
	defer r.Close()
	start := time.Now()
	resp := r.Exchange(buildQuery(0x9200, "trap.example"))
	if len(resp) < 12 || resp[3]&0x0F == 2 {
		t.Fatalf("first exchange still SERVFAILs after %v — trap not escaped", time.Since(start))
	}
	if d := time.Since(start); d > 16*time.Second {
		t.Fatalf("first exchange took %v, want success well inside the 20s hard cap", d)
	}
	pa, _ := r.CurrentBudgets()
	if pa < 6*time.Second {
		t.Fatalf("perAttempt after learning = %v, want >= 6s (timeout lower bound must feed budgets)", pa)
	}
	start = time.Now()
	resp = r.Exchange(buildQuery(0x9201, "trap.example"))
	if len(resp) < 12 || resp[3]&0x0F == 2 {
		t.Fatal("second exchange SERVFAILed despite the learned cost")
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("second exchange took %v, want first-attempt success (~5.5s)", d)
	}
}

// Package dns is the helper's tunnelled resolver (TUN notes v2 §4,
// mandatory change E): DNS queries captured on the TUN adapter are
// forwarded as DNS-over-TCP THROUGH the Hollow tunnel (i.e. inside
// the Hollow tunnel, resolved at the exit side).
//
// Discipline, all load-bearing:
//   - ONE persistent upstream connection, multiplexed by DNS message ID
//     (upstream IDs are allocated here; collisions with in-flight IDs are
//     rewritten and mapped back). Never one connection per query.
//   - Per-query timeout 5s -> SERVFAIL, no retries.
//   - Fail-closed: any failure (no tunnel, upstream down, timeout) yields
//     SERVFAIL. The resolver has NO path to the physical DNS — its only
//     dialer goes through SOCKS.
//   - The connection lives and dies with the tunnel path: when the
//     carrier rotates, the stream breaks, in-flight queries are failed
//     with SERVFAIL, and the next query redials on the new carrier.
//   - Query CONTENT is never logged (privacy rule); only counters move.
package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DialFunc opens a TCP connection to the upstream resolver. In the pump
// this opens a core stream; tests inject direct dials.
type DialFunc func() (net.Conn, error)

// Stats is a point-in-time counter snapshot for the status surface.
type Stats struct {
	Queries       uint64 // datagrams accepted for resolution
	Resolved      uint64 // upstream answers relayed back
	Servfail      uint64 // SERVFAIL synthesized (timeout / upstream failure)
	UpstreamConns uint64 // upstream connections ever established (reuse proof)
}

type pending struct {
	origID uint16
	resp   chan []byte // buffered 1
}

// Resolver multiplexes DNS exchanges over one persistent connection.
type Resolver struct {
	dialers []DialFunc // upstreams in preference order (NP-1118-14)
	timeout time.Duration // base timeout (ctor); the adaptive floor

	// Adaptive budget (NP-1118-19): exchange budgets scale with
	// the measured path RTT — an external hint (the session's
	// carrier handshake RTT) and/or the resolver's own EWMA of
	// successful exchange durations, whichever is larger. Set
	// once at construction via SetRTTHint.
	hintFn      func() (int64, bool)
	ewmaMs      atomic.Int64
	timeoutLbMs atomic.Int64 // largest unanswered per-attempt wait (NP-1118-23)

	mu      sync.Mutex
	conn    net.Conn
	dieCh   chan struct{} // closed when the current conn dies
	upIdx   int           // dialer that produced the current conn
	nextTry int           // dialer the next establishment starts from
	pending map[uint16]*pending
	nextID  uint16

	queries  uint64
	resolved uint64
	servfail uint64
	conns    uint64
}

// NewResolver builds a resolver. timeout is per-query (spec: 5s).
func NewResolver(dial DialFunc, timeout time.Duration) *Resolver {
	return NewResolverMulti([]DialFunc{dial}, timeout)
}

// NewResolverMulti builds a resolver over several upstreams in
// preference order (NP-1118-14): a query is only SERVFAILed after
// every upstream has failed it (dial/write/connection death) or
// the per-query timeout elapses. The production motive: the exit
// kills connections to 1.1.1.1:53 outright (stream opens, first
// read EOFs), so a single-upstream resolver SERVFAILs everything;
// 8.8.8.8 / 9.9.9.9 answer normally through the same exit.
func NewResolverMulti(dialers []DialFunc, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		dialers: dialers,
		timeout: timeout,
		pending: make(map[uint16]*pending),
		nextID:  0x4000,
	}
}

func (r *Resolver) Stats() Stats {
	return Stats{
		Queries:       atomic.LoadUint64(&r.queries),
		Resolved:      atomic.LoadUint64(&r.resolved),
		Servfail:      atomic.LoadUint64(&r.servfail),
		UpstreamConns: atomic.LoadUint64(&r.conns),
	}
}

// Exchange resolves one raw DNS message. It ALWAYS returns a response
// message: the upstream answer, or a synthesized SERVFAIL. It never
// returns nil and never leaks the query anywhere but the tunnel.
func (r *Resolver) Exchange(query []byte) []byte {
	atomic.AddUint64(&r.queries, 1)
	if len(query) < 12 {
		atomic.AddUint64(&r.servfail, 1)
		return servfailFor(query)
	}
	// Adaptive budgets (NP-1118-19): the per-attempt wait and the
	// total budget scale with the measured path RTT. One attempt
	// per upstream at most. A transport failure (dial — handled
	// inside register — write error, or connection death) retries
	// on the next upstream, and so does an attempt timeout: the
	// timed-out connection is killed so the next attempt starts
	// clean, but the upstream is NOT demoted — slow is not dead,
	// and the cross-query winner keeps its ranking.
	exchangeStart := time.Now()
	deadline := exchangeStart
	r.mu.Lock()
	winner := r.nextTry
	r.mu.Unlock()
	for attempt := 0; attempt < len(r.dialers); attempt++ {
		// Budgets are recomputed per attempt (NP-1118-23): a
		// timeout earlier in THIS exchange raises the timeout
		// lower bound, and the next attempt must already profit
		// from it — otherwise the escalation only helps the next
		// query while this one dies at the old numbers. The
		// deadline only ever extends, and budgets() clamps the
		// total to 20s, so the extension is bounded.
		perAttempt, total := r.budgets()
		if d := exchangeStart.Add(total); d.After(deadline) {
			deadline = d
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		wait := perAttempt
		if wait > remaining {
			wait = remaining
		}
		conn, dieCh, upID, p, err := r.registerFrom(query, (winner+attempt)%len(r.dialers), attempt == 0)
		if err != nil {
			break // every upstream failed at dial time
		}
		// Frame and send: 2-byte length prefix (RFC 7766).
		up := make([]byte, len(query))
		copy(up, query)
		binary.BigEndian.PutUint16(up[0:2], upID)
		frame := make([]byte, 2+len(up))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(up)))
		copy(frame[2:], up)
		if err := writeAll(conn, frame); err != nil {
			r.deregister(upID, p)
			r.killConn(conn, true)
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case resp := <-p.resp:
			timer.Stop()
			r.noteExchangeDuration(time.Since(exchangeStart))
			atomic.AddUint64(&r.resolved, 1)
			return resp
		case <-dieCh:
			timer.Stop()
			r.deregister(upID, p)
			continue
		case <-timer.C:
			r.deregister(upID, p)
			r.noteTimeout(wait)
			r.killConn(conn, false)
			continue
		}
	}
	atomic.AddUint64(&r.servfail, 1)
	return servfailFor(query)
}

// SetRTTHint installs an external path-RTT source (milliseconds).
func (r *Resolver) SetRTTHint(fn func() (int64, bool)) { r.hintFn = fn }

// pathCost estimates what one exchange actually costs on this
// path (NP-1118-23). The maximum of:
//   - twice the external RTT hint: an exchange is a stream open
//     plus a question/answer round trip over the tunnel, so the
//     standing prior is 2x the carrier handshake RTT (the hint
//     alone proved to be a lower bound, not an estimate);
//   - the EWMA of FULL successful exchange durations;
//   - the timeout lower bound: the largest per-attempt wait that
//     ever expired unanswered — a censored sample proving the
//     true cost was larger. Without it, a path whose exchanges
//     all time out teaches the resolver nothing (zero successes
//     -> EWMA frozen -> budgets frozen at the floor -> every
//     later query repeats the failure: the cold-start trap
//     reproduced in NP-1118-23).
func (r *Resolver) pathCost() time.Duration {
	var ms int64
	if r.hintFn != nil {
		if h, ok := r.hintFn(); ok && 2*h > ms {
			ms = 2 * h
		}
	}
	if e := r.ewmaMs.Load(); e > ms {
		ms = e
	}
	if lb := r.timeoutLbMs.Load(); lb > ms {
		ms = lb
	}
	return time.Duration(ms) * time.Millisecond
}

// CurrentBudgets exposes the live budget pair for status
// surfaces (field reconciliation against observed SERVFAILs).
func (r *Resolver) CurrentBudgets() (time.Duration, time.Duration) { return r.budgets() }

// budgets derives the per-attempt wait and the total exchange
// budget from the path RTT (NP-1118-19). The per-attempt wait
// never drops below the ctor base timeout; the total is clamped
// to [8s, 20s] so a slow answer beats no answer on multi-second
// paths, while a dead path still fails in bounded time.
func (r *Resolver) budgets() (perAttempt, total time.Duration) {
	cost := r.pathCost()
	base := r.timeout
	if base <= 0 {
		base = 5 * time.Second
	}
	perAttempt = cost + time.Second
	if perAttempt < base {
		perAttempt = base
	}
	if perAttempt > 12*time.Second {
		perAttempt = 12 * time.Second
	}
	total = cost*3/2 + base
	if total < 8*time.Second {
		total = 8 * time.Second
	}
	if total > 20*time.Second {
		total = 20 * time.Second
	}
	if total < perAttempt {
		total = perAttempt
	}
	return perAttempt, total
}

// noteTimeout records a censored cost sample: an attempt waited
// this long and got nothing, so the path costs more than this.
func (r *Resolver) noteTimeout(waited time.Duration) {
	ms := waited.Milliseconds()
	for {
		cur := r.timeoutLbMs.Load()
		if ms <= cur || r.timeoutLbMs.CompareAndSwap(cur, ms) {
			return
		}
	}
}

func (r *Resolver) noteExchangeDuration(d time.Duration) {
	ms := d.Milliseconds()
	if ms <= 0 {
		return
	}
	for {
		cur := r.ewmaMs.Load()
		next := ms
		if cur > 0 {
			next = (cur*7 + ms*3) / 10
		}
		if r.ewmaMs.CompareAndSwap(cur, next) {
			return
		}
	}
}

// register ensures the upstream connection and parks the query.
func (r *Resolver) register(query []byte) (net.Conn, chan struct{}, uint16, *pending, error) {
	r.mu.Lock()
	start := r.nextTry
	r.mu.Unlock()
	return r.registerFrom(query, start, true)
}

// registerFrom is register with an explicit dial start index.
// sticky establishments (the query's first attempt) move the
// cross-query winner (nextTry) to the dialer that connected;
// failover attempts inside one query do not.
func (r *Resolver) registerFrom(query []byte, startIdx int, sticky bool) (net.Conn, chan struct{}, uint16, *pending, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		// Try every upstream once, starting from startIdx.
		var c net.Conn
		var err error
		for k := 0; k < len(r.dialers); k++ {
			idx := (startIdx + k) % len(r.dialers)
			c, err = r.dialers[idx]()
			if err == nil {
				r.upIdx = idx
				if sticky {
					r.nextTry = idx // stick with the winner until it dies
				}
				break
			}
		}
		if err != nil {
			return nil, nil, 0, nil, fmt.Errorf("upstream dial: %w", err)
		}
		r.conn = c
		r.dieCh = make(chan struct{})
		atomic.AddUint64(&r.conns, 1)
		go r.readLoop(c, r.dieCh)
	}
	// Allocate an upstream ID not currently in flight (queries whose
	// original ID collides are rewritten, mapped back on the way out).
	origID := binary.BigEndian.Uint16(query[0:2])
	for {
		r.nextID++
		if _, taken := r.pending[r.nextID]; !taken {
			break
		}
	}
	p := &pending{origID: origID, resp: make(chan []byte, 1)}
	r.pending[r.nextID] = p
	return r.conn, r.dieCh, r.nextID, p, nil
}

func (r *Resolver) deregister(upID uint16, p *pending) {
	r.mu.Lock()
	if cur, ok := r.pending[upID]; ok && cur == p {
		delete(r.pending, upID)
	}
	r.mu.Unlock()
}

// readLoop demultiplexes upstream answers until the connection dies;
// death fails every in-flight query (their Exchange selects on dieCh).
func (r *Resolver) readLoop(conn net.Conn, dieCh chan struct{}) {
	defer r.killConn(conn, true)
	hdr := make([]byte, 2)
	for {
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr))
		if n < 12 || n > 65535 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		upID := binary.BigEndian.Uint16(msg[0:2])
		r.mu.Lock()
		p, ok := r.pending[upID]
		if ok {
			delete(r.pending, upID)
		}
		r.mu.Unlock()
		if !ok {
			continue // late answer for a timed-out query: drop
		}
		binary.BigEndian.PutUint16(msg[0:2], p.origID)
		select {
		case p.resp <- msg:
		default:
		}
	}
}

// killConn tears down the current connection (idempotent per conn) and
// wakes all in-flight exchanges so they SERVFAIL promptly. With
// demote set, the next establishment starts AFTER the dialer
// whose connection died (NP-1118-14 failover advance); without
// it — a mere timeout (NP-1118-19) — the winner keeps its place:
// slow is not dead, and a slow-but-alive upstream must not lose
// its ranking for answering late.
func (r *Resolver) killConn(conn net.Conn, demote bool) {
	r.mu.Lock()
	if r.conn != conn {
		r.mu.Unlock()
		return
	}
	r.conn = nil
	dieCh := r.dieCh
	r.dieCh = nil
	if demote && len(r.dialers) > 0 {
		r.nextTry = (r.upIdx + 1) % len(r.dialers)
	}
	r.mu.Unlock()
	conn.Close()
	if dieCh != nil {
		close(dieCh)
	}
}

// Close shuts the resolver down (helper teardown).
func (r *Resolver) Close() {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn != nil {
		r.killConn(conn, true)
	}
}

func writeAll(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

// servfailFor synthesizes a SERVFAIL response echoing the query's
// question: QR set, RCODE=2, counts zeroed beyond the question section.
func servfailFor(query []byte) []byte {
	if len(query) < 12 {
		// Not even a header: answer with a bare FORMERR-style header.
		out := make([]byte, 12)
		out[2] = 0x80 // QR
		out[3] = 0x82 // RA + SERVFAIL
		return out
	}
	end := questionEnd(query)
	out := make([]byte, end)
	copy(out, query[:end])
	out[2] |= 0x80        // QR (opcode and RD pass through from the query)
	out[3] = 0x80 | 0x02  // RA + RCODE SERVFAIL (drop Z/AD/CD)
	out[6], out[7] = 0, 0 // ANCOUNT
	out[8], out[9] = 0, 0 // NSCOUNT
	out[10], out[11] = 0, 0
	return out
}

// questionEnd returns the offset just past the question section, or the
// header length when the question cannot be walked.
func questionEnd(msg []byte) int {
	if len(msg) < 12 {
		return len(msg)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	off := 12
	for i := 0; i < qd; i++ {
		for {
			if off >= len(msg) {
				return 12
			}
			l := int(msg[off])
			off++
			if l == 0 {
				break
			}
			if l&0xC0 == 0xC0 { // compression pointer (shouldn't appear in queries)
				off++
				break
			}
			off += l
		}
		off += 4 // QTYPE + QCLASS
	}
	if off > len(msg) {
		return 12
	}
	return off
}

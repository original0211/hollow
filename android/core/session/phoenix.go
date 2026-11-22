// Phoenix connections (NP-1118-30, design NP-1118-28 layer 1):
// a stream that dies BEFORE its first inbound byte is
// transparently reopened on a fresh carrier and the buffered
// first flight replayed, so the pump's local TCP connection
// never breaks. No protocol change: the server sees ordinary
// independent connections. All knobs are local parameters.
package session

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Replay buffer hard cap: a TLS ClientHello is ~0.5-2 KiB,
	// an HTTP request head rarely exceeds 16 KiB; 64 KiB covers
	// the establishment flight with margin. Overflow drops the
	// stream out of the protected set.
	phoenixBufferCap = 64 * 1024
	// At most 2 reopens (3 streams total) per flow.
	phoenixMaxReopens = 2
	// Session breaker: 5 fast pre-first-byte reopen deaths
	// inside 30s open it for 60s (deterministic-death targets
	// must not triple every flow's failure latency forever).
	phoenixBreakerThreshold = 5
	phoenixBreakerWindow    = 30 * time.Second
	phoenixBreakerCooldown  = 60 * time.Second
	// NP-1118-48: the establishment window and the fast-death
	// bar scale with the measured path cost (NP-1118-46: at
	// device RTTs a fixed 15s window holds only ~2.2 attempts,
	// and a fixed 2s fast-death bar sits BELOW the natural
	// death latency of a reopened stream, so the breaker
	// almost never trips on deterministic targets). The floors
	// are the pre-NP-1118-48 constants, so a zero/unknown cost
	// reproduces the old behavior exactly.
	phoenixWindowFloor    = 15 * time.Second
	phoenixWindowCap      = 45 * time.Second
	phoenixFastDeathFloor = 2 * time.Second
	phoenixFastDeathCap   = 10 * time.Second
)

// phoenixWindowFor is the establishment window at a given path
// cost: clamp(3*cost + 5s, 15s, 45s). At cost 0 it is exactly
// the historical 15s.
func phoenixWindowFor(cost time.Duration) time.Duration {
	w := 3*cost + 5*time.Second
	if w < phoenixWindowFloor {
		return phoenixWindowFloor
	}
	if w > phoenixWindowCap {
		return phoenixWindowCap
	}
	return w
}

// phoenixFastDeathFor is the breaker's fast-death bar at a
// given path cost: clamp(1.5*cost, 2s, 10s). At cost 0 it is
// exactly the historical 2s.
func phoenixFastDeathFor(cost time.Duration) time.Duration {
	f := (cost * 3) / 2
	if f < phoenixFastDeathFloor {
		return phoenixFastDeathFloor
	}
	if f > phoenixFastDeathCap {
		return phoenixFastDeathCap
	}
	return f
}

// phoenixBreaker is the session-wide futility guard.
type phoenixBreaker struct {
	mu            sync.Mutex
	fastDeaths    int
	lastFastDeath time.Time
	openUntil     time.Time
	trips         int64
	// Path-cost estimate (NP-1118-48), mirroring the DNS
	// resolver's pathCost structure: the max of an EWMA of
	// resolved attempt durations (dial start -> first byte or
	// -> death; a death is a censored sample — the attempt
	// provably consumed that much wall time) and an EWMA of
	// bare dial durations as a seed that exists before any
	// attempt resolves.
	attemptCostMs atomic.Int64
	dialCostMs    atomic.Int64
}

// noteAttemptCost folds one resolved attempt's duration into
// the EWMA (0.7 old / 0.3 new, as the DNS resolver uses).
func (b *phoenixBreaker) noteAttemptCost(d time.Duration) {
	ms := d.Milliseconds()
	for {
		cur := b.attemptCostMs.Load()
		next := ms
		if cur > 0 {
			next = (7*cur + 3*ms) / 10
		}
		if b.attemptCostMs.CompareAndSwap(cur, next) {
			return
		}
	}
}

// noteDialCost seeds the cost estimate with a bare dial
// duration (dial start -> stream open).
func (b *phoenixBreaker) noteDialCost(d time.Duration) {
	ms := d.Milliseconds()
	for {
		cur := b.dialCostMs.Load()
		next := ms
		if cur > 0 {
			next = (7*cur + 3*ms) / 10
		}
		if b.dialCostMs.CompareAndSwap(cur, next) {
			return
		}
	}
}

// cost is the current path-cost estimate (0 = unknown, which
// reproduces the pre-NP-1118-48 fixed parameters).
func (b *phoenixBreaker) cost() time.Duration {
	ms := b.attemptCostMs.Load()
	if d := b.dialCostMs.Load(); d > ms {
		ms = d
	}
	return time.Duration(ms) * time.Millisecond
}

func (b *phoenixBreaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().After(b.openUntil)
}

func (b *phoenixBreaker) noteFastDeath() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if now.Sub(b.lastFastDeath) > phoenixBreakerWindow {
		b.fastDeaths = 0
	}
	b.fastDeaths++
	b.lastFastDeath = now
	if b.fastDeaths >= phoenixBreakerThreshold {
		b.openUntil = now.Add(phoenixBreakerCooldown)
		b.trips++
		b.fastDeaths = 0
	}
}

func (b *phoenixBreaker) noteSuccess() {
	b.mu.Lock()
	b.fastDeaths = 0
	b.mu.Unlock()
}

var idempotentMethods = []string{"GET", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"}

// replayableFlight decides whether the buffered first flight
// may be replayed onto a fresh stream (design §1.2): nothing
// sent is always safe; a TLS record is always safe (the peer
// committed no application state before answering); plaintext
// HTTP only for idempotent methods; anything opaque is not
// replayed. An incomplete prefix is replayable only while it
// can still become a TLS record or an idempotent method — a
// complete non-idempotent request can never hide in a prefix
// without its terminating space.
func replayableFlight(buf []byte) bool {
	if len(buf) == 0 {
		return true
	}
	if buf[0] == 0x16 { // TLS handshake record
		return len(buf) == 1 || buf[1] == 0x03
	}
	sp := bytes.IndexByte(buf, ' ')
	if sp < 0 {
		for _, m := range idempotentMethods {
			if len(buf) < len(m) && m[:len(buf)] == string(buf) {
				return true
			}
		}
		return false
	}
	for _, m := range idempotentMethods {
		if string(buf[:sp]) == m {
			return true
		}
	}
	return false
}

// phoenixConn wraps the pump-facing stream connection.
type phoenixConn struct {
	sess   *Session
	ip     net.IP
	port   uint16
	remote net.Addr

	mu           sync.Mutex
	cur          net.Conn
	curBorn      time.Time
	attemptStart time.Time // dial start of the current attempt
	buf          []byte
	protected    bool
	firstByte    bool
	attempts     int
	startedAt    time.Time
	closed       bool
	failErr      error
	deadline     time.Time
}

// dialFlowPhoenix is the pump's TCP dialer: dialFlow plus the
// phoenix wrapper. (DNS keeps the raw dialFlow — resolver
// exchanges have their own failover and are out of layer 1's
// scope per the design.)
func (s *Session) dialFlowPhoenix(ip net.IP, port uint16) (net.Conn, error) {
	start := time.Now()
	first, err := s.dialFlow(ip, port)
	if err != nil {
		return nil, err
	}
	s.phx.noteDialCost(time.Since(start))
	return &phoenixConn{
		sess: s, ip: ip, port: port, remote: first.RemoteAddr(),
		cur: first, curBorn: time.Now(), attemptStart: start,
		protected: true, startedAt: start,
	}, nil
}

// errPhoenixGapWrite is returned for a write that lands in the
// redial gap after replay protection has ended (NP-1118-66 S5).
var errPhoenixGapWrite = errors.New("phoenix: write during redial gap after replay protection ended")

func (c *phoenixConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.failErr != nil {
		return 0, c.failErr
	}
	if c.protected {
		c.buf = append(c.buf, b...)
		if len(c.buf) > phoenixBufferCap {
			c.protected = false
			c.buf = nil
		}
	}
	if c.cur != nil {
		c.cur.Write(b) // streamConn.Write never errors; death surfaces on Read
		return len(b), nil
	}
	if c.protected {
		return len(b), nil // buffered above; replayed on install
	}
	// NP-1118-66 (S5): mid-redial with protection already ended —
	// the chunk would be discarded. Surface it as a write error
	// (the pump's ordinary failure path) instead of reporting
	// success for bytes that go nowhere.
	return 0, errPhoenixGapWrite
}

func (c *phoenixConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if c.failErr != nil {
			err := c.failErr
			c.mu.Unlock()
			return 0, err
		}
		cur := c.cur
		c.mu.Unlock()
		if cur == nil {
			return 0, io.EOF
		}
		n, err := cur.Read(b)
		if n > 0 {
			c.mu.Lock()
			if !c.firstByte {
				c.firstByte = true
				c.protected = false
				c.buf = nil
				c.sess.phx.noteAttemptCost(time.Since(c.attemptStart))
				if c.attempts > 0 {
					c.sess.phxSaved.Add(1)
					c.sess.phx.noteSuccess()
				}
			}
			c.mu.Unlock()
			return n, nil
		}
		if err == nil {
			continue
		}
		if !c.handleDeath(cur) {
			return 0, io.EOF
		}
	}
}

// handleDeath processes the death of cur: reopen + replay when
// eligible, else fail the connection with the pre-NP-1118-30
// semantics (EOF). Returns true when a fresh stream is live.
func (c *phoenixConn) handleDeath(cur net.Conn) bool {
	c.mu.Lock()
	if c.cur != cur { // defensive; the pump runs a single reader
		ok := c.failErr == nil && !c.closed && c.cur != nil
		c.mu.Unlock()
		return ok
	}
	c.cur = nil
	// The death itself is cost evidence: fold it in BEFORE the
	// eligibility checks so this flow's own window reflects
	// what its attempts actually cost (NP-1118-48).
	c.sess.phx.noteAttemptCost(time.Since(c.attemptStart))
	cost := c.sess.phx.cost()
	fastDeath := c.attempts > 0 && time.Since(c.curBorn) < phoenixFastDeathFor(cost)
	eligible := !c.closed && !c.firstByte && c.protected &&
		c.attempts < phoenixMaxReopens &&
		time.Since(c.startedAt) < phoenixWindowFor(cost) &&
		replayableFlight(c.buf) && c.sess.phx.allow()
	c.mu.Unlock()
	if fastDeath {
		c.sess.phx.noteFastDeath()
	}
	if !eligible {
		c.mu.Lock()
		c.failErr = io.EOF
		c.mu.Unlock()
		return false
	}
	// Redial, retrying while the establishment window lasts: a
	// dial that fails because every lineage is mid-recovery has
	// not consumed a reopen — only a stream that actually opens
	// counts as one. The window bounds the wait.
	var nc net.Conn
	redialStart := time.Now()
	for {
		var err error
		nc, err = c.sess.dialFlow(c.ip, c.port)
		if err == nil {
			break
		}
		if time.Since(c.startedAt) > phoenixWindowFor(c.sess.phx.cost()) {
			c.mu.Lock()
			c.failErr = io.EOF
			c.mu.Unlock()
			return false
		}
		time.Sleep(400 * time.Millisecond)
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return false
		}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		nc.Close()
		return false
	}
	c.attempts++
	c.sess.phxReopens.Add(1)
	c.sess.phx.noteDialCost(time.Since(redialStart))
	c.cur = nc
	c.curBorn = time.Now()
	c.attemptStart = redialStart
	if !c.deadline.IsZero() {
		nc.SetReadDeadline(c.deadline)
	}
	// Replay the whole current buffer: bytes written while the
	// redial was in flight were appended to buf and forwarded
	// nowhere (cur was nil), so buf is exactly the unsent-on-
	// this-stream prefix, in order.
	if len(c.buf) > 0 {
		nc.Write(c.buf)
	}
	c.mu.Unlock()
	return true
}

func (c *phoenixConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cur := c.cur
	c.cur = nil
	c.mu.Unlock()
	if cur != nil {
		return cur.Close()
	}
	return nil
}

func (c *phoenixConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("10.99.0.1"), Port: 0}
}
func (c *phoenixConn) RemoteAddr() net.Addr { return c.remote }

func (c *phoenixConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}

func (c *phoenixConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	cur := c.cur
	c.mu.Unlock()
	if cur != nil {
		return cur.SetReadDeadline(t)
	}
	return nil
}

func (c *phoenixConn) SetWriteDeadline(time.Time) error { return nil }

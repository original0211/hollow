// Phoenix connections (NP-1118-30, design NP-1118-28 layer 1):
// a stream that dies BEFORE its first inbound byte is
// transparently reopened on a fresh carrier and the buffered
// first flight replayed, so the pump's local TCP connection
// never breaks. No protocol change: the server sees ordinary
// independent connections. All knobs are local parameters.
package session

import (
	"bytes"
	"io"
	"net"
	"sync"
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
	// Reopens only inside a 15s establishment window from the
	// first dial — a flow still unborn after that fails as
	// before instead of dragging its failure out.
	phoenixEstablishWindow = 15 * time.Second
	// Session breaker: 5 fast pre-first-byte reopen deaths
	// inside 30s open it for 60s (deterministic-death targets
	// must not triple every flow's failure latency forever).
	phoenixBreakerThreshold = 5
	phoenixBreakerWindow    = 30 * time.Second
	phoenixBreakerCooldown  = 60 * time.Second
	phoenixFastDeath        = 2 * time.Second
)

// phoenixBreaker is the session-wide futility guard.
type phoenixBreaker struct {
	mu            sync.Mutex
	fastDeaths    int
	lastFastDeath time.Time
	openUntil     time.Time
	trips         int64
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

	mu        sync.Mutex
	cur       net.Conn
	curBorn   time.Time
	buf       []byte
	protected bool
	firstByte bool
	attempts  int
	startedAt time.Time
	closed    bool
	failErr   error
	deadline  time.Time
}

// dialFlowPhoenix is the pump's TCP dialer: dialFlow plus the
// phoenix wrapper. (DNS keeps the raw dialFlow — resolver
// exchanges have their own failover and are out of layer 1's
// scope per the design.)
func (s *Session) dialFlowPhoenix(ip net.IP, port uint16) (net.Conn, error) {
	first, err := s.dialFlow(ip, port)
	if err != nil {
		return nil, err
	}
	return &phoenixConn{
		sess: s, ip: ip, port: port, remote: first.RemoteAddr(),
		cur: first, curBorn: time.Now(), protected: true, startedAt: time.Now(),
	}, nil
}

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
	}
	return len(b), nil
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
	fastDeath := c.attempts > 0 && time.Since(c.curBorn) < phoenixFastDeath
	eligible := !c.closed && !c.firstByte && c.protected &&
		c.attempts < phoenixMaxReopens &&
		time.Since(c.startedAt) < phoenixEstablishWindow &&
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
	for {
		var err error
		nc, err = c.sess.dialFlow(c.ip, c.port)
		if err == nil {
			break
		}
		if time.Since(c.startedAt) > phoenixEstablishWindow {
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
	c.cur = nc
	c.curBorn = time.Now()
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

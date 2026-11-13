// Package dns is the helper's tunnelled resolver (TUN notes v2 §4,
// mandatory change E): DNS queries captured on the TUN adapter are
// forwarded as DNS-over-TCP THROUGH the app's SOCKS listener (i.e. inside
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
// this dials through SOCKS; tests inject direct dials.
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
	dial    DialFunc
	timeout time.Duration

	mu      sync.Mutex
	conn    net.Conn
	dieCh   chan struct{} // closed when the current conn dies
	pending map[uint16]*pending
	nextID  uint16

	queries  uint64
	resolved uint64
	servfail uint64
	conns    uint64
}

// NewResolver builds a resolver. timeout is per-query (spec: 5s).
func NewResolver(dial DialFunc, timeout time.Duration) *Resolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		dial:    dial,
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
	conn, dieCh, upID, p, err := r.register(query)
	if err != nil {
		atomic.AddUint64(&r.servfail, 1)
		return servfailFor(query)
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
		r.killConn(conn)
		atomic.AddUint64(&r.servfail, 1)
		return servfailFor(query)
	}
	timer := time.NewTimer(r.timeout)
	defer timer.Stop()
	select {
	case resp := <-p.resp:
		atomic.AddUint64(&r.resolved, 1)
		return resp
	case <-dieCh:
		r.deregister(upID, p)
		atomic.AddUint64(&r.servfail, 1)
		return servfailFor(query)
	case <-timer.C:
		r.deregister(upID, p)
		atomic.AddUint64(&r.servfail, 1)
		return servfailFor(query)
	}
}

// register ensures the upstream connection and parks the query.
func (r *Resolver) register(query []byte) (net.Conn, chan struct{}, uint16, *pending, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		c, err := r.dial()
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
	defer r.killConn(conn)
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
// wakes all in-flight exchanges so they SERVFAIL promptly.
func (r *Resolver) killConn(conn net.Conn) {
	r.mu.Lock()
	if r.conn != conn {
		r.mu.Unlock()
		return
	}
	r.conn = nil
	dieCh := r.dieCh
	r.dieCh = nil
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
		r.killConn(conn)
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

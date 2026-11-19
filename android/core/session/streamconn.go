// streamConn adapts a core ClientStream to net.Conn so the pump and the
// DNS resolver can treat a Hollow stream as an ordinary connection.
package session

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"hollow/androidcore/core"
)

type streamConn struct {
	stream *core.ClientStream
	remote net.Addr

	mu       sync.Mutex
	cond     *sync.Cond
	queue    [][]byte
	readEOF  bool
	closed   bool
	deadline time.Time
}

func newStreamConn(stream *core.ClientStream, remote net.Addr) *streamConn {
	c := &streamConn{stream: stream, remote: remote}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// callbacks returns the stream event handlers wired to this
// conn, for installation at stream construction via
// OpenStreamWithCallbacks (see core.StreamCallbacks).
func (c *streamConn) callbacks() *core.StreamCallbacks {
	end := func() {
		c.mu.Lock()
		c.readEOF = true
		c.mu.Unlock()
		c.cond.Broadcast()
	}
	return &core.StreamCallbacks{
		OnData: func(d []byte) {
			c.mu.Lock()
			if !c.closed {
				c.queue = append(c.queue, append([]byte(nil), d...))
			}
			c.mu.Unlock()
			c.cond.Broadcast()
		},
		OnEnd:   end,
		OnReset: func(byte) { end() },
		OnFail:  func(string) { end() },
	}
}

// bind attaches the stream created with this conn's callbacks.
func (c *streamConn) bind(stream *core.ClientStream) {
	c.stream = stream
}

func (c *streamConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if len(c.queue) > 0 {
			head := c.queue[0]
			n := copy(b, head)
			if n == len(head) {
				c.queue = c.queue[1:]
			} else {
				c.queue[0] = head[n:]
			}
			return n, nil
		}
		if c.readEOF || c.closed {
			return 0, io.EOF
		}
		if !c.deadline.IsZero() && time.Until(c.deadline) <= 0 {
			return 0, errTimeout
		}
		// Deadlines are only honored at wake points (data / EOF / close);
		// the pump's splice uses no deadlines and the DNS layer enforces
		// its own per-query timeout above this conn, so a cond wait is
		// sufficient (noted divergence from socket semantics).
		c.cond.Wait()
	}
}

var errTimeout = &net.OpError{Op: "read", Err: errors.New("i/o timeout")}

func (c *streamConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	c.stream.Write(b)
	return len(b), nil
}

func (c *streamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.stream.CloseWrite()
	c.cond.Broadcast()
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.ParseIP("10.99.0.1"), Port: 0} }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}

func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

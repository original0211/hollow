package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
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

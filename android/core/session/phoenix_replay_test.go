package session

// NP-1118-48: the NP-1118-46 diagnosis replay, productized as
// permanent regression grids. A delay proxy gives every
// protocol round trip ~2.2s (the real device's headline RTT),
// a pool of 1 keeps carriers deterministic, and the flight is
// TLS-shaped so it is always replayable.
//
// Grids:
//   - transient single death: must save (both eras).
//   - transient DOUBLE death: must save — only the cost-scaled
//     window fits three ~5-7s attempts (the fixed 15s window
//     held ~2.2); this is fix A's discrimination grid.
//   - churn (carrier dies every ~4s): must save.
//   - deterministic post-flight kill (the SNI-guard shape):
//     nothing can save these; with the cost-scaled fast-death
//     bar the breaker must trip during warmup flows, after
//     which a flow fails FAST (no reopens, bounded elapsed)
//     instead of burning ~13s x 3 streams. Fix B's grid.

import (
	"io"
	"net"
	"testing"
	"time"
)

type phxDelayProxy struct {
	ln     net.Listener
	target string
	delay  time.Duration
}

func newPhxDelayProxy(t *testing.T, target string, delay time.Duration) *phxDelayProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &phxDelayProxy{ln: ln, target: target, delay: delay}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *phxDelayProxy) handle(c net.Conn) {
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		c.Close()
		return
	}
	shovel := func(dst, src net.Conn) {
		buf := make([]byte, 65536)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				time.Sleep(p.delay)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				dst.Close()
				src.Close()
				return
			}
		}
	}
	go shovel(up, c)
	go shovel(c, up)
}

func (p *phxDelayProxy) wsURL() string { return "ws://" + p.ln.Addr().String() }

var phxFlight = append([]byte{0x16, 0x03, 0x01, 0x00, 0x2e}, []byte("client-hello-body")...)

func phxReadOutcome(conn net.Conn, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				done <- nil
				return
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		return time.Since(start), err
	case <-time.After(timeout):
		return time.Since(start), io.ErrClosedPipe
	}
}

func phxWaitReceived(t *testing.T, ps *phxServer, idx, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ps.streamCount() > idx {
			s := ps.stream(idx)
			s.mu.Lock()
			got := len(s.received)
			s.mu.Unlock()
			if got >= n {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("stream %d never received %d bytes", idx, n)
}

func newPhxReplaySession(t *testing.T) (*phxServer, *Session) {
	t.Helper()
	psk := testPSK()
	ps := newPhxServer(t, psk)
	proxy := newPhxDelayProxy(t, ps.srv.Listener.Addr().String(), 1100*time.Millisecond)
	sess := newTestPoolSession(proxy.wsURL(), psk, 1)
	establishAll(t, sess)
	t.Cleanup(sess.Stop)
	startWatchdogs(sess)
	return ps, sess
}

func phxTrips(s *Session) int64 {
	s.phx.mu.Lock()
	defer s.phx.mu.Unlock()
	return s.phx.trips
}

func TestPhoenixReplayTransientSaves(t *testing.T) {
	ps, sess := newPhxReplaySession(t)
	conn, err := sess.dialFlowPhoenix(net.ParseIP("10.0.0.9"), 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(phxFlight); err != nil {
		t.Fatal(err)
	}
	phxWaitReceived(t, ps, 0, len(phxFlight))
	ps.killStreamCarrier(0)
	ps.echoOn.Store(true)
	elapsed, rerr := phxReadOutcome(conn, 60*time.Second)
	if rerr != nil || sess.phxSaved.Load() != 1 {
		t.Fatalf("transient: elapsed=%v err=%v saved=%d reopens=%d, want saved=1",
			elapsed, rerr, sess.phxSaved.Load(), sess.phxReopens.Load())
	}
	t.Logf("transient saved in %v", elapsed)
}

// Fix A's discrimination grid: TWO carrier deaths during one
// establishment. Three attempts at ~5-7s each cannot fit the
// old fixed 15s window; the cost-scaled window (cost learned
// from the first death, ~5-6s -> window ~20-23s) must fit them.
func TestPhoenixReplayDoubleDeathSaves(t *testing.T) {
	ps, sess := newPhxReplaySession(t)
	conn, err := sess.dialFlowPhoenix(net.ParseIP("10.0.0.9"), 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(phxFlight); err != nil {
		t.Fatal(err)
	}
	// The reader must be running from the start: phoenix is
	// Read-driven (in production the pump reads continuously),
	// so a death is only noticed — and a reopen only begun —
	// once a Read is in flight.
	type outcome struct {
		elapsed time.Duration
		err     error
	}
	outCh := make(chan outcome, 1)
	go func() {
		e, err := phxReadOutcome(conn, 90*time.Second)
		outCh <- outcome{e, err}
	}()
	phxWaitReceived(t, ps, 0, len(phxFlight))
	ps.killStreamCarrier(0)
	phxWaitReceived(t, ps, 1, len(phxFlight))
	ps.killStreamCarrier(1)
	ps.echoOn.Store(true)
	out := <-outCh
	elapsed, rerr := out.elapsed, out.err
	if rerr != nil || sess.phxSaved.Load() != 1 {
		t.Fatalf("double death: elapsed=%v err=%v saved=%d reopens=%d cost=%v window=%v, want saved=1",
			elapsed, rerr, sess.phxSaved.Load(), sess.phxReopens.Load(),
			sess.phx.cost(), phoenixWindowFor(sess.phx.cost()))
	}
	if elapsed < 15*time.Second {
		t.Fatalf("double death saved in %v — impossibly fast for three attempts; grid not discriminating", elapsed)
	}
	t.Logf("double death saved in %v (cost %v, window %v)", elapsed, sess.phx.cost(), phoenixWindowFor(sess.phx.cost()))
}

func TestPhoenixReplayChurnSaves(t *testing.T) {
	ps, sess := newPhxReplaySession(t)
	ps.echoOn.Store(true)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		killed := -1
		for {
			select {
			case <-stop:
				return
			case <-time.After(4 * time.Second):
				if n := ps.streamCount(); n > 0 && n-1 != killed {
					ps.killStreamCarrier(n - 1)
					killed = n - 1
				}
			}
		}
	}()
	conn, err := sess.dialFlowPhoenix(net.ParseIP("10.0.0.9"), 443)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(phxFlight); err != nil {
		t.Fatal(err)
	}
	elapsed, rerr := phxReadOutcome(conn, 60*time.Second)
	if rerr != nil || sess.phxSaved.Load() != 1 {
		t.Fatalf("churn: elapsed=%v err=%v saved=%d reopens=%d, want saved=1",
			elapsed, rerr, sess.phxSaved.Load(), sess.phxReopens.Load())
	}
	t.Logf("churn saved in %v", elapsed)
}

// Fix B's grid: deterministic post-flight kills. Warmup flows
// burn their reopens (nothing can save a deterministic kill),
// but their reopened streams die ~2.5-4s after birth — under
// the OLD fixed 2s bar those were not "fast" deaths and the
// breaker effectively never tripped (NP-1118-46: 1 trip per 3
// flows, every flow ~13s). With the bar scaled to the learned
// cost (~5-6s -> bar ~8-9s) the breaker must trip during the
// warmup, and the post-trip flow must fail with ZERO reopens
// inside a bound far below the ~13s baseline.
func TestPhoenixReplayDeterministicFastFail(t *testing.T) {
	ps, sess := newPhxReplaySession(t)
	runFlow := func(flow int) (time.Duration, int64) {
		establishAll(t, sess)
		base := ps.streamCount()
		reopensBefore := sess.phxReopens.Load()
		conn, err := sess.dialFlowPhoenix(net.ParseIP("10.0.0.9"), 443)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(phxFlight); err != nil {
			t.Fatal(err)
		}
		go func() {
			for i := 0; i < 3; i++ {
				phxWaitReceived(t, ps, base+i, len(phxFlight))
				ps.killStreamCarrier(base + i)
			}
		}()
		elapsed, _ := phxReadOutcome(conn, 90*time.Second)
		conn.Close()
		return elapsed, sess.phxReopens.Load() - reopensBefore
	}
	for flow := 0; flow < 3; flow++ {
		elapsed, reopens := runFlow(flow)
		if sess.phxSaved.Load() != 0 {
			t.Fatalf("flow %d: saved=%d, deterministic kills must never save", flow, sess.phxSaved.Load())
		}
		t.Logf("warmup flow %d: elapsed=%v reopens=%d trips=%d cost=%v fastBar=%v",
			flow, elapsed, reopens, phxTrips(sess), sess.phx.cost(), phoenixFastDeathFor(sess.phx.cost()))
	}
	if sess.phx.trips < 1 {
		t.Fatalf("breaker never tripped during warmup (trips=%d cost=%v)", phxTrips(sess), sess.phx.cost())
	}
	elapsed, reopens := runFlow(3)
	if reopens != 0 {
		t.Fatalf("post-trip flow reopened %d times, want 0 (breaker open)", reopens)
	}
	if elapsed > 9*time.Second {
		t.Fatalf("post-trip flow took %v, want <= 9s (baseline ~13s)", elapsed)
	}
	t.Logf("post-trip flow failed in %v with 0 reopens", elapsed)
}

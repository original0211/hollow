// Package session orchestrates one Android VPN session: WS carrier +
// core client + fd pump, with carrier rotation (§8.4 backoff) while the
// pump and its flow table stay put — the same split as the Windows
// helper/app pair, in one process.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"

	"hollow/androidcore/core"
	"hollow/androidcore/pump"
)

// Config is the session configuration (pairing-supplied; M3-3 fills it
// from the hollow:// payload, M3-2 defines the shape).
type Config struct {
	WSURL    string `json:"wsUrl"`    // full wss URL of the Worker endpoint
	PSK      []byte `json:"-"`        // raw PSK bytes (never serialized here)
	KeyID    int    `json:"keyId"`    // default 1
	MetaPath string `json:"metaPath"` // random-segment /meta path (may be empty)
	HostBase string `json:"hostBase"` // https base for /meta (may be empty)
}

type Session struct {
	cfg       Config
	protector Protector

	mu       sync.Mutex
	client   *core.HollowClient
	stopping bool
	pump     *pump.Pump

	stopCh  chan struct{} // closed on Stop
	deathCh chan struct{} // carrier deaths (buffered 1)
	tunFD   int           // owned once Start succeeds; closed by Stop

	// NP-1117-16 parity (NP-1118-03): budget / timed rotation.
	rotateCh chan struct{}  // rotation requests (buffered 1)
	rotateMu sync.Mutex     // serializes carrier rotations
	drains   map[*core.HollowClient]struct{} // swapped-out clients draining
	counters *byteCounters  // wire traffic (display only)
	lastRTT  time.Duration  // handshake RTT of the current carrier
	rotateEvery time.Duration // timed rotation interval (0 = 15 min)

	// UI-facing state machine (M3-4), guarded by mu: disconnected /
	// connecting / connected / error, plus the counters the status
	// surface presents. The error state surfaces via Start's return
	// (the facade keeps the reason); a live session is never in it.
	state     string
	detail    string
	sinceMs   int64
	carriers  int
	streamsOK int
}

// StateSnapshot is the session's presentation state (no internals).
type StateSnapshot struct {
	State     string
	Detail    string
	SinceMs   int64
	Carriers  int
	StreamsOK int
	// NP-1118-03 readings: wire bytes at the transport boundary,
	// the current carrier's handshake RTT, live/total carriers.
	TrafficUp   int64
	TrafficDown int64
	CarrierRTTMs int64
	LiveCarriers int
	PoolSize     int
}

// State reads the presentation snapshot.
func (s *Session) State() StateSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := StateSnapshot{State: s.state, Detail: s.detail, SinceMs: s.sinceMs, Carriers: s.carriers, StreamsOK: s.streamsOK, CarrierRTTMs: s.lastRTT.Milliseconds(), PoolSize: 1}
	if s.counters != nil {
		snap.TrafficUp = s.counters.up.Load()
		snap.TrafficDown = s.counters.down.Load()
	}
	if s.client != nil {
		snap.LiveCarriers = 1
	}
	return snap
}

var (
	errStopped   = errors.New("session stopped")
	errNoCarrier = errors.New("no live carrier")
)

// Start builds the pump on the TUN fd and the first carrier, and returns
// once the Hollow handshake is open. The pump is built FIRST so a failed
// handshake still leaves no half-attached data plane behind: on any
// error the whole session is torn down (fail-closed, plan §2).
func Start(cfg Config, tunFD int, protector Protector) (*Session, error) {
	if cfg.WSURL == "" || len(cfg.PSK) == 0 {
		return nil, errors.New("session: incomplete config (wsUrl/psk)")
	}
	if cfg.KeyID == 0 {
		cfg.KeyID = 1
	}
	s := &Session{cfg: cfg, protector: protector, stopCh: make(chan struct{}), deathCh: make(chan struct{}, 1), tunFD: tunFD, state: "connecting", rotateCh: make(chan struct{}, 1), counters: &byteCounters{}, drains: map[*core.HollowClient]struct{}{}}

	ep, err := fdbased.New(&fdbased.Options{FDs: []int{tunFD}, MTU: 1280})
	if err != nil {
		return nil, fmt.Errorf("session: fd endpoint: %w", err)
	}
	p, err := pump.NewPump(pump.Config{DialFlow: s.dialFlow}, ep)
	if err != nil {
		return nil, fmt.Errorf("session: pump: %w", err)
	}
	s.pump = p

	if err := s.rotateCarrier(context.Background()); err != nil {
		p.Close()
		return nil, err
	}
	go s.watchdog()
	return s, nil
}

// rotateCarrier dials a fresh carrier and handshakes it in, replacing
// any previous client (§8.4: the data plane persists across rotations).
// The replaced client is closed immediately (death path: it is dead
// or dying anyway).
func (s *Session) rotateCarrier(ctx context.Context) error {
	return s.rotate(ctx, false)
}

// rotateCarrierDrain is the NP-1117-16 build-then-swap rotation: the
// replacement is built and handshaken FIRST, the pointer swaps
// atomically, and the replaced client DRAINS — it closes when its
// stream table empties or after the 10-minute grace, whichever first.
func (s *Session) rotateCarrierDrain(ctx context.Context) error {
	return s.rotate(ctx, true)
}

// signalRotate requests a budget/timed rotation (non-blocking; safe
// on a nil channel and from the core event loop).
func (s *Session) signalRotate() {
	select {
	case s.rotateCh <- struct{}{}:
	default:
	}
}

func (s *Session) rotate(ctx context.Context, drainOld bool) error {
	s.rotateMu.Lock()
	defer s.rotateMu.Unlock()
	s.mu.Lock()
	if s.counters == nil {
		s.counters = &byteCounters{}
	}
	counters := s.counters
	s.mu.Unlock()
	dialStart := time.Now()
	tport, err := dialCarrier(ctx, s.cfg.WSURL, s.protector, counters)
	if err != nil {
		return fmt.Errorf("session: carrier dial: %w", err)
	}
	client := core.NewClient(tport, core.ClientOptions{PSK: s.cfg.PSK, KeyID: byte(s.cfg.KeyID)})
	client.OnOpenThreshold = s.signalRotate
	tport.attach(client)
	client.OnCarrierDead = func(reason string) {
		s.mu.Lock()
		if s.client == client {
			s.client = nil
			if !s.stopping {
				s.state, s.detail = "connecting", "承载中断，正在重连"
			}
		}
		stopping := s.stopping
		s.mu.Unlock()
		if !stopping {
			select {
			case s.deathCh <- struct{}{}:
			default:
			}
		}
	}
	done := client.Handshake()
	select {
	case <-done:
		if err := client.Err(); err != nil {
			tport.Close()
			return fmt.Errorf("session: handshake: %w", err)
		}
	case <-time.After(20 * time.Second):
		tport.Close()
		return errors.New("session: handshake timeout")
	case <-ctx.Done():
		tport.Close()
		return ctx.Err()
	}
	s.mu.Lock()
	old := s.client
	s.client = client
	s.carriers++
	s.lastRTT = time.Since(dialStart)
	if s.sinceMs == 0 {
		s.sinceMs = time.Now().UnixMilli()
	}
	s.state, s.detail = "connected", ""
	s.mu.Unlock()
	if old != nil {
		if drainOld {
			s.trackDrain(old)
		} else {
			old.Close()
		}
	}
	return nil
}

// trackDrain keeps a swapped-out client alive until its streams end
// or the 10-minute grace expires (NP-1117-16 drain semantics).
func (s *Session) trackDrain(c *core.HollowClient) {
	s.mu.Lock()
	if s.drains == nil {
		s.drains = map[*core.HollowClient]struct{}{}
	}
	s.drains[c] = struct{}{}
	s.mu.Unlock()
	go func() {
		deadline := time.Now().Add(10 * time.Minute)
		for {
			if c.ActiveStreams() == 0 || time.Now().After(deadline) {
				c.Close()
				s.mu.Lock()
				delete(s.drains, c)
				s.mu.Unlock()
				return
			}
			select {
			case <-s.stopCh:
				return // Stop closes drains itself
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
}

// watchdog re-dials dead carriers with the §8.4 backoff (1s doubling,
// capped 60s, ±25% jitter) until Stop. It also serves the NP-1117-16
// rotation triggers: the per-client OPEN budget (rotateCh, signalled
// by core at 40 opens) and the 15-minute timer — both take the
// build-then-swap drain path, and a failed rotation retries on a
// slow timer instead of disturbing the live carrier.
func (s *Session) watchdog() {
	if s.rotateCh == nil {
		s.rotateCh = make(chan struct{}, 1)
	}
	rotateEvery := s.rotateEvery
	if rotateEvery <= 0 {
		rotateEvery = 15 * time.Minute
	}
	ticker := time.NewTicker(rotateEvery)
	defer ticker.Stop()
	backoff := time.Second
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.rotateCh:
			if err := s.rotateCarrierDrain(context.Background()); err != nil {
				time.AfterFunc(5*time.Second, s.signalRotate)
			}
			continue
		case <-ticker.C:
			s.signalRotate()
			continue
		case <-s.deathCh:
		}
		for {
			jittered := time.Duration(float64(backoff) * (0.75 + 0.5*mathrand.Float64()))
			select {
			case <-s.stopCh:
				return
			case <-time.After(jittered):
			}
			if err := s.rotateCarrier(context.Background()); err == nil {
				backoff = time.Second
				break
			}
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}
}

// dialFlow is the pump's FlowDialer: open a core stream to ip:port on
// the current carrier (10s total open budget). Retry semantics mirror
// the Windows client (NP-1117-14 + NP-1117-16): an OPEN_REJECT with
// 0x01 (concurrency) retries on the SAME carrier with a fresh stream
// (250ms backoff doubling to 2s, ±25% jitter, retry_after as floor);
// a 0x06 on a carrier at/over its rotation threshold rotates the
// carrier (build-then-swap, old drains) and retries ONCE on the new
// carrier — at most one migration per dial.
func (s *Session) dialFlow(ip net.IP, port uint16) (net.Conn, error) {
	deadline := time.Now().Add(10 * time.Second)
	migrated := false
	backoff := 250 * time.Millisecond
	for {
		s.mu.Lock()
		client := s.client
		s.mu.Unlock()
		if client == nil {
			return nil, errNoCarrier
		}
		stream, err := client.OpenStream(ip.String(), int(port), core.SchemeUnknown, 0)
		if err != nil {
			return nil, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			stream.Reset(core.ErrStreamTimeout)
			return nil, errors.New("session: stream open timeout")
		}
		openErr := waitStreamOpen(stream, remaining)
		if openErr == nil {
			s.mu.Lock()
			s.streamsOK++
			s.mu.Unlock()
			return newStreamConn(stream, &net.TCPAddr{IP: ip, Port: int(port)}), nil
		}
		var rej *core.OpenRejectError
		if errors.As(openErr, &rej) {
			if rej.Code == core.ErrConcurrencyLimit && time.Now().Before(deadline) {
				wait := time.Duration(float64(backoff) * (0.75 + 0.5*mathrand.Float64()))
				if ra := time.Duration(rej.RetryAfterMs) * time.Millisecond; ra > wait {
					wait = ra
				}
				if wait > time.Until(deadline) {
					wait = time.Until(deadline)
				}
				select {
				case <-s.stopCh:
					return nil, errStopped
				case <-time.After(wait):
				}
				backoff *= 2
				if backoff > 2*time.Second {
					backoff = 2 * time.Second
				}
				continue
			}
			if rej.Code == core.ErrOutboundFailed && !migrated &&
				(client.OpensSent() >= core.SessionRotateThreshold || client.BudgetExhausted()) {
				migrated = true
				rctx, cancel := context.WithDeadline(context.Background(), deadline)
				rerr := s.rotateCarrierDrain(rctx)
				cancel()
				if rerr == nil {
					continue
				}
				return nil, openErr
			}
		}
		return nil, openErr
	}
}

// waitStreamOpen waits for a stream's open resolution with a timeout;
// on timeout the stream is reset (the pre-NP-1118-03 behavior).
func waitStreamOpen(stream *core.ClientStream, timeout time.Duration) error {
	type res struct {
		gate byte
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		gate, err := stream.WaitOpen()
		ch <- res{gate, err}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(timeout):
		stream.Reset(core.ErrStreamTimeout)
		return errors.New("session: stream open timeout")
	}
}

// FetchMeta performs the /meta landing identification fetch over the
// protected dialer (protect class 3) — auxiliary like on Windows: any
// error is the caller's to log, never fatal to the session.
func (s *Session) FetchMeta(ctx context.Context) (map[string]any, error) {
	if s.cfg.HostBase == "" || s.cfg.MetaPath == "" {
		return nil, errors.New("session: meta not configured")
	}
	tr := &http.Transport{DialContext: protectedDialContext(s.protector)}
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.HostBase+s.cfg.MetaPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ClientUA)
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Stats snapshots the pump counters for the status surface.
func (s *Session) Stats() pump.Stats {
	if s.pump == nil {
		return pump.Stats{}
	}
	return s.pump.Stats()
}

// Stop tears the session down: carrier first (flows fail fast), then
// the pump and its flow table.
func (s *Session) Stop() {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	client := s.client
	s.client = nil
	s.state, s.detail = "disconnected", ""
	s.mu.Unlock()
	close(s.stopCh)
	if client != nil {
		client.Close()
	}
	s.mu.Lock()
	drains := make([]*core.HollowClient, 0, len(s.drains))
	for c := range s.drains {
		drains = append(drains, c)
	}
	s.drains = map[*core.HollowClient]struct{}{}
	s.mu.Unlock()
	for _, c := range drains {
		c.Close()
	}
	if s.pump != nil {
		s.pump.Close()
	}
	// The fd endpoint does not own the fd (fdbased contract); the
	// session does, and closes it last, after the pump has stopped.
	if s.tunFD >= 0 {
		_ = syscall.Close(s.tunFD)
		s.tunFD = -1
	}
}

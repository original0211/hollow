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
	s := &Session{cfg: cfg, protector: protector, stopCh: make(chan struct{}), deathCh: make(chan struct{}, 1), tunFD: tunFD}

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
func (s *Session) rotateCarrier(ctx context.Context) error {
	tport, err := dialCarrier(ctx, s.cfg.WSURL, s.protector)
	if err != nil {
		return fmt.Errorf("session: carrier dial: %w", err)
	}
	client := core.NewClient(tport, core.ClientOptions{PSK: s.cfg.PSK, KeyID: byte(s.cfg.KeyID)})
	tport.attach(client)
	client.OnCarrierDead = func(reason string) {
		s.mu.Lock()
		if s.client == client {
			s.client = nil
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
	s.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

// watchdog re-dials dead carriers with the §8.4 backoff (1s doubling,
// capped 60s, ±25% jitter) until Stop.
func (s *Session) watchdog() {
	backoff := time.Second
	for {
		select {
		case <-s.stopCh:
			return
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
// the current carrier (10s open budget).
func (s *Session) dialFlow(ip net.IP, port uint16) (net.Conn, error) {
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
		if r.err != nil {
			return nil, r.err
		}
	case <-time.After(10 * time.Second):
		stream.Reset(core.ErrStreamTimeout)
		return nil, errors.New("session: stream open timeout")
	}
	return newStreamConn(stream, &net.TCPAddr{IP: ip, Port: int(port)}), nil
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
	s.mu.Unlock()
	close(s.stopCh)
	if client != nil {
		client.Close()
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

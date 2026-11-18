// Package session orchestrates one Android VPN session: a POOL of WS
// carriers (lineages) + core clients + the fd pump, with per-carrier
// rotation (§8.4 backoff, NP-1117-16 budget/timed rotation) while the
// pump and its flow table stay put — the Go counterpart of the JS
// SessionManager pool (NP-1117-23), in one process.
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/link/fdbased"

	"hollow/androidcore/core"
	"hollow/androidcore/pump"
)

// Config is the session configuration (pairing-supplied; M3-3 fills it
// from the hollow:// payload, M3-2 defines the shape).
type Config struct {
	WSURL     string `json:"wsUrl"`     // full wss URL of the Worker endpoint
	PSK       []byte `json:"-"`         // raw PSK bytes (never serialized here)
	KeyID     int    `json:"keyId"`     // default 1
	MetaPath  string `json:"metaPath"`  // random-segment /meta path (may be empty)
	HostBase  string `json:"hostBase"`  // https base for /meta (may be empty)
	EdgesPath string `json:"edgesPath"` // random-segment /edges.json path (may be empty)
	// BootstrapIPs seeds the entry hostname's last-known-good
	// address set (persisted by the facade); OnBootstrapIPs is
	// called when a fresh resolution changes the set (NP-1118-11).
	BootstrapIPs   []string
	OnBootstrapIPs func([]string)
	PoolSize       int `json:"poolSize"` // carriers in the pool; 0 = default, clamped 1-8
}

// DefaultPoolSize mirrors the JS pool default (NP-1117-23).
const DefaultPoolSize = 4

func (c Config) poolSize() int {
	n := c.PoolSize
	if n == 0 {
		n = DefaultPoolSize
	}
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// isAuthFatal mirrors the Windows bridge's AUTH_FATAL pattern: a
// handshake/authentication failure can never heal by redialing, so
// the whole pool stops instead of looping.
func isAuthFatal(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "undecryptable") ||
		strings.Contains(s, "server hello rejected") ||
		strings.Contains(s, "finished") ||
		strings.Contains(s, "verifier")
}

var (
	errStopped   = errors.New("session stopped")
	errNoCarrier = errors.New("no live carrier")
)

// ---------------------------------------------------------------------------
// lineage: one carrier's full lifecycle (the pre-pool Session's carrier
// machinery, scoped to a single client).
// ---------------------------------------------------------------------------

type lineage struct {
	pool *Session
	idx  int

	mu       sync.Mutex
	client   *core.HollowClient
	deathCh  chan struct{} // carrier deaths (buffered 1)
	rotateCh chan struct{} // rotation requests (buffered 1)
	rotateMu sync.Mutex    // serializes this lineage's rotations
	drains   map[*core.HollowClient]struct{}
	carriers int           // carriers established over this lineage's life
	lastRTT  time.Duration // handshake RTT of the current carrier
	fatal    bool          // auth-fatal: never redial again
}

func (l *lineage) currentClient() *core.HollowClient {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.client
}

// healthy reports whether this lineage currently holds a live client.
func (l *lineage) healthy() bool { return l.currentClient() != nil }

func (l *lineage) activeStreams() int64 {
	if c := l.currentClient(); c != nil {
		return c.ActiveStreams()
	}
	return 0
}

func (l *lineage) budgetSpent() bool {
	if c := l.currentClient(); c != nil {
		return c.OpensSent() >= core.SessionRotateThreshold || c.BudgetExhausted()
	}
	return false
}

// signalRotate requests a budget/timed rotation (non-blocking; safe
// on a nil channel and from the core event loop).
func (l *lineage) signalRotate() {
	select {
	case l.rotateCh <- struct{}{}:
	default:
	}
}

func (l *lineage) signalDeath() {
	select {
	case l.deathCh <- struct{}{}:
	default:
	}
}

// rotateCarrier replaces the client, closing the replaced one
// immediately (death path: it is dead or dying anyway).
func (l *lineage) rotateCarrier(ctx context.Context) error { return l.rotate(ctx, false) }

// rotateCarrierDrain is the NP-1117-16 build-then-swap rotation: the
// replacement is built and handshaken FIRST, the pointer swaps
// atomically, and the replaced client DRAINS — it closes when its
// stream table empties or after the 10-minute grace, whichever first.
func (l *lineage) rotateCarrierDrain(ctx context.Context) error { return l.rotate(ctx, true) }

func (l *lineage) rotate(ctx context.Context, drainOld bool) error {
	l.rotateMu.Lock()
	defer l.rotateMu.Unlock()
	if l.fatal {
		return errors.New("session: lineage stopped (auth fatal)")
	}
	dialStart := time.Now()
	pin := l.pool.pickSlotEdge(l.idx)
	tport, err := dialCarrier(ctx, l.pool.cfg.WSURL, l.pool.dialContext(), l.pool.counters, pin)
	if err != nil {
		l.pool.noteEdgeFailure(pin, err)
		return fmt.Errorf("session: carrier dial: %w", err)
	}
	client := core.NewClient(tport, core.ClientOptions{PSK: l.pool.cfg.PSK, KeyID: byte(l.pool.cfg.KeyID)})
	client.OnOpenThreshold = l.signalRotate
	tport.attach(client)
	client.OnCarrierDead = func(reason string) {
		l.mu.Lock()
		if l.client == client {
			l.client = nil
		}
		l.mu.Unlock()
		l.pool.refreshState()
		if !l.pool.isStopping() {
			l.signalDeath()
		}
	}
	done := client.Handshake()
	select {
	case <-done:
		if err := client.Err(); err != nil {
			tport.Close()
			l.pool.noteEdgeFailure(pin, err)
			return fmt.Errorf("session: handshake: %w", err)
		}
	case <-time.After(20 * time.Second):
		tport.Close()
		l.pool.noteEdgeFailure(pin, errors.New("session: handshake timeout"))
		return errors.New("session: handshake timeout")
	case <-ctx.Done():
		tport.Close()
		return ctx.Err()
	}
	l.pool.noteEdgeSuccess(pin)
	l.mu.Lock()
	old := l.client
	l.client = client
	l.carriers++
	l.lastRTT = time.Since(dialStart)
	l.mu.Unlock()
	l.pool.noteRotation(l.lastRTT)
	if old != nil {
		if drainOld {
			l.trackDrain(old)
		} else {
			old.Close()
		}
	}
	return nil
}

// trackDrain keeps a swapped-out client alive until its streams end
// or the 10-minute grace expires (NP-1117-16 drain semantics).
func (l *lineage) trackDrain(c *core.HollowClient) {
	l.mu.Lock()
	if l.drains == nil {
		l.drains = map[*core.HollowClient]struct{}{}
	}
	l.drains[c] = struct{}{}
	l.mu.Unlock()
	go func() {
		drainStart := time.Now()
		deadline := drainStart.Add(10 * time.Minute)
		for {
			// The empty check needs a floor: a dial goroutine may
			// have captured this client just before the swap, with
			// its OPEN not yet registered on the client's event
			// loop (the JS original registers synchronously, so it
			// needs no floor; Go's goroutine + event-loop hop does).
			// 2s is far inside the stream-open budget.
			empty := c.ActiveStreams() == 0 && time.Since(drainStart) > 2*time.Second
			if empty || time.Now().After(deadline) {
				c.Close()
				l.mu.Lock()
				delete(l.drains, c)
				l.mu.Unlock()
				return
			}
			select {
			case <-l.pool.stopCh:
				return // pool Stop closes drains itself
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
}

// noteOutboundFailure mirrors the JS manager's 0x06 hook: when the
// failing client is at/over its open budget, arrange for a retry —
// if that client was already rotated away, the live client serves
// (true, no new rotation); otherwise rotate (drain path) first.
func (l *lineage) noteOutboundFailure(failed *core.HollowClient, deadline time.Time) bool {
	cur := l.currentClient()
	if failed == nil || cur == nil {
		return false
	}
	if !(failed.OpensSent() >= core.SessionRotateThreshold || failed.BudgetExhausted()) {
		return false
	}
	if failed != cur {
		return true // already swapped; retry lands on the live client
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return l.rotateCarrierDrain(ctx) == nil
}

// dial opens one stream on this lineage's current client, applying
// the NP-1117-14 0x01 retry on the SAME client (fresh stream, 250ms
// backoff doubling to 2s, ±25% jitter, retry_after as floor). It
// returns the client that served the final attempt so the pool can
// apply the 0x06 migration policy against the right budget.
func (l *lineage) dial(ip net.IP, port uint16, deadline time.Time) (net.Conn, *core.HollowClient, error) {
	backoff := 250 * time.Millisecond
	for {
		client := l.currentClient()
		if client == nil {
			return nil, nil, errNoCarrier
		}
		stream, err := client.OpenStream(ip.String(), int(port), core.SchemeUnknown, 0)
		if err != nil {
			return nil, client, err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			stream.Reset(core.ErrStreamTimeout)
			return nil, client, errors.New("session: stream open timeout")
		}
		openErr := waitStreamOpen(stream, remaining)
		if openErr == nil {
			return newStreamConn(stream, &net.TCPAddr{IP: ip, Port: int(port)}), client, nil
		}
		var rej *core.OpenRejectError
		if errors.As(openErr, &rej) && rej.Code == core.ErrConcurrencyLimit && time.Now().Before(deadline) {
			wait := time.Duration(float64(backoff) * (0.75 + 0.5*mathrand.Float64()))
			if ra := time.Duration(rej.RetryAfterMs) * time.Millisecond; ra > wait {
				wait = ra
			}
			if wait > time.Until(deadline) {
				wait = time.Until(deadline)
			}
			select {
			case <-l.pool.stopCh:
				return nil, client, errStopped
			case <-time.After(wait):
			}
			backoff *= 2
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
			continue
		}
		return nil, client, openErr
	}
}

// watchdog serves this lineage: §8.4 death redial (1s doubling,
// capped 60s, ±25% jitter), the OPEN-budget trigger and the 15-minute
// timer (both via the drain path). An auth-fatal establish failure
// stops the lineage and escalates to the pool — redialing can never
// fix a rejected handshake.
func (l *lineage) watchdog() {
	rotateEvery := l.pool.rotateEvery
	if rotateEvery <= 0 {
		rotateEvery = 15 * time.Minute
	}
	ticker := time.NewTicker(rotateEvery)
	defer ticker.Stop()
	backoff := time.Second
	for {
		select {
		case <-l.pool.stopCh:
			return
		case <-l.rotateCh:
			if l.fatal {
				return
			}
			if err := l.rotateCarrierDrain(context.Background()); err != nil {
				if isAuthFatal(err) {
					l.escalateFatal(err)
					return
				}
				time.AfterFunc(5*time.Second, l.signalRotate)
			}
			continue
		case <-ticker.C:
			l.signalRotate()
			continue
		case <-l.deathCh:
		}
		if l.pool.isStopping() || l.fatal {
			return
		}
		for {
			eff := backoff
			if cap := l.pool.redialCap(); eff > cap {
				eff = cap
			}
			jittered := time.Duration(float64(eff) * (0.75 + 0.5*mathrand.Float64()))
			select {
			case <-l.pool.stopCh:
				return
			case <-time.After(jittered):
			}
			if err := l.rotateCarrier(context.Background()); err == nil {
				backoff = time.Second
				break
			} else if isAuthFatal(err) {
				l.escalateFatal(err)
				return
			}
			backoff *= 2
			if cap := l.pool.redialCap(); backoff > cap {
				backoff = cap
			}
		}
	}
}

// escalateFatal marks the lineage dead for good and tells the pool.
func (l *lineage) escalateFatal(err error) {
	l.mu.Lock()
	l.fatal = true
	l.mu.Unlock()
	l.pool.onFatal(err)
}

// stop closes the current client and any draining clients.
func (l *lineage) stop() {
	l.mu.Lock()
	client := l.client
	l.client = nil
	drains := make([]*core.HollowClient, 0, len(l.drains))
	for c := range l.drains {
		drains = append(drains, c)
	}
	l.drains = map[*core.HollowClient]struct{}{}
	l.mu.Unlock()
	if client != nil {
		client.Close()
	}
	for _, c := range drains {
		c.Close()
	}
}

// ---------------------------------------------------------------------------
// Session: the pool facade the pump and the shell talk to.
// ---------------------------------------------------------------------------

type Session struct {
	cfg       Config
	protector Protector
	// dialOverride, when set, replaces the protected dialer for
	// every egress dial (carriers, probes, /meta, /edges.json).
	// Test-only seam (the sandbox production smoke routes through
	// the egress proxy); production paths never set it.
	dialOverride func(ctx context.Context, network, addr string) (net.Conn, error)

	mu       sync.Mutex
	lines    []*lineage
	pump     *pump.Pump
	stopping bool
	fatalErr error

	stopCh   chan struct{} // closed on Stop
	tunFD    int           // owned once Start succeeds; closed by Stop
	counters *byteCounters // wire traffic (display only), shared by all lineages
	rr       atomic.Uint64 // round-robin cursor for placement ties

	rotateEvery time.Duration // timed rotation interval (0 = 15 min)

	// Entry dispersion (NP-1118-09, edges.go), guarded by mu.
	bootstrapIPs   []string // entry hostname's resolved set (NP-1118-11), guarded by mu
	bootstrapPinned map[int]bool // slots whose current pin came from the bootstrap tier (NP-1118-14)
	edgeCandidates []EdgeCandidate
	edgeFailCounts map[string]int
	edgeDisfavored map[string]bool
	slotEdges      map[int]string
	measuring      bool
	lastMeasure    time.Time

	// UI-facing state machine (M3-4), guarded by mu: disconnected /
	// connecting / connected / error, plus the counters the status
	// surface presents.
	state     string
	detail    string
	sinceMs   int64
	streamsOK int
	lastRTT   time.Duration
}

func (s *Session) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

// initLines builds the lineage set (idempotent).
func (s *Session) initLines() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lines != nil {
		return
	}
	if s.counters == nil {
		s.counters = &byteCounters{}
	}
	n := s.cfg.poolSize()
	s.lines = make([]*lineage, n)
	for i := range s.lines {
		s.lines[i] = &lineage{
			pool:     s,
			idx:      i,
			deathCh:  make(chan struct{}, 1),
			rotateCh: make(chan struct{}, 1),
			drains:   map[*core.HollowClient]struct{}{},
		}
	}
}

// dialContext resolves the egress dial function for this session.
func (s *Session) dialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	if s.dialOverride != nil {
		return s.dialOverride
	}
	return protectedDialContext(s.protector)
}

func (s *Session) lineages() []*lineage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lines
}

// refreshState recomputes the presentation state from pool health:
// connected iff at least one lineage is live; error iff a lineage
// escalated an auth-fatal failure; connecting otherwise.
func (s *Session) refreshState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopping {
		return
	}
	if s.fatalErr != nil {
		s.state, s.detail = "error", s.fatalErr.Error()
		return
	}
	live := 0
	for _, l := range s.lines {
		if l.healthy() {
			live++
		}
	}
	if live > 0 {
		if s.sinceMs == 0 {
			s.sinceMs = time.Now().UnixMilli()
		}
		s.state, s.detail = "connected", ""
	} else if s.state == "connected" {
		s.state, s.detail = "connecting", "承载中断，正在重连"
	}
	if live == 0 && s.sinceMs != 0 && s.fatalErr == nil && !s.measuring &&
		time.Since(s.lastMeasure) > 5*time.Minute {
		// Full outage after having been up: fresh entry evidence is
		// worth the most right now. refreshState holds s.mu, so the
		// cycle starts in its own goroutine (its guard re-locks).
		go s.refreshEdges()
	}
}

// noteRotation records a successful carrier establishment.
func (s *Session) noteRotation(rtt time.Duration) {
	s.mu.Lock()
	s.lastRTT = rtt
	s.mu.Unlock()
	s.refreshState()
}

// onFatal stops the whole pool on an auth-fatal lineage failure:
// every client closes, the state machine lands in error with the
// reason, and no lineage redials (their watchdog checks fatal).
func (s *Session) onFatal(err error) {
	s.mu.Lock()
	if s.fatalErr == nil {
		s.fatalErr = err
	}
	s.mu.Unlock()
	s.refreshState()
	for _, l := range s.lineages() {
		l.mu.Lock()
		l.fatal = true
		l.mu.Unlock()
		l.stop()
	}
}

// pick chooses the healthy lineage with the fewest active streams;
// ties break round-robin via the pool cursor. The excluded lineage
// (a just-failed one) is skipped unless it is the only healthy one.
func (s *Session) pick(exclude *lineage) *lineage {
	lines := s.lineages()
	if len(lines) == 0 {
		return nil
	}
	start := int(s.rr.Add(1))
	var best *lineage
	var bestLoad int64
	for i := 0; i < len(lines); i++ {
		l := lines[(start+i)%len(lines)]
		if l == exclude || !l.healthy() {
			continue
		}
		load := l.activeStreams()
		if best == nil || load < bestLoad {
			best, bestLoad = l, load
		}
	}
	if best == nil && exclude != nil && exclude.healthy() {
		return exclude
	}
	return best
}

// StateSnapshot is the session's presentation state (no internals).
type StateSnapshot struct {
	State     string
	Detail    string
	SinceMs   int64
	Carriers  int
	StreamsOK int
	// Readings: wire bytes at the transport boundary, the most
	// recent carrier handshake RTT, live/total carriers.
	TrafficUp    int64
	TrafficDown  int64
	CarrierRTTMs int64
	LiveCarriers int
	PoolSize     int
	// Entry dispersion (NP-1118-09): per-lineage pinned entry IP
	// ("" = by domain), index-aligned, and the ranked candidate
	// list — same field names as the JS bridge snapshot.
	SlotEdges      []string
	EdgeCandidates []EdgeCandidate
}

// State reads the presentation snapshot.
func (s *Session) State() StateSnapshot {
	lines := s.lineages()
	snap := StateSnapshot{PoolSize: len(lines)}
	live := 0
	for _, l := range lines {
		if l.healthy() {
			live++
		}
		l.mu.Lock()
		snap.Carriers += l.carriers
		l.mu.Unlock()
	}
	snap.LiveCarriers = live
	s.mu.Lock()
	snap.State, snap.Detail, snap.SinceMs, snap.StreamsOK = s.state, s.detail, s.sinceMs, s.streamsOK
	snap.CarrierRTTMs = s.lastRTT.Milliseconds()
	snap.SlotEdges = make([]string, len(lines))
	for i := range lines {
		snap.SlotEdges[i] = s.slotEdges[i]
	}
	snap.EdgeCandidates = append([]EdgeCandidate(nil), s.edgeCandidates...)
	s.mu.Unlock()
	if s.counters != nil {
		snap.TrafficUp = s.counters.up.Load()
		snap.TrafficDown = s.counters.down.Load()
	}
	return snap
}

// Start builds the pump on the TUN fd and the carrier pool, and
// returns once at least one carrier's Hollow handshake is open. The
// pump is built FIRST so a failed start still leaves no half-attached
// data plane behind: when NO lineage can establish, the whole session
// is torn down (fail-closed, plan §2) — an auth-fatal failure returns
// at once, since every lineage shares the same key material.
func Start(cfg Config, tunFD int, protector Protector) (*Session, error) {
	if cfg.WSURL == "" || len(cfg.PSK) == 0 {
		return nil, errors.New("session: incomplete config (wsUrl/psk)")
	}
	if cfg.KeyID == 0 {
		cfg.KeyID = 1
	}
	s := &Session{cfg: cfg, protector: protector, stopCh: make(chan struct{}), tunFD: tunFD, state: "connecting", counters: &byteCounters{}}
	// Bootstrap resolution (NP-1118-11): seed from the persisted
	// last-known-good set, then refresh it over the protected
	// dialer — protect()ed sockets bypass the TUN, so this works
	// in the connected state where the system resolver answers
	// the entry name with a definitive negative. Fail-open: an
	// empty set degrades to plain domain dialing, as before.
	s.bootstrapIPs = append([]string(nil), cfg.BootstrapIPs...)
	s.refreshBootstrap(context.Background())
	s.initLines()

	ep, err := fdbased.New(&fdbased.Options{FDs: []int{tunFD}, MTU: 1280})
	if err != nil {
		return nil, fmt.Errorf("session: fd endpoint: %w", err)
	}
	p, err := pump.NewPump(pump.Config{
		DialFlow: s.dialFlow,
		RTTHint: func() (int64, bool) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.lastRTT > 0 {
				return s.lastRTT.Milliseconds(), true
			}
			return 0, false
		},
	}, ep)
	if err != nil {
		return nil, fmt.Errorf("session: pump: %w", err)
	}
	s.pump = p

	lines := s.lineages()
	for _, l := range lines {
		go l.watchdog()
	}
	established := 0
	var firstErr error
	for _, l := range lines {
		if err := l.rotateCarrier(context.Background()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if isAuthFatal(err) {
				s.Stop()
				return nil, err
			}
			l.signalDeath() // the watchdog keeps retrying this lineage
			continue
		}
		established++
	}
	if established == 0 {
		s.Stop()
		return nil, firstErr
	}
	s.refreshState()
	// Entry dispersion evidence gathers in the background; the pool
	// is already serving by domain and pins apply at each lineage's
	// next establishment (NP-1118-09).
	go s.refreshEdges()
	return s, nil
}

// dialFlow is the pump's FlowDialer: pick a lineage, open a core
// stream on it (10s total budget). A stream belongs to its lineage
// for life. On a 0x06 from a budget-spent lineage, the dial migrates
// ONCE: the lineage rotates (or already has), and the retry re-picks
// — another healthy lineage when one exists.
func (s *Session) dialFlow(ip net.IP, port uint16) (net.Conn, error) {
	deadline := time.Now().Add(10 * time.Second)
	migrated := false
	var exclude *lineage
	for {
		lin := s.pick(exclude)
		if lin == nil {
			return nil, errNoCarrier
		}
		conn, failedClient, err := lin.dial(ip, port, deadline)
		if err == nil {
			s.mu.Lock()
			s.streamsOK++
			s.mu.Unlock()
			return conn, nil
		}
		var rej *core.OpenRejectError
		if !migrated && errors.As(err, &rej) && rej.Code == core.ErrOutboundFailed &&
			lin.noteOutboundFailure(failedClient, deadline) {
			migrated = true
			exclude = lin
			continue
		}
		return nil, err
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
	// /meta rides the best available entry pin (NP-1118-09 (d),
	// NP-1118-14 (b)): the best-ranked edge, or the bootstrap set
	// when nothing is ranked yet. The TCP target is the pinned IP;
	// TLS ServerName and Host stay on the URL's hostname. (In
	// v0.2.3/v0.2.4 this consulted only the ranked list, so with an
	// empty ranking it dialed by name and died in the connected-
	// state resolver — the split-brain NP-1118-14 closes.)
	dial := pinDial(s.dialContext(), s.bestDialIP())
	tr := &http.Transport{DialContext: dial}
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

// Stop tears the session down: carriers first (flows fail fast), then
// the pump and its flow table.
func (s *Session) Stop() {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	s.state, s.detail = "disconnected", ""
	s.mu.Unlock()
	close(s.stopCh)
	for _, l := range s.lineages() {
		l.stop()
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

// Package server is the helper's portable core: it owns the mode state,
// the pump lifecycle, the heartbeat emission, and the dead-man's switch
// (if the app's frames stop arriving while TUN is up, the helper tears
// the tunnel down on its own — TUN notes v2 §6 mandatory change D; the
// netcfg restore joins this path in T-2).
//
// Platform pieces (elevation, Wintun endpoint, pipe listener) are injected
// via Deps so the whole core is testable in-process on any OS.
package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"hollow/tun-helper/internal/clock"
	"hollow/tun-helper/internal/ipc"
	"hollow/tun-helper/internal/netcfg"
	"hollow/tun-helper/internal/pump"
)

// Deps injects platform behavior.
type Deps struct {
	// Elevated reports whether this process may create adapters.
	Elevated func() bool
	// Shutdown, when set, is invoked after a successful shutdown
	// verb reply (NP-1118-38): the process exits. The verb is
	// refused while the TUN takeover is up — disable_tun first,
	// so a shutdown can never strand the takeover without its
	// ordered unwind.
	Shutdown func()
	// NewLinkEndpoint creates the TUN link endpoint (Wintun in production).
	NewLinkEndpoint func() (stack.LinkEndpoint, io.Closer, error)
	// HeartbeatInterval defaults to 2s; FreshnessThreshold to 10s.
	HeartbeatInterval  time.Duration
	FreshnessThreshold time.Duration
	// PumpConfig carries data-plane tuning; SocksAddr is set per enable.
	PumpConfig pump.Config
	Logger     *log.Logger
	// Netcfg, when set, owns the routing takeover discipline (T-2): it is
	// self-healed at startup, enabled with the candidate/exclusion set on
	// enable_tun, refreshed by set_exclusions, and restored on every
	// teardown path (disable / restore / dead-man). Nil disables netcfg
	// (unit tests of the pure state machine, non-Windows builds).
	Netcfg *netcfg.Engine
}

func (d *Deps) withDefaults() {
	if d.HeartbeatInterval <= 0 {
		d.HeartbeatInterval = 2 * time.Second
	}
	if d.FreshnessThreshold <= 0 {
		d.FreshnessThreshold = 10 * time.Second
	}
	if d.Logger == nil {
		d.Logger = log.Default()
	}
}

// Server is the helper core state machine.
type Server struct {
	deps Deps

	mu       sync.Mutex
	mode     ipc.Mode
	pump     *pump.Pump
	linkHold io.Closer
	lastSeen int64 // clock.NowMs() of the last frame from the app
	seq      uint64

	// Connection generations (RF-21-03①): the dead-man's switch is a
	// SERVER-level concern, not a per-connection one — when the app dies
	// the pipe breaks and a per-connection watchdog dies with it, leaving
	// the takeover up forever. connGen increments per connection;
	// activeGen is the live connection's generation (0 = none);
	// connLostAt is when the latest generation disconnected.
	connGen      uint64
	activeGen    uint64
	connLostAt   int64
	watchdogOnce sync.Once
}

func New(deps Deps) *Server {
	deps.withDefaults()
	s := &Server{deps: deps, mode: ipc.ModeOff, lastSeen: clock.NowMs()}
	if deps.Netcfg != nil {
		// Startup self-heal (spec R4): a previous run may have died with
		// the takeover live (kill -9, power loss). Heal before serving.
		if res, err := deps.Netcfg.SelfHeal(); err != nil {
			deps.Logger.Printf("netcfg self-heal error: %v", err)
		} else if res.Mode != "none" {
			deps.Logger.Printf("netcfg self-heal: mode=%s healed=%v", res.Mode, res.Healed)
		}
	}
	return s
}

// Mode returns the current arbitrated mode.
func (s *Server) Mode() ipc.Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// Status is the payload of a status reply.
type Status struct {
	Mode     ipc.Mode   `json:"mode"`
	Elevated bool       `json:"elevated"`
	Pump     *pumpStats `json:"pump,omitempty"`
}

type pumpStats struct {
	ActiveFlows int    `json:"activeFlows"`
	TotalFlows  uint64 `json:"totalFlows"`
	RefusedFull uint64 `json:"refusedFull"`
	DroppedUDP  uint64 `json:"droppedUdp"`
	DroppedV6   uint64 `json:"droppedV6"`
	DNSQueries  uint64 `json:"dnsQueries"`
	DNSResolved uint64 `json:"dnsResolved"`
	DNSServfail uint64 `json:"dnsServfail"`
	DNSConns    uint64 `json:"dnsConns"`
}

func (s *Server) status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Mode: s.mode, Elevated: s.deps.Elevated != nil && s.deps.Elevated()}
	if s.pump != nil {
		ps := s.pump.Stats()
		st.Pump = &pumpStats{ActiveFlows: ps.ActiveFlows, TotalFlows: ps.TotalFlows, RefusedFull: ps.RefusedFull, DroppedUDP: ps.DroppedUDP, DroppedV6: ps.DroppedV6, DNSQueries: ps.DNSQueries, DNSResolved: ps.DNSResolved, DNSServfail: ps.DNSServfail, DNSConns: ps.DNSConns}
	}
	return st
}

// teardownLocked stops the pump and returns to off. Caller holds s.mu.
// The netcfg takeover is restored on EVERY teardown path (disable,
// restore command, dead-man) — a restore failure keeps the snapshot for
// the next self-heal / --restore-tun and is logged, never hidden.
func (s *Server) teardownLocked(reason string) {
	if s.pump != nil {
		s.pump.Close()
		s.pump = nil
	}
	if s.linkHold != nil {
		s.linkHold.Close()
		s.linkHold = nil
	}
	if s.mode == ipc.ModeTun {
		s.mode = ipc.ModeOff
	}
	if s.deps.Netcfg != nil {
		if res, err := s.deps.Netcfg.Restore(); err != nil {
			s.deps.Logger.Printf("netcfg restore (%s) error: %v", reason, err)
		} else if res.Mode != "none" {
			s.deps.Logger.Printf("netcfg restore (%s): mode=%s verified=%v", reason, res.Mode, res.Verified)
		}
	}
	s.deps.Logger.Printf("tun teardown: %s", reason)
}

// dispatch executes one validated request frame and returns the reply.
func (s *Server) dispatch(f *ipc.Frame) *ipc.Frame {
	ok := true
	reply := &ipc.Frame{ID: f.ID, OK: &ok}
	fail := func(err error) *ipc.Frame {
		no := false
		return &ipc.Frame{ID: f.ID, OK: &no, Error: err.Error()}
	}
	switch f.Verb {
	case ipc.VerbPing:
		// Liveness only; lastSeen is updated by the serve loop.
	case ipc.VerbStatus:
		b, _ := json.Marshal(s.status())
		reply.Result = b
	case ipc.VerbNoteMode:
		var p ipc.NoteModeParams
		_ = json.Unmarshal(f.Params, &p)
		s.mu.Lock()
		if s.mode == ipc.ModeTun && p.Mode != ipc.ModeTun {
			s.mu.Unlock()
			return fail(fmt.Errorf("mode conflict: TUN is active in the helper; disable_tun first"))
		}
		s.mode = p.Mode
		s.mu.Unlock()
	case ipc.VerbEnableTun:
		var p ipc.EnableTunParams
		_ = json.Unmarshal(f.Params, &p)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.mode == ipc.ModeTun {
			return fail(fmt.Errorf("TUN already enabled"))
		}
		if s.deps.Elevated == nil || !s.deps.Elevated() {
			return fail(fmt.Errorf("helper is not elevated; the app must relaunch it with UAC consent (nothing was changed)"))
		}
		ep, hold, err := s.deps.NewLinkEndpoint()
		if err != nil {
			return fail(fmt.Errorf("open adapter: %w", err))
		}
		cfg := s.deps.PumpConfig
		cfg.SocksAddr = fmt.Sprintf("127.0.0.1:%d", p.SocksPort)
		pm, err := pump.NewPump(cfg, ep)
		if err != nil {
			hold.Close()
			return fail(fmt.Errorf("start pump: %w", err))
		}
		s.pump, s.linkHold = pm, hold
		if s.deps.Netcfg != nil {
			if _, err := s.deps.Netcfg.Enable(p.Exclusions); err != nil {
				// Fail closed: no takeover, no TUN. The netcfg snapshot
				// (if written) stays for self-heal/--restore-tun.
				s.pump.Close()
				s.pump = nil
				hold.Close()
				s.linkHold = nil
				return fail(fmt.Errorf("netcfg takeover: %w", err))
			}
		}
		s.mode = ipc.ModeTun
		s.deps.Logger.Printf("tun enabled (socks %s)", cfg.SocksAddr)
	case ipc.VerbSetExclusions:
		var p ipc.SetExclusionsParams
		_ = json.Unmarshal(f.Params, &p)
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.deps.Netcfg == nil {
			return fail(fmt.Errorf("netcfg not available in this helper"))
		}
		if s.mode != ipc.ModeTun {
			return fail(fmt.Errorf("set_exclusions requires TUN active"))
		}
		if _, err := s.deps.Netcfg.Enable(p.IPs); err != nil {
			return fail(fmt.Errorf("set_exclusions: %w", err))
		}
	case ipc.VerbShutdown:
		if s.mode == ipc.ModeTun {
			return fail(fmt.Errorf("shutdown refused while TUN is up — disable_tun first"))
		}
		if s.deps.Shutdown != nil {
			go s.deps.Shutdown()
		}
		return reply
	case ipc.VerbDisableTun:
		s.mu.Lock()
		s.teardownLocked("disable_tun")
		s.mu.Unlock()
	case ipc.VerbRestore:
		s.mu.Lock()
		s.teardownLocked("restore command")
		s.mode = ipc.ModeOff
		s.mu.Unlock()
	default:
		return fail(fmt.Errorf("unhandled verb %q", string(f.Verb)))
	}
	return reply
}

// watchdog is the server-level dead-man's switch (RF-21-03①). While TUN
// is up it judges liveness two ways: a live connection is judged by its
// frame freshness; NO connection (the app died, the pipe broke) is
// judged by the time since the latest generation disconnected — a newer
// generation connecting inside the threshold cancels the pending
// teardown by definition (activeGen != 0 switches the basis back).
func (s *Server) watchdog() {
	t := time.NewTicker(s.deps.FreshnessThreshold / 4)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		if s.mode == ipc.ModeTun {
			now := clock.NowMs()
			basis := s.lastSeen
			reason := "dead-man: app heartbeat stale"
			if s.activeGen == 0 {
				basis = s.connLostAt
				reason = "dead-man: connection lost and not re-established"
			}
			if !clock.Freshness(now, basis, s.deps.FreshnessThreshold.Milliseconds()) {
				s.teardownLocked(reason)
			}
		}
		s.mu.Unlock()
	}
}

// ServeConn runs the protocol over one app connection until it closes:
// reads requests, writes replies + heartbeats. The dead-man's switch is
// server-level (see watchdog) so it survives this connection's death.
func (s *Server) ServeConn(conn io.ReadWriteCloser) {
	defer conn.Close()
	s.watchdogOnce.Do(func() { go s.watchdog() })
	s.mu.Lock()
	s.connGen++
	gen := s.connGen
	s.activeGen = gen
	s.lastSeen = clock.NowMs()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.activeGen == gen {
			s.activeGen = 0
			s.connLostAt = clock.NowMs()
		}
		s.mu.Unlock()
	}()
	var writeMu sync.Mutex
	write := func(f *ipc.Frame) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = ipc.WriteFrame(conn, f)
	}
	done := make(chan struct{})
	defer close(done)

	// Heartbeat emitter: unsolicited frames every interval; the app judges
	// OUR liveness by their freshness on its own monotonic clock.
	go func() {
		t := time.NewTicker(s.deps.HeartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				s.mu.Lock()
				s.seq++
				seq := s.seq
				s.mu.Unlock()
				yes := true
				write(&ipc.Frame{Event: "heartbeat", Seq: seq, Uptime: clock.NowMs(), OK: &yes})
			}
		}
	}()

	r := bufio.NewReader(conn)
	for {
		f, err := ipc.ReadFrame(r)
		if err != nil {
			s.deps.Logger.Printf("conn read: %v", err)
			return
		}
		s.mu.Lock()
		s.lastSeen = clock.NowMs()
		s.mu.Unlock()
		if err := f.ValidateRequest(); err != nil {
			no := false
			write(&ipc.Frame{ID: f.ID, OK: &no, Error: err.Error()})
			continue
		}
		write(s.dispatch(f))
	}
}

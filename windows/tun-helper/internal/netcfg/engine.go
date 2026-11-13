package netcfg

import (
	"fmt"
	"strings"
	"time"
)

// System abstracts the OS routing table so the policy engine is testable
// off-Windows. The Windows implementation shells out to route.exe/netsh.
type System interface {
	CurrentRoutes() ([]Route, error)
	AddRoute(r Route) error
	DelRoute(r Route) error
	DefaultGateway() (string, error)
	PhysicalDNS() (map[string][]string, error)
}

// Engine executes the discipline (spec §3) over a System.
type Engine struct {
	Dir string
	Sys System
	Log func(string)
	Now func() time.Time
}

func (e *Engine) logf(format string, args ...any) {
	if e.Log != nil {
		e.Log(fmt.Sprintf(format, args...))
	}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) applyOps(ops []Op) error {
	for _, op := range ops {
		var err error
		if op.Kind == "add" {
			err = e.Sys.AddRoute(op.Route)
		} else {
			err = e.Sys.DelRoute(op.Route)
		}
		if err != nil {
			return fmt.Errorf("%s route %s: %w", op.Kind, op.Route.Dest, err)
		}
	}
	return nil
}

func (e *Engine) currentOur(written State) ([]Route, error) {
	cur, err := e.Sys.CurrentRoutes()
	if err != nil {
		return nil, err
	}
	return OurRoutesPresent(cur, written), nil
}

// Enable performs (or refreshes) the takeover.
// exclusions: the bearer candidate IP set — candidate set = exclusion set,
// one ledger (spec/定版稿 §3). Iron rule: a held snapshot's Original is
// never rewritten; only Written follows the live form.
func (e *Engine) Enable(exclusions []string) (*Snapshot, error) {
	// RF-21-05 (defense in depth behind the app policy layer): IPv6
	// exclusions are stripped with a logged reason — never a bare error
	// that sinks the whole enable, never a /128 the netsh surface cannot
	// be trusted with this phase.
	v4only := exclusions[:0:0]
	for _, ex := range exclusions {
		if strings.Contains(ex, ":") {
			e.logf("netcfg: STRIPPED ipv6 exclusion %s — TUN exclusions are IPv4 /32 only this phase (RF-21-05)", ex)
			continue
		}
		v4only = append(v4only, ex)
	}
	exclusions = v4only
	gw, err := e.Sys.DefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("default gateway: %w", err)
	}
	desired, err := DesiredRoutes(exclusions, gw)
	if err != nil {
		return nil, err
	}
	// DNS field (T-3): the adapter's resolver is the helper's own address —
	// queries land in the pump and leave through the tunnel. The field is
	// part of Written; original keeps whatever the adapter had (empty in
	// phase 1: we never touch the physical adapters' DNS, spec §1.2).
	adapter := AdapterCfg{Name: AdapterName, IPv4: AdapterIPv4PF, IPv6: AdapterIPv6PF, DNS: []string{AdapterIPv4}}

	kind, held := ReadSnapshot(e.Dir)
	switch kind {
	case SnapOK:
		e.logf("netcfg: backup already held — snapshot kept verbatim (iron rule)")
		cur, err := e.Sys.CurrentRoutes()
		if err != nil {
			return nil, err
		}
		if unrec := UnrecognizedRoutes(cur, held.Written); len(unrec) > 0 {
			return nil, fmt.Errorf("netcfg: unrecognized route forms share our destinations (%v) — unknown state, refusing to proceed", unrec)
		}
		if routeSetsEqual(held.Written.AddedRoutes, desired) {
			// Ensure the routes are actually live (self-repair of a
			// half-applied earlier attempt), then done.
			present, err := e.currentOur(held.Written)
			if err != nil {
				return nil, err
			}
			if !routeSetsEqual(present, held.Written.AddedRoutes) {
				ops, _ := PlanTakeover(exclusions, gw)
				if err := e.applyOps(ops); err != nil {
					return nil, err
				}
			}
			return held, nil
		}
		// Written follows the new form (exclusion set changed): refresh
		// add-before-delete, then re-anchor Written. Original untouched.
		ops, err := PlanExclusionRefresh(held.Written.AddedRoutes, exclusions, gw)
		if err != nil {
			return nil, err
		}
		// Ensure takeover routes themselves are present (idempotent adds
		// are the System adapter's business; a missing /1 is re-added).
		present, err := e.currentOur(held.Written)
		if err != nil {
			return nil, err
		}
		for _, r := range takeoverRoutes() {
			if !containsRoute(present, r) {
				ops = append([]Op{{Kind: "add", Route: r}}, ops...)
			}
		}
		if err := e.applyOps(ops); err != nil {
			return nil, err
		}
		held.Written.AddedRoutes = desired
		held.Written.Adapter = adapter
		if err := WriteSnapshotAtomic(e.Dir, held); err != nil {
			return nil, err
		}
		e.logf("netcfg: held backup written state updated (original untouched)")
		return held, nil
	case SnapCorrupt:
		// Mirror sysproxy: keep the corrupt file untouched, apply the
		// takeover anyway, and let Restore degrade. Never fabricate an
		// Original we did not measure.
		e.logf("netcfg: WARNING existing backup unreadable — keeping it untouched; restore will degrade safely")
		ops, _ := PlanTakeover(exclusions, gw)
		if err := e.applyOps(ops); err != nil {
			return nil, err
		}
		return &Snapshot{Version: SnapshotVersion, Written: State{DefaultGateway: gw, Adapter: adapter, AddedRoutes: desired}}, nil
	default: // SnapNone
		dns, err := e.Sys.PhysicalDNS()
		if err != nil {
			return nil, fmt.Errorf("physical dns: %w", err)
		}
		snap := &Snapshot{
			Version: SnapshotVersion,
			TakenAt: e.now().UTC().Format(time.RFC3339),
			Original: State{
				DefaultGateway: gw,
				PhysicalDNS:    dns,
				Adapter:        AdapterCfg{Name: AdapterName},
				AddedRoutes:    []Route{},
			},
			Written: State{
				DefaultGateway: gw,
				PhysicalDNS:    dns,
				Adapter:        adapter,
				AddedRoutes:    desired,
			},
		}
		if err := WriteSnapshotAtomic(e.Dir, snap); err != nil {
			return nil, err
		}
		e.logf("netcfg: snapshot saved")
		ops, _ := PlanTakeover(exclusions, gw)
		if err := e.applyOps(ops); err != nil {
			return nil, err // backup kept; restore/self-heal can unwind
		}
		present, err := e.currentOur(snap.Written)
		if err != nil {
			return nil, err
		}
		if !routeSetsEqual(present, snap.Written.AddedRoutes) {
			return nil, fmt.Errorf("netcfg: enable verification failed — written routes not all present (backup kept)")
		}
		return snap, nil
	}
}

// RestoreResult reports what a restore did, per outcome (spec R2/R3).
type RestoreResult struct {
	Restored bool
	Mode     string // none | snapshot | degraded-corrupt-backup | degraded-partial-state
	Verified bool
	Missing  []string // route dests still present after a failed verify
	// Unrecognized lists live routes sharing a written destination that
	// read back in a form we cannot account for (RF-21-01). Non-empty
	// means UNKNOWN state: verification failed by definition, backup kept.
	Unrecognized []string
}

// Restore unwinds the takeover per the held snapshot.
func (e *Engine) Restore() (RestoreResult, error) {
	kind, held := ReadSnapshot(e.Dir)
	switch kind {
	case SnapNone:
		return RestoreResult{Restored: false, Mode: "none", Verified: true}, nil
	case SnapCorrupt:
		e.logf("netcfg: WARNING backup corrupt — degrading to fingerprint-set removal")
		return e.degradedRestore("degraded-corrupt-backup", nil)
	default:
		return e.finishRestore(held.Written, "snapshot")
	}
}

// finishRestore removes the written set and verifies by re-reading the
// table; the backup is dropped ONLY on a verified clean table (R3).
// Verification requires BOTH: none of the written routes remain, AND no
// unrecognized same-destination forms remain (RF-21-01: unreadable state
// is unknown state, never "restored").
func (e *Engine) finishRestore(written State, mode string) (RestoreResult, error) {
	if err := e.applyOps(PlanRestore(written)); err != nil {
		return RestoreResult{Mode: mode}, err
	}
	cur, err := e.Sys.CurrentRoutes()
	if err != nil {
		return RestoreResult{Mode: mode}, err
	}
	present := OurRoutesPresent(cur, written)
	unrec := UnrecognizedRoutes(cur, written)
	if len(unrec) > 0 {
		dests := []string{}
		for _, r := range unrec {
			dests = append(dests, r.Dest)
		}
		e.logf("netcfg: READ-BACK UNRECOGNIZED (%s) — routes in unknown forms remain: %v — state treated as UNKNOWN, backup kept, NOT verified", mode, dests)
		return RestoreResult{Restored: false, Mode: mode, Verified: false, Unrecognized: dests}, nil
	}
	if len(present) > 0 {
		missing := []string{}
		for _, r := range present {
			missing = append(missing, r.Dest)
		}
		e.logf("netcfg: RESTORE VERIFICATION FAILED (%s) on: %v — backup kept for retry", mode, missing)
		return RestoreResult{Restored: false, Mode: mode, Verified: false, Missing: missing}, nil
	}
	RemoveSnapshot(e.Dir)
	e.logf("netcfg: restored (%s) and verified", mode)
	return RestoreResult{Restored: true, Mode: mode, Verified: true}, nil
}

// degradedRestore removes only what can be identified as ours without a
// trustworthy snapshot: the fingerprint takeover routes (spec §6). A
// caller-provided written set narrows it further when available.
func (e *Engine) degradedRestore(mode string, written *State) (RestoreResult, error) {
	target := State{AddedRoutes: FingerprintRoutes()}
	if written != nil {
		target = *written
	}
	res, err := e.finishRestore(target, mode)
	if err != nil {
		return res, err
	}
	if mode == "degraded-corrupt-backup" && res.Verified {
		// The corrupt file has served its purpose; the degraded restore
		// is verified, so it may now be cleared (spec R2).
		RemoveSnapshot(e.Dir)
	}
	return res, nil
}

// HealResult mirrors sysproxy's startup outcomes (spec R4).
type HealResult struct {
	Healed   bool
	Mode     string // none | self-heal | already-original | degraded-partial-state | foreign-state | degraded-corrupt-backup | unknown-state
	Verified bool
}

// SelfHeal runs the four-state startup discipline over the routing table.
func (e *Engine) SelfHeal() (HealResult, error) {
	kind, held := ReadSnapshot(e.Dir)
	switch kind {
	case SnapNone:
		return HealResult{Mode: "none"}, nil
	case SnapCorrupt:
		e.logf("netcfg: startup found corrupt backup — degrading to fingerprint-set removal")
		r, err := e.degradedRestore("degraded-corrupt-backup", nil)
		return HealResult{Healed: r.Restored, Mode: r.Mode, Verified: r.Verified}, err
	}
	cur, err := e.Sys.CurrentRoutes()
	if err != nil {
		return HealResult{}, err
	}
	// RF-21-01: unrecognized same-destination forms poison every other
	// judgement — classify UNKNOWN, touch nothing, keep the backup.
	if unrec := UnrecognizedRoutes(cur, held.Written); len(unrec) > 0 {
		e.logf("netcfg: startup found UNRECOGNIZED route forms sharing our destinations: %v — state UNKNOWN; table untouched, backup kept (--restore-tun remains available)", unrec)
		return HealResult{Mode: "unknown-state"}, nil
	}
	present := OurRoutesPresent(cur, held.Written)
	switch {
	case routeSetsEqual(present, held.Written.AddedRoutes) && len(present) > 0:
		r, err := e.finishRestore(held.Written, "snapshot")
		return HealResult{Healed: r.Restored, Mode: "self-heal", Verified: r.Verified}, err
	case len(present) == 0:
		RemoveSnapshot(e.Dir)
		e.logf("netcfg: startup found none of our routes present — stale backup dropped")
		return HealResult{Mode: "already-original"}, nil
	case HasFingerprint(cur):
		e.logf("netcfg: startup found a PARTIAL state carrying the Hollow fingerprint — degrading removal of our written set")
		r, err := e.finishRestore(held.Written, "degraded-partial-state")
		return HealResult{Healed: r.Restored, Mode: r.Mode, Verified: r.Verified}, err
	default:
		e.logf("netcfg: startup found only non-fingerprint remnants (bare /32s) — table left untouched; manual handling advised (--restore-tun remains available)")
		return HealResult{Mode: "foreign-state"}, nil
	}
}

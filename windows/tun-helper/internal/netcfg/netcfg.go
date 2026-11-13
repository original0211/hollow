// Package netcfg implements the TUN network-configuration takeover under
// the Self-Heal Discipline Spec (files/m2/self-heal-discipline-spec.md):
// snapshot-before-touch, iron rule, verified restore, four-state startup
// self-heal, add-before-delete set changes. All policy lives here over an
// injected System adapter, so the whole discipline is testable off-Windows;
// the Windows route.exe/netsh adapter is a separate build-tagged file.
//
// Takeover shape: the original default route is NEVER modified. Two /1
// routes per family steer everything into the TUN adapter, and every
// exclusion (bearer candidate IPs, the Worker endpoint) gets a /32 (v6:
// /128) host route via the physical gateway so control traffic can never
// loop into the tunnel.
package netcfg

import (
	"fmt"
	"net/netip"
	"sort"
)

// Address plan (spec §1.3, aligned NP-1114-20). The pump's netstack anchor
// is the same IPv4 (assigned /32 inside the stack).
const (
	AdapterName   = "Hollow"
	AdapterIPv4   = "10.99.0.1"
	AdapterIPv4PF = "10.99.0.1/24" // address/prefix written on the adapter
	AdapterIPv6   = "fd00::1"
	AdapterIPv6PF = "fd00::1/64"
)

// Takeover prefixes (spec §5 items 1-2).
var (
	TakeoverV4 = []string{"0.0.0.0/1", "128.0.0.0/1"}
	TakeoverV6 = []string{"::/1", "8000::/1"}
)

// Route is one canonical routing-table entry. Interface names the adapter
// for routes we add into the tunnel; exclusions leave it empty (the OS
// picks the physical interface by gateway).
type Route struct {
	Dest      string `json:"dest"` // CIDR, canonical (e.g. "0.0.0.0/1", "203.0.113.7/32")
	Gateway   string `json:"gateway"`
	Interface string `json:"interface,omitempty"`
}

func (r Route) Key() string { return r.Dest + "|" + r.Gateway + "|" + r.Interface }

// CanonicalKey reduces a route to the form used for ALL comparisons
// (RF-21-01): on a real machine the same route reads back with the
// interface spelled differently — `route print -4` shows the interface
// IP, our snapshot records the adapter NAME, `route print -6` has no
// interface column at all. Comparing raw keys across those spellings
// makes written state unrecognizable (and "unrecognized" must never be
// read as "restored"). The canonical form keeps dest + gateway exact
// (the security-relevant anchors) and classifies the interface:
// "tun" for anything pointing at our adapter (by name or by either of
// its addresses), "phys" for everything else (the recorded form leaves
// it empty; read-back shows the physical NIC's IP).
func (r Route) CanonicalKey() string {
	return r.Dest + "|" + r.Gateway + "|" + ifaceClass(r)
}

func ifaceClass(r Route) string {
	if r.Interface == AdapterName || r.Gateway == AdapterIPv4 || r.Gateway == AdapterIPv6 ||
		r.Interface == AdapterIPv4 || r.Interface == AdapterIPv6 {
		return "tun"
	}
	return "phys"
}

// SameRoute compares two routes in canonical form.
func SameRoute(a, b Route) bool { return a.CanonicalKey() == b.CanonicalKey() }

func (r Route) IsTakeover() bool {
	for _, p := range append(append([]string{}, TakeoverV4...), TakeoverV6...) {
		if r.Dest == p {
			return true
		}
	}
	return false
}

// AdapterCfg is the TUN adapter's recorded configuration (spec §1.2).
// DNS is reserved: T-3 writes the virtual resolver address there.
type AdapterCfg struct {
	Name string   `json:"name"`
	IPv4 string   `json:"ipv4"` // address/prefix
	IPv6 string   `json:"ipv6"`
	DNS  []string `json:"dns"`
}

// State is one side (original | written) of a snapshot.
type State struct {
	DefaultGateway string              `json:"defaultGateway"` // recorded only, never modified
	PhysicalDNS    map[string][]string `json:"physicalDns"`    // recorded only, never modified
	Adapter        AdapterCfg          `json:"adapter"`
	AddedRoutes    []Route             `json:"addedRoutes"` // routes WE added; empty in original
}

// Snapshot is the on-disk backup (spec §2).
type Snapshot struct {
	Version  int    `json:"version"`
	TakenAt  string `json:"takenAt"`
	Original State  `json:"original"`
	Written  State  `json:"written"`
}

const SnapshotVersion = 1
const SnapshotFile = "netcfg-backup.json"

// ExclusionRoute builds the host route for one candidate IP via the
// physical gateway (/32 for v4, /128 for v6).
func ExclusionRoute(ip, physicalGW string) (Route, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return Route{}, fmt.Errorf("exclusion ip %q: %w", ip, err)
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	return Route{Dest: fmt.Sprintf("%s/%d", a.String(), bits), Gateway: physicalGW}, nil
}

func takeoverRoutes() []Route {
	out := []Route{}
	for _, p := range TakeoverV4 {
		out = append(out, Route{Dest: p, Gateway: AdapterIPv4, Interface: AdapterName})
	}
	for _, p := range TakeoverV6 {
		out = append(out, Route{Dest: p, Gateway: AdapterIPv6, Interface: AdapterName})
	}
	return out
}

// DesiredRoutes is the full written route set for an exclusion list:
// exclusions first (they must exist before the /1s can be safe), then the
// takeover routes. Canonical order: sorted exclusions, then /1s in the
// declared order.
func DesiredRoutes(exclusions []string, physicalGW string) ([]Route, error) {
	seen := map[string]bool{}
	out := []Route{}
	sorted := append([]string{}, exclusions...)
	sort.Strings(sorted)
	for _, ip := range sorted {
		r, err := ExclusionRoute(ip, physicalGW)
		if err != nil {
			return nil, err
		}
		if seen[r.Key()] {
			continue
		}
		seen[r.Key()] = true
		out = append(out, r)
	}
	return append(out, takeoverRoutes()...), nil
}

// Op is one planned routing-table mutation.
type Op struct {
	Kind  string // "add" | "del"
	Route Route
}

// PlanTakeover orders a fresh takeover per spec R5: every exclusion /32
// is added BEFORE any /1 (the tunnel must never capture its own bearer).
func PlanTakeover(exclusions []string, physicalGW string) ([]Op, error) {
	routes, err := DesiredRoutes(exclusions, physicalGW)
	if err != nil {
		return nil, err
	}
	ops := make([]Op, 0, len(routes))
	for _, r := range routes {
		ops = append(ops, Op{Kind: "add", Route: r})
	}
	return ops, nil
}

// PlanRestore reverses a takeover: /1s come off first, exclusions last
// (spec R5), so no intermediate state routes bearer traffic into a
// half-torn-down tunnel.
func PlanRestore(written State) []Op {
	ops := []Op{}
	for _, r := range written.AddedRoutes {
		if r.IsTakeover() {
			ops = append(ops, Op{Kind: "del", Route: r})
		}
	}
	for _, r := range written.AddedRoutes {
		if !r.IsTakeover() {
			ops = append(ops, Op{Kind: "del", Route: r})
		}
	}
	return ops
}

// PlanExclusionRefresh implements spec R5 for a live exclusion-set change:
// ALL additions land before ANY deletion (no empty-window state). The old
// set is passed as RECORDED routes (with their original gateways — after a
// network change the gateway may differ, and a deletion must name the
// route exactly as it exists in the table).
func PlanExclusionRefresh(oldRoutes []Route, newSet []string, physicalGW string) ([]Op, error) {
	newR, err := exclusionSet(newSet, physicalGW)
	if err != nil {
		return nil, err
	}
	ops := []Op{}
	for _, r := range newR {
		if !containsRoute(oldRoutes, r) {
			ops = append(ops, Op{Kind: "add", Route: r})
		}
	}
	for _, r := range oldRoutes {
		if r.IsTakeover() {
			continue
		}
		if !containsRoute(newR, r) {
			ops = append(ops, Op{Kind: "del", Route: r})
		}
	}
	return ops, nil
}

func exclusionSet(ips []string, gw string) ([]Route, error) {
	out := []Route{}
	for _, ip := range ips {
		r, err := ExclusionRoute(ip, gw)
		if err != nil {
			return nil, err
		}
		if !containsRoute(out, r) {
			out = append(out, r)
		}
	}
	return out, nil
}

func containsRoute(rs []Route, want Route) bool {
	for _, r := range rs {
		if SameRoute(r, want) {
			return true
		}
	}
	return false
}

// FingerprintRoutes are the routes whose presence proves a partial state
// is OURS (spec §4): the takeover /1s via our adapter anchors. Bare /32s
// never count.
func FingerprintRoutes() []Route { return takeoverRoutes() }

func HasFingerprint(current []Route) bool {
	for _, f := range FingerprintRoutes() {
		if containsRoute(current, f) {
			return true
		}
	}
	return false
}

// OurRoutesPresent filters the live table down to routes that belong to
// the snapshot's written set (canonical-form match, RF-21-01).
func OurRoutesPresent(current []Route, written State) []Route {
	out := []Route{}
	for _, r := range written.AddedRoutes {
		if containsRoute(current, r) {
			out = append(out, r)
		}
	}
	return out
}

// UnrecognizedRoutes returns live routes that look like OUR written
// routes read back in a form we cannot account for (RF-21-01): same
// destination as a written route, pointing at our adapter by some
// spelling (our addresses as gateway/interface, the adapter name, or a
// link-local gateway — netsh may rewrite a v6 next-hop to the adapter's
// link-local), yet not canonically matching. A foreign route that merely
// shares a destination via a foreign gateway is NOT unrecognized — it is
// simply not ours. Callers must treat a non-empty result as UNKNOWN
// state: never as "restored", never as grounds to drop the backup.
func UnrecognizedRoutes(current []Route, written State) []Route {
	out := []Route{}
	for _, live := range current {
		sharesDest := false
		for _, w := range written.AddedRoutes {
			if live.Dest == w.Dest {
				sharesDest = true
				break
			}
		}
		if sharesDest && pointsAtUs(live) && !routeInSet(live, written.AddedRoutes) {
			out = append(out, live)
		}
	}
	return out
}

// pointsAtUs reports whether a route's next hop/interface is attributable
// to our adapter in any spelling.
func pointsAtUs(r Route) bool {
	if r.Gateway == AdapterIPv4 || r.Gateway == AdapterIPv6 ||
		r.Interface == AdapterName || r.Interface == AdapterIPv4 || r.Interface == AdapterIPv6 {
		return true
	}
	if a, err := netip.ParseAddr(r.Gateway); err == nil && a.IsLinkLocalUnicast() {
		return true
	}
	return false
}

func routeInSet(r Route, set []Route) bool {
	for _, w := range set {
		if SameRoute(r, w) {
			return true
		}
	}
	return false
}

func routeSetsEqual(a, b []Route) bool {
	if len(a) != len(b) {
		return false
	}
	for _, r := range a {
		if !containsRoute(b, r) {
			return false
		}
	}
	return true
}

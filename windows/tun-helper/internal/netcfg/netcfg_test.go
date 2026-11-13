package netcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystem is an in-memory routing table.
type fakeSystem struct {
	routes   []Route
	gw       string
	dns      map[string][]string
	dropDels map[string]bool // dests whose DelRoute silently no-ops (M-6)
	ops      []Op            // recorded mutation order (M-15/M-16)
}

func newFake() *fakeSystem {
	return &fakeSystem{
		gw:       "192.168.1.1",
		dns:      map[string][]string{"Wi-Fi": {"192.168.1.1"}},
		dropDels: map[string]bool{},
	}
}

func (f *fakeSystem) CurrentRoutes() ([]Route, error) {
	out := append([]Route{}, f.routes...)
	out = append(out, Route{Dest: "0.0.0.0/0", Gateway: f.gw, Interface: "Wi-Fi"})
	return out, nil
}

func (f *fakeSystem) AddRoute(r Route) error {
	f.ops = append(f.ops, Op{Kind: "add", Route: r})
	if !containsRoute(f.routes, r) {
		f.routes = append(f.routes, r)
	}
	return nil
}

func (f *fakeSystem) DelRoute(r Route) error {
	f.ops = append(f.ops, Op{Kind: "del", Route: r})
	if f.dropDels[r.Dest] {
		return nil // silently dropped write (M-6)
	}
	out := f.routes[:0]
	kept := []Route{}
	for _, x := range f.routes {
		if x.Key() != r.Key() {
			kept = append(kept, x)
		}
	}
	f.routes = kept
	_ = out
	return nil
}

func (f *fakeSystem) DefaultGateway() (string, error)           { return f.gw, nil }
func (f *fakeSystem) PhysicalDNS() (map[string][]string, error) { return f.dns, nil }

func newEngine(t *testing.T, sys *fakeSystem) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	return &Engine{Dir: dir, Sys: sys}, dir
}

var testExclusions = []string{"203.0.113.7", "198.51.100.9"}

// M-1: verbatim roundtrip.
func TestRoundtripVerbatim(t *testing.T) {
	sys := newFake()
	e, dir := newEngine(t, sys)
	snap, err := e.Enable(testExclusions)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Written.AddedRoutes) != 6 { // 2 exclusions + 4 takeover
		t.Fatalf("written routes = %d, want 6", len(snap.Written.AddedRoutes))
	}
	if snap.Original.DefaultGateway != "192.168.1.1" || len(snap.Original.AddedRoutes) != 0 {
		t.Fatalf("original polluted: %+v", snap.Original)
	}
	res, err := e.Restore()
	if err != nil || !res.Restored || !res.Verified || res.Mode != "snapshot" {
		t.Fatalf("restore = %+v, %v", res, err)
	}
	if len(sys.routes) != 0 {
		t.Fatalf("routes remain after restore: %v", sys.routes)
	}
	if _, err := os.Stat(filepath.Join(dir, SnapshotFile)); !os.IsNotExist(err) {
		t.Fatal("backup should be removed after verified restore")
	}
}

// M-2 + M-3: iron rule — second enable keeps Original; Written follows.
func TestIronRuleSnapshotKept(t *testing.T) {
	sys := newFake()
	e, _ := newEngine(t, sys)
	first, err := e.Enable(testExclusions)
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.Enable([]string{"203.0.113.7", "192.0.2.55"})
	if err != nil {
		t.Fatal(err)
	}
	_ = second
	kind, held := ReadSnapshot(e.Dir)
	if kind != SnapOK {
		t.Fatalf("snapshot kind = %s", kind)
	}
	if held.Original.DefaultGateway != first.Original.DefaultGateway || held.TakenAt != first.TakenAt {
		t.Fatal("original/takenAt moved on second enable")
	}
	foundNew := false
	for _, r := range held.Written.AddedRoutes {
		if r.Dest == "192.0.2.55/32" {
			foundNew = true
		}
		if r.Dest == "198.51.100.9/32" {
			t.Fatal("stale exclusion still in written after refresh")
		}
	}
	if !foundNew {
		t.Fatal("new exclusion missing from written")
	}
	// And the live table matches written exactly.
	present := OurRoutesPresent(mustRoutes(t, sys), held.Written)
	if !routeSetsEqual(present, held.Written.AddedRoutes) {
		t.Fatalf("live table diverged from written: %v vs %v", present, held.Written.AddedRoutes)
	}
}

func mustRoutes(t *testing.T, sys *fakeSystem) []Route {
	t.Helper()
	rs, err := sys.CurrentRoutes()
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// M-4: foreign state untouched.
func TestSelfHealForeignUntouched(t *testing.T) {
	sys := newFake()
	e, _ := newEngine(t, sys)
	if _, err := e.Enable(testExclusions); err != nil {
		t.Fatal(err)
	}
	// Everything of ours vanishes, replaced by someone else's full config:
	// emulate by clearing our routes and adding a foreign /1 via another gw.
	sys.routes = []Route{{Dest: "0.0.0.0/1", Gateway: "10.8.0.1", Interface: "OtherVPN"}}
	res, err := e.SelfHeal()
	if err != nil {
		t.Fatal(err)
	}
	// Only bare state: our routes absent → already-original path.
	if res.Mode != "already-original" {
		t.Fatalf("mode = %s, want already-original", res.Mode)
	}
	if len(sys.routes) != 1 {
		t.Fatalf("foreign routes were touched: %v", sys.routes)
	}
}

// M-5: corrupt backup degrades (removes fingerprint set), never silent.
func TestCorruptDegrades(t *testing.T) {
	sys := newFake()
	e, dir := newEngine(t, sys)
	// Pre-seed our fingerprint routes as a crashed run would leave them.
	for _, r := range FingerprintRoutes() {
		sys.routes = append(sys.routes, r)
	}
	if err := os.WriteFile(filepath.Join(dir, SnapshotFile), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs []string
	e.Log = func(s string) { logs = append(logs, s) }
	res, err := e.Restore()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Restored || res.Mode != "degraded-corrupt-backup" {
		t.Fatalf("restore = %+v", res)
	}
	if len(sys.routes) != 0 {
		t.Fatalf("fingerprint routes remain: %v", sys.routes)
	}
	if len(logs) == 0 || !strings.Contains(logs[0], "corrupt") {
		t.Fatalf("degradation not logged: %v", logs)
	}
}

// M-6: restore assertion catches a dropped delete; backup kept.
func TestRestoreAssertionKeepsBackup(t *testing.T) {
	sys := newFake()
	e, dir := newEngine(t, sys)
	if _, err := e.Enable(testExclusions); err != nil {
		t.Fatal(err)
	}
	sys.dropDels["0.0.0.0/1"] = true
	res, err := e.Restore()
	if err != nil {
		t.Fatal(err)
	}
	if res.Restored || res.Verified || len(res.Missing) == 0 {
		t.Fatalf("restore should fail verification: %+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, SnapshotFile)); err != nil {
		t.Fatal("backup must be kept when verification fails")
	}
}

// M-7: self-heal exact-written.
func TestSelfHealExactWritten(t *testing.T) {
	sys := newFake()
	e, _ := newEngine(t, sys)
	if _, err := e.Enable(testExclusions); err != nil {
		t.Fatal(err)
	}
	res, err := e.SelfHeal()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Healed || res.Mode != "self-heal" || len(sys.routes) != 0 {
		t.Fatalf("heal = %+v, routes = %v", res, sys.routes)
	}
}

// M-8: already-original — backup dropped, nothing touched.
func TestSelfHealAlreadyOriginal(t *testing.T) {
	sys := newFake()
	e, dir := newEngine(t, sys)
	if _, err := e.Enable(testExclusions); err != nil {
		t.Fatal(err)
	}
	sys.routes = nil // someone already cleaned up
	res, err := e.SelfHeal()
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "already-original" {
		t.Fatalf("mode = %s", res.Mode)
	}
	if _, err := os.Stat(filepath.Join(dir, SnapshotFile)); !os.IsNotExist(err) {
		t.Fatal("stale backup should be dropped")
	}
}

// M-9: partial state WITH fingerprint degrades by removing our set.
func TestSelfHealPartialOursDegrades(t *testing.T) {
	sys := newFake()
	e, _ := newEngine(t, sys)
	if _, err := e.Enable(testExclusions); err != nil {
		t.Fatal(err)
	}
	// Damage: remove one exclusion and one /1; the rest (incl. a /1) stays.
	sys.routes = sys.routes[2:]
	res, err := e.SelfHeal()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Healed || res.Mode != "degraded-partial-state" || len(sys.routes) != 0 {
		t.Fatalf("heal = %+v, routes = %v", res, sys.routes)
	}
}

// M-10: fingerprint negative — bare /32s only => NOT ours to touch.
func TestFingerprintNegative(t *testing.T) {
	sys := newFake()
	e, _ := newEngine(t, sys)
	if _, err := e.Enable(testExclusions); err != nil {
		t.Fatal(err)
	}
	// Only the two /32 exclusions remain (no /1s): no fingerprint.
	kept := []Route{}
	for _, r := range sys.routes {
		if !r.IsTakeover() {
			kept = append(kept, r)
		}
	}
	sys.routes = kept
	res, err := e.SelfHeal()
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != "foreign-state" {
		t.Fatalf("mode = %s, want foreign-state", res.Mode)
	}
	if len(sys.routes) != 2 {
		t.Fatalf("bare /32s were touched: %v", sys.routes)
	}
}

// M-11: atomic write — valid JSON, no tmp residue.
func TestSnapshotAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	snap := &Snapshot{Version: SnapshotVersion, TakenAt: "2026-11-14T00:00:00Z",
		Written: State{Adapter: AdapterCfg{Name: AdapterName}}}
	if err := WriteSnapshotAtomic(dir, snap); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, en := range entries {
		if strings.HasSuffix(en.Name(), ".tmp") {
			t.Fatalf("tmp residue: %s", en.Name())
		}
	}
	kind, got := ReadSnapshot(dir)
	if kind != SnapOK || got.TakenAt != snap.TakenAt {
		t.Fatalf("read back = %s %+v", kind, got)
	}
}

// M-12: route print parser.
func TestParseRoutePrint(t *testing.T) {
	sample := `
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     35
          0.0.0.0        128.0.0.0        10.99.0.1       10.99.0.1     35
        203.0.113.7  255.255.255.255      192.168.1.1     192.168.1.50     36
===========================================================================
Persistent Routes:
  None
`
	routes := ParseRoutePrint(sample)
	if len(routes) != 3 {
		t.Fatalf("parsed %d routes: %v", len(routes), routes)
	}
	if routes[1].Dest != "0.0.0.0/1" || routes[1].Gateway != "10.99.0.1" {
		t.Fatalf("takeover row misparsed: %+v", routes[1])
	}
	if routes[2].Dest != "203.0.113.7/32" {
		t.Fatalf("host row misparsed: %+v", routes[2])
	}
}

// M-15: exclusion refresh — all adds precede all deletes.
func TestExclusionRefreshAddBeforeDelete(t *testing.T) {
	old := []Route{
		{Dest: "198.51.100.9/32", Gateway: "192.168.1.1"},
		{Dest: "203.0.113.7/32", Gateway: "192.168.1.1"},
	}
	ops, err := PlanExclusionRefresh(old, []string{"203.0.113.7", "192.0.2.55"}, "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	lastAdd, firstDel := -1, 1<<30
	for i, op := range ops {
		if op.Kind == "add" {
			lastAdd = i
		}
		if op.Kind == "del" && i < firstDel {
			firstDel = i
		}
	}
	if lastAdd > firstDel {
		t.Fatalf("a delete precedes an add: %v", ops)
	}
	if len(ops) != 2 {
		t.Fatalf("ops = %v, want 1 add + 1 del", ops)
	}
}

// M-16: takeover order (exclusions before /1s) and restore order (inverse).
func TestTakeoverAndRestoreOrdering(t *testing.T) {
	ops, err := PlanTakeover(testExclusions, "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	for i, op := range ops {
		if op.Route.IsTakeover() && i < 2 {
			t.Fatalf("takeover route added before exclusions: %v", ops)
		}
	}
	written := State{AddedRoutes: func() []Route {
		rs := []Route{}
		for _, op := range ops {
			rs = append(rs, op.Route)
		}
		return rs
	}()}
	rops := PlanRestore(written)
	if !rops[0].Route.IsTakeover() || rops[len(rops)-1].Route.IsTakeover() {
		t.Fatalf("restore must remove /1s first, exclusions last: %v", rops)
	}
}

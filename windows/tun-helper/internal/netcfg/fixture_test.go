package netcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// RF-21-02 cross-language fixture: the app (JS) and the helper (Go) read
// ONE canonical netcfg-backup.json. This side asserts every field the JS
// validator asserts, and that the fixture passes the Go structural
// validation verbatim (it is copied into a snapshot dir and classified).
// The JS mirror is windows/tests/netcfg-backup.test.mjs.
func fixturePath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "tests", "fixtures", "netcfg-backup.json")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	return p
}

func TestCrossLanguageFixture(t *testing.T) {
	raw, err := os.ReadFile(fixturePath(t))
	if err != nil {
		t.Fatal(err)
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Version != 1 || snap.TakenAt != "2026-11-14T00:00:00Z" {
		t.Fatalf("header = %d %q", snap.Version, snap.TakenAt)
	}
	if snap.Original.DefaultGateway != "192.168.1.1" || snap.Written.DefaultGateway != "192.168.1.1" {
		t.Fatal("gateway fields differ")
	}
	if !reflect.DeepEqual(snap.Original.PhysicalDNS, map[string][]string{"Wi-Fi": {"192.168.1.1"}}) {
		t.Fatalf("physicalDns = %v", snap.Original.PhysicalDNS)
	}
	if !reflect.DeepEqual(snap.Written.Adapter, AdapterCfg{Name: "Hollow", IPv4: "10.99.0.1/24", IPv6: "fd00::1/64", DNS: []string{"10.99.0.1"}}) {
		t.Fatalf("written adapter = %+v", snap.Written.Adapter)
	}
	wantRoutes := []Route{
		{Dest: "203.0.113.7/32", Gateway: "192.168.1.1"},
		{Dest: "0.0.0.0/1", Gateway: "10.99.0.1", Interface: "Hollow"},
		{Dest: "128.0.0.0/1", Gateway: "10.99.0.1", Interface: "Hollow"},
		{Dest: "::/1", Gateway: "fd00::1", Interface: "Hollow"},
		{Dest: "8000::/1", Gateway: "fd00::1", Interface: "Hollow"},
	}
	if !reflect.DeepEqual(snap.Written.AddedRoutes, wantRoutes) {
		t.Fatalf("written routes = %+v", snap.Written.AddedRoutes)
	}
	if len(snap.Original.AddedRoutes) != 0 {
		t.Fatal("original must carry no added routes")
	}
	// The fixture must classify OK through the production reader.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, SnapshotFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if kind, _ := ReadSnapshot(dir); kind != SnapOK {
		t.Fatalf("fixture classifies %v, want ok", kind)
	}
	// And re-marshaling the parsed value must be field-stable.
	raw2, _ := json.Marshal(snap)
	var snap2 Snapshot
	if err := json.Unmarshal(raw2, &snap2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snap, snap2) {
		t.Fatal("marshal round-trip drift")
	}
}

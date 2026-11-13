package server

import (
	"testing"

	"hollow/tun-helper/internal/ipc"
	"hollow/tun-helper/internal/netcfg"
	"hollow/tun-helper/internal/pump"
)

// fakeNetcfgSystem is an in-memory routing table for the wiring test.
type fakeNetcfgSystem struct{ routes []netcfg.Route }

func (f *fakeNetcfgSystem) CurrentRoutes() ([]netcfg.Route, error) {
	out := append([]netcfg.Route{}, f.routes...)
	out = append(out, netcfg.Route{Dest: "0.0.0.0/0", Gateway: "192.168.1.1", Interface: "Wi-Fi"})
	return out, nil
}
func (f *fakeNetcfgSystem) AddRoute(r netcfg.Route) error {
	for _, x := range f.routes {
		if x.Key() == r.Key() {
			return nil
		}
	}
	f.routes = append(f.routes, r)
	return nil
}
func (f *fakeNetcfgSystem) DelRoute(r netcfg.Route) error {
	kept := []netcfg.Route{}
	for _, x := range f.routes {
		if x.Key() != r.Key() {
			kept = append(kept, x)
		}
	}
	f.routes = kept
	return nil
}
func (f *fakeNetcfgSystem) DefaultGateway() (string, error) { return "192.168.1.1", nil }
func (f *fakeNetcfgSystem) PhysicalDNS() (map[string][]string, error) {
	return map[string][]string{"Wi-Fi": {"192.168.1.1"}}, nil
}

// T-2 wiring: enable_tun lands the takeover (exclusions + /1s),
// set_exclusions refreshes the set live, disable_tun unwinds everything.
func TestNetcfgWiringEnableRefreshDisable(t *testing.T) {
	aEP, _ := pump.NewChannelPair(1280)
	sys := &fakeNetcfgSystem{}
	eng := &netcfg.Engine{Dir: t.TempDir(), Sys: sys}
	deps := testDeps(aEP)
	deps.Netcfg = eng
	srv := New(deps)
	c := newTestClient(t, srv)

	// Use the raw dispatch path via the client helper's verb request:
	rep := c.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11080, Exclusions: []string{"203.0.113.7"}})
	if rep.OK == nil || !*rep.OK {
		t.Fatalf("enable_tun reply: %+v", rep)
	}
	if len(sys.routes) != 5 { // 1 exclusion + 4 takeover
		t.Fatalf("routes after enable = %v", sys.routes)
	}

	rep = c.request(t, ipc.VerbSetExclusions, ipc.SetExclusionsParams{IPs: []string{"198.51.100.9"}})
	if rep.OK == nil || !*rep.OK {
		t.Fatalf("set_exclusions reply: %+v", rep)
	}
	foundNew, foundOld := false, false
	for _, r := range sys.routes {
		if r.Dest == "198.51.100.9/32" {
			foundNew = true
		}
		if r.Dest == "203.0.113.7/32" {
			foundOld = true
		}
	}
	if !foundNew || foundOld {
		t.Fatalf("refresh wrong: new=%v old-still-there=%v routes=%v", foundNew, foundOld, sys.routes)
	}

	rep = c.request(t, ipc.VerbDisableTun, nil)
	if rep.OK == nil || !*rep.OK {
		t.Fatalf("disable_tun reply: %+v", rep)
	}
	if len(sys.routes) != 0 {
		t.Fatalf("routes after disable = %v", sys.routes)
	}
}

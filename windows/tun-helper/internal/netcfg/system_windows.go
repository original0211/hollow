//go:build windows

package netcfg

import (
	"fmt"
	"os/exec"
	"strings"
)

// Windows System adapter over route.exe / netsh. Route mutations are
// idempotent at this layer (adding an existing route or deleting a
// missing one is success) so restores and self-heals can be re-run
// safely; verification always happens in the engine by re-reading the
// table. Real-machine behavior is NOT verified from the sandbox — see
// files/m2/real-machine-tun-t2-addendum.md.
type winSystem struct{}

func NewSystem() (System, error) { return winSystem{}, nil }

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func (winSystem) CurrentRoutes() ([]Route, error) {
	out4, err := runCmd("route", "print", "-4")
	if err != nil {
		return nil, fmt.Errorf("route print -4: %w", err)
	}
	out6, err := runCmd("route", "print", "-6")
	if err != nil {
		return nil, fmt.Errorf("route print -6: %w", err)
	}
	return append(ParseRoutePrint(out4), ParseRoutePrint6(out6)...), nil
}

func splitDest(dest string) (string, int, bool) {
	var ip string
	var bits int
	is6 := strings.Contains(dest, ":")
	if _, err := fmt.Sscanf(dest, "%s", &ip); err != nil {
		return "", 0, is6
	}
	slash := strings.LastIndex(dest, "/")
	if slash < 0 {
		return dest, -1, is6
	}
	fmt.Sscanf(dest[slash+1:], "%d", &bits)
	return dest[:slash], bits, is6
}

func prefixToMask(bits int) string {
	m := uint32(0)
	for i := 0; i < bits; i++ {
		m |= 1 << (31 - i)
	}
	return fmt.Sprintf("%d.%d.%d.%d", m>>24, (m>>16)&0xff, (m>>8)&0xff, m&0xff)
}

func (winSystem) AddRoute(r Route) error {
	ip, bits, is6 := splitDest(r.Dest)
	if is6 {
		if r.Interface == "" {
			return fmt.Errorf("v6 route %s: interface required by netsh (v6 exclusions not supported by this adapter)", r.Dest)
		}
		out, err := runCmd("netsh", "interface", "ipv6", "add", "route", r.Dest, "interface="+r.Interface, r.Gateway)
		if err != nil && !strings.Contains(out, "already exists") {
			return fmt.Errorf("netsh add %s: %v (%s)", r.Dest, err, strings.TrimSpace(out))
		}
		return nil
	}
	out, err := runCmd("route", "add", ip, "mask", prefixToMask(bits), r.Gateway)
	if err != nil && !strings.Contains(out, "already exists") {
		return fmt.Errorf("route add %s: %v (%s)", r.Dest, err, strings.TrimSpace(out))
	}
	return nil
}

func (winSystem) DelRoute(r Route) error {
	ip, bits, is6 := splitDest(r.Dest)
	if is6 {
		if r.Interface == "" {
			return fmt.Errorf("v6 route %s: interface required by netsh", r.Dest)
		}
		out, err := runCmd("netsh", "interface", "ipv6", "delete", "route", r.Dest, "interface="+r.Interface, r.Gateway)
		if err != nil && !strings.Contains(out, "not found") {
			return fmt.Errorf("netsh delete %s: %v (%s)", r.Dest, err, strings.TrimSpace(out))
		}
		return nil
	}
	out, err := runCmd("route", "delete", ip, "mask", prefixToMask(bits), r.Gateway)
	if err != nil && !strings.Contains(out, "not found") {
		return fmt.Errorf("route delete %s: %v (%s)", r.Dest, err, strings.TrimSpace(out))
	}
	return nil
}

func (winSystem) DefaultGateway() (string, error) {
	routes, err := winSystem{}.CurrentRoutes()
	if err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dest == "0.0.0.0/0" {
			return r.Gateway, nil
		}
	}
	return "", fmt.Errorf("no default route found")
}

func (winSystem) PhysicalDNS() (map[string][]string, error) {
	out, err := runCmd("netsh", "interface", "ip", "show", "dnsservers")
	if err != nil {
		return nil, err
	}
	// Best-effort record (spec §1.2: recorded, never modified). Lines look
	// like: Configuration for interface "Wi-Fi" / DNS servers: 1.1.1.1 ...
	result := map[string][]string{}
	current := ""
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Configuration for interface") {
			current = strings.Trim(t[strings.Index(t, "\""):], "\"")
			result[current] = []string{}
			continue
		}
		if current != "" {
			for _, tok := range strings.Fields(t) {
				if isIPv4(tok) {
					result[current] = append(result[current], tok)
				}
			}
		}
	}
	return result, nil
}

package netcfg

import (
	"fmt"
	"sort"
	"strings"
)

// ParseRoutePrint parses Windows `route print` output into canonical
// routes (mapping table M-12: the netcfg counterpart of sysproxy's
// parseRegQuery). Handles the IPv4 table (Network Destination / Netmask /
// Gateway / Interface columns). IPv6 route print has a different layout
// and is parsed by ParseRoutePrint6.
func ParseRoutePrint(text string) []Route {
	out := []Route{}
	inTable := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Network Destination") {
			inTable = true
			continue
		}
		if inTable {
			if trimmed == "" || strings.HasPrefix(trimmed, "===") || strings.HasPrefix(trimmed, "Persistent Routes") {
				if strings.HasPrefix(trimmed, "Persistent") {
					break
				}
				continue
			}
			f := strings.Fields(trimmed)
			if len(f) < 4 {
				continue
			}
			dest, mask, gw := f[0], f[1], f[2]
			prefix, err := maskToPrefix(mask)
			if err != nil || !isIPv4(dest) {
				continue
			}
			iface := ""
			if len(f) >= 4 {
				iface = f[3]
			}
			out = append(out, Route{Dest: fmt.Sprintf("%s/%d", dest, prefix), Gateway: gw, Interface: iface})
		}
	}
	return out
}

// ParseRoutePrint6 parses `route print -6` rows:
// "if  Metric  Network Destination  Gateway" — destination already CIDR.
func ParseRoutePrint6(text string) []Route {
	out := []Route{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 4 {
			continue
		}
		dest := f[2]
		if !strings.Contains(dest, "/") || !strings.Contains(dest, ":") {
			continue
		}
		out = append(out, Route{Dest: dest, Gateway: f[3]})
	}
	return out
}

func maskToPrefix(mask string) (int, error) {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("bad mask")
	}
	bits := 0
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 0 || n > 255 {
			return 0, fmt.Errorf("bad mask octet")
		}
		for n > 0 {
			bits += n & 1
			n >>= 1
		}
	}
	return bits, nil
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return false
		}
	}
	return true
}

// sortRoutes gives snapshots a canonical order for stable files/diffs.
func sortRoutes(rs []Route) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Key() < rs[j].Key() })
}

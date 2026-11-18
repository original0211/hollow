package session

// Entry dispersion (NP-1118-09): the Go port of NP-1117-27 (JS
// windows/src/edges.js + core-bridge). The candidate list comes from
// the Worker's own /edges.json (protected direct fetch; the shipped
// builtin list is the fallback), each candidate is measured with
// three real Hollow handshakes (median RTT, all three must succeed),
// and the ranked survivors are pinned one-per-lineage: the dial
// target is the pinned IP while TLS ServerName and the WS Host stay
// on the configured hostname. Per-IP health memory demotes an entry
// after 3 consecutive establishment failures until the next refresh;
// a lineage whose primary is demoted or taken re-pins to the best
// free candidate, and a lineage past the end of the list dials by
// domain — never by substitute. Live carriers are never torn down
// by a refresh; pins apply at each lineage's next establishment.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"time"

	"hollow/androidcore/core"
)

// EdgeCandidate is one ranked entry candidate (state surface shape
// mirrors the JS bridge: ip + rttMs).
type EdgeCandidate struct {
	IP    string `json:"ip"`
	RTTMs int64  `json:"rttMs"`
}

// builtinEdges mirrors windows/src/edges.js BUILTIN_EDGES (the
// shipped fallback when /edges.json cannot be fetched).
var builtinEdges = []string{
	"104.16.85.20", "104.17.164.30", "104.18.12.149", "104.19.152.10",
	"104.20.24.10", "104.21.56.100", "104.22.10.10", "172.64.80.100",
	"172.67.74.152", "104.24.10.20",
}

var ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)

// parseEdgesJSON accepts the v2 payload ({edges: ["1.2.3.4", ...]})
// and the v1 object form ({edges: [{ip: ...}]}), IPv4 only, ≤64.
func parseEdgesJSON(body []byte) ([]string, error) {
	var payload struct {
		Edges []json.RawMessage `json:"edges"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("edges payload malformed: %w", err)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, raw := range payload.Edges {
		if len(out) >= 64 {
			break
		}
		var ip string
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			ip = s
		} else {
			var obj struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(raw, &obj); err == nil {
				ip = obj.IP
			}
		}
		if ip != "" && ipv4Re.MatchString(ip) && net.ParseIP(ip) != nil && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("edges payload empty")
	}
	return out, nil
}

// fetchEdgesList gets the candidate list: /edges.json over the
// protected direct dialer when configured, else the builtin list.
// Any failure falls back to the builtin list (fail-open: dispersion
// is an optimization, never a connection prerequisite).
func (s *Session) fetchEdgesList(ctx context.Context) []string {
	if s.cfg.HostBase == "" || s.cfg.EdgesPath == "" {
		return builtinEdges
	}
	tr := &http.Transport{DialContext: pinDial(s.dialContext(), s.bestDialIP())}
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.HostBase+s.cfg.EdgesPath, nil)
	if err != nil {
		return builtinEdges
	}
	req.Header.Set("User-Agent", ClientUA)
	resp, err := hc.Do(req)
	if err != nil {
		return builtinEdges
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return builtinEdges
	}
	list, err := parseEdgesJSON(body)
	if err != nil {
		return builtinEdges
	}
	return list
}

// handshakeProbeOnce performs one full Hollow handshake through the
// pinned IP and returns its RTT. Probe traffic is NOT counted in the
// session's display counters (nil counters), as on Windows.
func (s *Session) handshakeProbeOnce(ctx context.Context, ip string) (time.Duration, error) {
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	start := time.Now()
	tport, err := dialCarrier(pctx, s.cfg.WSURL, s.dialContext(), nil, ip)
	if err != nil {
		return 0, err
	}
	client := core.NewClient(tport, core.ClientOptions{PSK: s.cfg.PSK, KeyID: byte(s.cfg.KeyID)})
	tport.attach(client)
	done := client.Handshake()
	select {
	case <-done:
		if err := client.Err(); err != nil {
			tport.Close()
			return 0, err
		}
	case <-pctx.Done():
		tport.Close()
		return 0, pctx.Err()
	}
	rtt := time.Since(start)
	client.Close()
	return rtt, nil
}

// measureEdges probes every candidate (3 handshakes, median; any
// failure disqualifies the candidate, mirroring measureEdges) and
// returns the ranked survivors, best first.
func (s *Session) measureEdges(ctx context.Context, list []string) []EdgeCandidate {
	out := []EdgeCandidate{}
	for _, ip := range list {
		samples := []time.Duration{}
		ok := true
		for i := 0; i < 3; i++ {
			rtt, err := s.handshakeProbeOnce(ctx, ip)
			if err != nil {
				ok = false
				break
			}
			samples = append(samples, rtt)
		}
		if !ok {
			continue
		}
		sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
		out = append(out, EdgeCandidate{IP: ip, RTTMs: samples[1].Milliseconds()})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].RTTMs < out[b].RTTMs })
	return out
}

// setEdgeCandidates installs a fresh ranked list. A refresh is new
// health evidence: failure counts and demotions reset (JS parity).
func (s *Session) setEdgeCandidates(list []EdgeCandidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(list) == 0 {
		s.edgeCandidates = nil
	} else {
		s.edgeCandidates = list
	}
	s.edgeFailCounts = map[string]int{}
	s.edgeDisfavored = map[string]bool{}
}

// refreshEdges runs one fetch+measure cycle and installs the result.
// Guarded against overlap; safe to call from multiple triggers.
func (s *Session) refreshEdges() {
	s.mu.Lock()
	if s.measuring {
		s.mu.Unlock()
		return
	}
	s.measuring = true
	s.lastMeasure = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.measuring = false
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	s.refreshBootstrap(ctx)
	list := s.fetchEdgesList(ctx)
	ranked := s.measureEdges(ctx, list)
	if len(ranked) > 0 {
		s.setEdgeCandidates(ranked)
	}
}

// pickSlotEdge returns the pinned candidate IP for a lineage ("" =
// dial by domain), reserving the pin at pick time so concurrent
// establishments never land two lineages on the same entry (JS
// _pickSlotEdge parity, minus the Windows bearer-lock concept).
func (s *Session) pickSlotEdge(slot int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.edgeCandidates
	if len(list) == 0 {
		// No ranked candidates yet: the bootstrap set (the entry
		// hostname's own resolved addresses, NP-1118-11) pins the
		// slot. Distribution mirrors the ranked path (NP-1118-14
		// (c)): the slot's wrap position first, but if another
		// slot already holds it and a set member is unheld, take
		// the first unheld member — slots only share an address
		// when the set is smaller than the pool.
		if len(s.bootstrapIPs) > 0 {
			ip := s.bootstrapIPs[slot%len(s.bootstrapIPs)]
			held := map[string]bool{}
			for other, e := range s.slotEdges {
				if other != slot {
					held[e] = true
				}
			}
			if held[ip] {
				for _, cand := range s.bootstrapIPs {
					if !held[cand] {
						ip = cand
						break
					}
				}
			}
			if s.slotEdges == nil {
				s.slotEdges = map[int]string{}
			}
			if s.bootstrapPinned == nil {
				s.bootstrapPinned = map[int]bool{}
			}
			s.slotEdges[slot] = ip
			s.bootstrapPinned[slot] = true
			return ip
		}
		return ""
	}
	delete(s.bootstrapPinned, slot)
	// A slot past the end of the list has no primary: it dials by
	// domain, never by substitute.
	if slot >= len(list) {
		if s.slotEdges != nil {
			delete(s.slotEdges, slot)
		}
		return ""
	}
	usedByOthers := map[string]bool{}
	for other, ip := range s.slotEdges {
		if other != slot {
			usedByOthers[ip] = true
		}
	}
	pick := ""
	primary := list[slot]
	if !s.edgeDisfavored[primary.IP] && !usedByOthers[primary.IP] {
		pick = primary.IP
	} else {
		for _, c := range list {
			if !s.edgeDisfavored[c.IP] && !usedByOthers[c.IP] {
				pick = c.IP
				break
			}
		}
	}
	if s.slotEdges == nil {
		s.slotEdges = map[int]string{}
	}
	if pick == "" {
		delete(s.slotEdges, slot)
	} else {
		s.slotEdges[slot] = pick
	}
	return pick
}

// noteEdgeFailure records one establishment failure against an IP;
// at 3 consecutive failures the IP is demoted until the next
// refresh. Auth-fatal failures are excluded (JS parity — they stop
// the pool instead).
func (s *Session) noteEdgeFailure(ip string, err error) {
	if ip == "" || isAuthFatal(err) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.edgeFailCounts == nil {
		s.edgeFailCounts = map[string]int{}
	}
	if s.edgeDisfavored == nil {
		s.edgeDisfavored = map[string]bool{}
	}
	s.edgeFailCounts[ip]++
	if s.edgeFailCounts[ip] >= 3 {
		s.edgeDisfavored[ip] = true
	}
}

// noteEdgeSuccess resets an IP's consecutive-failure count.
func (s *Session) noteEdgeSuccess(ip string) {
	if ip == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.edgeFailCounts != nil {
		delete(s.edgeFailCounts, ip)
	}
}

// bestEdgeIP is the best currently-usable candidate (for /meta).
func (s *Session) bestEdgeIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.edgeCandidates {
		if !s.edgeDisfavored[c.IP] {
			return c.IP
		}
	}
	return ""
}

// liveCount reports how many lineages currently hold a live client.
func (s *Session) liveCount() int {
	n := 0
	for _, l := range s.lineages() {
		if l.healthy() {
			n++
		}
	}
	return n
}

// redialCap is the pool-aware §8.4 backoff cap (NP-1118-09 (e)):
// while the pool is degraded (live < total) redials stay eager at
// ~5s; at full health the standard 60s cap applies. §8.4 tiers are
// local parameters (§10.2), so this does not touch frozen spec.
func (s *Session) redialCap() time.Duration {
	lines := s.lineages()
	if len(lines) > 0 && s.liveCount() < len(lines) {
		return 5 * time.Second
	}
	return 60 * time.Second
}

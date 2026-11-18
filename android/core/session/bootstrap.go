package session

// Bootstrap resolution (NP-1118-11). Diagnosis in brief: once the
// VPN is up, the process's default resolver answers the entry
// hostname with a definitive negative ("no such host" — the Go
// resolver's mapping of NXDOMAIN / empty NOERROR, reproduced
// in-sandbox; SERVFAIL and timeouts map to different strings and
// are ruled out). Every name-based dial in the connected state is
// therefore dead on some devices: /meta, the /edges.json fetch,
// and any carrier establishment that needs the name.
//
// The fix removes the dependency: the entry hostname is resolved
// by an explicit DNS A query to public resolvers over the
// session's protected dialer — protect()ed sockets bypass the
// TUN entirely, so the answer never depends on the tunnel or on
// the connected-state system resolver. The resulting IP set is
// persisted across sessions (last-known-good), seeds the carrier
// pins before any edge measurement exists, and backs the
// edges/meta control-plane dials.
import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// bootstrapServers are queried in order until one answers with
// A records.
var bootstrapServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// buildDNSQueryA builds a standard RD query for A records.
func buildDNSQueryA(host string, id uint16) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(out[4:6], 1)      // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], 1) // A
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	return append(out, tail[:]...)
}

// skipDNSName returns the offset just past the name at off,
// following the "pointer ends the name here" rule.
func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errors.New("dns: name overruns message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, errors.New("dns: bad label type")
		default:
			off += 1 + l
		}
	}
}

// parseDNSARecords extracts A records from a response message.
func parseDNSARecords(msg []byte, wantID uint16) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("dns: short message")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != wantID {
		return nil, errors.New("dns: id mismatch")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("dns: not a response")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return nil, fmt.Errorf("dns: rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4
		if off > len(msg) {
			return nil, errors.New("dns: question overruns message")
		}
	}
	ips := []string{}
	for i := 0; i < an; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(msg) {
			return nil, errors.New("dns: rr header overruns message")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return nil, errors.New("dns: rdata overruns message")
		}
		if typ == 1 && rdlen == 4 {
			ips = append(ips, net.IP(msg[off:off+4]).String())
		}
		off += rdlen
	}
	return ips, nil
}

// resolveHostA resolves host's A records with explicit DNS
// queries over dialFn (the session's protected dialer in
// production — never the system resolver, never the tunnel).
func resolveHostA(ctx context.Context, dialFn func(ctx context.Context, network, addr string) (net.Conn, error), host string) ([]string, error) {
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	query := buildDNSQueryA(host, id)
	var lastErr error
	for _, server := range bootstrapServers {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		conn, err := dialFn(sctx, "udp", server)
		if err != nil {
			lastErr = err
			cancel()
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			lastErr = err
			conn.Close()
			cancel()
			continue
		}
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				lastErr = err
				break
			}
			ips, perr := parseDNSARecords(buf[:n], id)
			if perr != nil {
				continue // mismatched/stray datagram: keep reading
			}
			conn.Close()
			cancel()
			if len(ips) == 0 {
				lastErr = errors.New("dns: no A records")
				break
			}
			return ips, nil
		}
		conn.Close()
		cancel()
	}
	return nil, lastErr
}

// refreshBootstrap re-resolves the entry hostname and, on a
// changed non-empty answer, swaps the bootstrap set and persists
// it via the configured callback. Fail-open throughout: any error
// keeps the previous set.
func (s *Session) refreshBootstrap(ctx context.Context) {
	host := ""
	if u, err := url.Parse(s.cfg.WSURL); err == nil {
		host = u.Hostname()
	}
	if host == "" {
		return
	}
	if ip := net.ParseIP(host); ip != nil {
		s.mu.Lock()
		s.bootstrapIPs = []string{host}
		s.mu.Unlock()
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ips, err := resolveHostA(rctx, s.dialContext(), host)
	if err != nil || len(ips) == 0 {
		return
	}
	s.mu.Lock()
	changed := strings.Join(ips, ",") != strings.Join(s.bootstrapIPs, ",")
	s.bootstrapIPs = ips
	cb := s.cfg.OnBootstrapIPs
	s.mu.Unlock()
	if changed && cb != nil {
		go cb(append([]string(nil), ips...))
	}
}

// bootstrapIPFor returns the bootstrap pin for a slot: the set is
// the hostname's own addresses, so slots wrap around it (unlike
// ranked candidates, sharing one of the host's anycast addresses
// is equivalent to what domain dialing would land on anyway).
func (s *Session) bootstrapIPFor(slot int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bootstrapIPs) == 0 {
		return ""
	}
	return s.bootstrapIPs[slot%len(s.bootstrapIPs)]
}

// bestDialIP is the control-plane dial pin: the best ranked edge
// when one exists, else the first bootstrap address, else "".
func (s *Session) bestDialIP() string {
	if ip := s.bestEdgeIP(); ip != "" {
		return ip
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bootstrapIPs) > 0 {
		return s.bootstrapIPs[0]
	}
	return ""
}

// pinDial wraps a dial function so the TCP target becomes ip
// (same port), leaving TLS ServerName / Host to the URL as usual.
func pinDial(dial func(ctx context.Context, network, addr string) (net.Conn, error), ip string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if ip == "" {
		return dial
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return dial(ctx, network, net.JoinHostPort(ip, port))
	}
}

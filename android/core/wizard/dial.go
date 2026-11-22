package wizard

// The wizard's direct network path (NP-1118-62 increment 2).
//
// Platform fact: the app's TUN takes 0.0.0.0/0 + ::/0 and the app
// does NOT exclude itself, so every unprotected socket of this
// process enters the tunnel while the VPN is up. The wizard must
// never ride its own tunnel — it deploys the very Worker the
// tunnel may not even have yet — so all of its traffic uses this
// dialer, which mirrors the session layer's two established
// constructions:
//
//   - every socket is protect()ed before connect (session/ws.go's
//     protectedDialContext, D10), bypassing the TUN entirely; the
//     protector is nil when no VPN service runs, in which case
//     there is no TUN and a plain dial IS a direct dial;
//   - names are resolved by explicit DNS A queries to public
//     resolvers over protected sockets (session/bootstrap.go's
//     NP-1118-11 construction) — the system resolver is never
//     consulted (with the VPN up it points at the tunnel's virtual
//     gateway, and Go's resolver on Android is not to be relied
//     on in the first place). The dial pins the resolved IP while
//     TLS ServerName / WS Host stay on the original name, because
//     callers always see the name form.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// Protector is implemented on the Kotlin side (VpnService.protect);
// identical in shape to session.Protector.
type Protector interface {
	Protect(fd int) bool
}

var errProtectFailed = errors.New("VpnService.protect refused the socket")

// protectedDialer is the raw protected dial (TCP and UDP).
func protectedDialer(p Protector) *net.Dialer {
	return &net.Dialer{
		Timeout: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if p == nil {
				return nil
			}
			var perr error
			cerr := c.Control(func(fd uintptr) {
				if !p.Protect(int(fd)) {
					perr = errProtectFailed
				}
			})
			if cerr != nil {
				return cerr
			}
			return perr
		},
	}
}

// DirectDialer dials hostnames by resolving them itself and
// pinning the answer, always over protected sockets.
type DirectDialer struct {
	Protector Protector

	mu    sync.Mutex
	cache map[string][]string
}

func (d *DirectDialer) raw() *net.Dialer { return protectedDialer(d.Protector) }

// DialContext implements the net dialer shape http.Transport and
// the websocket dialer consume: addr's host is resolved (unless
// already an IP), the resolved IP is dialed, and the caller keeps
// using the name for TLS/Host purposes.
func (d *DirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return d.raw().DialContext(ctx, network, addr)
	}
	ips, err := d.ResolveA(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.raw().DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// bootstrapServers are queried in order until one answers with A
// records (session/bootstrap.go's order).
var bootstrapServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// ResolveA returns the A records for host, asking public
// resolvers over protected UDP sockets. Answers are cached for
// the dialer's lifetime (one wizard run / probe set).
func (d *DirectDialer) ResolveA(ctx context.Context, host string) ([]string, error) {
	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[string][]string{}
	}
	if ips, ok := d.cache[host]; ok {
		d.mu.Unlock()
		return ips, nil
	}
	d.mu.Unlock()
	var lastErr error
	for _, server := range bootstrapServers {
		ips, err := d.queryA(ctx, server, host)
		if err == nil && len(ips) > 0 {
			d.mu.Lock()
			d.cache[host] = ips
			d.mu.Unlock()
			return ips, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns: no A records for %s", host)
	}
	return nil, lastErr
}

func (d *DirectDialer) queryA(ctx context.Context, server, host string) ([]string, error) {
	qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	conn, err := d.raw().DialContext(qctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	if _, err := conn.Write(buildDNSQueryA(host, id)); err != nil {
		return nil, err
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseDNSAnswersA(buf[:n], id)
}

// buildDNSQueryA builds a standard RD query for A records
// (session/bootstrap.go's wire shape).
func buildDNSQueryA(host string, id uint16) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(out[4:6], 1)      // QDCOUNT
	for _, label := range splitLabels(host) {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], 1) // A
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	return append(out, tail[:]...)
}

func splitLabels(host string) []string {
	var labels []string
	cur := ""
	for _, ch := range host {
		if ch == '.' {
			if cur != "" {
				labels = append(labels, cur)
				cur = ""
			}
			continue
		}
		cur += string(ch)
	}
	if cur != "" {
		labels = append(labels, cur)
	}
	return labels
}

// skipDNSName returns the offset just past the name at off,
// following the compression-pointer rule (session/bootstrap.go).
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
		default:
			off += 1 + l
		}
	}
}

// parseDNSAnswersA extracts A records from a response message.
func parseDNSAnswersA(msg []byte, wantID uint16) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("dns: short message")
	}
	if binary.BigEndian.Uint16(msg[0:2]) != wantID {
		return nil, errors.New("dns: id mismatch")
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		off += 4
	}
	var ips []string
	for i := 0; i < an; i++ {
		var err error
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(msg) {
			return nil, errors.New("dns: answer overruns message")
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

// HTTPClient is the wizard's HTTP client over the direct dialer.
// Per-request bounds come from the client timeout (no unbounded
// waits anywhere in the wizard path).
func (d *DirectDialer) HTTPClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext:         d.DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

package session

// NP-1118-11 loopback evidence: the bootstrap wire resolver, the
// bootstrap pin tier, and — the headline grid — full pool
// establishment against a hostname that cannot resolve, carried
// entirely by the persisted bootstrap set.
import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/url"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// datagramFakeConn is an in-memory UDP-style conn: each Write
// stores the query and synthesizes the response for the next Read.
type datagramFakeConn struct {
	query []byte
	resp  []byte
}

func (c *datagramFakeConn) Read(b []byte) (int, error) {
	if c.resp == nil {
		return 0, errors.New("no response queued")
	}
	n := copy(b, c.resp)
	c.resp = nil
	return n, nil
}
func (c *datagramFakeConn) Write(b []byte) (int, error) {
	c.query = append([]byte(nil), b...)
	c.resp = synthDNSResponse(c.query)
	return len(b), nil
}
func (c *datagramFakeConn) Close() error                       { return nil }
func (c *datagramFakeConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *datagramFakeConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *datagramFakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *datagramFakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *datagramFakeConn) SetWriteDeadline(t time.Time) error { return nil }

// synthDNSResponse answers an A query with a CNAME (compressed
// pointer) followed by two A records.
func synthDNSResponse(q []byte) []byte {
	id := q[0:2]
	i := 12
	for q[i] != 0 {
		i += int(q[i]) + 1
	}
	question := q[12 : i+5]
	hdr := make([]byte, 12)
	copy(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8180)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[6:8], 3) // CNAME + 2 A
	out := append(hdr, question...)
	rr := func(typ uint16, rdata []byte) {
		out = append(out, 0xC0, 0x0C)
		var fixed [10]byte
		binary.BigEndian.PutUint16(fixed[0:2], typ)
		binary.BigEndian.PutUint16(fixed[2:4], 1)
		binary.BigEndian.PutUint32(fixed[4:8], 60)
		binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
		out = append(out, fixed[:]...)
		out = append(out, rdata...)
	}
	// CNAME target: a label-encoded name (parser must skip it).
	rr(5, []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0})
	rr(1, net.ParseIP("104.16.85.20").To4())
	rr(1, net.ParseIP("104.17.164.30").To4())
	return out
}

func TestResolveHostA(t *testing.T) {
	var dialedAddr string
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "udp" {
			return nil, errors.New("want udp")
		}
		dialedAddr = addr
		return &datagramFakeConn{}, nil
	}
	ips, err := resolveHostA(context.Background(), dialFn, "v-hollow.kdns.fr")
	if err != nil {
		t.Fatalf("resolveHostA: %v", err)
	}
	if dialedAddr != "1.1.1.1:53" {
		t.Fatalf("first server dialed = %s, want 1.1.1.1:53", dialedAddr)
	}
	if len(ips) != 2 || ips[0] != "104.16.85.20" || ips[1] != "104.17.164.30" {
		t.Fatalf("ips = %v", ips)
	}
	// ID mismatch is rejected.
	if _, err := parseDNSARecords(synthDNSResponse(buildDNSQueryA("x.example", 0x1111)), 0x2222); err == nil {
		t.Fatal("id mismatch accepted")
	}
	// NXDOMAIN maps to an error (never an empty success).
	nx := synthDNSResponse(buildDNSQueryA("x.example", 0x1111))
	binary.BigEndian.PutUint16(nx[2:4], 0x8183)
	if _, err := parseDNSARecords(nx, 0x1111); err == nil {
		t.Fatal("nxdomain accepted")
	}
}

func TestBootstrapPinTier(t *testing.T) {
	s := newTestPoolSession("ws://127.0.0.1:1", testPSK(), 4)
	s.mu.Lock()
	s.bootstrapIPs = []string{"10.9.0.1", "10.9.0.2"}
	s.mu.Unlock()
	// No ranked candidates: bootstrap pins, wrapping around the set.
	for slot, want := range []string{"10.9.0.1", "10.9.0.2", "10.9.0.1", "10.9.0.2"} {
		if got := s.pickSlotEdge(slot); got != want {
			t.Fatalf("slot %d bootstrap pin = %q, want %q", slot, got, want)
		}
	}
	// Ranked candidates take precedence over the bootstrap set.
	s.setEdgeCandidates(rankedFixture())
	if got := s.pickSlotEdge(0); got != "10.0.0.1" {
		t.Fatalf("ranked precedence pick = %q, want 10.0.0.1", got)
	}
	// bestDialIP: ranked first, bootstrap as fallback.
	if got := s.bestDialIP(); got != "10.0.0.1" {
		t.Fatalf("bestDialIP with ranked = %q", got)
	}
	s2 := newTestPoolSession("ws://127.0.0.1:1", testPSK(), 1)
	s2.mu.Lock()
	s2.bootstrapIPs = []string{"10.9.0.9"}
	s2.mu.Unlock()
	if got := s2.bestDialIP(); got != "10.9.0.9" {
		t.Fatalf("bestDialIP bootstrap fallback = %q", got)
	}
}

// The headline grid: the WS hostname does not resolve at all; the
// pool still establishes every lineage on bootstrap pins.
func TestEstablishWithLookupDead(t *testing.T) {
	psk := testPSK()
	srv := testServer(t, psk)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	wsURL := "ws://unresolvable.invalid:" + u.Port()
	s := newTestPoolSession(wsURL, psk, 4)
	s.mu.Lock()
	s.bootstrapIPs = []string{"127.0.0.1"}
	s.mu.Unlock()
	establishAll(t, s)
	defer s.Stop()
	st := s.State()
	if st.LiveCarriers != 4 {
		t.Fatalf("live = %d/4 with lookup dead, want 4 (state %+v)", st.LiveCarriers, st)
	}
	for i, ip := range st.SlotEdges {
		if ip != "127.0.0.1" {
			t.Fatalf("slot %d edge = %q, want the bootstrap pin", i, ip)
		}
	}
}

// NP-1118-14 (c): bootstrap pins distribute over the set, and a
// set change redistributes instead of leaving slots collapsed
// onto the subset that existed at their first pick.
func TestBootstrapDistributionAndRedistribution(t *testing.T) {
	s := newTestPoolSession("ws://127.0.0.1:1", testPSK(), 4)
	s.installBootstrapIPs([]string{"10.9.0.1"})
	for slot := 0; slot < 4; slot++ {
		if got := s.pickSlotEdge(slot); got != "10.9.0.1" {
			t.Fatalf("single-member set: slot %d = %q, want the only member", slot, got)
		}
	}
	// The set grows: bootstrap pin records are dropped...
	if !s.installBootstrapIPs([]string{"10.9.0.1", "10.9.0.2"}) {
		t.Fatal("install should report the change")
	}
	st := s.State()
	for i, e := range st.SlotEdges {
		if e != "" {
			t.Fatalf("slot %d pin record = %q after set change, want cleared", i, e)
		}
	}
	// ...and fresh picks distribute A,B,A,B (sharing only because
	// the pool is larger than the set).
	want := []string{"10.9.0.1", "10.9.0.2", "10.9.0.1", "10.9.0.2"}
	for slot, w := range want {
		if got := s.pickSlotEdge(slot); got != w {
			t.Fatalf("slot %d = %q, want %q", slot, got, w)
		}
	}
	// Same set again: no change, pins stay.
	if s.installBootstrapIPs([]string{"10.9.0.1", "10.9.0.2"}) {
		t.Fatal("identical set reported as changed")
	}
}

// NP-1118-14 (b) regression: /meta with NO ranked candidates but
// a bootstrap set must dial the pinned IP — the hostname does not
// resolve at all, so any by-name dial fails the test.
func TestFetchMetaBootstrapPin(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/meta", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"colo":"TST","country":"TS"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	u, _ := url.Parse(ts.URL)
	s := newTestPoolSession("ws://127.0.0.1:1", testPSK(), 1)
	s.cfg.HostBase = "http://unresolvable.invalid:" + u.Port()
	s.cfg.MetaPath = "/meta"
	s.mu.Lock()
	s.bootstrapIPs = []string{"127.0.0.1"}
	s.mu.Unlock()
	m, err := s.FetchMeta(context.Background())
	if err != nil {
		t.Fatalf("FetchMeta via bootstrap pin: %v", err)
	}
	if m["colo"] != "TST" {
		t.Fatalf("meta = %v", m)
	}
}

package session

// Production smoke for entry dispersion (NP-1118-09), env-gated:
//
//	HOLLOW_PROD_SMOKE=1 HOLLOW_SMOKE_CONFIG=<client-config.json> \
//	  go test ./session/ -run TestProductionEdgeSmoke -v -timeout 600s
//
// The sandbox has no direct egress, so the session's dialOverride
// seam routes every dial through the egress proxy (HTTP CONNECT
// from HTTPS_PROXY). On a normal network the same flow would use
// the protected dialer — the seam changes only HOW the TCP
// connection is established, never the protocol bytes: pinned
// dials CONNECT to the candidate IP with TLS ServerName/Host on
// the configured hostname, exactly as on device.
//
// Assertions: a ranked candidate list materializes, rotations pin
// lineages onto >= 2 distinct entry IPs, >= 2 carriers stay live,
// and /meta answers through the best entry.
import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"hollow/androidcore/dns"
	"os"
	"sync"
	"testing"
	"time"
)

func connectDialer(proxyURL string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	pu, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 15 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", pu.Host)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
		}
		_ = conn.SetDeadline(time.Time{})
		if br.Buffered() > 0 {
			return nil, fmt.Errorf("proxy sent unexpected buffered bytes")
		}
		return conn, nil
	}, nil
}

func TestProductionEdgeSmoke(t *testing.T) {
	if os.Getenv("HOLLOW_PROD_SMOKE") != "1" {
		t.Skip("env-gated production smoke")
	}
	cfgPath := os.Getenv("HOLLOW_SMOKE_CONFIG")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cc struct {
		WorkerURL string `json:"workerUrl"`
		PSKBase64 string `json:"pskBase64"`
		KeyID     int    `json:"keyId"`
		MetaPath  string `json:"metaPath"`
		EdgesPath string `json:"edgesPath"`
	}
	if err := json.Unmarshal(raw, &cc); err != nil {
		t.Fatal(err)
	}
	psk, err := base64.StdEncoding.DecodeString(cc.PSKBase64)
	if err != nil {
		t.Fatal(err)
	}
	proxy := os.Getenv("HTTPS_PROXY")
	if proxy == "" {
		proxy = os.Getenv("https_proxy")
	}
	dialFn, err := connectDialer(proxy)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(cc.WorkerURL)
	hostBase := "https://" + u.Host

	s := &Session{
		cfg: Config{
			WSURL: cc.WorkerURL, PSK: psk, KeyID: cc.KeyID,
			MetaPath: cc.MetaPath, HostBase: hostBase, EdgesPath: cc.EdgesPath,
			PoolSize: 4,
		},
		counters:     &byteCounters{},
		stopCh:       make(chan struct{}),
		tunFD:        -1,
		state:        "connecting",
		dialOverride: dialFn,
	}
	s.initLines()
	startWatchdogs(s)
	establishAll(t, s)
	defer s.Stop()

	// Baseline: live by domain before any measurement lands.
	st := s.State()
	t.Logf("baseline: live=%d/%d state=%s", st.LiveCarriers, st.PoolSize, st.State)
	if st.LiveCarriers == 0 {
		t.Fatal("no carrier established by domain")
	}

	// One measurement cycle (fetch + 3-handshake probes per entry).
	s.refreshEdges()
	st = s.State()
	t.Logf("candidates: %+v", st.EdgeCandidates)
	if len(st.EdgeCandidates) == 0 {
		t.Fatal("no ranked candidates after measurement")
	}

	// Force every lineage to re-establish so pins apply, then read
	// the placement.
	for _, l := range s.lineages() {
		if err := l.rotateCarrier(context.Background()); err != nil {
			t.Logf("rotate lineage %d: %v", l.idx, err)
		}
	}
	st = s.State()
	t.Logf("slotEdges: %v live=%d/%d", st.SlotEdges, st.LiveCarriers, st.PoolSize)
	distinct := map[string]bool{}
	for _, ip := range st.SlotEdges {
		if ip != "" {
			distinct[ip] = true
		}
	}
	if len(distinct) < 2 {
		t.Fatalf("lineages pinned onto %d distinct entries, want >= 2 (slotEdges %v)", len(distinct), st.SlotEdges)
	}
	if st.LiveCarriers < 2 {
		t.Fatalf("live carriers after pinning = %d, want >= 2", st.LiveCarriers)
	}

	// /meta through the best entry.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta, err := s.FetchMeta(ctx)
	if err != nil {
		t.Fatalf("FetchMeta via best entry: %v", err)
	}
	t.Logf("meta: %v", meta)
	if meta["colo"] == nil && meta["country"] == nil {
		t.Fatalf("meta payload lacks colo/country: %v", meta)
	}
}

// Lookup-dead production smoke (NP-1118-11): the dial override
// refuses every TCP dial addressed by hostname — any code path
// that still depends on name resolution fails loudly — and
// rejects UDP (the sandbox proxy cannot carry it, so the
// bootstrap resolver keeps its seed, exactly the fail-open
// contract). The pool must still establish on bootstrap pins,
// rank edges, and answer /meta, all against production.
func TestProductionLookupDeadSmoke(t *testing.T) {
	if os.Getenv("HOLLOW_PROD_SMOKE") != "1" {
		t.Skip("env-gated production smoke")
	}
	cfgPath := os.Getenv("HOLLOW_SMOKE_CONFIG")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cc struct {
		WorkerURL string `json:"workerUrl"`
		PSKBase64 string `json:"pskBase64"`
		KeyID     int    `json:"keyId"`
		MetaPath  string `json:"metaPath"`
		EdgesPath string `json:"edgesPath"`
	}
	if err := json.Unmarshal(raw, &cc); err != nil {
		t.Fatal(err)
	}
	psk, err := base64.StdEncoding.DecodeString(cc.PSKBase64)
	if err != nil {
		t.Fatal(err)
	}
	proxy := os.Getenv("HTTPS_PROXY")
	if proxy == "" {
		proxy = os.Getenv("https_proxy")
	}
	connect, err := connectDialer(proxy)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var nameDials []string
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" {
			return nil, fmt.Errorf("smoke: %s dials unsupported (proxy is TCP-only)", network)
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if net.ParseIP(host) == nil {
			mu.Lock()
			nameDials = append(nameDials, addr)
			mu.Unlock()
			return nil, fmt.Errorf("smoke: name-based dial refused: %s", addr)
		}
		return connect(ctx, network, addr)
	}
	u, _ := url.Parse(cc.WorkerURL)
	s := &Session{
		cfg: Config{
			WSURL: cc.WorkerURL, PSK: psk, KeyID: cc.KeyID,
			MetaPath: cc.MetaPath, HostBase: "https://" + u.Host, EdgesPath: cc.EdgesPath,
			PoolSize: 4,
		},
		counters:     &byteCounters{},
		stopCh:       make(chan struct{}),
		tunFD:        -1,
		state:        "connecting",
		dialOverride: dialFn,
	}
	// The persisted last-known-good set from a previous session:
	// one anycast address of the entry hostname.
	s.bootstrapIPs = []string{"104.16.85.20"}
	s.initLines()
	startWatchdogs(s)
	establishAll(t, s)
	defer s.Stop()
	st := s.State()
	t.Logf("lookup-dead baseline: live=%d/%d slotEdges=%v", st.LiveCarriers, st.PoolSize, st.SlotEdges)
	if st.LiveCarriers < 2 {
		t.Fatalf("live = %d with lookup dead, want >= 2", st.LiveCarriers)
	}
	// Edges cycle: fetch (pinned), re-resolve (UDP refused -> seed
	// kept), probes (pinned).
	s.refreshEdges()
	st = s.State()
	t.Logf("after edges cycle: candidates=%v slotEdges=%v", st.EdgeCandidates, st.SlotEdges)
	if len(st.EdgeCandidates) == 0 {
		t.Fatal("no ranked candidates under lookup-dead conditions")
	}
	for _, l := range s.lineages() {
		_ = l.rotateCarrier(context.Background())
	}
	// /meta through the best entry.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	meta, err := s.FetchMeta(ctx)
	if err != nil {
		t.Fatalf("FetchMeta under lookup-dead: %v", err)
	}
	t.Logf("meta: %v", meta)
	mu.Lock()
	defer mu.Unlock()
	if len(nameDials) > 0 {
		t.Fatalf("name-based dials slipped through: %v", nameDials)
	}
}

// PERMANENT production DNS smoke (NP-1118-14 (d)): a full DNS
// question-and-answer through a REAL carrier against the
// production Worker, using the resolver's production upstream
// list and failover. This is the factory-surface check whose
// absence let v0.2.4 ship with a 100%-SERVFAIL tunnel resolver:
// loopback fake upstreams can never see that the exit kills
// connections to one real upstream. Keep this test.
func TestProductionDNSSmoke(t *testing.T) {
	if os.Getenv("HOLLOW_PROD_SMOKE") != "1" {
		t.Skip("env-gated production smoke")
	}
	raw, err := os.ReadFile(os.Getenv("HOLLOW_SMOKE_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	var cc struct {
		WorkerURL string `json:"workerUrl"`
		PSKBase64 string `json:"pskBase64"`
		KeyID     int    `json:"keyId"`
		MetaPath  string `json:"metaPath"`
		EdgesPath string `json:"edgesPath"`
	}
	if err := json.Unmarshal(raw, &cc); err != nil {
		t.Fatal(err)
	}
	psk, err := base64.StdEncoding.DecodeString(cc.PSKBase64)
	if err != nil {
		t.Fatal(err)
	}
	proxy := os.Getenv("HTTPS_PROXY")
	if proxy == "" {
		proxy = os.Getenv("https_proxy")
	}
	connect, err := connectDialer(proxy)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(cc.WorkerURL)
	s := &Session{
		cfg: Config{
			WSURL: cc.WorkerURL, PSK: psk, KeyID: cc.KeyID,
			MetaPath: cc.MetaPath, HostBase: "https://" + u.Host, EdgesPath: cc.EdgesPath,
			PoolSize: 2,
		},
		counters:     &byteCounters{},
		stopCh:       make(chan struct{}),
		tunFD:        -1,
		state:        "connecting",
		dialOverride: connect,
	}
	s.initLines()
	startWatchdogs(s)
	establishAll(t, s)
	defer s.Stop()

	// The pump's production upstream list, in order, dialed
	// through the session exactly as the pump dials them.
	upstreams := []string{"8.8.8.8:53", "9.9.9.9:53", "1.1.1.1:53"}
	dialers := make([]dns.DialFunc, 0, len(upstreams))
	for _, addr := range upstreams {
		addr := addr
		dialers = append(dialers, func() (net.Conn, error) {
			host, portStr, _ := net.SplitHostPort(addr)
			var port int
			fmt.Sscanf(portStr, "%d", &port)
			return s.dialFlow(net.ParseIP(host), uint16(port))
		})
	}
	r := dns.NewResolverMulti(dialers, 5*time.Second)
	resp := r.Exchange(buildDNSQueryA("example.com", 0x3333))
	ips, perr := parseDNSARecords(resp, 0x3333)
	if perr != nil || len(ips) == 0 {
		t.Fatalf("production DNS exchange failed: ips=%v err=%v stats=%+v", ips, perr, r.Stats())
	}
	st := r.Stats()
	t.Logf("production DNS: answer ips=%v stats=%+v", ips, st)
	if st.Resolved != 1 {
		t.Fatalf("resolved = %d, want 1", st.Resolved)
	}
}

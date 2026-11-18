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
	"os"
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

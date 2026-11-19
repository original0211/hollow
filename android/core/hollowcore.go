// Package hollowcore is the gomobile binding facade for the Hollow
// Android core. The protocol implementation lives in ./core, the data
// plane in ./pump + ./dns, and session orchestration in ./session;
// this package keeps the bound surface small and JSON-shaped, exactly
// as the M3-0 seam promised.
package hollowcore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"hollow/androidcore/core"
	"hollow/androidcore/pairing"
	"hollow/androidcore/pump"
	"hollow/androidcore/session"
)

// Version returns the core library identifier the shell displays on its
// status screen — if this string renders on device, the whole gomobile
// chain (bind, AAR packaging, JNI) is alive.
func Version() string {
	return "hollowcore 0.5.0 (M3-4 UI state)"
}

// Echo round-trips a string across the binding boundary (both
// directions marshalled), the cheapest end-to-end seam check.
func Echo(s string) string {
	return "echo:" + s
}

// configJSON is the wire shape of the session configuration as stored
// by the shell (pairing import writes it in M3-3):
//
//	{"wsUrl":"wss://…","pskHex":"…","keyId":1,"metaPath":"/…","hostBase":"https://…"}
type configJSON struct {
	WSURL     string `json:"wsUrl"`
	PSKHex    string `json:"pskHex"`
	KeyID     int    `json:"keyId"`
	MetaPath  string `json:"metaPath"`
	HostBase  string `json:"hostBase"`
	PoolSize  int    `json:"poolSize"`
	EdgesPath string `json:"edgesPath"`
}

var (
	mu      sync.Mutex
	current *session.Session
)

// StartVPN starts the single VPN session of this process (D6) on an
// established TUN fd. protector is the shell's VpnService.protect
// bridge; every egress socket of the session goes through it (D10).
// A second StartVPN without StopVPN is an error, never a silent
// replace — the service owns the lifecycle.
// Protector is the gomobile-facing mirror of session.Protector:
// gobind binds only types declared in THIS package, so StartVPN takes
// this interface and hands the value to the session layer
// structurally (identical method set). Kotlin implements
// hollowcore.Protector. (A cross-package interface in this signature
// made gobind silently drop StartVPN — first CI compile, NP-1114-35
// catch-up runs.)
type Protector interface {
	Protect(fd int) bool
}

func StartVPN(cfgJSONText string, tunFD int, protector Protector) error {
	var cj configJSON
	if err := json.Unmarshal([]byte(cfgJSONText), &cj); err != nil {
		return err
	}
	psk, err := hex.DecodeString(cj.PSKHex)
	if err != nil || len(psk) == 0 {
		return errors.New("hollowcore: bad or empty pskHex")
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		return errors.New("hollowcore: session already running")
	}
	s, err := session.Start(session.Config{
		WSURL:          cj.WSURL,
		PSK:            psk,
		KeyID:          cj.KeyID,
		MetaPath:       cj.MetaPath,
		HostBase:       cj.HostBase,
		PoolSize:       cj.PoolSize,
		EdgesPath:      cj.EdgesPath,
		BootstrapIPs:   pairing.LoadBootstrapIPs(pairingDir),
		OnBootstrapIPs: func(ips []string) { _ = pairing.SaveBootstrapIPs(pairingDir, ips) },
	}, tunFD, protector)
	if err != nil {
		lastStartError = err.Error()
		return err
	}
	lastStartError = ""
	vpnRevoked = false
	current = s
	return nil
}

// StopVPN tears the running session down (no-op when none).
func StopVPN() {
	mu.Lock()
	s := current
	current = nil
	mu.Unlock()
	if s != nil {
		s.Stop()
	}
}

// VPNStatsJSON returns the pump counters as JSON for the status
// surface ({} when no session runs).
func VPNStatsJSON() string {
	mu.Lock()
	s := current
	mu.Unlock()
	if s == nil {
		return "{}"
	}
	b, _ := json.Marshal(s.Stats())
	return string(b)
}

// FetchMetaJSON performs the /meta landing-identification fetch over
// the session's protected dialer and returns the decoded document as
// JSON. Auxiliary (as on Windows): errors are the caller's to log.
func FetchMetaJSON() (string, error) {
	mu.Lock()
	s := current
	mu.Unlock()
	if s == nil {
		return "", errors.New("hollowcore: no session")
	}
	m, err := s.FetchMeta(context.Background())
	if err != nil {
		return "", err
	}
	b, _ := json.Marshal(m)
	return string(b), nil
}

// StoredPairingJSON returns the stored pairing's DISPLAY fields for
// the settings surface (NP-1118-03): address, keyId, endpoint paths
// and the pairing verifier V — the same V the Windows client shows.
// The PSK itself never leaves the store; V is a one-way derivation.
func StoredPairingJSON() string {
	sc, err := readStored()
	if err != nil || sc == nil {
		return "{}"
	}
	out := struct {
		WSURL     string `json:"wsUrl"`
		KeyID     int    `json:"keyId"`
		MetaPath  string `json:"metaPath"`
		EdgesPath string `json:"edgesPath"`
		HasPSK    bool   `json:"hasPsk"`
		Verifier  string `json:"pskVerifier,omitempty"`
	}{sc.WSURL, sc.KeyID, sc.MetaPath, sc.EdgesPath, sc.PSKEnc != "", ""}
	if psk, err := unsealStoredPSK(sc); err == nil && psk != nil {
		out.Verifier = hex.EncodeToString(core.DeriveVerifier(psk))
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// ---- M3-4 presentation state ----

// lastStartError holds the most recent StartVPN failure for the UI's
// error state (the session object is gone by then; the reason must
// not be). Cleared on the next successful start.
var lastStartError string

// vpnRevoked records that the system tore our VPN down from the
// outside (NP-1118-16): Android has ONE VPN slot, so another app
// establishing its VPN (or the user switching VPN off) revokes
// ours. The session state alone cannot express this — carriers
// would happily stay "connected" with a dead TUN — so the
// service reports it explicitly and the state surface shows a
// dedicated "revoked" state instead of a lying "connected" or a
// bland "disconnected". Cleared by the next successful StartVPN.
var vpnRevoked bool

// NoteVpnRevoked is called by the VpnService's onRevoke.
func NoteVpnRevoked() {
	mu.Lock()
	vpnRevoked = true
	mu.Unlock()
}

// VPNStateJSON is the status surface's single read: session state
// machine + pump counters + pairing identity (display fields only —
// the PSK is never part of it).
func VPNStateJSON() string {
	mu.Lock()
	cur := current
	errText := lastStartError
	revoked := vpnRevoked
	mu.Unlock()
	snap := session.StateSnapshot{State: "disconnected"}
	var stats pump.Stats
	if cur != nil {
		snap = cur.State()
		stats = cur.Stats()
	} else if revoked {
		snap.State, snap.Detail = "revoked", "VPN 已被其他应用接管"
	} else if errText != "" {
		snap.State, snap.Detail = "error", errText
	}
	configured, wsURL, keyID := false, "", 0
	if sc, err := readStored(); err == nil && sc != nil && sc.WSURL != "" {
		configured, wsURL, keyID = sc.PSKEnc != "", sc.WSURL, sc.KeyID
	}
	out, _ := json.Marshal(struct {
		State          string                  `json:"state"`
		Detail         string                  `json:"detail"`
		SinceMs        int64                   `json:"sinceMs"`
		Carriers       int                     `json:"carriers"`
		StreamsOK      int                     `json:"streams"`
		Stats          pump.Stats              `json:"stats"`
		Configured     bool                    `json:"configured"`
		WSURL          string                  `json:"wsUrl"`
		KeyID          int                     `json:"keyId"`
		TrafficUp      int64                   `json:"trafficUp"`
		TrafficDown    int64                   `json:"trafficDown"`
		CarrierRTTMs   int64                   `json:"carrierRttMs"`
		LiveCarriers   int                     `json:"liveCarriers"`
		PoolSize       int                     `json:"poolSize"`
		SlotEdges      []string                `json:"slotEdges"`
		EdgeCandidates []session.EdgeCandidate `json:"edgeCandidates"`
		PhoenixReopens int64                   `json:"phoenixReopens"`
		PhoenixSaved   int64                   `json:"phoenixSaved"`
	}{snap.State, snap.Detail, snap.SinceMs, snap.Carriers, snap.StreamsOK, stats, configured, wsURL, keyID, snap.TrafficUp, snap.TrafficDown, snap.CarrierRTTMs, snap.LiveCarriers, snap.PoolSize, snap.SlotEdges, snap.EdgeCandidates, snap.PhoenixReopens, snap.PhoenixSaved})
	return string(out)
}

package hollowcore

// M3-3 (NP-1114-36): the import/export funnel's storage half. The
// grammar lives in the pairing package (fixture-locked to Windows);
// this file owns staging, the stored config, and the Keystore seam.
//
// stageImport semantics mirror Windows main.js item for item:
//   - parse through pairing.ParseAnyPayload, stage in MEMORY only;
//     a failed parse leaves any previously staged import untouched
//     and the staged payload is never logged (nothing here logs);
//   - confirm applies Windows' merge: workerUrl/keyId always,
//     endpoint paths only when the payload carries them, PSK only
//     when carried — sealed through the SecretBox before it touches
//     disk, so the stored file never holds a plaintext PSK;
//   - "current PSK exists" for the overwrite warning counts a corrupt
//     or unreadable store as EXISTING (Windows' catch→true rule);
//   - an unwrap failure at read time is a hard error — the stored PSK
//     is never silently regenerated (there is no generation path).

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"hollow/androidcore/pairing"
)

// SecretBox seals the stored PSK. Implemented on the Kotlin side with
// the Android Keystore (AES-GCM); Seal returns an opaque token string
// that is all that ever reaches disk.
type SecretBox interface {
	Seal(plain []byte) (string, error)
	Open(token string) ([]byte, error)
}

type storedConfig struct {
	WSURL     string `json:"wsUrl"`
	KeyID     int    `json:"keyId"`
	MetaPath  string `json:"metaPath,omitempty"`
	EdgesPath string `json:"edgesPath,omitempty"`
	PSKEnc    string `json:"pskEnc,omitempty"`
}

var pairingMu sync.Mutex
var (
	pairingDir    string
	pairingBox    SecretBox
	stagedPayload *pairing.Payload
)

const storedFileName = "hollow-config.json"

// InitPairing wires the storage dir and the Keystore box. Called by
// the shell on service/activity start; safe to call again (last wins).
func InitPairing(dir string, box SecretBox) {
	pairingMu.Lock()
	defer pairingMu.Unlock()
	pairingDir, pairingBox = dir, box
}

func storedPath() string { return filepath.Join(pairingDir, storedFileName) }

// readStored returns (nil, nil) when no config is stored yet.
func readStored() (*storedConfig, error) {
	raw, err := os.ReadFile(storedPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sc storedConfig
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil, fmt.Errorf("stored config unreadable: %w", err)
	}
	return &sc, nil
}

func currentPSKExists() bool {
	sc, err := readStored()
	if err != nil {
		return true // corrupt counts as exists (Windows rule)
	}
	return sc != nil && sc.PSKEnc != ""
}

func writeStored(sc *storedConfig) error {
	raw, err := json.Marshal(sc)
	if err != nil {
		return err
	}
	tmp := storedPath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, storedPath())
}

// StageImport parses and stages a payload, returning the preview JSON
// (the same shape Windows' confirmation UI shows). Nothing is written.
func StageImport(text string) (string, error) {
	p, err := pairing.ParseAnyPayload(text)
	if err != nil {
		return "", err
	}
	pairingMu.Lock()
	stagedPayload = p
	exists := currentPSKExists()
	pairingMu.Unlock()
	out, err := json.Marshal(p.Preview(exists))
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ConfirmImport applies the staged payload (Windows merge rules) and
// clears the stage. PSK material is sealed before it reaches disk.
func ConfirmImport() error {
	pairingMu.Lock()
	defer pairingMu.Unlock()
	if stagedPayload == nil {
		return errors.New("nothing staged")
	}
	p := stagedPayload
	stagedPayload = nil
	sc, err := readStored()
	if err != nil {
		return err
	}
	if sc == nil {
		sc = &storedConfig{}
	}
	sc.WSURL, sc.KeyID = p.WorkerURL, p.KeyID
	if p.MetaPath != "" {
		sc.MetaPath = p.MetaPath
	}
	if p.EdgesPath != "" {
		sc.EdgesPath = p.EdgesPath
	}
	if p.PSK != nil {
		if pairingBox == nil {
			return errors.New("secret box not initialized")
		}
		token, err := pairingBox.Seal(p.PSK)
		if err != nil {
			return fmt.Errorf("seal psk: %w", err)
		}
		sc.PSKEnc = token
	}
	return writeStored(sc)
}

// CancelImport drops the staged payload without applying it.
func CancelImport() {
	pairingMu.Lock()
	defer pairingMu.Unlock()
	stagedPayload = nil
}

// unsealStoredPSK returns the stored PSK (nil when none is stored).
// An unwrap failure is a HARD error — never a silent regeneration.
func unsealStoredPSK(sc *storedConfig) ([]byte, error) {
	if sc == nil || sc.PSKEnc == "" {
		return nil, nil
	}
	if pairingBox == nil {
		return nil, errors.New("secret box not initialized")
	}
	psk, err := pairingBox.Open(sc.PSKEnc)
	if err != nil {
		return nil, fmt.Errorf("psk unwrap failed (stored key material corrupt or keystore key lost): %w", err)
	}
	if len(psk) != 32 {
		return nil, errors.New("psk unwrap failed: stored PSK has wrong length")
	}
	return psk, nil
}

func storedPayload(includePSK bool) (*pairing.Payload, error) {
	sc, err := readStored()
	if err != nil {
		return nil, err
	}
	if sc == nil || sc.WSURL == "" {
		return nil, errors.New("not configured")
	}
	p := &pairing.Payload{WorkerURL: sc.WSURL, KeyID: sc.KeyID, MetaPath: sc.MetaPath, EdgesPath: sc.EdgesPath}
	if includePSK {
		psk, err := unsealStoredPSK(sc)
		if err != nil {
			return nil, err
		}
		if psk == nil {
			return nil, errors.New("no PSK stored")
		}
		p.PSK = psk
	}
	return p, nil
}

// ExportConfigJSON builds the .hollow.json text (Windows pretty-print
// form: 2-space indent + trailing newline, as its file export writes).
func ExportConfigJSON(includePSK bool) (string, error) {
	p, err := storedPayload(includePSK)
	if err != nil {
		return "", err
	}
	compact, err := pairing.BuildExportJSON(p)
	if err != nil {
		return "", err
	}
	// Pretty-print with the field order BuildExportJSON produced:
	// decode into an ordered map alternative — a raw message walk
	// would lose order, so indent the compact text structurally is
	// overkill; MarshalIndent over the typed shape keeps order.
	var typed struct {
		App       string  `json:"app"`
		Version   int     `json:"version"`
		WorkerURL string  `json:"workerUrl"`
		KeyID     int     `json:"keyId"`
		PSKBase64 *string `json:"pskBase64,omitempty"`
		MetaPath  *string `json:"metaPath,omitempty"`
		EdgesPath *string `json:"edgesPath,omitempty"`
	}
	if err := json.Unmarshal([]byte(compact), &typed); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(typed, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty) + "\n", nil
}

// ExportLink builds the hollow:// link for the stored config.
func ExportLink(includePSK bool) (string, error) {
	p, err := storedPayload(includePSK)
	if err != nil {
		return "", err
	}
	return pairing.BuildLink(p)
}

// StoredRuntimeConfigJSON is the M3-2 read side's other half: the
// runtime config (plaintext PSK hex, in memory only) for StartVPN.
// Any unwrap problem surfaces as an error — the caller treats it as
// "config incomplete" and fails closed.
func StoredRuntimeConfigJSON() (string, error) {
	sc, err := readStored()
	if err != nil {
		return "", err
	}
	if sc == nil || sc.WSURL == "" {
		return "", errors.New("not configured")
	}
	psk, err := unsealStoredPSK(sc)
	if err != nil {
		return "", err
	}
	if psk == nil {
		return "", errors.New("not configured: no PSK stored")
	}
	u, err := url.Parse(sc.WSURL)
	if err != nil {
		return "", err
	}
	scheme := "https"
	if u.Scheme == "ws" {
		scheme = "http"
	}
	out, err := json.Marshal(struct {
		WSURL    string `json:"wsUrl"`
		PSKHex   string `json:"pskHex"`
		KeyID    int    `json:"keyId"`
		MetaPath string `json:"metaPath"`
		HostBase string `json:"hostBase"`
	}{sc.WSURL, hex.EncodeToString(psk), sc.KeyID, sc.MetaPath, scheme + "://" + u.Host})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

package hollowcore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hollow/androidcore/pairing"
)

// fakeBox is a test SecretBox (NOT cryptography — a reversible tag).
type fakeBox struct{ broken bool }

func (b fakeBox) Seal(plain []byte) (string, error) {
	rev := make([]byte, len(plain))
	for i, c := range plain {
		rev[len(plain)-1-i] = c
	}
	return "v1." + base64.StdEncoding.EncodeToString(rev), nil
}
func (b fakeBox) Open(token string) ([]byte, error) {
	if b.broken {
		return nil, errors.New("keystore gone")
	}
	if !strings.HasPrefix(token, "v1.") {
		return nil, errors.New("bad token")
	}
	rev, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "v1."))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(rev))
	for i, c := range rev {
		out[len(rev)-1-i] = c
	}
	return out, nil
}

var testPSK = func() []byte { b := make([]byte, 32); for i := range b { b[i] = byte(i) }; return b }()

func setupPairing(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	InitPairing(dir, fakeBox{})
	CancelImport()
	return dir
}

func stageFull(t *testing.T) string {
	t.Helper()
	link, err := pairing.BuildLink(&pairing.Payload{
		WorkerURL: "wss://example.com/socket", KeyID: 7, PSK: testPSK,
		MetaPath: "/m_x", EdgesPath: "/e_y",
	})
	if err != nil {
		t.Fatal(err)
	}
	pv, err := StageImport(link)
	if err != nil {
		t.Fatal(err)
	}
	return pv
}

func TestStagePreviewAndConfirm(t *testing.T) {
	dir := setupPairing(t)
	pvJSON := stageFull(t)
	var pv pairing.Preview
	if err := json.Unmarshal([]byte(pvJSON), &pv); err != nil {
		t.Fatal(err)
	}
	if !pv.HasPSK || pv.OverwritesPSK || pv.WorkerURL != "wss://example.com/socket" || !pv.HasEndpointPaths {
		t.Fatalf("preview: %+v", pv)
	}
	// Nothing on disk before confirm (staging is memory-only).
	if _, err := os.Stat(filepath.Join(dir, storedFileName)); !os.IsNotExist(err) {
		t.Fatal("stored file exists before confirm")
	}
	if err := ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, storedFileName))
	if err != nil {
		t.Fatal(err)
	}
	// The plaintext PSK (hex or base64) must not appear in the file.
	if strings.Contains(string(raw), hex.EncodeToString(testPSK)) ||
		strings.Contains(string(raw), base64.StdEncoding.EncodeToString(testPSK)) {
		t.Fatal("plaintext PSK leaked into the stored file")
	}
	// Runtime config roundtrip returns the same PSK.
	rc, err := StoredRuntimeConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		WSURL, PSKHex, HostBase string
		KeyID                   int
	}
	if err := json.Unmarshal([]byte(rc), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.PSKHex != hex.EncodeToString(testPSK) || cfg.WSURL != "wss://example.com/socket" ||
		cfg.KeyID != 7 || cfg.HostBase != "https://example.com" {
		t.Fatalf("runtime cfg: %+v", cfg)
	}
	// Second import (address only): PSK and paths survive, overwrite
	// warning now armed for a PSK-carrying payload.
	if _, err := StageImport("hollow://v1?worker=wss%3A%2F%2Fother.example%2F&keyId=2"); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	rc2, err := StoredRuntimeConfigJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rc2, `"wsUrl":"wss://other.example/"`) || !strings.Contains(rc2, hex.EncodeToString(testPSK)) {
		t.Fatalf("address-only import clobbered state: %s", rc2)
	}
	pv2 := stageFull(t)
	var pv2s pairing.Preview
	if err := json.Unmarshal([]byte(pv2), &pv2s); err != nil {
		t.Fatal(err)
	}
	if !pv2s.OverwritesPSK {
		t.Fatal("overwrite warning not armed when a PSK is stored")
	}
	CancelImport()
}

func TestUnwrapFailureIsHardError(t *testing.T) {
	setupPairing(t)
	stageFull(t)
	if err := ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	InitPairing(pairingDir, fakeBox{broken: true}) // keystore key "lost"
	if _, err := StoredRuntimeConfigJSON(); err == nil || !strings.Contains(err.Error(), "unwrap failed") {
		t.Fatalf("want unwrap hard error, got %v", err)
	}
	if _, err := ExportLink(true); err == nil {
		t.Fatal("export with PSK must fail when unwrap fails")
	}
	// And the stored file must be untouched (no silent regeneration).
	if !currentPSKExists() {
		t.Fatal("stored PSK vanished after unwrap failure")
	}
}

func TestConfirmWithoutStageAndExports(t *testing.T) {
	setupPairing(t)
	if err := ConfirmImport(); err == nil {
		t.Fatal("confirm without stage must fail")
	}
	if _, err := ExportLink(false); err == nil {
		t.Fatal("export before configure must fail")
	}
	stageFull(t)
	if err := ConfirmImport(); err != nil {
		t.Fatal(err)
	}
	link, err := ExportLink(true)
	if err != nil {
		t.Fatal(err)
	}
	back, err := pairing.ParseAnyPayload(link)
	if err != nil || back.PSKHex() != hex.EncodeToString(testPSK) {
		t.Fatalf("export link roundtrip: %v", err)
	}
	js, err := ExportConfigJSON(false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(js, "pskBase64") || !strings.HasSuffix(js, "\n") {
		t.Fatalf("export json without PSK malformed: %q", js)
	}
	back2, err := pairing.ParseAnyPayload(js)
	if err != nil || back2.PSK != nil {
		t.Fatalf("export json roundtrip: %v", err)
	}
}

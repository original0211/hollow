package pairing

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared fixture set: generated from the canonical JS
// implementation, asserted identically by windows/tests. Path is
// relative to this package inside the repo checkout.
func loadFixtures(t *testing.T) (builds []struct {
	Name  string `json:"name"`
	Input struct {
		WorkerURL string  `json:"workerUrl"`
		KeyID     *int    `json:"keyId"`
		PSKHex    *string `json:"pskHex"`
		MetaPath  *string `json:"metaPath"`
		EdgesPath *string `json:"edgesPath"`
	} `json:"input"`
	Link       string `json:"link"`
	ExportJSON string `json:"exportJson"`
}, parses []struct {
	Name string `json:"name"`
	Text string `json:"text"`
	OK   struct {
		WorkerURL string  `json:"workerUrl"`
		KeyID     int     `json:"keyId"`
		PSKHex    *string `json:"pskHex"`
		MetaPath  *string `json:"metaPath"`
		EdgesPath *string `json:"edgesPath"`
	} `json:"ok"`
}, errs []struct {
	Name  string `json:"name"`
	Text  string `json:"text"`
	Error string `json:"error"`
}, previews []struct {
	CurrentPskExists bool    `json:"currentPskExists"`
	Preview          Preview `json:"preview"`
}) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "testvectors", "pairing-v1.json"))
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	var f struct {
		Builds   json.RawMessage `json:"builds"`
		Parses   json.RawMessage `json:"parses"`
		Errors   json.RawMessage `json:"errors"`
		Previews json.RawMessage `json:"previews"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.Builds, &builds); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.Parses, &parses); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.Errors, &errs); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.Previews, &previews); err != nil {
		t.Fatal(err)
	}
	return
}

func unhex(t *testing.T, s *string) []byte {
	t.Helper()
	if s == nil {
		return nil
	}
	b, err := hex.DecodeString(*s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func strp(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestPairingFixtures(t *testing.T) {
	builds, parses, errs, previews := loadFixtures(t)
	for _, b := range builds {
		kid := 1
		if b.Input.KeyID != nil {
			kid = *b.Input.KeyID
		}
		p := &Payload{WorkerURL: b.Input.WorkerURL, KeyID: kid, PSK: unhex(t, b.Input.PSKHex), MetaPath: strp(b.Input.MetaPath), EdgesPath: strp(b.Input.EdgesPath)}
		link, err := BuildLink(p)
		if err != nil {
			t.Fatalf("%s build link: %v", b.Name, err)
		}
		if link != b.Link {
			t.Errorf("%s link:\n got %s\nwant %s", b.Name, link, b.Link)
		}
		js, err := BuildExportJSON(p)
		if err != nil {
			t.Fatalf("%s build export: %v", b.Name, err)
		}
		if js != b.ExportJSON {
			t.Errorf("%s export:\n got %s\nwant %s", b.Name, js, b.ExportJSON)
		}
	}
	for _, pc := range parses {
		p, err := ParseAnyPayload(pc.Text)
		if err != nil {
			t.Fatalf("%s parse: %v", pc.Name, err)
		}
		if p.WorkerURL != pc.OK.WorkerURL || p.KeyID != pc.OK.KeyID || p.PSKHex() != strp(pc.OK.PSKHex) ||
			p.MetaPath != strp(pc.OK.MetaPath) || p.EdgesPath != strp(pc.OK.EdgesPath) {
			t.Errorf("%s shape: got %+v", pc.Name, p)
		}
	}
	for _, ec := range errs {
		_, err := ParseAnyPayload(ec.Text)
		if err == nil {
			t.Errorf("%s: parsed cleanly, want error %q", ec.Name, ec.Error)
		} else if !strings.Contains(err.Error(), ec.Error) {
			t.Errorf("%s: error %q, want %q", ec.Name, err, ec.Error)
		}
	}
	full, err := ParseAnyPayload(builds[1].Link)
	if err != nil {
		t.Fatal(err)
	}
	for _, pv := range previews {
		got := full.Preview(pv.CurrentPskExists)
		if got != pv.Preview {
			t.Errorf("preview(exists=%v): got %+v want %+v", pv.CurrentPskExists, got, pv.Preview)
		}
	}
}

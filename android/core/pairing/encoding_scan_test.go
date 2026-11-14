package pairing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFormEncodeScan is the folded-in JS<->Go serialization
// equivalence scan (NP-1114-41): every corpus string's WHATWG
// urlencoded form (recorded from URLSearchParams in
// shared/testvectors/form-encoding-v1.json) must equal formEncode's
// output. Corpus: printable ASCII bare+embedded, multibyte samples,
// and the known-difference charset (~, +, %, &, =, …) — the set most
// likely to drift if either side's encoder changes.
func TestFormEncodeScan(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "shared", "testvectors", "form-encoding-v1.json"))
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	var f struct {
		Cases []struct {
			Input   string `json:"input"`
			Encoded string `json:"encoded"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 200 {
		t.Fatalf("scan corpus suspiciously small: %d", len(f.Cases))
	}
	for _, c := range f.Cases {
		if got := formEncode(c.Input); got != c.Encoded {
			t.Errorf("formEncode(%q) = %q, want %q (URLSearchParams)", c.Input, got, c.Encoded)
		}
	}
}

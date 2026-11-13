package tun

import (
	"os"
	"path/filepath"
	"testing"
)

// The vendored DLL in the repo must be exactly the pinned build — this
// test makes a wrong or swapped DLL a CI failure.
func TestVendoredDLLMatchesPin(t *testing.T) {
	p := filepath.Join("..", "..", "third_party", "wintun", "wintun.dll")
	if err := VerifyDLLFile(p); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDLLRejectsOtherBytes(t *testing.T) {
	f := filepath.Join(t.TempDir(), "wintun.dll")
	if err := os.WriteFile(f, []byte("not the pinned dll"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDLLFile(f); err == nil {
		t.Fatal("expected mismatch error for non-pinned bytes")
	}
}

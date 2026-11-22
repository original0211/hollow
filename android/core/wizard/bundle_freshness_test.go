package wizard

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The committed bundle copy must never drift from the worker
// bundle source: in a repo checkout, bundle.js equals
// worker/src/index.js byte for byte. Outside a checkout (the
// package on its own) the guard skips — there is nothing to
// compare against.
func TestBundleCopyMatchesWorkerSource(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "worker", "src", "index.js"))
	if err != nil {
		t.Skipf("worker bundle source not readable (%v); freshness guard inactive", err)
	}
	if !bytes.Equal(BundleBytes, src) {
		t.Fatalf("wizard bundle copy drifted from worker/src/index.js (%d vs %d bytes) — refresh the copy", len(BundleBytes), len(src))
	}
}

package hollowcore

import (
	"encoding/json"
	"testing"
)

func TestSeam(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
	if Echo("x") != "echo:x" {
		t.Fatal("echo broken")
	}
}

// TestVPNStateJSONShape (M3-4): with nothing running and nothing
// stored, the state surface reports a plain disconnected — and after
// a stored config exists it reports the pairing identity.
func TestVPNStateJSONShape(t *testing.T) {
	out := VPNStateJSON()
	var v struct {
		State      string `json:"state"`
		Configured bool   `json:"configured"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("state json: %v (%s)", err, out)
	}
	if v.State != "disconnected" {
		t.Fatalf("state = %s, want disconnected", v.State)
	}
}

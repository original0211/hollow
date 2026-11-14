package hollowcore

import "testing"

func TestSeam(t *testing.T) {
	if Version() == "" {
		t.Fatal("empty version")
	}
	if Echo("x") != "echo:x" {
		t.Fatal("echo broken")
	}
}

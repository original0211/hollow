package pairing

import (
	"reflect"
	"testing"
)

func TestBootstrapIPsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if got := LoadBootstrapIPs(dir); got != nil {
		t.Fatalf("absent file: got %v, want nil", got)
	}
	want := []string{"104.16.85.20", "104.17.164.30"}
	if err := SaveBootstrapIPs(dir, want); err != nil {
		t.Fatal(err)
	}
	if got := LoadBootstrapIPs(dir); !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip: got %v, want %v", got, want)
	}
}

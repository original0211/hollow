package pairing

// Last-known-good bootstrap IP persistence (NP-1118-11): the
// entry hostname's resolved address set, stored next to the
// pairing config so a fresh process can dial by IP before any
// resolution happens. Display-grade state: any read/write error
// degrades to "no seed", never to a failed start.
import (
	"encoding/json"
	"os"
	"path/filepath"
)

const bootstrapFile = "hollow-bootstrap.json"

// LoadBootstrapIPs reads the persisted set (nil when absent/bad).
func LoadBootstrapIPs(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, bootstrapFile))
	if err != nil {
		return nil
	}
	var ips []string
	if err := json.Unmarshal(b, &ips); err != nil {
		return nil
	}
	return ips
}

// SaveBootstrapIPs persists the set atomically (tmp + rename).
func SaveBootstrapIPs(dir string, ips []string) error {
	b, err := json.Marshal(ips)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, bootstrapFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, bootstrapFile))
}

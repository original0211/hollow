package netcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Snapshot file layer — same semantics as the JS shared layer
// (windows/src/snapshot.js): atomic tmp+rename write, three-way read
// classification. The app reads this file through the JS layer; the
// formats are one spec (self-heal spec §2).

type SnapKind string

const (
	SnapNone    SnapKind = "none"
	SnapCorrupt SnapKind = "corrupt"
	SnapOK      SnapKind = "ok"
)

func SnapshotPath(dir string) string { return filepath.Join(dir, SnapshotFile) }

func WriteSnapshotAtomic(dir string, snap *Snapshot) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf("netcfg-backup.%d.tmp", os.Getpid()))
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, SnapshotPath(dir))
}

func ReadSnapshot(dir string) (SnapKind, *Snapshot) {
	raw, err := os.ReadFile(SnapshotPath(dir))
	if os.IsNotExist(err) {
		return SnapNone, nil
	}
	if err != nil {
		return SnapCorrupt, nil
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return SnapCorrupt, nil
	}
	if snap.Version != SnapshotVersion || snap.Written.Adapter.Name == "" {
		return SnapCorrupt, nil
	}
	return SnapOK, &snap
}

func RemoveSnapshot(dir string) {
	_ = os.Remove(SnapshotPath(dir))
}

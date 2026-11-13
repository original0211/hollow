// Package tun owns the Wintun side of the helper: the pinned driver DLL
// and (on Windows) the link endpoint that feeds the pump's netstack.
package tun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// Wintun is pinned: version 0.14.1, amd64 DLL, verified twice — the
// download zip against the hash published on wintun.net, and the DLL
// itself below. The helper refuses to load any other bytes (no silent
// fallback, no trying other paths): a mismatch is a hard error.
const (
	WintunVersion   = "0.14.1"
	WintunZipSHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
	WintunDLLSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
)

// VerifyDLLFile checks that the file at path is byte-identical to the
// pinned Wintun DLL.
func VerifyDLLFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("wintun.dll unreadable at %s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != WintunDLLSHA256 {
		return fmt.Errorf("wintun.dll at %s does not match the pinned %s build (sha256 %s) — refusing to load", path, WintunVersion, hex.EncodeToString(sum[:]))
	}
	return nil
}

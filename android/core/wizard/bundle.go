package wizard

// The bundled Worker and the local generation effects
// (NP-1118-62 increment 4): bundle.js is a byte copy of
// worker/src/index.js — the exact text the Windows wizard deploys
// (its prepare-vendor copy) and the production bundle source.
// The copy is COMMITTED alongside this package (unlike the
// Windows vendor copy, which is build-generated): the stored
// GitHub credential cannot update workflow files, so no CI copy
// step exists yet. bundle_freshness_test.go guards the copy —
// in a repo checkout it must equal worker/src/index.js byte for
// byte. Client and server ship in lockstep; deploying needs no
// fetch.

import (
	crand "crypto/rand"
	_ "embed"
	"encoding/hex"

	"hollow/androidcore/core"
)

//go:embed bundle.js
var BundleBytes []byte

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		// crypto/rand failure is not survivable for key material:
		// panic rather than mint a weak PSK (the caller recovers at
		// the facade boundary and reports a failed run).
		panic("wizard: crypto/rand failed: " + err.Error())
	}
	return b
}

func randomHex(n int) string {
	return hex.EncodeToString(randomBytes(n))
}

func deriveVerifierHex(psk []byte) string {
	return hex.EncodeToString(core.DeriveVerifier(psk))
}

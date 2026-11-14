// Crypto primitives for the Hollow protocol core — the Go counterpart of
// shared/crypto.js (spec v0.1 §0.4, §5.3, §6.1). Standard mature
// primitives only: SHA-256/HMAC from the stdlib, HKDF (RFC 5869) built
// from HMAC exactly as the JS does, X25519 via crypto/ecdh, and
// ChaCha20-Poly1305 (RFC 8439) via golang.org/x/crypto.
package core

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// hkdfExtract (RFC 5869): PRK = HMAC(salt, IKM)
func hkdfExtract(salt, ikm []byte) []byte { return hmacSHA256(salt, ikm) }

// hkdfExpand (RFC 5869), general loop like the JS implementation.
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length)
	var t []byte
	for i := byte(1); len(out) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{i})
		t = m.Sum(nil)
		take := 32
		if length-len(out) < take {
			take = length - len(out)
		}
		out = append(out, t[:take]...)
	}
	return out
}

// x25519Generate returns a fresh ephemeral key pair (raw public key).
func x25519Generate() (priv *ecdh.PrivateKey, pubRaw []byte, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// x25519Derive returns the 32-byte shared secret, or nil on failure /
// low-order peer key (RFC 7748 §5.3-1 all-zero check, as the JS).
func x25519Derive(priv *ecdh.PrivateKey, peerPublicRaw []byte) []byte {
	pub, err := ecdh.X25519().NewPublicKey(peerPublicRaw)
	if err != nil {
		return nil
	}
	dh, err := priv.ECDH(pub)
	if err != nil {
		return nil
	}
	if bytes.Equal(dh, make([]byte, 32)) {
		return nil
	}
	return dh
}

// x25519FromRaw rebuilds a private key from raw bytes (test vectors and
// the transcript replay inject fixed ephemerals through here).
func x25519FromRaw(privRaw []byte) (*ecdh.PrivateKey, error) {
	if len(privRaw) != 32 {
		return nil, errors.New("x25519: bad private key length")
	}
	return ecdh.X25519().NewPrivateKey(privRaw)
}

// chachaSeal: RFC 8439 AEAD seal, returns ciphertext || tag(16).
func chachaSeal(key, nonce, plaintext []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, plaintext, nil)
}

// chachaOpen returns the plaintext, or nil on tag verification failure.
func chachaOpen(key, nonce, ctTag []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil
	}
	pt, err := aead.Open(nil, nonce, ctTag, nil)
	if err != nil {
		return nil
	}
	return pt
}

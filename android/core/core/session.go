// Handshake messages and session derivation — the Go counterpart of
// the §5 parts of shared/protocol.js.
package core

import (
	"bytes"
	"crypto/ecdh"
)

// DeriveVerifier: §1.1 verifier = HMAC(PSK, "newproto-v0.1-server-verifier").
func DeriveVerifier(psk []byte) []byte {
	return hmacSHA256(psk, []byte("newproto-v0.1-server-verifier"))
}

// ---------- §5.1 / §5.2 hello messages ----------

func BuildClientHello(versions []byte, keyID byte, publicRaw, random, padding []byte) []byte {
	head := make([]byte, 0, 1+1+len(versions)+1+32+32+1)
	head = append(head, 0x01, byte(len(versions)))
	head = append(head, versions...)
	head = append(head, keyID)
	head = append(head, publicRaw...)
	head = append(head, random...)
	head = append(head, byte(len(padding)))
	return concat(head, padding)
}

type ClientHello struct {
	Versions  []byte
	KeyID     byte
	PublicRaw []byte
	Random    []byte
}

func ParseClientHello(b []byte) *ClientHello {
	if len(b) < 1+1+1+32+32+1 {
		return nil
	}
	o := 0
	if b[o] != 0x01 {
		return nil
	}
	o++
	vc := int(b[o])
	o++
	if vc < 1 || len(b) < 1+1+vc+1+32+32+1 {
		return nil
	}
	versions := append([]byte(nil), b[o:o+vc]...)
	o += vc
	keyID := b[o]
	o++
	publicRaw := append([]byte(nil), b[o:o+32]...)
	o += 32
	random := append([]byte(nil), b[o:o+32]...)
	o += 32
	padLen := int(b[o])
	o++
	if padLen > 128 || o+padLen != len(b) {
		return nil
	}
	return &ClientHello{versions, keyID, publicRaw, random}
}

func BuildServerHello(selectedVersion byte, publicRaw, random, padding []byte) []byte {
	head := make([]byte, 0, 67)
	head = append(head, 0x02, selectedVersion)
	head = append(head, publicRaw...)
	head = append(head, random...)
	head = append(head, byte(len(padding)))
	return concat(head, padding)
}

type ServerHello struct {
	SelectedVersion byte
	PublicRaw       []byte
	Random          []byte
}

func ParseServerHello(b []byte) *ServerHello {
	if len(b) < 67 {
		return nil
	}
	if len(b) != 67+int(b[66]) { // length must match padding_len exactly
		return nil
	}
	if b[0] != 0x02 {
		return nil
	}
	if b[66] > 128 {
		return nil
	}
	return &ServerHello{
		SelectedVersion: b[1],
		PublicRaw:       append([]byte(nil), b[2:34]...),
		Random:          append([]byte(nil), b[34:66]...),
	}
}

// ---------- §5.3 session derivation ----------

type SessionKeys struct {
	TH           []byte
	KC2s, KS2c   []byte
	IvC2s, IvS2c []byte
	FC, FS       []byte
}

func DeriveSession(dh, verifier, clientRandom, serverRandom, clientHello, serverHello []byte) *SessionKeys {
	th := sha256Sum(concat(clientHello, serverHello))
	ms := hkdfExtract(concat(clientRandom, serverRandom), concat(dh, verifier))
	expand := func(label string, n int) []byte {
		return hkdfExpand(ms, concat([]byte(label), th), n)
	}
	return &SessionKeys{
		TH:    th,
		KC2s:  expand("np-v0.1 c2s key", 32),
		KS2c:  expand("np-v0.1 s2c key", 32),
		IvC2s: expand("np-v0.1 c2s iv", 12),
		IvS2c: expand("np-v0.1 s2c iv", 12),
		FC:    expand("np-v0.1 client finished", 32),
		FS:    expand("np-v0.1 server finished", 32),
	}
}

// FinishedMAC: §5.4 — who is "server" | "client".
func FinishedMAC(fKey, th []byte, who string) []byte {
	return hmacSHA256(fKey, concat(th, []byte(who)))
}

// Ephemeral is one X25519 key pair in the forms the client needs.
type Ephemeral struct {
	Priv    *ecdh.PrivateKey
	PubRaw  []byte
	PrivRaw []byte
}

func GenerateEphemeral() (*Ephemeral, error) {
	priv, pub, err := x25519Generate()
	if err != nil {
		return nil, err
	}
	return &Ephemeral{Priv: priv, PubRaw: pub, PrivRaw: priv.Bytes()}, nil
}

func EphemeralFromRaw(privRaw []byte) (*Ephemeral, error) {
	priv, err := x25519FromRaw(privRaw)
	if err != nil {
		return nil, err
	}
	return &Ephemeral{Priv: priv, PubRaw: priv.PublicKey().Bytes(), PrivRaw: privRaw}, nil
}

// Eq is the constant-time-ish byte equality used on MACs (as the JS eq).
func Eq(a, b []byte) bool { return bytes.Equal(a, b) }

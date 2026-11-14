package core

// Tier A: component golden vectors (VECTORS.md). Every value here was
// produced by the JS canonical implementation and independently
// anchored at generation time (RFC constants / BigInt ladder).
import (
	"encoding/hex"

	"encoding/json"
	"golang.org/x/crypto/chacha20poly1305"
	"os"
	"testing"
)

type vectors struct {
	SpecVersion string `json:"specVersion"`
	HKDF        []struct {
		IKM, Salt, Info, PRK, OKM42 string
	} `json:"hkdf"`
	HMAC []struct {
		Key, Msg, Out string
	} `json:"hmac"`
	X25519 []struct {
		APriv, BPriv, APub, BPub, Shared string
	} `json:"x25519"`
	ChaCha []struct {
		Key, Nonce, Plaintext, Sealed string
	} `json:"chacha"`
	Handshake struct {
		PSK, Verifier, ClientHello, ServerHello, TH string
		KC2s, KS2c, IvC2s, IvS2c                    string
		FinishedServerMac, FinishedClientMac        string
	} `json:"handshake"`
	Records struct {
		Key, Iv        string
		FramesHex      []string
		RecordsHex     []string
		NextSeq        uint64
		FramesBlobsHex []string
		BucketFor      [][2]*int
	} `json:"records"`
	RecordsMulti struct {
		Key, Iv        string
		FramesHex      []string
		RecordsHex     []string
		NextSeq        uint64
		FramesBlobsHex []string
	} `json:"recordsMulti"`
	Frames struct {
		GoodBlob            string
		GoodCount           int
		GoodRecordError     bool
		TrailingRecordError bool
		OversizeBlobLen     int
		OversizeCount       int
		OversizeFrames      int
	} `json:"frames"`
	OpenPayload []struct {
		Host       string
		ParsedHost string
		Port       int
		SchemeHint byte
		GatePolicy byte
		Payload    string
	} `json:"openPayload"`
	Misc struct {
		RejectPayload string
		ResetPayload  string
		BanV4         [][2]any // [ip, bool] — decoded loosely below
	} `json:"misc"`
}

func un(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func eqHex(t *testing.T, name string, got []byte, wantHex string) {
	t.Helper()
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("%s mismatch:\n got %x\nwant %s", name, got, wantHex)
	}
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	raw, err := os.ReadFile("../testvectors/vectors-v0.1.2.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.SpecVersion != "v0.1.2" {
		t.Fatalf("vector set bound to %s, this port targets v0.1.2", v.SpecVersion)
	}
	return &v
}

func TestPrimitiveVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.HKDF {
		prk := hkdfExtract(un(t, c.Salt), un(t, c.IKM))
		eqHex(t, "hkdf prk", prk, c.PRK)
		eqHex(t, "hkdf okm", hkdfExpand(prk, un(t, c.Info), 42), c.OKM42)
	}
	for _, c := range v.HMAC {
		eqHex(t, "hmac", hmacSHA256(un(t, c.Key), un(t, c.Msg)), c.Out)
	}
	for _, c := range v.X25519 {
		aPriv, err := x25519FromRaw(un(t, c.APriv))
		if err != nil {
			t.Fatal(err)
		}
		bPriv, err := x25519FromRaw(un(t, c.BPriv))
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "x25519 aPub", aPriv.PublicKey().Bytes(), c.APub)
		eqHex(t, "x25519 bPub", bPriv.PublicKey().Bytes(), c.BPub)
		eqHex(t, "x25519 shared a->b", x25519Derive(aPriv, un(t, c.BPub)), c.Shared)
		eqHex(t, "x25519 shared b->a", x25519Derive(bPriv, un(t, c.APub)), c.Shared)
	}
	for _, c := range v.ChaCha {
		eqHex(t, "chacha seal", chachaSeal(un(t, c.Key), un(t, c.Nonce), un(t, c.Plaintext)), c.Sealed)
		eqHex(t, "chacha open", chachaOpen(un(t, c.Key), un(t, c.Nonce), un(t, c.Sealed)), c.Plaintext)
	}
}

func TestHandshakeVectors(t *testing.T) {
	v := loadVectors(t)
	h := v.Handshake
	psk := un(t, h.PSK)
	eqHex(t, "verifier", DeriveVerifier(psk), h.Verifier)

	// Rebuild the hellos from their recorded parts (pub keys ride in the
	// x25519 group; randoms/padding are re-derived from the recorded
	// hello bytes themselves to keep this test self-contained).
	ch := ParseClientHello(un(t, h.ClientHello))
	sh := ParseServerHello(un(t, h.ServerHello))
	if ch == nil || sh == nil {
		t.Fatal("recorded hellos do not parse")
	}
	clientHello := BuildClientHello(ch.Versions, ch.KeyID, ch.PublicRaw, ch.Random, helloPadding(un(t, h.ClientHello)))
	eqHex(t, "client hello rebuild", clientHello, h.ClientHello)
	serverHello := BuildServerHello(sh.SelectedVersion, sh.PublicRaw, sh.Random, helloPadding(un(t, h.ServerHello)))
	eqHex(t, "server hello rebuild", serverHello, h.ServerHello)

	keys := DeriveSession(un(t, v.X25519[0].Shared), un(t, h.Verifier), ch.Random, sh.Random, clientHello, serverHello)
	eqHex(t, "th", keys.TH, h.TH)
	eqHex(t, "kC2s", keys.KC2s, h.KC2s)
	eqHex(t, "kS2c", keys.KS2c, h.KS2c)
	eqHex(t, "ivC2s", keys.IvC2s, h.IvC2s)
	eqHex(t, "ivS2c", keys.IvS2c, h.IvS2c)
	eqHex(t, "finished server mac", FinishedMAC(keys.FS, keys.TH, "server"), h.FinishedServerMac)
	eqHex(t, "finished client mac", FinishedMAC(keys.FC, keys.TH, "client"), h.FinishedClientMac)
}

// helloPadding extracts the padding bytes from a hello of either kind
// (client layout varies with the version count; server is fixed-head).
func helloPadding(hello []byte) []byte {
	if hello[0] == 0x01 {
		vc := int(hello[1])
		off := 1 + 1 + vc + 1 + 32 + 32
		return hello[off+1:]
	}
	return hello[67:]
}

func TestRecordVectors(t *testing.T) {
	v := loadVectors(t)
	r := v.Records
	frames := make([][]byte, len(r.FramesHex))
	for i, f := range r.FramesHex {
		frames[i] = un(t, f)
	}
	records, nextSeq, err := SealRecords(un(t, r.Key), un(t, r.Iv), 0, frames)
	if err != nil {
		t.Fatal(err)
	}
	if nextSeq != r.NextSeq || len(records) != len(r.RecordsHex) {
		t.Fatalf("seal shape: %d records nextSeq %d, want %d/%d", len(records), nextSeq, len(r.RecordsHex), r.NextSeq)
	}
	for i := range records {
		eqHex(t, "sealed record", records[i], r.RecordsHex[i])
	}
	rx := NewRecordReceiver(un(t, r.Key), un(t, r.Iv))
	for i, rec := range r.RecordsHex {
		blob := rx.Open(un(t, rec))
		if blob == nil {
			t.Fatalf("record %d failed to open", i)
		}
		eqHex(t, "opened frames blob", blob, r.FramesBlobsHex[i])
	}
	for _, pair := range r.BucketFor {
		got, ok := BucketFor(*pair[0])
		if pair[1] == nil {
			if ok {
				t.Fatalf("BucketFor(%d) = %d, want none", *pair[0], got)
			}
		} else if !ok || got != *pair[1] {
			t.Fatalf("BucketFor(%d) = %d/%v, want %d", *pair[0], got, ok, *pair[1])
		}
	}
	// Negative: a tampered record must fail and count. (Out-of-order
	// delivery needs a multi-record set — see TestRecordMultiVector.)
	rx2 := NewRecordReceiver(un(t, r.Key), un(t, r.Iv))
	if len(r.RecordsHex) > 0 {
		bad := un(t, r.RecordsHex[0])
		bad[5] ^= 1
		if rx2.Open(bad) != nil {
			t.Fatal("tampered record opened")
		}
		if rx2.ConsecFails != 1 {
			t.Fatalf("consecFails = %d, want 1", rx2.ConsecFails)
		}
	}
}

func TestFrameAndPayloadVectors(t *testing.T) {
	v := loadVectors(t)
	frames, recordError, _ := ParseFrames(un(t, v.Frames.GoodBlob))
	if recordError != v.Frames.GoodRecordError || len(frames) != v.Frames.GoodCount {
		t.Fatalf("good blob: %d frames err=%v", len(frames), recordError)
	}
	good := un(t, v.Frames.GoodBlob)
	trailing := append(append([]byte(nil), good...), un(t, "0102030405")...)
	if _, recErr, _ := ParseFrames(trailing); recErr != v.Frames.TrailingRecordError {
		t.Fatalf("trailing: recordError=%v want %v", recErr, v.Frames.TrailingRecordError)
	}
	big := BuildFrame(FTData, 7, make([]byte, 16374))
	if len(big) != v.Frames.OversizeBlobLen {
		t.Fatalf("oversize blob len %d want %d", len(big), v.Frames.OversizeBlobLen)
	}
	fr, _, ov := ParseFrames(big)
	if len(ov) != v.Frames.OversizeCount || len(fr) != v.Frames.OversizeFrames {
		t.Fatalf("oversize: frames=%d oversize=%d", len(fr), len(ov))
	}
	for _, c := range v.OpenPayload {
		p, err := BuildOpenPayload(c.Host, c.Port, c.SchemeHint, c.GatePolicy)
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "open payload "+c.Host, p, c.Payload)
		back := ParseOpenPayload(p)
		if back == nil || back.Host != c.ParsedHost || back.Port != c.Port {
			t.Fatalf("open payload parse: %+v", back)
		}
	}
	eqHex(t, "reject payload", RejectPayload(0x01, 1000), v.Misc.RejectPayload)
	eqHex(t, "reset payload", ResetPayload(0x0c), v.Misc.ResetPayload)
	// Ban-list expectations were serialized as [ip, bool] pairs.
	raw, _ := os.ReadFile("../testvectors/vectors-v0.1.2.json")
	var doc struct {
		Misc struct {
			BanV4 [][]any `json:"banV4"`
		} `json:"misc"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, pair := range doc.Misc.BanV4 {
		ipStr, want := pair[0].(string), pair[1].(bool)
		var b []byte
		for _, part := range splitDots(ipStr) {
			b = append(b, part)
		}
		if got := IsPrivateIPv4Bytes(b); got != want {
			t.Fatalf("IsPrivateIPv4Bytes(%s) = %v, want %v", ipStr, got, want)
		}
	}
}

func splitDots(s string) []byte {
	out := []byte{}
	cur := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, byte(cur))
			cur = 0
		} else {
			cur = cur*10 + int(s[i]-'0')
		}
	}
	return out
}

// TestRecordMultiVector covers the forced multi-record set (NP-1114-34):
// sealing must split into exactly the recorded records, in-order opens
// must reproduce each frames blob, and OUT-OF-ORDER delivery must fail —
// a fresh receiver fed record[1] first cannot open it (its nonce is
// bound to seq 1 while seq 0 is expected), and a receiver that consumed
// record[0] cannot open record[2].
func TestRecordMultiVector(t *testing.T) {
	v := loadVectors(t)
	r := v.RecordsMulti
	frames := make([][]byte, len(r.FramesHex))
	for i, f := range r.FramesHex {
		frames[i] = un(t, f)
	}
	records, nextSeq, err := SealRecords(un(t, r.Key), un(t, r.Iv), 0, frames)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) < 2 {
		t.Fatalf("construction did not force multiple records: %d", len(records))
	}
	if nextSeq != r.NextSeq || len(records) != len(r.RecordsHex) {
		t.Fatalf("seal shape: %d records nextSeq %d", len(records), nextSeq)
	}
	for i := range records {
		eqHex(t, "multi sealed record", records[i], r.RecordsHex[i])
	}
	rx := NewRecordReceiver(un(t, r.Key), un(t, r.Iv))
	for i, rec := range r.RecordsHex {
		blob := rx.Open(un(t, rec))
		if blob == nil {
			t.Fatalf("multi record %d failed to open in order", i)
		}
		eqHex(t, "multi opened blob", blob, r.FramesBlobsHex[i])
	}
	// Out of order, fresh receiver: record[1] first must fail.
	rxLate := NewRecordReceiver(un(t, r.Key), un(t, r.Iv))
	if blob := rxLate.Open(un(t, r.RecordsHex[1])); blob != nil {
		t.Fatal("out-of-order record[1] opened on a fresh receiver")
	}
	if rxLate.ConsecFails != 1 {
		t.Fatalf("out-of-order consecFails = %d, want 1", rxLate.ConsecFails)
	}
	// The failed open must not have advanced the sequence: record[0]
	// still opens afterwards.
	if blob := rxLate.Open(un(t, r.RecordsHex[0])); blob == nil {
		t.Fatal("record[0] no longer opens after the out-of-order failure")
	}
	// Out of order mid-stream: consumed [0], record[2] must fail.
	rxSkip := NewRecordReceiver(un(t, r.Key), un(t, r.Iv))
	if blob := rxSkip.Open(un(t, r.RecordsHex[0])); blob == nil {
		t.Fatal("record[0] failed on skip receiver")
	}
	if blob := rxSkip.Open(un(t, r.RecordsHex[2])); blob != nil {
		t.Fatal("skipped-to record[2] opened out of order")
	}
}

// TestRFCAnchorsDirect hard-anchors the Go primitives to published RFC
// constants WITHOUT the vector file in between (NP-1114-34收口: the Go
// side checks RFC first, then JS — as VECTORS.md states). ChaCha uses
// the RFC 8439 §A.5 AEAD vector (with AAD, via the library directly;
// the protocol's own seal uses nil AAD and is anchored to JS through
// the vector set plus this shared library anchor).
func TestRFCAnchorsDirect(t *testing.T) {
	// RFC 5869 Test Case 1.
	ikm := make([]byte, 22)
	for i := range ikm {
		ikm[i] = 0x0b
	}
	prk := hkdfExtract(un(t, "000102030405060708090a0b0c"), ikm)
	eqHex(t, "RFC5869 prk", prk, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	eqHex(t, "RFC5869 okm", hkdfExpand(prk, un(t, "f0f1f2f3f4f5f6f7f8f9"), 42),
		"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	// RFC 4231 Test Case 1.
	key := make([]byte, 20)
	for i := range key {
		key[i] = 0x0b
	}
	eqHex(t, "RFC4231 hmac", hmacSHA256(key, []byte("Hi There")),
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	// RFC 8439 §A.5 AEAD (the "sunscreen" vector).
	aead, err := chacha20poly1305.New(un(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	sealed := aead.Seal(nil, un(t, "070000004041424344454647"), pt, un(t, "50515253c0c1c2c3c4c5c6c7"))
	eqHex(t, "RFC8439 A.5 sealed", sealed,
		"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"+
			"1ae10b594f09e26a7e902ecbd0600691")
}

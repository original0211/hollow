// Protocol framing/record/payload logic — the Go counterpart of
// shared/protocol.js (frozen spec v0.1.2). Pure byte logic, no I/O.
// Any conflict between this file and the frozen spec is a bug here.
package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const ProtoVersion = 0x01

var Buckets = []int{512, 4096, 16384}

const (
	MaxPayload       = 16373 // §6.1
	FrameHead        = 9
	ConnWindowInit   = 1 << 20 // §6.5
	StreamWindowInit = 256 * 1024
	MergeWindow      = 2 * time.Millisecond // §6.4
	RecordFailLimit  = 3                     // §6.1 consecutive
	StreamErrorLimit = 10                    // §8.2
)

// Frame types (§6.2).
const (
	FTFinish       = 0x00
	FTOpen         = 0x01
	FTOpenOK       = 0x02
	FTOpenReject   = 0x03
	FTData         = 0x04
	FTClose        = 0x05
	FTReset        = 0x06
	FTWindowUpdate = 0x07
	FTPing         = 0x08
	FTPong         = 0x09
	FTGoAway       = 0x0a
	FTOpenQueued   = 0x0b
)

// Error codes (§8.3).
const (
	ErrConcurrencyLimit      = 0x01
	ErrProhibitedPort        = 0x02
	ErrPrivateTarget         = 0x03
	ErrCFSegmentNonHTTP      = 0x04
	ErrTargetUnreachable     = 0x05
	ErrOutboundFailed        = 0x06
	ErrFetchFallbackFailed   = 0x07
	ErrFetchProfileUnsupp    = 0x08
	ErrFetchBodyTooLarge     = 0x09
	ErrLoopTarget            = 0x0a
	ErrUnsupportedTarget     = 0x0b
	ErrProtocolError         = 0x0c
	ErrFlowControlViolation  = 0x0d
	ErrQuotaGuard            = 0x0e
	ErrServerClosing         = 0x0f
	ErrStreamTimeout         = 0x10
)

// Gate policies / scheme hints.
const (
	GateConnect = 0x00
	GateFetch   = 0x01

	SchemeUnknown = 0x00
	SchemeHTTP    = 0x01
	SchemeHTTPS   = 0x02
)

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func u16be(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func u32be(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func readU16(b []byte, off int) int { return int(binary.BigEndian.Uint16(b[off:])) }
func readU32(b []byte, off int) uint32 {
	return binary.BigEndian.Uint32(b[off:])
}

// ---------- §6.2 stream frames ----------

type Frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

func BuildFrame(typ byte, streamID uint32, payload []byte) []byte {
	head := make([]byte, FrameHead)
	head[0] = typ
	binary.BigEndian.PutUint32(head[1:], streamID)
	binary.BigEndian.PutUint32(head[5:], uint32(len(payload)))
	return concat(head, payload)
}

// ParseFrames parses one record's frames_blob (see the JS for the
// R-1113-05-01 split): malformed exhaustion is a record-level error; a
// frame over the payload hard cap that otherwise fits is reported in
// oversize as a stream-level error.
func ParseFrames(blob []byte) (frames []Frame, recordError bool, oversize []uint32) {
	off := 0
	for off < len(blob) {
		if len(blob)-off < FrameHead {
			return frames, true, oversize
		}
		typ := blob[off]
		sid := readU32(blob, off+1)
		payloadLen := int(readU32(blob, off+5))
		if off+FrameHead+payloadLen > len(blob) {
			return frames, true, oversize
		}
		payload := blob[off+FrameHead : off+FrameHead+payloadLen]
		if payloadLen > MaxPayload {
			oversize = append(oversize, sid)
		} else {
			frames = append(frames, Frame{typ, sid, append([]byte(nil), payload...)})
		}
		off += FrameHead + payloadLen
	}
	return frames, false, oversize
}

// ---------- §6.1 record layer ----------

func BucketFor(framesLen int) (int, bool) {
	for _, b := range Buckets {
		if 2+framesLen <= b {
			return b, true
		}
	}
	return 0, false
}

func nonceFor(iv []byte, seq uint64) []byte {
	nonce := append([]byte(nil), iv...)
	for i := 11; i >= 4; i-- {
		nonce[i] ^= byte(seq & 0xff)
		seq >>= 8
	}
	return nonce
}

// SealRecords packs frames into bucket-sized AEAD records; frames never
// split across records (§6.1-3).
func SealRecords(key, iv []byte, startSeq uint64, frames [][]byte) (records [][]byte, nextSeq uint64, err error) {
	seq := startSeq
	var blob [][]byte
	blobLen := 0
	flush := func() error {
		if len(blob) == 0 {
			return nil
		}
		framesBlob := concat(blob...)
		bucket, ok := BucketFor(len(framesBlob))
		if !ok {
			return errors.New("frames blob exceeds largest bucket")
		}
		pt := make([]byte, bucket)
		copy(pt, u16be(len(framesBlob)))
		copy(pt[2:], framesBlob)
		records = append(records, chachaSeal(key, nonceFor(iv, seq), pt))
		seq++
		blob = nil
		blobLen = 0
		return nil
	}
	for _, f := range frames {
		if len(f) > MaxPayload+FrameHead {
			return nil, 0, errors.New("frame too large")
		}
		if blobLen+len(f) > Buckets[2]-2 {
			if err := flush(); err != nil {
				return nil, 0, err
			}
		}
		blob = append(blob, f)
		blobLen += len(f)
	}
	if err := flush(); err != nil {
		return nil, 0, err
	}
	return records, seq, nil
}

// RecordReceiver is the stateful one-direction receiver (§6.1 failure
// counting mirrors the JS: AEAD/structure failures count inside Open;
// frame-exhaustion failures are reported via NoteFailure; a fully valid
// record is confirmed via NoteSuccess).
type RecordReceiver struct {
	key, iv     []byte
	expectSeq   uint64
	ConsecFails int
}

func NewRecordReceiver(key, iv []byte) *RecordReceiver {
	return &RecordReceiver{key: key, iv: iv}
}

func (r *RecordReceiver) NoteFailure() { r.ConsecFails++ }
func (r *RecordReceiver) NoteSuccess() { r.ConsecFails = 0 }

// Open returns the frames_blob, or nil on a record-level failure.
func (r *RecordReceiver) Open(msg []byte) []byte {
	pt := chachaOpen(r.key, nonceFor(r.iv, r.expectSeq), msg)
	if pt == nil {
		r.ConsecFails++
		return nil
	}
	framesLen := readU16(pt, 0)
	bucketOK := false
	for _, b := range Buckets {
		if b == len(pt) {
			bucketOK = true
		}
	}
	if !bucketOK || 2+framesLen > len(pt) {
		r.ConsecFails++
		return nil
	}
	for i := 2 + framesLen; i < len(pt); i++ {
		if pt[i] != 0 {
			r.ConsecFails++
			return nil
		}
	}
	r.expectSeq++
	return append([]byte(nil), pt[2:2+framesLen]...)
}

// ---------- §6.4 record sender with merge window ----------

// RecordSender queues frames; immediate pushes flush, DATA may wait up
// to MergeWindow to coalesce. All methods are called from the client's
// event loop (and Flush from tests) — not goroutine-safe by design,
// same contract as the JS original's single-threaded host.
type RecordSender struct {
	key, iv []byte
	seq     uint64
	send    func([]byte)
	queue   [][]byte
	timer   *time.Timer
}

func NewRecordSender(key, iv []byte, send func([]byte)) *RecordSender {
	return &RecordSender{key: key, iv: iv, send: send}
}

func (s *RecordSender) Push(frameBytes []byte, immediate bool) {
	s.queue = append(s.queue, frameBytes)
	if immediate {
		s.Flush()
	} else if s.timer == nil {
		s.timer = time.AfterFunc(MergeWindow, s.Flush)
	}
}

func (s *RecordSender) Flush() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if len(s.queue) == 0 {
		return
	}
	frames := s.queue
	s.queue = nil
	records, nextSeq, err := SealRecords(s.key, s.iv, s.seq, frames)
	if err != nil {
		return // frame sizes are caller-checked; mirrors JS throw path being unreachable here
	}
	s.seq = nextSeq
	for _, r := range records {
		s.send(r)
	}
}

// ---------- §6.3 OPEN payload ----------

func BuildOpenPayload(host string, port int, schemeHint, gatePolicy byte) ([]byte, error) {
	var addrType byte
	var addr []byte
	if isIPv4Literal(host) {
		addrType = 0x01
		parts := strings.Split(host, ".")
		addr = make([]byte, 4)
		for i, p := range parts {
			var v int
			if _, err := fmt.Sscanf(p, "%d", &v); err != nil || v < 0 || v > 255 {
				return nil, errors.New("bad ipv4")
			}
			addr[i] = byte(v)
		}
	} else if strings.Contains(host, ":") {
		addrType = 0x02
		b, err := ipv6ToBytes(host)
		if err != nil {
			return nil, err
		}
		addr = b
	} else {
		name := []byte(host)
		if len(name) > 253 {
			return nil, errors.New("domain too long")
		}
		addrType = 0x03
		addr = concat([]byte{byte(len(name))}, name)
	}
	return concat([]byte{addrType}, addr, u16be(port), []byte{schemeHint, gatePolicy}), nil
}

func isIPv4Literal(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

type OpenPayload struct {
	AddrType   byte
	Host       string
	AddrBytes  []byte
	Port       int
	SchemeHint byte
	GatePolicy byte
}

func ParseOpenPayload(p []byte) *OpenPayload {
	if len(p) < 1+2+1+1 {
		return nil
	}
	addrType := p[0]
	o := 1
	var host string
	var addrBytes []byte
	switch addrType {
	case 0x01:
		if len(p) < o+4+4 {
			return nil
		}
		addrBytes = append([]byte(nil), p[o:o+4]...)
		host = fmt.Sprintf("%d.%d.%d.%d", addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3])
		o += 4
	case 0x02:
		if len(p) < o+16+4 {
			return nil
		}
		addrBytes = append([]byte(nil), p[o:o+16]...)
		host = ipv6FromBytes(addrBytes)
		o += 16
	case 0x03:
		l := int(p[o])
		o++
		if l < 1 || l > 253 || len(p) < o+l+4 {
			return nil
		}
		if !utf8.Valid(p[o : o+l]) {
			return nil
		}
		host = string(p[o : o+l])
		o += l
	default:
		return nil
	}
	port := readU16(p, o)
	o += 2
	schemeHint := p[o]
	o++
	gatePolicy := p[o]
	o++
	if o != len(p) {
		return nil
	}
	return &OpenPayload{addrType, host, addrBytes, port, schemeHint, gatePolicy}
}

// ipv6ToBytes mirrors the JS minimal literal parser (full + "::"
// compressed; IPv4-mapped tails unsupported, as in the JS).
func ipv6ToBytes(host string) ([]byte, error) {
	parseSide := func(s string) ([]int, error) {
		if s == "" {
			return nil, nil
		}
		parts := strings.Split(s, ":")
		out := make([]int, 0, len(parts))
		for _, g := range parts {
			if g == "" {
				return nil, errors.New("bad ipv6")
			}
			n := 0
			for _, c := range []byte(g) {
				if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
					return nil, errors.New("bad ipv6")
				}
				n = n*16 + hexVal(c)
			}
			out = append(out, n)
		}
		return out, nil
	}
	var groups []int
	if halves := strings.Split(host, "::"); len(halves) == 2 {
		left, err := parseSide(halves[0])
		if err != nil {
			return nil, err
		}
		right, err := parseSide(halves[1])
		if err != nil {
			return nil, err
		}
		fill := 8 - len(left) - len(right)
		if fill < 0 {
			return nil, errors.New("bad ipv6")
		}
		groups = append(groups, left...)
		for i := 0; i < fill; i++ {
			groups = append(groups, 0)
		}
		groups = append(groups, right...)
	} else {
		g, err := parseSide(host)
		if err != nil {
			return nil, err
		}
		groups = g
	}
	if len(groups) != 8 {
		return nil, errors.New("bad ipv6")
	}
	out := make([]byte, 16)
	for i, g := range groups {
		if g < 0 || g > 0xffff {
			return nil, errors.New("bad ipv6")
		}
		out[i*2] = byte(g >> 8)
		out[i*2+1] = byte(g & 0xff)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}

// ipv6FromBytes mirrors the JS renderer: uncompressed lowercase groups.
func ipv6FromBytes(b []byte) string {
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		groups[i] = fmt.Sprintf("%x", int(b[i*2])<<8|int(b[i*2+1]))
	}
	return strings.Join(groups, ":")
}

// ---------- §7.2 ban list (literal IPs) ----------

func IsPrivateIPv4Bytes(b []byte) bool {
	a, c := b[0], b[1]
	if a == 127 || a == 10 || a == 0 {
		return true
	}
	if a == 172 && c >= 16 && c <= 31 {
		return true
	}
	if a == 192 && c == 168 {
		return true
	}
	if a == 169 && c == 254 {
		return true
	}
	return false
}

func IsPrivateIPv6Bytes(b []byte) bool {
	isLoop := true
	for i, x := range b {
		want := byte(0)
		if i == 15 {
			want = 1
		}
		if x != want {
			isLoop = false
		}
	}
	if isLoop {
		return true // ::1
	}
	if b[0]&0xfe == 0xfc {
		return true // fc00::/7
	}
	if b[0] == 0xfe && b[1]&0xc0 == 0x80 {
		return true // fe80::/10
	}
	mapped := true
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			mapped = false
		}
	}
	if mapped && b[10] == 0xff && b[11] == 0xff {
		return IsPrivateIPv4Bytes(b[12:16])
	}
	allZero := true
	for _, x := range b {
		if x != 0 {
			allZero = false
		}
	}
	return allZero // :: unspecified
}

// ---------- §8.3 payloads ----------

func RejectPayload(code byte, retryAfterMs int) []byte {
	return concat([]byte{code}, u16be(retryAfterMs), []byte{0})
}

func ResetPayload(code byte) []byte {
	return concat([]byte{code}, u16be(0))
}

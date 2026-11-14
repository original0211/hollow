// Package pairing is the Go port of the Windows pairing grammar
// (windows/src/pairing.js, M2-3 / NP-1114-07), built for M3-3
// (NP-1114-36). The JS implementation is canonical; both sides assert
// against the same fixture set (shared/testvectors/pairing-v1.json),
// and any grammar divergence found is registered, never silently
// resolved on one side.
//
// Error strings mirror the JS messages exactly — the fixtures pin them.
package pairing

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"hollow/androidcore/core"
)

const LinkPrefix = "hollow://v1"
const maxPayload = 8192

// Payload is a parsed (and validated) pairing payload. Empty MetaPath /
// EdgesPath mean "not carried" (JS null).
type Payload struct {
	WorkerURL string
	KeyID     int
	PSK       []byte // nil = not carried
	MetaPath  string
	EdgesPath string
}

// Preview mirrors previewOf: what the confirmation UI may show. The PSK
// itself never appears — only its verifier.
type Preview struct {
	WorkerURL        string `json:"workerUrl"`
	KeyID            int    `json:"keyId"`
	HasPSK           bool   `json:"hasPsk"`
	PSKVerifier      string `json:"pskVerifier,omitempty"`
	OverwritesPSK    bool   `json:"overwritesPsk"`
	HasEndpointPaths bool   `json:"hasEndpointPaths"`
}

func (p *Payload) Preview(currentPskExists bool) Preview {
	pv := Preview{
		WorkerURL:        p.WorkerURL,
		KeyID:            p.KeyID,
		HasPSK:           p.PSK != nil,
		OverwritesPSK:    p.PSK != nil && currentPskExists,
		HasEndpointPaths: p.MetaPath != "" || p.EdgesPath != "",
	}
	if p.PSK != nil {
		pv.PSKVerifier = hex.EncodeToString(core.DeriveVerifier(p.PSK))
	}
	return pv
}

var (
	b64urlChars = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	b64Chars    = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	httpPathRe  = regexp.MustCompile(`^/[A-Za-z0-9\-._~/]+$`)
)

// unb64url mirrors the JS decoder: strict charset (no padding allowed),
// then Node's lenient base64url decode (a trailing single char that
// cannot complete a group is dropped).
func unb64url(s string) ([]byte, error) {
	if !b64urlChars.MatchString(s) {
		return nil, errors.New("invalid base64url")
	}
	switch len(s) % 4 {
	case 1:
		s = s[:len(s)-1]
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func ValidateWorkerURL(u string) (string, error) {
	if len(u) > 512 {
		return "", errors.New("worker url missing/too long")
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme == "" {
		return "", errors.New("worker url not a URL")
	}
	switch parsed.Scheme {
	case "wss":
		return u, nil
	case "ws":
		if h := strings.ToLower(parsed.Hostname()); h == "localhost" || h == "127.0.0.1" {
			return u, nil
		}
	}
	return "", errors.New("worker url must be wss:// (ws:// only for localhost)")
}

func validateHTTPPath(p, label string) (string, error) {
	if len(p) > 200 || !httpPathRe.MatchString(p) {
		return "", fmt.Errorf("%s malformed", label)
	}
	return p, nil
}

// jsNumberKeyID mirrors JS Number(...) + the integer range check for
// the keyId field: empty/absent defaults at the call sites; here any
// non-integer or out-of-range value is the same error.
func jsKeyID(s string) (int, error) {
	t := strings.TrimSpace(s)
	var n int64
	var err error
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		n, err = strconv.ParseInt(t[2:], 16, 64)
	} else {
		var f float64
		f, err = strconv.ParseFloat(t, 64)
		if err == nil {
			if f != float64(int64(f)) {
				err = errors.New("not integer")
			}
			n = int64(f)
		}
	}
	if err != nil || n < 0 || n > 255 {
		return 0, errors.New("keyId out of range")
	}
	return int(n), nil
}

type rawFields struct {
	workerURL string
	keyID     int
	hasKeyID  bool
	psk       []byte
	metaPath  string
	edgesPath string
}

func validateFields(f rawFields) (*Payload, error) {
	u, err := ValidateWorkerURL(f.workerURL)
	if err != nil {
		return nil, err
	}
	kid := 1
	if f.hasKeyID {
		kid = f.keyID
	}
	if kid < 0 || kid > 255 {
		return nil, errors.New("keyId out of range")
	}
	if f.psk != nil && len(f.psk) != 32 {
		return nil, errors.New("psk must be 32 bytes")
	}
	p := &Payload{WorkerURL: u, KeyID: kid, PSK: f.psk}
	if f.metaPath != "" {
		if p.MetaPath, err = validateHTTPPath(f.metaPath, "metaPath"); err != nil {
			return nil, err
		}
	}
	if f.edgesPath != "" {
		if p.EdgesPath, err = validateHTTPPath(f.edgesPath, "edgesPath"); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// formEncode is the WHATWG application/x-www-form-urlencoded
// serializer (what URLSearchParams produces): alphanumerics and
// *-._ pass through, space becomes +, everything else (including ~,
// which Go's QueryEscape would leave raw) is %XX uppercase.
func formEncode(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '*' || c == '-' || c == '.' || c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func BuildLink(p *Payload) (string, error) {
	v, err := validateFields(rawFields{p.WorkerURL, p.KeyID, true, p.PSK, p.MetaPath, p.EdgesPath})
	if err != nil {
		return "", err
	}
	parts := []string{"worker=" + formEncode(v.WorkerURL), "keyId=" + strconv.Itoa(v.KeyID)}
	if v.PSK != nil {
		parts = append(parts, "psk="+base64.RawURLEncoding.EncodeToString(v.PSK))
	}
	if v.MetaPath != "" {
		parts = append(parts, "mp="+formEncode(v.MetaPath))
	}
	if v.EdgesPath != "" {
		parts = append(parts, "ep="+formEncode(v.EdgesPath))
	}
	return LinkPrefix + "?" + strings.Join(parts, "&"), nil
}

func parseLink(text string) (*Payload, error) {
	if len(text) > maxPayload {
		return nil, errors.New("payload too large")
	}
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, LinkPrefix) {
		return nil, errors.New("not a hollow://v1 link")
	}
	u, err := url.Parse(t)
	if err != nil {
		return nil, errors.New("Invalid URL") // V8's message, JS-uncaught
	}
	q := u.Query()
	f := rawFields{workerURL: q.Get("worker"), hasKeyID: false}
	if ks := q.Get("keyId"); ks != "" {
		kid, err := jsKeyID(ks)
		if err != nil {
			return nil, err
		}
		f.keyID, f.hasKeyID = kid, true
	}
	if ps := q.Get("psk"); ps != "" {
		b, err := unb64url(ps)
		if err != nil {
			return nil, err
		}
		f.psk = b
	}
	f.metaPath = q.Get("mp")
	f.edgesPath = q.Get("ep")
	return validateFields(f)
}

type exportObj struct {
	App       string  `json:"app"`
	Version   int     `json:"version"`
	WorkerURL string  `json:"workerUrl"`
	KeyID     int     `json:"keyId"`
	PSKBase64 *string `json:"pskBase64,omitempty"`
	MetaPath  *string `json:"metaPath,omitempty"`
	EdgesPath *string `json:"edgesPath,omitempty"`
}

func BuildExportJSON(p *Payload) (string, error) {
	v, err := validateFields(rawFields{p.WorkerURL, p.KeyID, true, p.PSK, p.MetaPath, p.EdgesPath})
	if err != nil {
		return "", err
	}
	o := exportObj{App: "hollow", Version: 1, WorkerURL: v.WorkerURL, KeyID: v.KeyID}
	if v.PSK != nil {
		s := base64.StdEncoding.EncodeToString(v.PSK)
		o.PSKBase64 = &s
	}
	if v.MetaPath != "" {
		o.MetaPath = &v.MetaPath
	}
	if v.EdgesPath != "" {
		o.EdgesPath = &v.EdgesPath
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(o); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

func parseExportObject(text string) (*Payload, error) {
	if len(text) > maxPayload {
		return nil, errors.New("payload too large")
	}
	var obj struct {
		App       string  `json:"app"`
		Version   int     `json:"version"`
		WorkerURL string  `json:"workerUrl"`
		KeyID     any     `json:"keyId"`
		PSKBase64 *string `json:"pskBase64"`
		MetaPath  *string `json:"metaPath"`
		EdgesPath *string `json:"edgesPath"`
	}
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return nil, errors.New("not JSON")
	}
	if obj.App != "hollow" || obj.Version != 1 {
		return nil, errors.New("not a hollow export file")
	}
	f := rawFields{workerURL: obj.WorkerURL}
	if obj.KeyID != nil {
		// JS checks Number.isInteger on whatever JSON held: a float
		// with a fraction, a string, a bool — all the same error.
		fl, ok := obj.KeyID.(float64)
		if !ok || fl != float64(int64(fl)) {
			return nil, errors.New("keyId out of range")
		}
		f.keyID, f.hasKeyID = int(fl), true
	}
	if obj.PSKBase64 != nil {
		if !b64Chars.MatchString(*obj.PSKBase64) {
			return nil, errors.New("bad pskBase64")
		}
		b, err := base64.StdEncoding.DecodeString(*obj.PSKBase64)
		if err != nil {
			return nil, errors.New("bad pskBase64")
		}
		f.psk = b
	}
	if obj.MetaPath != nil {
		f.metaPath = *obj.MetaPath
	}
	if obj.EdgesPath != nil {
		f.edgesPath = *obj.EdgesPath
	}
	return validateFields(f)
}

// ParseAnyPayload is the single funnel every import surface feeds
// through (link, file text, QR contents, clipboard).
func ParseAnyPayload(text string) (*Payload, error) {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, LinkPrefix) {
		return parseLink(t)
	}
	if strings.HasPrefix(t, "{") {
		return parseExportObject(t)
	}
	return nil, errors.New("unrecognized payload form")
}

// PSKHex is a small helper for tests and the storage layer.
func (p *Payload) PSKHex() string {
	if p.PSK == nil {
		return ""
	}
	return hex.EncodeToString(p.PSK)
}

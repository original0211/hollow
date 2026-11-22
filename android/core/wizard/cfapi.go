package wizard

// The wizard's real Cloudflare effects (NP-1118-62): the API
// client, the multipart script deploy, and the three-part
// liveness probe — all over the DirectDialer, so the wizard's
// traffic never enters the app's own tunnel. Every request is
// bounded by a client timeout; there is no unbounded wait in
// this file.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"hollow/androidcore/core"
)

// APIBase is the Cloudflare API root.
const APIBase = "https://api.cloudflare.com/client/v4"

// CFClient is the token-carrying API effect set for one run.
type CFClient struct {
	Token string
	HTTP  *http.Client
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result"`
	Errors  json.RawMessage `json:"errors"`
}

// API performs one API call and folds the envelope into an
// APIResult (OK = HTTP 2xx && success), mirroring the JS cfApi.
func (c *CFClient) API(method, path string, body any) (*APIResult, error) {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, APIBase+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := &APIResult{Status: resp.StatusCode}
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err == nil {
		out.Result = env.Result
		out.Errors = env.Errors
		out.OK = resp.StatusCode >= 200 && resp.StatusCode < 300 && env.Success
	}
	return out, nil
}

// DeployScript PUTs the Worker: multipart with a "metadata" JSON
// part and the bundle as the "index.js" module part — the exact
// form the production deploy procedure and the Windows wizard
// use.
func (c *CFClient) DeployScript(accountID, scriptName string, bundle []byte, metadata DeployMetadata) (*APIResult, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	metaRaw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	part, err := mw.CreatePart(partHeader("metadata", "", "application/json"))
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(metaRaw); err != nil {
		return nil, err
	}
	part, err = mw.CreatePart(partHeader("index.js", "index.js", "application/javascript+module"))
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(bundle); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	req, err := http.NewRequest("PUT", APIBase+"/accounts/"+accountID+"/workers/scripts/"+scriptName, &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := &APIResult{Status: resp.StatusCode}
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err == nil {
		out.Result = env.Result
		out.Errors = env.Errors
		out.OK = resp.StatusCode >= 200 && resp.StatusCode < 300 && env.Success
	}
	return out, nil
}

func partHeader(name, filename, contentType string) textproto.MIMEHeader {
	h := textproto.MIMEHeader{}
	disp := fmt.Sprintf("form-data; name=%q", name)
	if filename != "" {
		disp += fmt.Sprintf("; filename=%q", filename)
	}
	h.Set("Content-Disposition", disp)
	h.Set("Content-Type", contentType)
	return h
}

// NewEffects assembles the production Deps around a DirectDialer
// and a token. Storage-facing effects (Finalize, OnTokenVerified)
// are the caller's to supply.
func NewEffects(dialer *DirectDialer, token string) Deps {
	cf := &CFClient{Token: token, HTTP: dialer.HTTPClient(60 * time.Second)}
	probeHTTP := dialer.HTTPClient(20 * time.Second)
	return Deps{
		API:          cf.API,
		DeployScript: cf.DeployScript,
		ProbeLiveness: func(p Pairing) LivenessParts {
			return probeLiveness(probeHTTP, dialer, p)
		},
		RandomBytes:       randomBytes,
		RandomHex:         randomHex,
		DeriveVerifierHex: deriveVerifierHex,
		Bundle:            func() []byte { return BundleBytes },
	}
}

// probeLiveness runs the three parts with the Windows semantics:
// facade = GET / answers 200 with the exact 81-byte page; meta =
// GET /<metaPath> answers 200 with parseable JSON; handshake = a
// real Hollow handshake against the fresh Worker.
func probeLiveness(httpClient *http.Client, dialer *DirectDialer, p Pairing) LivenessParts {
	parts := LivenessParts{}
	httpBase := "https://" + strings.TrimPrefix(strings.TrimPrefix(p.WorkerURL, "wss://"), "ws://")
	if resp, err := httpClient.Get(httpBase + "/"); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		parts.Facade = resp.StatusCode == 200 && len(body) == 81
	}
	if resp, err := httpClient.Get(httpBase + "/" + p.MetaPath); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			var doc map[string]any
			parts.Meta = json.Unmarshal(body, &doc) == nil
		}
	}
	parts.Handshake = probeHandshake(dialer, p)
	return parts
}

// wsTransport adapts a gorilla connection to core.Transport (the
// session package's adapter, reduced to what a one-shot probe
// needs).
type wsTransport struct {
	conn   *websocket.Conn
	client *core.HollowClient
	done   chan struct{}
}

func (t *wsTransport) Send(b []byte) {
	_ = t.conn.WriteMessage(websocket.BinaryMessage, b)
}

func (t *wsTransport) Close() {
	_ = t.conn.Close()
}

func (t *wsTransport) readLoop() {
	defer close(t.done)
	for {
		_, data, err := t.conn.ReadMessage()
		if err != nil {
			t.client.HandleClose()
			return
		}
		t.client.HandleMessage(data)
	}
}

// probeHandshake dials the fresh Worker over the direct dialer
// and runs one real handshake (bounded at 20s, the session
// layer's own handshake bound).
func probeHandshake(dialer *DirectDialer, p Pairing) bool {
	d := websocket.Dialer{
		NetDialContext:   dialer.DialContext,
		HandshakeTimeout: 15 * time.Second,
	}
	header := http.Header{}
	header.Set("User-Agent", "HollowClient/0.1")
	conn, _, err := d.Dial(p.WorkerURL, header)
	if err != nil {
		return false
	}
	tr := &wsTransport{conn: conn, done: make(chan struct{})}
	client := core.NewClient(tr, core.ClientOptions{PSK: p.PSK, KeyID: byte(p.KeyID)})
	tr.client = client
	go tr.readLoop()
	done := client.Handshake()
	select {
	case <-done:
		ok := client.Err() == nil && client.State == "open"
		client.Close()
		return ok
	case <-time.After(20 * time.Second):
		client.Close()
		return false
	}
}

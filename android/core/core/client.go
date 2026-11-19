// Client session core — the Go counterpart of shared/client-core.js
// (spec v0.1 §4, §5, §6, §7.5 client side).
//
// Concurrency model: a single event loop goroutine owns all state,
// mirroring the JS promise-chain serialization. Transport callbacks and
// public methods enqueue ops; callbacks fire on the loop goroutine and
// may safely call the fire-and-forget stream methods (Write/CloseWrite/
// Reset/Consume), which simply enqueue behind the current op.
package core

import (
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"
)

// Transport carries raw WebSocket messages (hello plaintext, then AEAD
// records). Inbound delivery goes through Client.HandleMessage /
// Client.HandleClose, callable from any goroutine.
type Transport interface {
	Send([]byte)
	Close()
}

// QueuedInfo is the parsed OPEN_QUEUED payload (§7.5).
type QueuedInfo struct {
	Position  int
	EstWaitMs int
	MaxWaitMs int
}

// OpenRejectError is the typed form of an OPEN_REJECT: WaitOpen
// returns it so callers can branch on the code (the session layer's
// retry / rotation policy keys off 0x01 vs 0x06, NP-1118-03).
type OpenRejectError struct {
	Code         byte
	RetryAfterMs int
}

func (e *OpenRejectError) Error() string {
	return fmt.Sprintf("open rejected (code 0x%02x)", e.Code)
}

type ClientStream struct {
	client *HollowClient
	ID     uint32

	State      string // opening | queued | open | rejected | closed | reset | failed
	Gate       byte
	HasGate    bool
	QueuedInfo *QueuedInfo

	pending      [][]byte
	sendWindow   int
	recvWindow   int
	recvUnacked  int
	localClosed  bool
	remoteClosed bool
	closePending bool
	Paused       bool
	openErr      error
	openDone     chan struct{}

	OnOpenOK    func(gate byte)
	OnQueued    func(info QueuedInfo)
	OnReject    func(code byte, retryAfterMs int)
	OnOpenError func(reason string)
	OnData      func([]byte)
	OnEnd       func()
	OnReset     func(code byte)
	OnFail      func(reason string)
	OnDrain     func()
}

// Write queues data for sending (framed by the pump as windows allow).
// Deliberate divergence from the JS signature: JS returns an acceptance
// bool because it runs on the caller's thread; here the op executes on
// the event loop, so a returned bool would be a data race by design.
// Acceptance is observable through State and OnDrain instead.
func (s *ClientStream) Write(data []byte) {
	cp := append([]byte(nil), data...)
	s.client.enqueue(func() {
		if s.State != "open" && s.State != "opening" && s.State != "queued" {
			return
		}
		s.pending = append(s.pending, cp)
		s.client.pumpStream(s)
	})
}

// CloseWrite sends CLOSE after all queued DATA has been framed
// (stream-ordered, as the JS).
func (s *ClientStream) CloseWrite() {
	s.client.enqueue(func() {
		if s.localClosed || s.closePending {
			return
		}
		s.closePending = true
		if len(s.pending) == 0 {
			s.client.sendCloseFrame(s)
		}
	})
}

func (s *ClientStream) Reset(code byte) {
	s.client.enqueue(func() {
		s.client.sendFrame(BuildFrame(FTReset, s.ID, []byte{code, 0, 0}), true)
		s.State = "reset"
		s.client.forgetStream(s)
	})
}

// Consume signals the app has consumed n received bytes (§6.5).
func (s *ClientStream) Consume(n int) {
	s.client.enqueue(func() { s.client.onConsume(s, n) })
}

// WaitOpen blocks until the stream opens or fails (not for use inside
// callbacks — those should use OnOpenOK/OnReject/OnOpenError).
func (s *ClientStream) WaitOpen() (byte, error) {
	<-s.openDone
	if s.openErr != nil {
		return 0, s.openErr
	}
	return s.Gate, nil
}

type ClientOptions struct {
	// §6.5 v0.2.1 grant targets; 0 selects the protocol defaults
	// (StreamWindowGrant / ConnWindowGrant). Setting them to the
	// INIT values reproduces pre-v0.2.1 behavior exactly.
	StreamWindowGrant int
	ConnWindowGrant   int
	PSK               []byte
	KeyID             byte // zero means 1, as the JS default

	// Test-only determinism hooks (nil in production): a fixed ephemeral
	// key pair, client random and hello padding, so a recorded session
	// transcript can be replayed byte for byte.
	EphemeralOverride *Ephemeral
	RandomOverride    []byte
	PaddingOverride   []byte
}

type HollowClient struct {
	transport Transport
	psk       []byte
	keyID     byte
	opts      ClientOptions

	State      string // idle | hello | wait-finished | open | dead
	FailReason string
	GoAwayCode *byte

	streams           map[uint32]*ClientStream
	nextStreamID      uint32
	streamWindowGrant int
	connWindowGrant   int
	halfStreamWindow  int
	halfConnWindow    int
	sender            *RecordSender
	receiver          *RecordReceiver
	connSendWindow    int
	connRecvWindow    int
	connRecvUnacked   int
	WireSizes         []int // observed inbound WS message sizes (F-8)

	keys           *SessionKeys
	th             []byte
	eph            *Ephemeral
	clientRandom   []byte
	clientHello    []byte
	serverHello    []byte
	hsErr          atomic.Value // error; written once by die() (run loop), read via Err() from any goroutine
	hsDone         chan struct{}
	lastSentRecord []byte

	OnCarrierDead func(reason string)

	// NP-1117-16 parity (NP-1118-03): every OPEN frame this client
	// sends is counted; when the count reaches exactly
	// SessionRotateThreshold, OnOpenThreshold fires (once). The
	// callback runs on the event loop and MUST be non-blocking
	// (signal a channel; the session layer rotates asynchronously).
	opensSent       atomic.Int64
	activeStreams   atomic.Int64
	OnOpenThreshold func()

	inbox chan func()
}

func NewClient(t Transport, opts ClientOptions) *HollowClient {
	keyID := opts.KeyID
	if keyID == 0 {
		keyID = 1
	}
	streamGrant := opts.StreamWindowGrant
	if streamGrant == 0 {
		streamGrant = StreamWindowGrant
	}
	connGrant := opts.ConnWindowGrant
	if connGrant == 0 {
		connGrant = ConnWindowGrant
	}
	c := &HollowClient{
		transport:         t,
		psk:               opts.PSK,
		keyID:             keyID,
		opts:              opts,
		State:             "idle",
		streams:           map[uint32]*ClientStream{},
		nextStreamID:      1,
		streamWindowGrant: streamGrant,
		connWindowGrant:   connGrant,
		halfStreamWindow:  streamGrant / 2,
		halfConnWindow:    connGrant / 2,
		connSendWindow:    ConnWindowInit,
		connRecvWindow:    connGrant,
		hsDone:            make(chan struct{}),
		inbox:             make(chan func(), 4096),
	}
	go c.run()
	return c
}

func (c *HollowClient) run() {
	for op := range c.inbox {
		op()
	}
}

func (c *HollowClient) enqueue(op func()) { c.inbox <- op }

// Sync blocks until every op enqueued so far has been processed — the
// deterministic barrier tests and careful callers use.
func (c *HollowClient) Sync() {
	done := make(chan struct{})
	c.enqueue(func() { close(done) })
	<-done
}

// HandleMessage delivers one inbound wire message (any goroutine).
func (c *HollowClient) HandleMessage(b []byte) {
	cp := append([]byte(nil), b...)
	c.enqueue(func() { c.onMessage(cp) })
}

// HandleClose delivers the transport's close event (any goroutine).
func (c *HollowClient) HandleClose() {
	c.enqueue(func() { c.die("carrier closed") })
}

// Handshake starts the §5 exchange; the returned channel closes when the
// session is open or dead (check Err()).
func (c *HollowClient) Handshake() <-chan struct{} {
	c.enqueue(func() {
		if c.State != "idle" {
			return
		}
		c.State = "hello"
		eph := c.opts.EphemeralOverride
		if eph == nil {
			var err error
			eph, err = GenerateEphemeral()
			if err != nil {
				c.die("ephemeral generation failed")
				return
			}
		}
		c.eph = eph
		if c.opts.RandomOverride != nil {
			c.clientRandom = c.opts.RandomOverride
		} else {
			c.clientRandom = randomBytes(32)
		}
		padding := c.opts.PaddingOverride
		if padding == nil {
			padding = randomBytes(rand.Intn(129)) // 0..128 bytes, as the JS
		}
		c.clientHello = BuildClientHello([]byte{ProtoVersion}, c.keyID, eph.PubRaw, c.clientRandom, padding)
		c.transport.Send(c.clientHello)
	})
	return c.hsDone
}

// Err returns the handshake-fatal error, if any. Safe from any
// goroutine: hsErr is stored atomically by die() — a carrier that dies
// AFTER a successful handshake writes it with no other happens-before
// edge to readers (caught by TestSessionCarrierDeathRecovery -race).
func (c *HollowClient) Err() error {
	if e := c.hsErr.Load(); e != nil {
		return e.(error)
	}
	return nil
}

// Session budget constants (NP-1117-16 semantics, spec-anchored in
// the M4 long-run diagnosis): a Worker invocation admits ~50
// subrequests, so a carrier is retired BEFORE the ceiling.
const (
	SessionRotateThreshold = 40
	SessionOpenHardCap     = 50
)

// OpensSent reports how many OPEN frames this client has sent.
func (c *HollowClient) OpensSent() int64 { return c.opensSent.Load() }

// ActiveStreams reports how many streams are currently registered.
func (c *HollowClient) ActiveStreams() int64 { return c.activeStreams.Load() }

// BudgetExhausted reports whether this client has hit the hard cap.
func (c *HollowClient) BudgetExhausted() bool { return c.opensSent.Load() >= SessionOpenHardCap }

// OpenStream registers a stream and sends OPEN (§6.3).
// StreamCallbacks bundles a stream's event handlers. They are
// installed at construction, BEFORE the stream is registered
// with the client's event loop, so the loop can never observe
// a half-wired stream when the carrier dies mid-dial
// (NP-1118-30 race fix: callback assignment used to race die()).
type StreamCallbacks struct {
	OnData  func([]byte)
	OnEnd   func()
	OnReset func(code byte)
	OnFail  func(reason string)
}

func (c *HollowClient) OpenStream(host string, port int, schemeHint, gatePolicy byte) (*ClientStream, error) {
	return c.OpenStreamWithCallbacks(host, port, schemeHint, gatePolicy, nil)
}

func (c *HollowClient) OpenStreamWithCallbacks(host string, port int, schemeHint, gatePolicy byte, cb *StreamCallbacks) (*ClientStream, error) {
	s := &ClientStream{
		client:     c,
		State:      "opening",
		sendWindow: StreamWindowInit,
		recvWindow: c.streamWindowGrant,
		openDone:   make(chan struct{}),
	}
	if cb != nil {
		s.OnData, s.OnEnd, s.OnReset, s.OnFail = cb.OnData, cb.OnEnd, cb.OnReset, cb.OnFail
	}
	var buildErr error
	c.enqueue(func() {
		if c.State != "open" {
			buildErr = errors.New("session not open")
			s.openErr = buildErr
			close(s.openDone)
			return
		}
		s.ID = c.nextStreamID
		c.nextStreamID += 2
		c.streams[s.ID] = s
		payload, err := BuildOpenPayload(host, port, schemeHint, gatePolicy)
		if err != nil {
			buildErr = err
			s.openErr = err
			close(s.openDone)
			delete(c.streams, s.ID)
			return
		}
		c.sendFrame(BuildFrame(FTOpen, s.ID, payload), true)
		c.activeStreams.Add(1)
		if n := c.opensSent.Add(1); n == SessionRotateThreshold && c.OnOpenThreshold != nil {
			c.OnOpenThreshold()
		}
		// §6.5 v0.2.1: top up the server's per-stream window for
		// the return direction (rides right behind OPEN).
		c.topUp(s.ID, c.streamWindowGrant-StreamWindowInit)
	})
	// Resolve the ID assignment synchronously for the caller: the op
	// above runs on the loop; wait for it via a barrier.
	c.Sync()
	if buildErr != nil {
		return nil, buildErr
	}
	return s, nil
}

func (c *HollowClient) Close() {
	c.enqueue(func() {
		c.transport.Close()
		c.die("closed by app")
	})
}

// FlushSender forces any merge-window queue out (tests / drain points).
func (c *HollowClient) FlushSender() {
	c.enqueue(func() {
		if c.sender != nil {
			c.sender.Flush()
		}
	})
	c.Sync()
}

func (c *HollowClient) die(reason string) {
	if c.State == "dead" {
		return
	}
	c.State = "dead"
	c.FailReason = reason
	if c.hsErr.Load() == nil {
		c.hsErr.Store(errors.New(reason))
		select {
		case <-c.hsDone:
		default:
			close(c.hsDone)
		}
	}
	for _, s := range c.streams {
		if s.OnFail != nil {
			s.OnFail(reason)
		}
		if s.openErr == nil && (s.State == "opening" || s.State == "queued") {
			s.openErr = errors.New(reason)
			if s.OnOpenError != nil {
				s.OnOpenError(reason)
			}
		}
		select {
		case <-s.openDone:
		default:
			close(s.openDone)
		}
	}
	c.streams = map[uint32]*ClientStream{}
	if c.OnCarrierDead != nil {
		c.OnCarrierDead(reason)
	}
}

func (c *HollowClient) onMessage(bytes []byte) {
	c.WireSizes = append(c.WireSizes, len(bytes))
	switch c.State {
	case "hello":
		c.onServerHello(bytes)
	case "wait-finished":
		c.onServerFinished(bytes)
	case "open":
		c.onRecord(bytes)
	}
}

func (c *HollowClient) onServerHello(bytes []byte) {
	sh := ParseServerHello(bytes)
	if sh == nil || sh.SelectedVersion != ProtoVersion {
		c.die("server hello rejected")
		c.transport.Close()
		return
	}
	c.serverHello = bytes
	dh := x25519Derive(c.eph.Priv, sh.PublicRaw)
	if dh == nil {
		c.die("x25519 failed")
		c.transport.Close()
		return
	}
	verifier := DeriveVerifier(c.psk)
	keys := DeriveSession(dh, verifier, c.clientRandom, sh.Random, c.clientHello, bytes)
	c.keys = keys
	c.th = keys.TH
	c.sender = NewRecordSender(keys.KC2s, keys.IvC2s, func(b []byte) {
		c.lastSentRecord = b
		c.transport.Send(b)
	})
	c.sender.SetFlushScheduler(c.enqueue)
	c.receiver = NewRecordReceiver(keys.KS2c, keys.IvS2c)
	c.State = "wait-finished"
}

func (c *HollowClient) onServerFinished(bytes []byte) {
	opened := c.receiver.Open(bytes)
	if opened == nil {
		c.die("server finished record undecryptable")
		c.transport.Close()
		return
	}
	frames, recordError, _ := ParseFrames(opened)
	expect := FinishedMAC(c.keys.FS, c.th, "server")
	if recordError || len(frames) != 1 || frames[0].Type != FTFinish || frames[0].StreamID != 0 || !Eq(frames[0].Payload, expect) {
		c.die("server finished mismatch")
		c.transport.Close()
		return
	}
	mac := FinishedMAC(c.keys.FC, c.th, "client")
	c.sender.Push(BuildFrame(FTFinish, 0, mac), true)
	c.State = "open"
	// §6.5 v0.2.1: top up the server's connection window from the
	// legacy INIT to our grant target.
	c.topUp(0, c.connWindowGrant-ConnWindowInit)
	select {
	case <-c.hsDone:
	default:
		close(c.hsDone)
	}
}

func (c *HollowClient) sendFrame(frameBytes []byte, immediate bool) {
	if c.sender != nil {
		c.sender.Push(frameBytes, immediate)
	}
}

// topUp expresses the difference between the legacy INIT window and
// our grant target as an explicit WINDOW_UPDATE (§6.5 v0.2.1).
// Zero/negative differences send nothing — exactly the legacy
// behavior.
func (c *HollowClient) topUp(streamID uint32, inc int) {
	if inc > 0 {
		c.sendFrame(BuildFrame(FTWindowUpdate, streamID, u32be(uint32(inc))), true)
	}
}

func (c *HollowClient) pumpStream(s *ClientStream) {
	for len(s.pending) > 0 && s.State == "open" {
		avail := s.sendWindow
		if c.connSendWindow < avail {
			avail = c.connSendWindow
		}
		if avail <= 0 {
			return
		}
		head := s.pending[0]
		take := len(head)
		if avail < take {
			take = avail
		}
		if MaxPayload < take {
			take = MaxPayload
		}
		chunk := head[:take]
		if take == len(head) {
			s.pending = s.pending[1:]
		} else {
			s.pending[0] = head[take:]
		}
		s.sendWindow -= take
		c.connSendWindow -= take
		c.sendFrame(BuildFrame(FTData, s.ID, chunk), false)
	}
	if len(s.pending) == 0 {
		if s.closePending && !s.localClosed {
			c.sendCloseFrame(s)
		}
		if s.OnDrain != nil {
			s.OnDrain()
		}
	}
}

func (c *HollowClient) sendCloseFrame(s *ClientStream) {
	s.localClosed = true
	s.closePending = false
	c.sendFrame(BuildFrame(FTClose, s.ID, []byte{0x00}), true)
	c.maybeFreeStream(s)
}

func (c *HollowClient) onConsume(s *ClientStream, n int) {
	// §6.5: WINDOW_UPDATE when accumulated consumption >= half the
	// window, per stream and connection level independently.
	s.recvUnacked += n
	if s.recvUnacked >= c.halfStreamWindow {
		inc := s.recvUnacked
		s.recvUnacked = 0
		s.recvWindow += inc
		c.sendFrame(BuildFrame(FTWindowUpdate, s.ID, u32be(uint32(inc))), true)
	}
	c.connRecvUnacked += n
	if c.connRecvUnacked >= c.halfConnWindow {
		inc := c.connRecvUnacked
		c.connRecvUnacked = 0
		c.connRecvWindow += inc
		c.sendFrame(BuildFrame(FTWindowUpdate, 0, u32be(uint32(inc))), true)
	}
}

func (c *HollowClient) onRecord(bytes []byte) {
	opened := c.receiver.Open(bytes)
	if opened == nil {
		if c.receiver.ConsecFails >= RecordFailLimit {
			c.die("record failure limit")
			c.transport.Close()
		}
		return
	}
	frames, recordError, oversize := ParseFrames(opened)
	if recordError {
		c.receiver.NoteFailure()
		if c.receiver.ConsecFails >= RecordFailLimit {
			c.die("record failure limit")
			c.transport.Close()
		}
		return
	}
	c.receiver.NoteSuccess()
	for _, sid := range oversize {
		if s := c.streams[sid]; s != nil {
			s.State = "reset"
			if s.OnReset != nil {
				s.OnReset(ErrProtocolError)
			}
			c.forgetStream(s)
		}
	}
	for _, f := range frames {
		c.dispatch(f)
	}
}

func (c *HollowClient) dispatch(f Frame) {
	s := c.streams[f.StreamID]
	switch f.Type {
	case FTOpenOK:
		if s == nil {
			return
		}
		if len(f.Payload) > 0 {
			s.Gate = f.Payload[0]
			s.HasGate = true
		}
		s.State = "open"
		if s.OnOpenOK != nil {
			s.OnOpenOK(s.Gate)
		}
		if s.openErr == nil {
			select {
			case <-s.openDone:
			default:
				close(s.openDone)
			}
		}
		c.pumpStream(s)
	case FTOpenQueued:
		if s == nil {
			return
		}
		s.State = "queued"
		info := QueuedInfo{
			Position:  readU16(f.Payload, 0),
			EstWaitMs: readU16(f.Payload, 2),
			MaxWaitMs: readU16(f.Payload, 4),
		}
		s.QueuedInfo = &info
		if s.OnQueued != nil {
			s.OnQueued(info)
		}
	case FTOpenReject:
		if s == nil {
			return
		}
		s.State = "rejected"
		code := f.Payload[0]
		retryAfterMs := readU16(f.Payload, 1)
		s.openErr = &OpenRejectError{Code: code, RetryAfterMs: retryAfterMs}
		if s.OnReject != nil {
			s.OnReject(code, retryAfterMs)
		}
		select {
		case <-s.openDone:
		default:
			close(s.openDone)
		}
		c.forgetStream(s)
	case FTData:
		if s == nil {
			return
		}
		if len(f.Payload) > s.recvWindow || len(f.Payload) > c.connRecvWindow {
			c.sendFrame(BuildFrame(FTReset, s.ID, []byte{ErrFlowControlViolation, 0, 0}), true)
			s.State = "reset"
			if s.OnReset != nil {
				s.OnReset(ErrFlowControlViolation)
			}
			c.forgetStream(s)
			return
		}
		s.recvWindow -= len(f.Payload)
		c.connRecvWindow -= len(f.Payload)
		if s.OnData != nil {
			s.OnData(f.Payload)
		}
		if !s.Paused {
			c.onConsume(s, len(f.Payload))
		}
	case FTClose:
		if s == nil {
			return
		}
		s.remoteClosed = true
		if s.OnEnd != nil {
			s.OnEnd()
		}
		c.maybeFreeStream(s)
	case FTReset:
		if s == nil {
			return
		}
		s.State = "reset"
		var code byte
		if len(f.Payload) > 0 {
			code = f.Payload[0]
		}
		if s.OnReset != nil {
			s.OnReset(code)
		}
		if s.openErr == nil {
			s.openErr = errors.New("stream reset")
			select {
			case <-s.openDone:
			default:
				close(s.openDone)
			}
		}
		c.forgetStream(s)
	case FTWindowUpdate:
		var inc int
		if len(f.Payload) >= 4 {
			inc = int(readU32(f.Payload, 0))
		}
		if f.StreamID == 0 {
			c.connSendWindow += inc
			for _, st := range c.streams {
				c.pumpStream(st)
			}
		} else if s != nil {
			s.sendWindow += inc
			c.pumpStream(s)
		}
	case FTPing:
		c.sendFrame(BuildFrame(FTPong, f.StreamID, f.Payload), true)
	case FTGoAway:
		if len(f.Payload) > 0 {
			code := f.Payload[0]
			c.GoAwayCode = &code
		}
	default:
		// unknown frame type: stream-level protocol error (§8.2/§10.2)
		if s != nil {
			s.State = "reset"
			if s.OnReset != nil {
				s.OnReset(ErrProtocolError)
			}
			c.forgetStream(s)
		}
	}
}

func (c *HollowClient) maybeFreeStream(s *ClientStream) {
	if s.localClosed && s.remoteClosed {
		s.State = "closed"
		c.forgetStream(s)
	}
}

func (c *HollowClient) forgetStream(s *ClientStream) {
	if c.sender != nil {
		c.sender.Flush()
	}
	if _, ok := c.streams[s.ID]; ok {
		c.activeStreams.Add(-1)
	}
	delete(c.streams, s.ID)
}

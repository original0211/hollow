package session

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hollow/androidcore/core"

	"github.com/gorilla/websocket"
)

// --- phxServer: a Hollow test server with per-stream receive
// logs, held echoes and carrier kill switches (NP-1118-30). ---

type phxStream struct {
	mu       sync.Mutex
	received []byte
	echoed   int
	push     func([]byte)
	ws       *websocket.Conn
}

type phxServer struct {
	srv        *httptest.Server
	mu         sync.Mutex
	streams    []*phxStream
	echoOn     atomic.Bool
	killOnOpen atomic.Bool
}

func newPhxServer(t *testing.T, psk []byte) *phxServer {
	t.Helper()
	ps := &phxServer{}
	ps.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, helloRaw, err := ws.ReadMessage()
		if err != nil {
			return
		}
		ch := core.ParseClientHello(helloRaw)
		if ch == nil {
			return
		}
		eph, err := core.GenerateEphemeral()
		if err != nil {
			return
		}
		serverRandom := make([]byte, 32)
		rand.Read(serverRandom)
		shRaw := core.BuildServerHello(core.ProtoVersion, eph.PubRaw, serverRandom, []byte{1, 2, 3})
		if err := ws.WriteMessage(websocket.BinaryMessage, shRaw); err != nil {
			return
		}
		peerPub, err := ecdh.X25519().NewPublicKey(ch.PublicRaw)
		if err != nil {
			return
		}
		dh, err := eph.Priv.ECDH(peerPub)
		if err != nil {
			return
		}
		keys := core.DeriveSession(dh, core.DeriveVerifier(psk), ch.Random, serverRandom, helloRaw, shRaw)
		var writeMu sync.Mutex
		send := func(b []byte) {
			writeMu.Lock()
			_ = ws.WriteMessage(websocket.BinaryMessage, b)
			writeMu.Unlock()
		}
		sender := core.NewRecordSender(keys.KS2c, keys.IvS2c, send)
		receiver := core.NewRecordReceiver(keys.KC2s, keys.IvC2s)
		sender.Push(core.BuildFrame(core.FTFinish, 0, core.FinishedMAC(keys.FS, keys.TH, "server")), true)
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		blob := receiver.Open(msg)
		if blob == nil {
			return
		}
		frames, recErr, _ := core.ParseFrames(blob)
		if recErr || len(frames) != 1 || frames[0].Type != core.FTFinish {
			return
		}
		mine := map[uint32]*phxStream{}
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			blob := receiver.Open(msg)
			if blob == nil {
				return
			}
			frames, _, _ := core.ParseFrames(blob)
			for _, f := range frames {
				switch f.Type {
				case core.FTOpen:
					st := &phxStream{ws: ws}
					sid := f.StreamID
					s := sender
					st.push = func(payload []byte) {
						s.Push(core.BuildFrame(core.FTData, sid, payload), true)
					}
					mine[sid] = st
					ps.mu.Lock()
					ps.streams = append(ps.streams, st)
					ps.mu.Unlock()
					sender.Push(core.BuildFrame(core.FTOpenOK, f.StreamID, []byte{core.GateConnect}), true)
					if ps.killOnOpen.Load() {
						go func() {
							time.Sleep(100 * time.Millisecond)
							ws.Close()
						}()
					}
				case core.FTData:
					st := mine[f.StreamID]
					if st == nil {
						continue
					}
					st.mu.Lock()
					st.received = append(st.received, f.Payload...)
					if ps.echoOn.Load() {
						newBytes := append([]byte(nil), st.received[st.echoed:]...)
						st.echoed = len(st.received)
						st.mu.Unlock()
						if len(newBytes) > 0 {
							st.push(newBytes)
						}
					} else {
						st.mu.Unlock()
					}
				case core.FTClose:
					sender.Push(core.BuildFrame(core.FTClose, f.StreamID, []byte{0}), true)
				}
			}
		}
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

func (ps *phxServer) streamCount() int {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return len(ps.streams)
}

func (ps *phxServer) stream(i int) *phxStream {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if i < len(ps.streams) {
		return ps.streams[i]
	}
	return nil
}

func (st *phxStream) got() []byte {
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([]byte(nil), st.received...)
}

// flush echoes everything held on live streams.
func (ps *phxServer) flush() {
	ps.mu.Lock()
	streams := append([]*phxStream(nil), ps.streams...)
	ps.mu.Unlock()
	for _, st := range streams {
		st.mu.Lock()
		newBytes := append([]byte(nil), st.received[st.echoed:]...)
		st.echoed = len(st.received)
		st.mu.Unlock()
		if len(newBytes) > 0 {
			st.push(newBytes)
		}
	}
}

// killStreamCarrier closes the WS conn hosting stream i.
func (ps *phxServer) killStreamCarrier(i int) bool {
	st := ps.stream(i)
	if st == nil {
		return false
	}
	return st.ws.Close() == nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func dialPhoenix(t *testing.T, s *Session) net.Conn {
	t.Helper()
	conn, err := s.dialFlowPhoenix(net.ParseIP("203.0.113.7"), 443)
	if err != nil {
		t.Fatalf("dialPhoenix: %v", err)
	}
	return conn
}

func readAll(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	got := make([]byte, n)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return got
}

var getFlight = []byte("GET /page HTTP/1.1\r\nHost: example.test\r\n\r\n")

// Kill after OPEN, before any write: the flight written into
// the dead stream must be replayed whole on the new carrier.
func TestPhoenixKillAfterOpen(t *testing.T) {
	psk := testPSK()
	ps := newPhxServer(t, psk)
	s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
	defer s.Stop()
	establishAll(t, s)

	conn := dialPhoenix(t, s)
	waitFor(t, "stream 0 accepted", func() bool { return ps.streamCount() == 1 })
	if !ps.killStreamCarrier(0) {
		t.Fatal("kill failed")
	}
	if _, err := conn.Write(getFlight); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Read drives the reopen; the echo arrives after flush.
	go func() {
		waitFor(t, "stream 1 accepted", func() bool { return ps.streamCount() == 2 })
		waitFor(t, "stream 1 got flight", func() bool { return bytes.Equal(ps.stream(1).got(), getFlight) })
		ps.flush()
	}()
	got := readAll(t, conn, len(getFlight))
	if !bytes.Equal(got, getFlight) {
		t.Fatalf("echo = %q, want the flight exactly", got)
	}
	if n := len(ps.stream(0).got()); n != 0 {
		t.Fatalf("dead stream received %d bytes, want 0", n)
	}
	st := s.State()
	if st.PhoenixReopens != 1 || st.PhoenixSaved != 1 {
		t.Fatalf("phoenix counters = %d/%d, want 1/1", st.PhoenixReopens, st.PhoenixSaved)
	}
	conn.Close()
}

// Kill mid-flight (TLS-shaped, sent in two writes): the new
// stream must receive part1+part2 spliced exactly.
func TestPhoenixKillMidFlight(t *testing.T) {
	psk := testPSK()
	ps := newPhxServer(t, psk)
	s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
	defer s.Stop()
	establishAll(t, s)

	conn := dialPhoenix(t, s)
	part1 := []byte{0x16, 0x03, 0x01, 0x00, 0x2a}
	part2 := []byte{0x01, 0x00, 0x00, 0x26, 0x03, 0x03}
	full := append(append([]byte(nil), part1...), part2...)
	if _, err := conn.Write(part1); err != nil {
		t.Fatalf("write part1: %v", err)
	}
	waitFor(t, "stream 0 got part1", func() bool { return bytes.Equal(ps.stream(0).got(), part1) })
	if !ps.killStreamCarrier(0) {
		t.Fatal("kill failed")
	}
	if _, err := conn.Write(part2); err != nil {
		t.Fatalf("write part2: %v", err)
	}
	go func() {
		waitFor(t, "stream 1 accepted", func() bool { return ps.streamCount() == 2 })
		waitFor(t, "stream 1 got full flight", func() bool { return bytes.Equal(ps.stream(1).got(), full) })
		ps.flush()
	}()
	got := readAll(t, conn, len(full))
	if !bytes.Equal(got, full) {
		t.Fatalf("echo mismatch: %x", got)
	}
	conn.Close()
}

// Kill after the full flight arrived but before the first
// response byte: replay delivers the flight to stream 1
// exactly once there, and the answer flows.
func TestPhoenixKillBeforeFirstByte(t *testing.T) {
	psk := testPSK()
	ps := newPhxServer(t, psk)
	s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
	defer s.Stop()
	establishAll(t, s)

	conn := dialPhoenix(t, s)
	if _, err := conn.Write(getFlight); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, "stream 0 got flight", func() bool { return bytes.Equal(ps.stream(0).got(), getFlight) })
	if !ps.killStreamCarrier(0) {
		t.Fatal("kill failed")
	}
	go func() {
		waitFor(t, "stream 1 accepted", func() bool { return ps.streamCount() == 2 })
		waitFor(t, "stream 1 got flight", func() bool { return bytes.Equal(ps.stream(1).got(), getFlight) })
		ps.flush()
	}()
	got := readAll(t, conn, len(getFlight))
	if !bytes.Equal(got, getFlight) {
		t.Fatalf("echo = %q", got)
	}
	conn.Close()
}

// Gate grids: POST and opaque flights must NOT be replayed.
func TestPhoenixGateNoReplay(t *testing.T) {
	for _, tc := range []struct {
		name   string
		flight []byte
	}{
		{"POST", []byte("POST /x HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc")},
		{"opaque", []byte{0x01, 0x02, 0x03, 0x04}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			psk := testPSK()
			ps := newPhxServer(t, psk)
			s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
			defer s.Stop()
			establishAll(t, s)
			conn := dialPhoenix(t, s)
			if _, err := conn.Write(tc.flight); err != nil {
				t.Fatalf("write: %v", err)
			}
			waitFor(t, "stream 0 got flight", func() bool { return len(ps.stream(0).got()) == len(tc.flight) })
			if !ps.killStreamCarrier(0) {
				t.Fatal("kill failed")
			}
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Read(make([]byte, 16)); err == nil {
				t.Fatal("read must fail for a non-replayable flight")
			}
			time.Sleep(300 * time.Millisecond)
			if n := ps.streamCount(); n != 1 {
				t.Fatalf("streams = %d, want 1 (no reopen for %s)", n, tc.name)
			}
			if st := s.State(); st.PhoenixReopens != 0 {
				t.Fatalf("reopens = %d, want 0", st.PhoenixReopens)
			}
			conn.Close()
		})
	}
}

// Death AFTER the first byte: no reopen, plain failure.
func TestPhoenixNoReopenAfterFirstByte(t *testing.T) {
	psk := testPSK()
	ps := newPhxServer(t, psk)
	ps.echoOn.Store(true)
	s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
	defer s.Stop()
	establishAll(t, s)

	conn := dialPhoenix(t, s)
	if _, err := conn.Write(getFlight); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := readAll(t, conn, len(getFlight))
	if !bytes.Equal(got, getFlight) {
		t.Fatalf("echo = %q", got)
	}
	if !ps.killStreamCarrier(0) {
		t.Fatal("kill failed")
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("read after post-first-byte death must fail")
	}
	if n := ps.streamCount(); n != 1 {
		t.Fatalf("streams = %d, want 1 (no reopen after first byte)", n)
	}
	conn.Close()
}

// Futility bound: a server that kills every carrier right
// after OPEN — the flow must stop after 2 reopens and fail.
func TestPhoenixReopenCapAgainstInstantKill(t *testing.T) {
	psk := testPSK()
	ps := newPhxServer(t, psk)
	ps.killOnOpen.Store(true)
	s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
	defer s.Stop()
	establishAll(t, s)

	conn := dialPhoenix(t, s)
	if _, err := conn.Write(getFlight); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("read must fail once reopens are exhausted")
	}
	elapsed := time.Since(start)
	// Invariants under a kill-everything server: the reopen cap
	// is respected (never more than 2), at least one reopen was
	// attempted, the failure is terminal inside the
	// establishment window plus dial slack (not unbounded), and
	// the server never saw more than 3 streams for this flow.
	st := s.State()
	if st.PhoenixReopens < 1 || st.PhoenixReopens > 2 {
		t.Fatalf("reopens = %d, want 1..2 (cap respected under churn)", st.PhoenixReopens)
	}
	if n := ps.streamCount(); n > 3 {
		t.Fatalf("server streams = %d, want <= 3", n)
	}
	if elapsed > 25*time.Second {
		t.Fatalf("failure took %v, want bounded by the establishment window", elapsed)
	}
	conn.Close()
}

// Breaker open: no reopen is attempted at all.
func TestPhoenixBreakerOpenBlocksReopen(t *testing.T) {
	psk := testPSK()
	ps := newPhxServer(t, psk)
	s := newTestPoolSession("ws"+ps.srv.URL[4:], psk, 2)
	defer s.Stop()
	establishAll(t, s)
	s.phx.mu.Lock()
	s.phx.openUntil = time.Now().Add(time.Minute)
	s.phx.mu.Unlock()

	conn := dialPhoenix(t, s)
	if _, err := conn.Write(getFlight); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, "stream 0 got flight", func() bool { return len(ps.stream(0).got()) == len(getFlight) })
	if !ps.killStreamCarrier(0) {
		t.Fatal("kill failed")
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(make([]byte, 16)); err == nil {
		t.Fatal("read must fail with the breaker open")
	}
	time.Sleep(300 * time.Millisecond)
	if n := ps.streamCount(); n != 1 {
		t.Fatalf("streams = %d, want 1 (breaker blocked the reopen)", n)
	}
	conn.Close()
}

func TestReplayableFlightTable(t *testing.T) {
	cases := []struct {
		buf  []byte
		want bool
	}{
		{nil, true},
		{[]byte{0x16}, true},
		{[]byte{0x16, 0x03, 0x01}, true},
		{[]byte{0x16, 0x02}, false},
		{[]byte("GET / HTTP/1.1\r\n\r\n"), true},
		{[]byte("HEAD / HTTP/1.1\r\n\r\n"), true},
		{[]byte("PUT /x HTTP/1.1\r\n\r\n"), true},
		{[]byte("DELETE /x HTTP/1.1\r\n\r\n"), true},
		{[]byte("POST /x HTTP/1.1\r\n\r\n"), false},
		{[]byte("PATCH /x HTTP/1.1\r\n\r\n"), false},
		{[]byte("G"), true},   // prefix of GET
		{[]byte("PO"), false}, // prefix of POST only
		{[]byte{0x01, 0x02}, false},
		{[]byte("SSH-2.0-client"), false},
	}
	for i, tc := range cases {
		if got := replayableFlight(tc.buf); got != tc.want {
			t.Errorf("case %d (%q): got %v, want %v", i, tc.buf, got, tc.want)
		}
	}
}

func TestPhoenixBreakerStateMachine(t *testing.T) {
	b := &phoenixBreaker{}
	if !b.allow() {
		t.Fatal("fresh breaker must allow")
	}
	for i := 0; i < phoenixBreakerThreshold; i++ {
		b.noteFastDeath()
	}
	if b.allow() {
		t.Fatal("breaker must be open after threshold fast deaths")
	}
	if b.trips != 1 {
		t.Fatalf("trips = %d, want 1", b.trips)
	}
	b.mu.Lock()
	b.openUntil = time.Now().Add(-time.Second)
	b.mu.Unlock()
	if !b.allow() {
		t.Fatal("breaker must allow again after cooldown")
	}
}

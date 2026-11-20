package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"hollow/tun-helper/internal/ipc"
	"hollow/tun-helper/internal/pump"
)

// testClient drives the server over net.Pipe.
type testClient struct {
	conn   net.Conn
	reader *bufio.Reader
	nextID uint64
}

func newTestClient(t *testing.T, srv *Server) *testClient {
	t.Helper()
	a, b := net.Pipe()
	go srv.ServeConn(b)
	t.Cleanup(func() { a.Close() })
	return &testClient{conn: a, reader: bufio.NewReader(a)}
}

// request sends a frame and returns the reply with the matching ID,
// skipping unsolicited heartbeat frames.
func (c *testClient) request(t *testing.T, verb ipc.Verb, params any) *ipc.Frame {
	t.Helper()
	c.nextID++
	id := c.nextID
	var raw json.RawMessage
	if params != nil {
		raw, _ = json.Marshal(params)
	}
	c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := ipc.WriteFrame(c.conn, &ipc.Frame{ID: id, Verb: verb, Params: raw}); err != nil {
		t.Fatalf("write: %v", err)
	}
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		f, err := ipc.ReadFrame(c.reader)
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if f.Event == "heartbeat" {
			continue
		}
		if f.ID == id {
			return f
		}
	}
}

func testDeps(ep stack.LinkEndpoint) Deps {
	return Deps{
		Elevated: func() bool { return true },
		NewLinkEndpoint: func() (stack.LinkEndpoint, io.Closer, error) {
			return ep, io.NopCloser(nil), nil
		},
		HeartbeatInterval:  25 * time.Millisecond,
		FreshnessThreshold: 400 * time.Millisecond,
	}
}

func TestClosedSetAndModeArbitration(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	srv := New(testDeps(helperEP))
	c := newTestClient(t, srv)

	// Unknown verb: rejected, connection stays usable.
	c.nextID++
	c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	_ = ipc.WriteFrame(c.conn, &ipc.Frame{ID: c.nextID, Verb: "exec"})
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var reply *ipc.Frame
	for {
		f, err := ipc.ReadFrame(c.reader)
		if err != nil {
			t.Fatal(err)
		}
		if f.Event == "heartbeat" {
			continue
		}
		reply = f
		break
	}
	if reply.OK == nil || *reply.OK {
		t.Fatalf("unknown verb must fail: %+v", reply)
	}

	if r := c.request(t, ipc.VerbNoteMode, ipc.NoteModeParams{Mode: ipc.ModeSysproxy}); !*r.OK {
		t.Fatalf("note_mode sysproxy: %+v", r)
	}
	if r := c.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11080}); !*r.OK {
		t.Fatalf("enable_tun: %+v", r)
	}
	if srv.Mode() != ipc.ModeTun {
		t.Fatalf("mode = %s, want tun", srv.Mode())
	}
	// While TUN is active the helper refuses a conflicting note_mode.
	if r := c.request(t, ipc.VerbNoteMode, ipc.NoteModeParams{Mode: ipc.ModeSysproxy}); r.OK != nil && *r.OK {
		t.Fatal("conflicting note_mode during TUN must fail")
	}
	st := c.request(t, ipc.VerbStatus, nil)
	var status Status
	if err := json.Unmarshal(st.Result, &status); err != nil || status.Mode != ipc.ModeTun {
		t.Fatalf("status: %v %+v", err, status)
	}
	if r := c.request(t, ipc.VerbDisableTun, nil); !*r.OK {
		t.Fatalf("disable_tun: %+v", r)
	}
	if srv.Mode() != ipc.ModeOff {
		t.Fatalf("mode after disable = %s", srv.Mode())
	}
}

func TestEnableRequiresElevation(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	d := testDeps(helperEP)
	d.Elevated = func() bool { return false }
	srv := New(d)
	c := newTestClient(t, srv)
	if r := c.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11080}); r.OK != nil && *r.OK {
		t.Fatal("enable without elevation must fail")
	}
	if srv.Mode() != ipc.ModeOff {
		t.Fatal("failed enable must change nothing")
	}
}

func TestDeadManTearsDownSilentPeer(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	srv := New(testDeps(helperEP))
	c := newTestClient(t, srv)
	if r := c.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11080}); !*r.OK {
		t.Fatalf("enable: %+v", r)
	}
	// Go silent: no pings. The watchdog must tear TUN down on its own.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Mode() == ipc.ModeOff {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("dead-man switch did not tear down a silent peer")
}

func TestHeartbeatsFlow(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	srv := New(testDeps(helperEP))
	c := newTestClient(t, srv)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	seen := 0
	for seen < 2 {
		f, err := ipc.ReadFrame(c.reader)
		if err != nil {
			t.Fatal(err)
		}
		if f.Event == "heartbeat" {
			seen++
			if f.Seq == 0 {
				t.Fatal("heartbeat seq must be set")
			}
		}
	}
}

// RF-21-03①: the app DIES (pipe breaks, no graceful close). The
// server-level watchdog must tear TUN down on its own — a
// per-connection watchdog would have died with the connection.
func TestDeadManAfterConnectionLoss(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	srv := New(testDeps(helperEP))
	c := newTestClient(t, srv)
	if r := c.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11080}); !*r.OK {
		t.Fatalf("enable: %+v", r)
	}
	c.conn.Close() // app process death: pipe gone, no more frames ever
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Mode() == ipc.ModeOff {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("TUN survived the app's death — generation watchdog failed")
}

// RF-21-03①: a NEW generation connecting inside the threshold cancels
// the pending teardown; when that generation also dies, teardown follows.
func TestReconnectNewGenerationCancelsTeardown(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	srv := New(testDeps(helperEP))
	c1 := newTestClient(t, srv)
	if r := c1.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11080}); !*r.OK {
		t.Fatalf("enable: %+v", r)
	}
	c1.conn.Close()
	// Reconnect well inside the 400ms threshold and stay active.
	time.Sleep(100 * time.Millisecond)
	c2 := newTestClient(t, srv)
	stop := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(stop) {
		if r := c2.request(t, ipc.VerbPing, nil); !*r.OK {
			t.Fatalf("ping on new generation: %+v", r)
		}
		time.Sleep(80 * time.Millisecond)
	}
	if srv.Mode() != ipc.ModeTun {
		t.Fatal("new generation was torn down despite being alive")
	}
	c2.conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.Mode() == ipc.ModeOff {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("second generation's death did not tear down")
}

// NP-1118-38: the shutdown verb — refused while the takeover is
// up (disable first, so the unwind stays ordered), accepted
// when off, and the exit hook fires only on acceptance.
func TestShutdownVerb(t *testing.T) {
	_, helperEP := pump.NewChannelPair(1280)
	fired := make(chan struct{}, 1)
	deps := testDeps(helperEP)
	deps.Shutdown = func() { fired <- struct{}{} }
	srv := New(deps)
	c := newTestClient(t, srv)

	if r := c.request(t, ipc.VerbEnableTun, ipc.EnableTunParams{SocksPort: 11081}); !*r.OK {
		t.Fatalf("enable_tun: %+v", r)
	}
	if r := c.request(t, ipc.VerbShutdown, nil); r.OK != nil && *r.OK {
		t.Fatal("shutdown during TUN must be refused")
	}
	select {
	case <-fired:
		t.Fatal("shutdown hook fired while TUN was up")
	default:
	}
	if r := c.request(t, ipc.VerbDisableTun, nil); !*r.OK {
		t.Fatalf("disable_tun: %+v", r)
	}
	if r := c.request(t, ipc.VerbShutdown, nil); !*r.OK {
		t.Fatalf("shutdown while off: %+v", r)
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown hook not fired after acceptance")
	}
}

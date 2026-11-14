package pump

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
)

// --- test fixtures ---------------------------------------------------------

// echoServer is a real TCP echo listener (the "internet" target).
func echoServer(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr()
}

// echoDialer stands in for the core-stream dialer: every flow is
// dialed to the echo server regardless of the requested destination
// (the TUN-side destination is an IP on the "internet"; in the test
// rig the echo listener plays that role).
func echoDialer(target net.Addr) FlowDialer {
	return func(ip net.IP, port uint16) (net.Conn, error) {
		return net.Dial("tcp", target.String())
	}
}

// clientStack builds the "LAN side" stack a test application dials from.
func clientStack(t *testing.T, linkEP stack.LinkEndpoint, selfIP string) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        false,
	})
	const nicID = 1
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		t.Fatalf("client nic: %v", err)
	}
	addr := addr4(selfIP)
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("client addr: %v", err)
	}
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFrom("\x00\x00\x00\x00"))
	s.SetRouteTable([]tcpip.Route{{Destination: sn, NIC: nicID}})
	t.Cleanup(s.Close)
	return s
}

func addr4(s string) tcpip.Address {
	var b [4]byte
	copy(b[:], net.ParseIP(s).To4())
	return tcpip.AddrFrom4(b)
}

func dialThrough(t *testing.T, s *stack.Stack, dest string) net.Conn {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(dest)
	p, err := net.LookupPort("tcp", portStr)
	if err != nil {
		t.Fatal(err)
	}
	fa := tcpip.FullAddress{Addr: addr4(host), Port: uint16(p)}
	conn, err := gonet.DialTCP(s, fa, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet dial %s: %v", dest, err)
	}
	return conn
}

func setup(t *testing.T, cfg Config) (*Pump, *stack.Stack) {
	t.Helper()
	echo := echoServer(t)
	cfg.DialFlow = echoDialer(echo)
	clientEP, helperEP := NewChannelPair(1280)
	p, err := NewPump(cfg, helperEP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	cs := clientStack(t, clientEP, "10.99.0.2")
	return p, cs
}

// --- tests -----------------------------------------------------------------

func TestFullChainEchoRoundtrip(t *testing.T) {
	_, cs := setup(t, Config{})
	conn := dialThrough(t, cs, "203.0.113.7:80")
	defer conn.Close()
	msg := []byte("hello through the tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestTableFullRefusesWithReset(t *testing.T) {
	p, cs := setup(t, Config{MaxFlows: 2})
	c1 := dialThrough(t, cs, "203.0.113.7:80")
	defer c1.Close()
	c2 := dialThrough(t, cs, "203.0.113.8:80")
	defer c2.Close()
	deadline := time.Now().Add(3 * time.Second)
	for p.Stats().ActiveFlows < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.Stats().ActiveFlows != 2 {
		t.Fatalf("expected 2 active flows, got %d", p.Stats().ActiveFlows)
	}
	// Third connection must fail (RST at the TUN side), not hang in a queue.
	fa := tcpip.FullAddress{Addr: addr4("203.0.113.9"), Port: 80}
	if _, err := gonet.DialTCP(cs, fa, ipv4.ProtocolNumber); err == nil {
		t.Fatal("third dial unexpectedly succeeded at a full table")
	}
	if p.Stats().RefusedFull < 1 {
		t.Fatalf("refusal not counted: %+v", p.Stats())
	}
}

func TestIdleFlowReaped(t *testing.T) {
	p, cs := setup(t, Config{IdleTimeout: 300 * time.Millisecond})
	conn := dialThrough(t, cs, "203.0.113.7:80")
	defer conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for p.Stats().ActiveFlows < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.Stats().ActiveFlows != 1 {
		t.Fatalf("flow not registered: %+v", p.Stats())
	}
	deadline = time.Now().Add(3 * time.Second)
	for p.Stats().ActiveFlows > 0 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if p.Stats().ActiveFlows != 0 {
		t.Fatalf("idle flow not reaped: %+v", p.Stats())
	}
	// The client side must observe the teardown.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("read on reaped flow unexpectedly succeeded")
	}
}

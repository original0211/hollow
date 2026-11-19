package pump

import (
	"io"
	"net"
	"testing"
	"time"

	"bytes"
	"encoding/binary"
	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
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

// fakeSocks is a minimal no-auth SOCKS5 server standing in for the app's
// loopback SOCKS listener: every CONNECT is dialed to the echo server
// regardless of the requested destination (the TUN-side destination is an
// IP on the "internet"; in the test rig the echo listener plays that role).
func fakeSocks(t *testing.T, target net.Addr) string {
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
			go handleFakeSocks(c, target)
		}
	}()
	return ln.Addr().String()
}

func handleFakeSocks(c net.Conn, target net.Addr) {
	defer c.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(c, buf[:nMethods]); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	switch buf[3] {
	case 0x01:
		io.ReadFull(c, buf[:6])
	case 0x04:
		io.ReadFull(c, buf[:18])
	case 0x03:
		if _, err := io.ReadFull(c, buf[:1]); err == nil {
			io.ReadFull(c, buf[:int(buf[0])+2])
		}
	}
	up, err := net.Dial("tcp", target.String())
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	go io.Copy(up, c)
	io.Copy(c, up)
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
	socksAddr := fakeSocks(t, echo)
	cfg.SocksAddr = socksAddr
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

// --- NP-1118-21: ICMP fast reject for non-carried UDP ----------------------

func csumFold(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildUDP4(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	src, dst := net.ParseIP(srcIP).To4(), net.ParseIP(dstIP).To4()
	udpLen := 8 + len(payload)
	pkt := make([]byte, 20+udpLen)
	pkt[0] = 0x45
	pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))
	pkt[4], pkt[5] = 0x12, 0x34
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], csumFold(pkt[:20]))
	u := pkt[20:]
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
	copy(u[8:], payload)
	pseudo := append(append(append(append([]byte{}, src...), dst...), 0, 17, byte(udpLen>>8), byte(udpLen)), u...)
	binary.BigEndian.PutUint16(u[6:8], csumFold(pseudo))
	return pkt
}

func buildUDP6(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	src, dst := net.ParseIP(srcIP).To16(), net.ParseIP(dstIP).To16()
	udpLen := 8 + len(payload)
	pkt := make([]byte, 40+udpLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = 17
	pkt[7] = 64
	copy(pkt[8:24], src)
	copy(pkt[24:40], dst)
	u := pkt[40:]
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
	copy(u[8:], payload)
	pseudo := append(append([]byte{}, src...), dst...)
	pseudo = append(pseudo, byte(udpLen>>24), byte(udpLen>>16), byte(udpLen>>8), byte(udpLen), 0, 0, 0, 17)
	pseudo = append(pseudo, u...)
	binary.BigEndian.PutUint16(u[6:8], csumFold(pseudo))
	return pkt
}

type rawRig struct {
	ep  *channel.Endpoint
	out chan []byte
}

func newRawRig(t *testing.T, cfg Config) (*Pump, *rawRig) {
	t.Helper()
	ep := channel.New(4096, 1280, "")
	p, err := NewPump(cfg, ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	r := &rawRig{ep: ep, out: make(chan []byte, 4096)}
	go func() {
		for {
			pkt := ep.Read()
			if pkt == nil {
				time.Sleep(time.Millisecond)
				continue
			}
			raw := append([]byte(nil), pkt.ToView().AsSlice()...)
			pkt.DecRef()
			r.out <- raw
		}
	}()
	return p, r
}

func (r *rawRig) inject(proto tcpip.NetworkProtocolNumber, raw []byte) {
	nb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
	r.ep.InjectInbound(proto, nb)
}

func (r *rawRig) next(timeout time.Duration) []byte {
	select {
	case raw := <-r.out:
		return raw
	case <-time.After(timeout):
		return nil
	}
}

func TestICMPRejectV4(t *testing.T) {
	p, rig := newRawRig(t, Config{})
	orig := buildUDP4("10.99.0.2", "93.184.216.34", 53000, 443, []byte("quic-initial"))
	rig.inject(ipv4.ProtocolNumber, orig)
	resp := rig.next(3 * time.Second)
	if resp == nil {
		t.Fatal("no ICMP reject emitted")
	}
	if resp[0]>>4 != 4 || resp[9] != 1 {
		t.Fatalf("not an IPv4/ICMP packet: %v", resp[:10])
	}
	if !net.IP(resp[12:16]).Equal(net.ParseIP("93.184.216.34")) || !net.IP(resp[16:20]).Equal(net.ParseIP("10.99.0.2")) {
		t.Fatalf("ICMP src/dst = %v -> %v", net.IP(resp[12:16]), net.IP(resp[16:20]))
	}
	icmp := resp[20:]
	if icmp[0] != 3 || icmp[1] != 3 {
		t.Fatalf("icmp type/code = %d/%d, want 3/3 (port unreachable)", icmp[0], icmp[1])
	}
	quoted := icmp[8:]
	if len(quoted) < 28 || !bytes.Equal(quoted[:20], orig[:20]) || !bytes.Equal(quoted[20:28], orig[20:28]) {
		t.Fatal("ICMP does not quote the original IP header + 8 bytes")
	}
	st := p.Stats()
	if st.ICMPRejects != 1 || st.DroppedUDP != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestICMPRejectV6(t *testing.T) {
	p, rig := newRawRig(t, Config{})
	orig := buildUDP6("fd00::1", "2606:4700::6810:85e5", 53000, 443, []byte("quic-initial"))
	rig.inject(ipv6.ProtocolNumber, orig)
	resp := rig.next(3 * time.Second)
	if resp == nil {
		t.Fatal("no ICMPv6 reject emitted")
	}
	if resp[0]>>4 != 6 || resp[6] != 58 {
		t.Fatalf("not an IPv6/ICMPv6 packet: %v", resp[:8])
	}
	if !net.IP(resp[8:24]).Equal(net.ParseIP("2606:4700::6810:85e5")) || !net.IP(resp[24:40]).Equal(net.ParseIP("fd00::1")) {
		t.Fatalf("ICMPv6 src/dst wrong: %v -> %v", net.IP(resp[8:24]), net.IP(resp[24:40]))
	}
	icmp := resp[40:]
	if icmp[0] != 1 || icmp[1] != 4 {
		t.Fatalf("icmpv6 type/code = %d/%d, want 1/4 (port unreachable)", icmp[0], icmp[1])
	}
	quoted := icmp[8:]
	if len(quoted) < 48 || !bytes.Equal(quoted[:40], orig[:40]) || !bytes.Equal(quoted[40:48], orig[40:48]) {
		t.Fatal("ICMPv6 does not quote the original IPv6 header + 8 bytes")
	}
	st := p.Stats()
	if st.ICMPRejects != 1 || st.DroppedV6 != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestICMPRejectRateLimit(t *testing.T) {
	p, rig := newRawRig(t, Config{})
	// Same tuple twice, back to back: exactly one reject (cooldown).
	same := buildUDP4("10.99.0.2", "93.184.216.34", 53001, 443, []byte("x"))
	rig.inject(ipv4.ProtocolNumber, same)
	rig.inject(ipv4.ProtocolNumber, same)
	if resp := rig.next(3 * time.Second); resp == nil {
		t.Fatal("first packet of a tuple must be rejected")
	}
	if resp := rig.next(300 * time.Millisecond); resp != nil {
		t.Fatal("second packet of the same tuple inside the cooldown must be silently dropped")
	}
	// Spray of distinct tuples: the global burst caps the rejects.
	for i := 0; i < 200; i++ {
		rig.inject(ipv4.ProtocolNumber, buildUDP4("10.99.0.2", "93.184.216.34", uint16(40000+i), 443, []byte("x")))
	}
	got := 0
	for {
		if resp := rig.next(250 * time.Millisecond); resp == nil {
			break
		}
		got++
	}
	if got < 50 || got > 80 {
		t.Fatalf("burst rejects = %d, want ~64 (burst cap)", got)
	}
	if st := p.Stats(); st.DroppedUDP != 202 {
		t.Fatalf("droppedUDP = %d, want 202 (every non-carried packet counted)", st.DroppedUDP)
	}
}

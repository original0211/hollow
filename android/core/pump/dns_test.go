package pump

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

// End-to-end DNS (T-3): a client stack sends a UDP query to the helper's
// resolver address (10.99.0.1:53); the pump must tunnel it — via the fake
// SOCKS — to the upstream DNS-over-TCP server and relay the answer back.
// A query to a NON-resolver UDP destination is dropped and counted.
func TestDNSThroughTunnel(t *testing.T) {
	// Upstream DNS-over-TCP server.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				for {
					if _, err := io.ReadFull(c, hdr); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(hdr))
					msg := make([]byte, n)
					if _, err := io.ReadFull(c, msg); err != nil {
						return
					}
					msg[2] |= 0x80 // QR
					out := append([]byte{byte(n >> 8), byte(n)}, msg...)
					if _, err := c.Write(out); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	// FlowDialer that forwards to the upstream (stands in for the core).
	clientEP, helperEP := NewChannelPair(1280)
	p, err := NewPump(Config{
		DialFlow:     echoDialer(upLn.Addr()),
		ResolverAddr: upLn.Addr().String(),
		DNSTimeout:   2 * time.Second,
	}, helperEP)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Client stack with a UDP endpoint.
	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		HandleLocal:        false,
	})
	if err := cs.CreateNIC(1, clientEP); err != nil {
		t.Fatal(err)
	}
	cpa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 99, 0, 55}),
			PrefixLen: 24,
		},
	}
	if err := cs.AddProtocolAddress(1, cpa, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	cs.SetRouteTable([]tcpip.Route{{Destination: headerSubnet(), NIC: 1}})

	var wq waiter.Queue
	ep, terr := cs.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatal(terr)
	}
	conn := gonet.NewUDPConn(&wq, ep)
	resolverAddr := &net.UDPAddr{IP: net.ParseIP("10.99.0.1"), Port: 53}

	query := buildDNSQuery(0x1234, "example.com")
	if _, err := conn.WriteTo(query, resolverAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no DNS reply: %v", err)
	}
	resp := buf[:n]
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 || resp[2]&0x80 == 0 {
		t.Fatalf("bad reply: id=%x flags=%08b", binary.BigEndian.Uint16(resp[0:2]), resp[2])
	}
	st := p.Stats()
	if st.DNSResolved != 1 || st.DNSConns != 1 {
		t.Fatalf("pump DNS stats = %+v", st)
	}

	// Non-resolver UDP traffic: dropped + counted, no reply.
	other := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1234}
	if _, err := conn.WriteTo([]byte("hello"), other); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if got := p.Stats().DroppedUDP; got < 1 {
		t.Fatalf("DroppedUDP = %d, want >= 1", got)
	}
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatal("unexpected reply for non-DNS UDP")
	}
}

func buildDNSQuery(id uint16, name string) []byte {
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], id)
	out[2] = 0x01
	binary.BigEndian.PutUint16(out[4:6], 1)
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			out = append(out, byte(i-start))
			out = append(out, name[start:i]...)
			start = i + 1
		}
	}
	out = append(out, 0, 0, 1, 0, 1)
	return out
}

// Fail-closed (notes v2 §4): with the tunnel path dead (the flow
// dialer cannot open streams), a query gets a SERVFAIL reply — never silence that
// invites fallback, and never a leak to a physical resolver.
func TestDNSFailClosedWhenTunnelDown(t *testing.T) {
	// Reserve then release a port so nothing listens on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	deadDialer := func(net.IP, uint16) (net.Conn, error) { return nil, net.ErrClosed }

	clientEP, helperEP := NewChannelPair(1280)
	p, err := NewPump(Config{
		DialFlow:     deadDialer,
		ResolverAddr: "1.1.1.1:53",
		DNSTimeout:   time.Second,
	}, helperEP)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		HandleLocal:        false,
	})
	if err := cs.CreateNIC(1, clientEP); err != nil {
		t.Fatal(err)
	}
	cpa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 99, 0, 55}),
			PrefixLen: 24,
		},
	}
	if err := cs.AddProtocolAddress(1, cpa, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	cs.SetRouteTable([]tcpip.Route{{Destination: headerSubnet(), NIC: 1}})
	var wq waiter.Queue
	ep, terr := cs.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatal(terr)
	}
	conn := gonet.NewUDPConn(&wq, ep)
	resolverAddr := &net.UDPAddr{IP: net.ParseIP("10.99.0.1"), Port: 53}
	if _, err := conn.WriteTo(buildDNSQuery(0x777, "nope.example"), resolverAddr); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("expected a SERVFAIL reply, got silence: %v", err)
	}
	resp := buf[:n]
	if resp[3]&0x0F != 2 {
		t.Fatalf("rcode = %d, want SERVFAIL(2)", resp[3]&0x0F)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x777 {
		t.Fatal("servfail id mismatch")
	}
	if p.Stats().DNSServfail != 1 {
		t.Fatalf("stats = %+v", p.Stats())
	}
}

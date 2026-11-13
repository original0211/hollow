package pump

import (
	"testing"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

// M-17: IPv6 traffic is dropped (no answer) and counted — the phase-1
// fast reject. A v6 client stack dials a v6 destination through the
// channel pair; the dial must NOT succeed, and the pump's DroppedV6
// counter must move.
func TestIPv6DroppedAndCounted(t *testing.T) {
	echo := echoServer(t)
	socksAddr := fakeSocks(t, echo)
	clientEP, helperEP := NewChannelPair(1280)
	p, err := NewPump(Config{SocksAddr: socksAddr}, helperEP)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Client stack, IPv6 only.
	cs := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	if err := cs.CreateNIC(1, clientEP); err != nil {
		t.Fatal(err)
	}
	var a16 [16]byte
	copy(a16[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2})
	pa := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(a16),
			PrefixLen: 64,
		},
	}
	if err := cs.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFrom(string(make([]byte, 16))))
	cs.SetRouteTable([]tcpip.Route{{Destination: sn, NIC: 1}})

	var d16 [16]byte
	copy(d16[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1})
	fa := tcpip.FullAddress{Addr: tcpip.AddrFrom16(d16), Port: 443}
	var wq waiter.Queue
	ep, terr := cs.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if terr != nil {
		t.Fatal(terr)
	}
	defer ep.Close()
	_ = ep.Connect(fa) // SYN leaves; nothing may ever answer it.

	// Give the SYNs (and retransmits) time to hit the pump.
	time.Sleep(1200 * time.Millisecond)
	st := p.Stats()
	if st.DroppedV6 < 1 {
		t.Fatalf("DroppedV6 = %d, want >= 1", st.DroppedV6)
	}
	if st.TotalFlows != 0 {
		t.Fatalf("v6 traffic reached the forwarder: TotalFlows = %d, want 0", st.TotalFlows)
	}
}

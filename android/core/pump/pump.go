// Package pump is the Android TUN data plane: a gVisor netstack
// terminates TCP from the VpnService fd and every flow is spliced to a
// Hollow core stream (opened through the injected FlowDialer). This is
// the Android counterpart of the Windows helper's pump (TUN notes v2
// §0/§2), with the SOCKS hop replaced by direct core streams — on
// Android the core lives in this same process (plan §2/D6).
//
// Flow discipline (notes v2 §2): at most MaxFlows concurrent flows, idle
// flows are reaped after IdleTimeout, and a flow that arrives at a full
// table is refused with a TCP RST — there is deliberately no second queue
// here (the protocol's own queueing lives in the Worker/session layer,
// exactly as in the non-TUN path).
package pump

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"

	"hollow/androidcore/dns"
)

// FlowDialer opens the upstream side of one flow: on Android this
// opens a Hollow core stream to the destination; tests inject direct
// dials. Implementations must honor their own open timeout.
type FlowDialer func(ip net.IP, port uint16) (net.Conn, error)

// Config tunes the pump. Zero values get the production defaults.
type Config struct {
	DialFlow    FlowDialer    // upstream opener for TCP flows and DNS (required)
	MaxFlows    int           // default 512
	IdleTimeout time.Duration // default 120s
	MTU         uint32        // default 1280
	DialTimeout time.Duration // retained for parity with the Windows config (default 10s)
	HelperAddr  string        // adapter's own IPv4 (default 10.99.0.1); the NIC needs an
	HelperAddr6 string        // adapter's own IPv6 (default fd00::1, spec §1.3)
	// assigned address before promiscuous acquisition will deliver
	// foreign-destination packets to the transport layer at all.
	ResolverAddr string        // DNS upstream reached through the tunnel (default 1.1.1.1:53)
	DNSTimeout   time.Duration // per-query DNS timeout (default 5s, notes v2 §4)
}

func (c *Config) withDefaults() {
	if c.MaxFlows <= 0 {
		c.MaxFlows = 512
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 120 * time.Second
	}
	if c.MTU <= 0 {
		c.MTU = 1280
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.HelperAddr == "" {
		c.HelperAddr = "10.99.0.1"
	}
	if c.HelperAddr6 == "" {
		c.HelperAddr6 = "fd00::1"
	}
	if c.ResolverAddr == "" {
		c.ResolverAddr = "1.1.1.1:53"
	}
	if c.DNSTimeout <= 0 {
		c.DNSTimeout = 5 * time.Second
	}
}

type flow struct {
	id       stack.TransportEndpointID
	lastUse  time.Time
	conns    [2]io.Closer
	done     chan struct{}
	closeOne sync.Once
}

func (f *flow) close() {
	f.closeOne.Do(func() {
		close(f.done)
		for _, c := range f.conns {
			if c != nil {
				c.Close()
			}
		}
	})
}

// Stats is a point-in-time snapshot for status reporting.
type Stats struct {
	ActiveFlows int
	TotalFlows  uint64
	RefusedFull uint64
	DroppedUDP  uint64
	DroppedV6   uint64 // IPv6 fast-reject counter (notes v2 §2)
	DNSQueries  uint64
	DNSResolved uint64
	DNSServfail uint64
	DNSConns    uint64 // upstream connections ever made (reuse proof, spec §4)
}

// Pump owns the netstack and the flow table.
type Pump struct {
	cfg   Config
	stack *stack.Stack
	nicID tcpip.NICID

	mu         sync.Mutex
	flows      map[*flow]struct{}
	total      uint64
	refused    uint64
	droppedUDP uint64
	droppedV6  uint64
	resolver   *dns.Resolver

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewPump builds the stack around an arbitrary link endpoint — the
// VpnService fd endpoint in production, a channel endpoint in tests.
func NewPump(cfg Config, linkEP stack.LinkEndpoint) (*Pump, error) {
	cfg.withDefaults()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	p := &Pump{cfg: cfg, stack: s, nicID: 1, flows: make(map[*flow]struct{}), stopCh: make(chan struct{})}
	if err := s.CreateNIC(p.nicID, linkEP); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	// Promiscuous + spoofing: the adapter terminates traffic for ANY
	// destination address (that's what a default-route TUN means).
	if err := s.SetPromiscuousMode(p.nicID, true); err != nil {
		return nil, fmt.Errorf("promiscuous: %v", err)
	}
	if err := s.SetSpoofing(p.nicID, true); err != nil {
		return nil, fmt.Errorf("spoofing: %v", err)
	}
	// The NIC must own at least one address: gVisor's IPv4 layer only
	// delivers foreign-destination packets locally when promiscuous
	// acquisition can anchor them to an assigned address (without one,
	// SYNs are dropped as invalid destinations before any transport
	// handler runs — verified empirically in NP-1114-19).
	var hb [4]byte
	copy(hb[:], net.ParseIP(p.cfg.HelperAddr).To4())
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(hb),
			PrefixLen: 32,
		},
	}
	if err := s.AddProtocolAddress(p.nicID, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("helper address: %v", err)
	}
	// IPv6 anchor address (spec §1.3): fd00::1 exists so promiscuous
	// acquisition can deliver v6 packets to the transport handlers below,
	// where they are counted and dropped (phase-1 fast reject, notes v2
	// §2). v6 is never proxied in phase 1.
	var hb6 [16]byte
	copy(hb6[:], net.ParseIP(p.cfg.HelperAddr6).To16())
	pa6 := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(hb6),
			PrefixLen: 128,
		},
	}
	if err := s.AddProtocolAddress(p.nicID, pa6, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("helper address6: %v", err)
	}
	// Catch-all routes so replies (v4) find their way back out.
	s.SetRouteTable([]tcpip.Route{
		{Destination: headerSubnet(), NIC: p.nicID},
		{Destination: headerSubnet6(), NIC: p.nicID},
	})
	fwd := tcp.NewForwarder(s, 0, 4096, p.handleRequest)
	isV6 := func(id stack.TransportEndpointID) bool { return len(id.LocalAddress.AsSlice()) == 16 }
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if isV6(id) {
			atomic.AddUint64(&p.droppedV6, 1)
			return true // consumed, no answer: fast reject (SYNs time out)
		}
		return fwd.HandlePacket(id, pkt)
	})
	// UDP disposition (notes v2 §4/§5): packets to the resolver address
	// (adapter IP, port 53) become DNS sessions tunnelled through the core;
	// everything else — and all of IPv6 — is dropped and counted. The DNS
	// resolver has no path around the tunnel (fail-closed by construction).
	p.resolver = dns.NewResolver(p.dnsDialer(), cfg.DNSTimeout)
	udpFwd := udp.NewForwarder(s, p.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	p.wg.Add(1)
	go p.sweeper()
	return p, nil
}

func headerSubnet() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFrom("\x00\x00\x00\x00"))
	return sn
}

func headerSubnet6() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFrom(string(make([]byte, 16))))
	return sn
}

// dnsDialer adapts the resolver's upstream dial to the flow dialer: the
// DNS connection itself travels inside the Hollow tunnel, as a core
// stream to the resolver address (plan §2: DialFunc = core direct stream).
func (p *Pump) dnsDialer() dns.DialFunc {
	return func() (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(p.cfg.ResolverAddr)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("resolver addr %q is not an IP", p.cfg.ResolverAddr)
		}
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			return nil, err
		}
		if p.cfg.DialFlow == nil {
			return nil, fmt.Errorf("pump: no DialFlow configured")
		}
		return p.cfg.DialFlow(ip, uint16(port))
	}
}

// handleUDP is the UDP forwarder entry: DNS-to-resolver sessions are
// created; every other datagram is dropped + counted (no endpoint is
// created for it, which IS the drop).
func (p *Pump) handleUDP(req *udp.ForwarderRequest) bool {
	id := req.ID()
	if len(id.LocalAddress.AsSlice()) == 16 {
		atomic.AddUint64(&p.droppedV6, 1)
		return true
	}
	if id.LocalPort != 53 || id.LocalAddress != tcpip.AddrFrom4Slice(net.ParseIP(p.cfg.HelperAddr).To4()) {
		atomic.AddUint64(&p.droppedUDP, 1)
		return true
	}
	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		atomic.AddUint64(&p.droppedUDP, 1)
		return true
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.serveDNSSession(gonet.NewUDPConn(&wq, ep))
	}()
	return true
}

// serveDNSSession pumps datagrams between one client source and the
// resolver. Exchanges run concurrently (a slow upstream must not head-of-
// line block the source); session writes are serialized.
func (p *Pump) serveDNSSession(conn *gonet.UDPConn) {
	defer conn.Close()
	var writeMu sync.Mutex
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return // idle for 60s or stack closing
		}
		query := append([]byte(nil), buf[:n]...)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			resp := p.resolver.Exchange(query)
			writeMu.Lock()
			_, _ = conn.Write(resp)
			writeMu.Unlock()
		}()
	}
}

// NewChannelPair returns two channel endpoints wired to each other for
// tests: copier goroutines move each endpoint's outbound queue into the
// other's inbound path (a channel endpoint's written packets sit in its
// queue until Read; InjectInbound is the inbound door — the pair replaces
// a wire). Test scaffolding only; production uses the Wintun endpoint.
func NewChannelPair(mtu uint32) (*channel.Endpoint, *channel.Endpoint) {
	a := channel.New(1024, mtu, "")
	b := channel.New(1024, mtu, "")
	go copyPackets(a, b)
	go copyPackets(b, a)
	return a, b
}

func copyPackets(src, dst *channel.Endpoint) {
	for {
		pkt := src.Read()
		if pkt == nil {
			runtime.Gosched()
			continue
		}
		// An outbound PacketBuffer cannot be re-injected as-is: its header
		// bookkeeping fails the receiver's parse (MalformedPacketsReceived).
		// Round-trip through bytes, exactly like a real wire would.
		proto := pkt.NetworkProtocolNumber
		raw := append([]byte(nil), pkt.ToView().AsSlice()...)
		pkt.DecRef()
		nb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(raw)})
		dst.InjectInbound(proto, nb)
	}
}

// handleRequest runs per inbound TCP connection attempt from the stack.
func (p *Pump) handleRequest(req *tcp.ForwarderRequest) {
	id := req.ID()
	p.mu.Lock()
	if len(p.flows) >= p.cfg.MaxFlows {
		p.refused++
		p.mu.Unlock()
		req.Complete(true) // RST: no queueing at this layer, by design
		return
	}
	p.mu.Unlock()

	var wq waiter.Queue
	ep, terr := req.CreateEndpoint(&wq)
	if terr != nil {
		req.Complete(true)
		return
	}
	req.Complete(false)
	tunConn := gonet.NewTCPConn(&wq, ep)

	destIP := net.IP(id.LocalAddress.AsSlice())
	destPort := id.LocalPort
	if p.cfg.DialFlow == nil {
		tunConn.Close()
		return
	}
	socksConn, err := p.cfg.DialFlow(destIP, destPort)
	if err != nil {
		tunConn.Close()
		return
	}

	f := &flow{id: id, lastUse: time.Now(), done: make(chan struct{})}
	f.conns = [2]io.Closer{tunConn, socksConn}
	p.mu.Lock()
	p.flows[f] = struct{}{}
	p.total++
	p.mu.Unlock()

	p.wg.Add(2)
	go p.splice(f, socksConn, tunConn)
	go p.splice(f, tunConn, socksConn)
	go func() {
		<-f.done
		p.mu.Lock()
		delete(p.flows, f)
		p.mu.Unlock()
	}()
}

// splice copies bytes one way, refreshing the flow's activity stamp; any
// error or EOF tears the whole flow down.
func (p *Pump) splice(f *flow, dst io.Writer, src io.Reader) {
	defer p.wg.Done()
	defer f.close()
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			p.mu.Lock()
			f.lastUse = time.Now()
			p.mu.Unlock()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// sweeper reaps flows idle beyond IdleTimeout.
func (p *Pump) sweeper() {
	defer p.wg.Done()
	t := time.NewTicker(p.cfg.IdleTimeout / 4)
	defer t.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case now := <-t.C:
			p.mu.Lock()
			var stale []*flow
			for f := range p.flows {
				if now.Sub(f.lastUse) > p.cfg.IdleTimeout {
					stale = append(stale, f)
				}
			}
			p.mu.Unlock()
			for _, f := range stale {
				f.close()
			}
		}
	}
}

// Stats snapshots the counters.
func (p *Pump) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := Stats{ActiveFlows: len(p.flows), TotalFlows: p.total, RefusedFull: p.refused, DroppedUDP: atomic.LoadUint64(&p.droppedUDP), DroppedV6: atomic.LoadUint64(&p.droppedV6)}
	if p.resolver != nil {
		ds := p.resolver.Stats()
		st.DNSQueries, st.DNSResolved, st.DNSServfail, st.DNSConns = ds.Queries, ds.Resolved, ds.Servfail, ds.UpstreamConns
	}
	return st
}

// Close tears down all flows and the stack.
func (p *Pump) Close() {
	if p.resolver != nil {
		p.resolver.Close()
	}
	close(p.stopCh)
	p.mu.Lock()
	all := make([]*flow, 0, len(p.flows))
	for f := range p.flows {
		all = append(all, f)
	}
	p.mu.Unlock()
	for _, f := range all {
		f.close()
	}
	p.stack.Close()
	p.wg.Wait()
}

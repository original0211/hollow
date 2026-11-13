// Package pump is the TUN data plane: a gVisor netstack terminates TCP
// from the virtual adapter and every flow is spliced to a SOCKS5 CONNECT
// into the Hollow app's existing loopback listener. The helper has ZERO
// knowledge of the Hollow protocol — it moves bytes only (TUN notes v2 §0/§2).
//
// Flow discipline (notes v2 §2): at most MaxFlows concurrent flows, idle
// flows are reaped after IdleTimeout, and a flow that arrives at a full
// table is refused with a TCP RST — there is deliberately no second queue
// here (the protocol's own queueing lives behind the SOCKS port, in the
// Worker/session layer, exactly as in the non-TUN path).
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
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

// Config tunes the pump. Zero values get the production defaults.
type Config struct {
	SocksAddr   string        // app loopback SOCKS listener, e.g. 127.0.0.1:1080
	MaxFlows    int           // default 512
	IdleTimeout time.Duration // default 120s
	MTU         uint32        // default 1280
	DialTimeout time.Duration // SOCKS connect timeout, default 10s
	HelperAddr  string        // adapter's own IPv4 (default 10.99.0.1); the NIC needs an
	// assigned address before promiscuous acquisition will deliver
	// foreign-destination packets to the transport layer at all.
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

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewPump builds the stack around an arbitrary link endpoint — the Wintun
// endpoint in production, a channel endpoint in tests.
func NewPump(cfg Config, linkEP stack.LinkEndpoint) (*Pump, error) {
	cfg.withDefaults()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
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
	// A catch-all route so replies find their way back out.
	s.SetRouteTable([]tcpip.Route{{Destination: headerSubnet(), NIC: p.nicID}})
	fwd := tcp.NewForwarder(s, 0, 4096, p.handleRequest)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	// UDP phase-1 disposition (notes v2 §5): non-DNS UDP is dropped and
	// counted; DNS handling arrives with T-3. Registering a counting
	// handler makes the drop visible instead of silent.
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		atomic.AddUint64(&p.droppedUDP, 1)
		return true
	})
	p.wg.Add(1)
	go p.sweeper()
	return p, nil
}

func headerSubnet() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFrom("\x00\x00\x00\x00"))
	return sn
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
	socksConn, err := socks5Connect(p.cfg.SocksAddr, destIP, destPort, p.cfg.DialTimeout)
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
	return Stats{ActiveFlows: len(p.flows), TotalFlows: p.total, RefusedFull: p.refused, DroppedUDP: atomic.LoadUint64(&p.droppedUDP)}
}

// Close tears down all flows and the stack.
func (p *Pump) Close() {
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

//go:build windows

package tun

import (
	"errors"
	"fmt"
	"sync"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// AdapterName is the Wintun adapter's display name.
const AdapterName = "Hollow"

// Endpoint is a gVisor link endpoint backed by a Wintun session.
// It follows the same shape as wireguard-go's netstack endpoint.
type Endpoint struct {
	mu         sync.Mutex
	dispatcher stack.NetworkDispatcher
	session    wintun.Session
	adapter    *wintun.Adapter
	mtu        uint32
	done       chan struct{}
	closeOnce  sync.Once
	onClose    func()
}

var errClosed = errors.New("tun endpoint closed")

// OpenEndpoint verifies the pinned DLL next to the executable, pins the
// DLL search directory to the executable directory (§9: no search-order
// hijack), then creates the adapter and starts a session.
func OpenEndpoint(exeDir string, mtu uint32) (*Endpoint, error) {
	dllPath := exeDir + `\wintun.dll`
	if err := VerifyDLLFile(dllPath); err != nil {
		return nil, err
	}
	if err := windows.SetDllDirectory(exeDir); err != nil {
		return nil, fmt.Errorf("pin dll directory: %w", err)
	}
	adapter, err := wintun.CreateAdapter(AdapterName, "Hollow", nil)
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w", err)
	}
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}
	if mtu == 0 {
		mtu = 1280
	}
	return &Endpoint{session: session, adapter: adapter, mtu: mtu, done: make(chan struct{})}, nil
}

func (e *Endpoint) readLoop() {
	for {
		select {
		case <-e.done:
			return
		default:
		}
		packet, err := e.session.ReceivePacket()
		if err != nil {
			// No packet ready: wait on the read event, then retry.
			h := e.session.ReadWaitEvent()
			timeout := uint32(250)
			_, _ = windows.WaitForSingleObject(h, timeout)
			select {
			case <-e.done:
				return
			default:
				continue
			}
		}
		data := make([]byte, len(packet))
		copy(data, packet)
		e.session.ReleaseReceivePacket(packet)
		e.mu.Lock()
		d := e.dispatcher
		e.mu.Unlock()
		if d == nil {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		d.DeliverNetworkPacket(protocolOf(data), pkt)
		pkt.DecRef()
	}
}

func protocolOf(data []byte) tcpip.NetworkProtocolNumber {
	if len(data) == 0 {
		return header.IPv4ProtocolNumber
	}
	switch data[0] >> 4 {
	case 6:
		return header.IPv6ProtocolNumber
	default:
		return header.IPv4ProtocolNumber
	}
}

// --- stack.LinkEndpoint ---

func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	e.dispatcher = dispatcher
	e.mu.Unlock()
	if dispatcher != nil {
		go e.readLoop()
	}
}

func (e *Endpoint) IsAttached() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dispatcher != nil
}

func (e *Endpoint) MTU() uint32 { return e.mtu }

func (e *Endpoint) SetMTU(mtu uint32) { e.mtu = mtu }

func (e *Endpoint) MaxHeaderLength() uint16 { return 0 }

func (e *Endpoint) LinkAddress() tcpip.LinkAddress { return "" }

func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }

func (e *Endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }

func (e *Endpoint) AddHeader(pkt *stack.PacketBuffer) {}

func (e *Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return true }

func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		data := pkt.ToView().AsSlice()
		buf, err := e.session.AllocateSendPacket(len(data))
		if err != nil {
			return n, &tcpip.ErrAborted{}
		}
		copy(buf, data)
		e.session.SendPacket(buf)
		n++
	}
	return n, nil
}

func (e *Endpoint) Wait() {}

func (e *Endpoint) SetOnCloseAction(action func()) { e.onClose = action }

// Close implements stack.LinkEndpoint (the pump also closes it via the
// server's io.Closer adapter in the cmd wiring).
func (e *Endpoint) Close() {
	e.closeOnce.Do(func() {
		close(e.done)
		e.session.End()
		_ = e.adapter.Close()
		if e.onClose != nil {
			e.onClose()
		}
	})
}

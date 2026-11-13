//go:build !windows

package tun

import (
	"errors"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

// OpenEndpoint on non-Windows platforms: the helper is Windows-only; the
// portable core (server/pump/ipc) is what CI exercises elsewhere.
func OpenEndpoint(exeDir string, mtu uint32) (stack.LinkEndpoint, error) {
	return nil, errors.New("wintun endpoint is windows-only")
}

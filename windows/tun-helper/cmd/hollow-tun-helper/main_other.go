//go:build !windows

package main

import (
	"errors"
	"io"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

// The helper binary targets Windows. These stubs let the module build and
// vet cleanly on dev/CI machines; the portable core is fully tested there.
func currentUserSID() (string, error) { return "", errors.New("windows-only") }

func isElevated() bool { return false }

func platformLinkFactory() func() (stack.LinkEndpoint, io.Closer, error) {
	return func() (stack.LinkEndpoint, io.Closer, error) {
		return nil, nil, errors.New("wintun endpoint is windows-only")
	}
}

//go:build !windows

package pipe

import (
	"errors"
	"net"
)

// Listen is Windows-only; on dev machines the server core is tested
// in-process over net.Pipe instead.
func Listen(userSID string) (net.Listener, error) {
	return nil, errors.New("named pipes are windows-only")
}

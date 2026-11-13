//go:build windows

// Package pipe (Windows implementation): the pipe ACL is restricted to
// LocalSystem and the owning user's SID (TUN notes v2 §9: no other local
// user may impersonate the app and drive the helper).
package pipe

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// Listen opens the pipe for the given user SID.
func Listen(userSID string) (net.Listener, error) {
	sddl := fmt.Sprintf("D:P(A;;GA;;;SY)(A;;GA;;;%s)", userSID)
	ln, err := winio.ListenPipe(PipeName, &winio.PipeConfig{
		SecurityDescriptor: sddl,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	})
	if err != nil {
		return nil, fmt.Errorf("listen pipe (owner-only ACL): %w", err)
	}
	return ln, nil
}

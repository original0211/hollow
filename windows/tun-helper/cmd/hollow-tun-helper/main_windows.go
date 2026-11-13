//go:build windows

package main

import (
	"io"

	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"golang.org/x/sys/windows"
	"hollow/tun-helper/internal/tun"
)

func currentUserSID() (string, error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return "", err
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func platformLinkFactory() func() (stack.LinkEndpoint, io.Closer, error) {
	return func() (stack.LinkEndpoint, io.Closer, error) {
		ep, err := tun.OpenEndpoint(exeDir(), 1280)
		if err != nil {
			return nil, nil, err
		}
		return ep, closerFunc(ep.Close), nil
	}
}

type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }

var _ stack.LinkEndpoint = (*tun.Endpoint)(nil)

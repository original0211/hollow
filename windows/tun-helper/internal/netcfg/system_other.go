//go:build !windows

package netcfg

import "errors"

// NewSystem is Windows-only; tests inject a fake System instead.
func NewSystem() (System, error) {
	return nil, errors.New("netcfg system adapter is Windows-only")
}

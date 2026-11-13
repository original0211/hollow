//go:build windows

package clock

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procQueryUnbiasedInterruptTime = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueryUnbiasedInterruptTime")

// platformNowMs uses QueryUnbiasedInterruptTime (100ns units, excludes
// sleep/hibernate) — the Windows time source that matches the spec's
// "deduct sleep" requirement.
func platformNowMs() int64 {
	var ticks uint64 // in 100ns units
	r, _, _ := procQueryUnbiasedInterruptTime.Call(uintptr(unsafe.Pointer(&ticks)))
	if r == 0 {
		// Extremely defensive fallback: process monotonic (includes sleep).
		return fallbackMs()
	}
	return int64(ticks / 10000)
}

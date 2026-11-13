//go:build !windows

package clock

// platformNowMs on non-Windows platforms (dev/CI only): process monotonic.
func platformNowMs() int64 { return fallbackMs() }

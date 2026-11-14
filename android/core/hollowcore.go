// Package hollowcore is the Android binding seam for the Hollow core.
//
// M3-0 scope: a minimal placeholder API proving the gomobile pathway
// (Go module -> AAR -> Kotlin call). The protocol core port lands in
// M3-1 behind this same seam; nothing here is protocol code yet.
package hollowcore

// Version returns the core library identifier the shell displays on its
// status placeholder — if this string renders on device, the whole
// gomobile chain (bind, AAR packaging, JNI) is alive.
func Version() string {
	return "hollowcore 0.2.0 (M3-1 core)"
}

// Echo round-trips a string across the binding boundary (both
// directions marshalled), the cheapest end-to-end seam check.
func Echo(s string) string {
	return "echo:" + s
}

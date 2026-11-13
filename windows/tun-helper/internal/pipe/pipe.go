// Package pipe hosts the helper's named-pipe listener (Windows) and its
// well-known name.
package pipe

// PipeName is the well-known pipe the app connects to.
const PipeName = `\\.\pipe\hollow-tun-helper`

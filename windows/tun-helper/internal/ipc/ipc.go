// Package ipc defines the fixed-verb protocol between the Hollow app
// (unprivileged) and the TUN helper (elevated), carried over a named pipe.
//
// Design rules (TUN notes v2 §9, red-team construction cautions):
//   - The verb set is FIXED and closed: enable_tun, disable_tun, note_mode,
//     status, restore, ping. There is deliberately no generic command or
//     config passthrough; an unknown verb is an error, never a fallback.
//   - Frames are newline-delimited JSON, size-capped.
//   - The helper emits unsolicited heartbeat frames; liveness is judged by
//     heartbeat FRESHNESS on a monotonic, sleep-excluded clock — never by
//     process existence (notes v2 §6, mandatory change D).
package ipc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Verb is a control verb in the closed command set.
type Verb string

const (
	VerbEnableTun  Verb = "enable_tun"
	VerbDisableTun Verb = "disable_tun"
	VerbNoteMode   Verb = "note_mode"
	VerbStatus     Verb = "status"
	VerbRestore    Verb = "restore"
	VerbPing       Verb = "ping"
)

// Mode is the app-wide proxy mode the helper arbitrates for mutual
// exclusion: exactly one of off / sysproxy / tun is active at a time.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeSysproxy Mode = "sysproxy"
	ModeTun      Mode = "tun"
)

func (m Mode) Valid() bool {
	return m == ModeOff || m == ModeSysproxy || m == ModeTun
}

// Frame is one protocol message. Requests carry ID + Verb; responses echo
// the ID with OK/Error (and Result for status); heartbeats and events are
// unsolicited (ID 0).
type Frame struct {
	ID     uint64          `json:"id,omitempty"`
	Verb   Verb            `json:"verb,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	OK     *bool           `json:"ok,omitempty"`
	Error  string          `json:"error,omitempty"`
	Event  string          `json:"event,omitempty"`
	Seq    uint64          `json:"seq,omitempty"`      // heartbeat sequence
	Uptime int64           `json:"uptimeMs,omitempty"` // sender monotonic uptime, diagnostics only
}

const MaxFrameBytes = 64 * 1024

var knownVerbs = map[Verb]bool{
	VerbEnableTun: true, VerbDisableTun: true, VerbNoteMode: true,
	VerbStatus: true, VerbRestore: true, VerbPing: true,
}

// ValidateRequest enforces the closed verb set and per-verb invariants.
func (f *Frame) ValidateRequest() error {
	if !knownVerbs[f.Verb] {
		return fmt.Errorf("unknown verb %q (the command set is closed)", string(f.Verb))
	}
	switch f.Verb {
	case VerbNoteMode:
		var p NoteModeParams
		if err := json.Unmarshal(f.Params, &p); err != nil {
			return fmt.Errorf("note_mode params: %w", err)
		}
		if !p.Mode.Valid() {
			return fmt.Errorf("note_mode: invalid mode %q", string(p.Mode))
		}
	case VerbEnableTun:
		var p EnableTunParams
		if err := json.Unmarshal(f.Params, &p); err != nil {
			return fmt.Errorf("enable_tun params: %w", err)
		}
		if p.SocksPort < 1 || p.SocksPort > 65535 {
			return fmt.Errorf("enable_tun: socks port out of range")
		}
	}
	return nil
}

// EnableTunParams are the only parameters enable_tun accepts.
type EnableTunParams struct {
	SocksPort int `json:"socksPort"`
}

// NoteModeParams are the only parameters note_mode accepts.
type NoteModeParams struct {
	Mode Mode `json:"mode"`
}

// WriteFrame serializes one frame as a JSON line.
func WriteFrame(w io.Writer, f *Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > MaxFrameBytes {
		return errors.New("frame too large")
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// ReadFrame reads one JSON line, enforcing the size cap.
func ReadFrame(r *bufio.Reader) (*Frame, error) {
	line, err := r.ReadBytes('\n')
	if len(line) > MaxFrameBytes {
		return nil, errors.New("frame too large")
	}
	if err != nil {
		return nil, err
	}
	line = []byte(strings.TrimSpace(string(line)))
	if len(line) == 0 {
		return nil, errors.New("empty frame")
	}
	var f Frame
	if err := json.Unmarshal(line, &f); err != nil {
		return nil, fmt.Errorf("malformed frame: %w", err)
	}
	return &f, nil
}

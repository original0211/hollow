// Package ipc defines the fixed-verb protocol between the Hollow app
// (unprivileged) and the TUN helper (elevated), carried over a named pipe.
//
// Design rules (TUN notes v2 §9, red-team construction cautions):
//   - The verb set is FIXED and closed: enable_tun, disable_tun, note_mode,
//     status, restore, ping, set_exclusions (T-2: the candidate/exclusion
//     set refresh — still a single-purpose verb, no passthrough).
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
	"net/netip"
	"strings"
)

// Verb is a control verb in the closed command set.
type Verb string

const (
	VerbEnableTun     Verb = "enable_tun"
	VerbSetExclusions Verb = "set_exclusions"
	VerbDisableTun    Verb = "disable_tun"
	VerbNoteMode      Verb = "note_mode"
	VerbStatus        Verb = "status"
	VerbRestore       Verb = "restore"
	VerbPing          Verb = "ping"
	VerbShutdown      Verb = "shutdown"
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
	VerbStatus: true, VerbRestore: true, VerbPing: true, VerbSetExclusions: true,
	VerbShutdown: true,
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
		if err := validateIPs(p.Exclusions); err != nil {
			return fmt.Errorf("enable_tun: %w", err)
		}
	case VerbSetExclusions:
		var p SetExclusionsParams
		if err := json.Unmarshal(f.Params, &p); err != nil {
			return fmt.Errorf("set_exclusions params: %w", err)
		}
		if err := validateIPs(p.IPs); err != nil {
			return fmt.Errorf("set_exclusions: %w", err)
		}
	}
	return nil
}

func validateIPs(ips []string) error {
	if len(ips) > 64 {
		return fmt.Errorf("too many exclusions (%d > 64)", len(ips))
	}
	for _, s := range ips {
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("invalid ip %q", s)
		}
	}
	return nil
}

// EnableTunParams are the only parameters enable_tun accepts.
// Exclusions is the bearer candidate set (candidate set = exclusion set,
// one ledger); each entry gets a /32 (v6: /128) host route via the
// physical gateway before the takeover routes go in.
type EnableTunParams struct {
	SocksPort  int      `json:"socksPort"`
	Exclusions []string `json:"exclusions,omitempty"`
}

// SetExclusionsParams are the only parameters set_exclusions accepts:
// the runtime refresh of the candidate/exclusion set while TUN is up
// (add-before-delete, self-heal spec R5).
type SetExclusionsParams struct {
	IPs []string `json:"ips"`
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

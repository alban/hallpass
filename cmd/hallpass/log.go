// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/alban/hallpass/internal/monitor"
)

// logEntry is one line of --log.
type logEntry struct {
	Time     string `json:"time"`
	PID      uint32 `json:"pid"`
	Exe      string `json:"exe,omitempty"`
	Syscall  string `json:"syscall"`
	Path     string `json:"path,omitempty"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// logEvents writes the decided accesses to w until evs is closed, then
// closes done. audit: the asker allows everything (--ask=allow).
func logEvents(evs <-chan []monitor.Event, w io.Writer, audit bool, done chan<- struct{}) {
	defer close(done)
	enc := json.NewEncoder(w)
	for batch := range evs {
		for _, ev := range batch {
			if ev.Decided != nil {
				_ = enc.Encode(decidedEntry(ev.Decided, audit))
			}
		}
	}
}

func decidedEntry(d *monitor.Decided, audit bool) logEntry {
	e := logEntry{Time: d.Time.Format(time.RFC3339Nano), Syscall: d.Syscall, Decision: "deny"}
	if d.Allowed {
		e.Decision = "allow"
	}
	if ch := d.Subject.Chain; len(ch) > 0 {
		e.PID, e.Exe = uint32(ch[0].TID), ch[0].Exe
		if d.Source == monitor.SourceLSM {
			e.Exe = ch[0].Comm
		}
	}
	if d.Source == monitor.SourceLSM {
		e.Reason = "lsm"
		if len(d.Objects) > 0 && d.Objects[0].Path != nil {
			e.Path = d.Objects[0].Path.Path
		}
		return e
	}

	asked, unknown, restarted := false, false, false
	for i, why := range d.Why {
		switch why.Builtin {
		case "bpf":
			e.Decision, e.Reason = "continue", "lsm: other mount namespace or unreadable path"
			return e
		case "unresolvable":
			e.Reason = "unresolvable path"
		case "restarted":
			asked, restarted = true, true
		}
		if why.Client != "" {
			asked = true
		}
		if i < len(d.Objects) && d.Objects[i].Unknown != nil && why != (monitor.Reason{}) {
			unknown = true
		}
	}
	// The path: the last one allowed, or the denied one.
	for i, o := range d.Objects {
		if !d.Allowed && (i >= len(d.Why) || d.Why[i] == (monitor.Reason{})) {
			continue
		}
		switch {
		case o.Path != nil:
			e.Path = o.Path.Path
		case o.Proc != nil:
			e.Path = procPath(o.Proc)
		default:
			e.Path = ""
		}
	}
	if e.Reason != "" {
		return e
	}
	e.Reason = "policy"
	if asked {
		e.Reason = "user"
		if audit {
			e.Reason = "audit" // would have been asked
		}
		if unknown {
			e.Reason += ": unknown path"
		}
		if restarted {
			e.Reason += ": restarted"
		}
	}
	return e
}

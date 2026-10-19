// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/alban/hallpass/internal/answer"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
)

// logEntry is one line of --log.
type logEntry struct {
	Time     string `json:"time"`
	PID      uint32 `json:"pid"`
	Exe      string `json:"exe,omitempty"`
	Syscall  string `json:"syscall"`
	Path     string `json:"path,omitempty"`
	Net      string `json:"net,omitempty"` // e.g. "tcp 127.0.0.1:80", "unix @name"
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// logEvents writes the decided accesses to w until evs is closed, then
// closes done. audit: the asker allows everything (--prompt=allow).
func logEvents(evs <-chan []monitor.Event, w io.Writer, audit bool, done chan<- struct{}) {
	defer close(done)
	enc := json.NewEncoder(w)
	for batch := range evs {
		for _, ev := range batch {
			if ev.Decided != nil && !isExec(ev.Decided) {
				_ = enc.Encode(decidedEntry(ev.Decided, audit))
			}
		}
	}
}

// isExec reports an exec, always continued: not logged until exec is
// mediated.
func isExec(d *monitor.Decided) bool {
	return len(d.Why) == 1 && d.Why[0].Builtin == "execve"
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
		if len(d.Objects) > 0 {
			o := d.Objects[0]
			if o.Path != nil {
				e.Path = o.Path.Path
			}
			e.Net = netName(o)
		}
		return e
	}

	asked, unknown, restarted, retried := false, false, false, false
	for i, why := range d.Why {
		switch why.Builtin {
		case "bpf":
			e.Decision, e.Reason = "continue", "lsm: other mount namespace or unreadable path"
			return e
		case "unresolvable":
			e.Reason = "unresolvable path"
		case "exec-retry":
			asked, retried = true, true
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
			e.Path = answer.ProcPath(o.Proc)
		default:
			e.Path = ""
		}
		e.Net = netName(o)
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
		if retried {
			e.Reason += ": denied just before"
		}
	}
	return e
}

// netName shows a network destination, "" for other objects.
func netName(o rules.Object) string {
	switch {
	case o.Inet != nil:
		return o.Inet.String()
	case o.Unix != nil:
		return o.Unix.String()
	}
	return ""
}

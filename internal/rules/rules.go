// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules holds the monitor's rule model and its evaluation. It is
// pure: no I/O and no clock, the time is a parameter. See
// docs/devel/monitor.md.
package rules

import (
	"path/filepath"
	"strings"
	"time"
)

// Op is a set of operations, so that a rule can carry several.
type Op uint32

const (
	OpWrite  Op = 1 << iota // open for write (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC)
	OpCreate                // mknod, open O_CREAT of a new file
	OpMkdir
	OpSymlink
	OpDelete // unlink, rmdir
	OpLink   // both objects: source and new name
	OpRename // both objects: old and new name
	OpTruncate

	OpAll = OpTruncate<<1 - 1
)

// String names op for people, the way prompts show it: "write", "create
// directory", ... An open with O_CREAT reports OpWrite|OpCreate and is a
// "write".
func (op Op) String() string {
	switch {
	case op&OpWrite != 0:
		return "write"
	case op&OpCreate != 0:
		return "create"
	case op&OpMkdir != 0:
		return "create directory"
	case op&OpSymlink != 0:
		return "create symlink"
	case op&OpDelete != 0:
		return "delete"
	case op&OpLink != 0:
		return "link"
	case op&OpRename != 0:
		return "rename"
	case op&OpTruncate != 0:
		return "truncate"
	}
	return "?"
}

// Object is what an access is to. Exactly one field is set.
type Object struct {
	Path *PathObject
	Proc *ProcObject
	// Unknown is set in lite mode when the path could not be read.
	Unknown error
}

// PathObject is a file.
type PathObject struct {
	Path string // absolute, symlink-resolved (lexical past the first missing component)
	Dev  uint64 // of the existing part; 0 when unknown (lite)
	Ino  uint64
}

// ProcObject is a write to another process's /proc/<pid>/<Name>, for a
// target outside the workload.
type ProcObject struct {
	Name   string  // e.g. "oom_score_adj"
	Target Subject // the target process; rules match its Comm
}

// Subject is who makes an access.
type Subject struct {
	// Chain[0] is the requesting thread, then its parents up to the
	// workload root.
	Chain []Task
}

// Task is one process (or thread) of a Subject. Fields the monitor did not
// read are zero.
type Task struct {
	PID, TID       int
	StartTime      uint64 // boot-relative, from /proc/<pid>/stat; with PID, a stable identity
	Comm           string
	Exe            string
	ExeDev, ExeIno uint64
	Cmdline        []string // written by the process itself
	Cwd            string
}

// Verdict is what a rule decides.
type Verdict int

const (
	Allow Verdict = iota
	Deny
	// Ask makes a request even when an Allow above matches.
	Ask
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	}
	return "ask"
}

// Rule decides accesses: Subject, Ops and Object select them.
type Rule struct {
	ID      uint64 // set by the monitor on Apply
	Subject SubjectMatch
	Ops     Op // a rule with no op matches nothing
	Object  ObjectMatch
	Verdict Verdict
	Label   string    // for Ask: shown in prompts, e.g. "SSH keys"
	Expires time.Time // zero: until removed
	Set     string    // opaque, chosen by the client
}

// SubjectMatch selects the processes a rule applies to. The zero value
// matches every process, the only behaviour for now.
type SubjectMatch struct{}

// ObjectMatch selects objects. Exactly one field is set.
type ObjectMatch struct {
	Path    *PathMatch
	Proc    *ProcMatch
	Unknown bool // all unreadable paths (lite)
}

// PathMatch is a path, or with Tree a path and everything below it.
type PathMatch struct {
	Path string // absolute and clean
	Tree bool
}

// ProcMatch is a /proc/<pid>/<Name> file of processes named Comm.
type ProcMatch struct {
	Name string
	Comm string
}

// Expired reports whether r no longer applies at now.
func (r Rule) Expired(now time.Time) bool {
	return !r.Expires.IsZero() && !now.Before(r.Expires)
}

// Eval returns the decision of rs on op on obj at now, and the deciding
// rule's ID; ok is false when no rule matches. Any Deny wins, at any depth;
// otherwise the deepest Allow or Ask decides (Ask on a tie).
func Eval(rs []Rule, op Op, obj Object, now time.Time) (v Verdict, id uint64, ok bool) {
	depth := -1
	for _, r := range rs {
		if r.Expired(now) || r.Ops&op == 0 {
			continue
		}
		d, match := r.Object.match(obj)
		if !match {
			continue
		}
		if r.Verdict == Deny {
			return Deny, r.ID, true
		}
		if op&^r.Ops != 0 {
			// An allow must cover every op of the access.
			continue
		}
		if d > depth || (d == depth && r.Verdict == Ask) {
			depth, v, id, ok = d, r.Verdict, r.ID, true
		}
	}
	return v, id, ok
}

// match reports whether m selects obj, and how deep (longer paths are
// deeper).
func (m ObjectMatch) match(obj Object) (depth int, ok bool) {
	switch {
	case obj.Path != nil && m.Path != nil:
		p := filepath.Clean(obj.Path.Path)
		if p == m.Path.Path || (m.Path.Tree && Under(p, m.Path.Path)) {
			return len(m.Path.Path), true
		}
	case obj.Proc != nil && m.Proc != nil:
		comm := ""
		if len(obj.Proc.Target.Chain) > 0 {
			comm = obj.Proc.Target.Chain[0].Comm
		}
		if m.Proc.Name == obj.Proc.Name && m.Proc.Comm == comm {
			return 0, true
		}
	case obj.Unknown != nil && m.Unknown:
		return 0, true
	}
	return 0, false
}

// Under reports whether path is prefix or lies beneath it, on a component
// boundary (/foo does not match /foobar).
func Under(path, prefix string) bool {
	if path == prefix || prefix == "/" {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

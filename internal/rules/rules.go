// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package rules holds the monitor's rule model and its evaluation. It is
// pure: no I/O and no clock, the time is a parameter. See
// docs/devel/monitor.md.
package rules

import (
	"net/netip"
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
	OpConnect // connect, and sendmsg/sendto with MSG_FASTOPEN
	OpSend    // sendto, sendmsg, sendmmsg with a destination address
	// OpExec runs the program at a path (execve, execveat). It is not in
	// OpAll: a file rule (the project dir, --allow-path) does not let programs
	// there run, and a file deny does not stop one from running.
	OpExec

	OpFiles = OpTruncate<<1 - 1
	OpNet   = OpConnect | OpSend
	// OpAll is every file and network op: what a file or network rule,
	// and an answer to a prompt about one, covers.
	OpAll = OpFiles | OpNet
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
	case op&OpConnect != 0:
		return "connect"
	case op&OpSend != 0:
		return "send"
	case op&OpExec != 0:
		return "exec"
	}
	return "?"
}

// Object is what an access is to. Exactly one field is set.
type Object struct {
	Path *PathObject
	Proc *ProcObject
	Inet *InetObject
	Unix *UnixObject
	// Unknown is set in lite mode when the path could not be read.
	Unknown error
}

// IsNet reports whether o is a network destination.
func (o Object) IsNet() bool { return o.Inet != nil || o.Unix != nil }

// InetObject is an IPv4 or IPv6 destination.
type InetObject struct {
	Proto uint16         // IP protocol number of the socket: 6 tcp, 17 udp...
	Addr  netip.AddrPort // IPv4-mapped IPv6 addresses are unmapped
	// OwnListener: the destination is on loopback and its listener was
	// started inside the sandbox.
	OwnListener bool
}

// UnixObject is a unix socket destination, bound to a path or an abstract
// name.
type UnixObject struct {
	Path        string // absolute and symlink-resolved; empty for an abstract name
	Abstract    bool
	Name        string // abstract name, without the leading NUL
	Type        int    // unix.SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET; display only
	OwnListener bool   // the peer socket was created inside the sandbox
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
	Label   string    // for Ask: shown in prompts, e.g. "SSH keys"; "@name" for an exec allow from a program group
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
	Inet    *InetMatch
	Unix    *UnixMatch
	Unknown bool // all unreadable paths (lite)
	// OwnListener: loopback or unix destinations whose listener was
	// started inside the sandbox.
	OwnListener bool
	// AnyNet: every network destination, unix sockets included.
	AnyNet bool
}

// InetMatch is a set of IPv4 or IPv6 destinations.
type InetMatch struct {
	Proto  uint16       // 0: any protocol
	Prefix netip.Prefix // invalid (zero): any address of any family
	// PortLo..PortHi, inclusive; both 0: any port.
	PortLo, PortHi uint16
}

// UnixMatch is a unix socket path (with Prefix, a tree), or an abstract
// name (with Prefix, every name starting with it).
type UnixMatch struct {
	Path     string // absolute and clean, when not Abstract
	Abstract bool
	Name     string
	Prefix   bool
}

// IsNet reports whether m selects network destinations.
func (m ObjectMatch) IsNet() bool {
	return m.Inet != nil || m.Unix != nil || m.OwnListener || m.AnyNet
}

// PathMatch is a path, or with Tree a path and everything below it.
//
// An exec rule (Ops OpExec) is a PathMatch on the program's path.
type PathMatch struct {
	Path string // absolute and clean
	Tree bool
	// Args is reserved for exec rules matching the arguments too ("allow
	// git log", docs/devel/plan-exec.md). It is not implemented: a rule
	// with Args matches nothing.
	Args []string
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

// match reports whether m selects obj, and how deep (m.Depth).
func (m ObjectMatch) match(obj Object) (depth int, ok bool) {
	switch {
	case obj.Path != nil && m.Path != nil && len(m.Path.Args) == 0:
		p := filepath.Clean(obj.Path.Path)
		ok = p == m.Path.Path || (m.Path.Tree && Under(p, m.Path.Path))
	case obj.Proc != nil && m.Proc != nil:
		comm := ""
		if len(obj.Proc.Target.Chain) > 0 {
			comm = obj.Proc.Target.Chain[0].Comm
		}
		ok = m.Proc.Name == obj.Proc.Name && m.Proc.Comm == comm
	case obj.Unknown != nil && m.Unknown:
		ok = true
	case obj.IsNet() && m.AnyNet:
		ok = true
	case obj.IsNet() && m.OwnListener:
		ok = (obj.Inet != nil && obj.Inet.OwnListener) || (obj.Unix != nil && obj.Unix.OwnListener)
	case obj.Inet != nil && m.Inet != nil:
		ok = m.Inet.match(obj.Inet)
	case obj.Unix != nil && m.Unix != nil:
		ok = m.Unix.match(obj.Unix)
	}
	if !ok {
		return 0, false
	}
	return m.Depth(), true
}

// Depth is how specific m is, the same for every object it selects: when
// no Deny matches, the deepest Allow or Ask decides. Longer paths and
// names are deeper; for inet, longer prefixes (IPv4 ones as IPv4-mapped
// IPv6 ones), then a port range, then a protocol. Every network
// destination (AnyNet) is the shallowest.
func (m ObjectMatch) Depth() int {
	switch {
	case m.Path != nil:
		return len(m.Path.Path)
	case m.OwnListener:
		return ownListenerDepth
	case m.Inet != nil:
		return m.Inet.depth()
	case m.Unix != nil && m.Unix.Abstract:
		return len(m.Unix.Name) + 1
	case m.Unix != nil:
		return len(m.Unix.Path)
	}
	return 0
}

// ownListenerDepth is deeper than any address rule: an Ask on an address
// does not override it, a Deny still does.
const ownListenerDepth = 1 << 20

func (m *InetMatch) match(o *InetObject) bool {
	if m.Proto != 0 && m.Proto != o.Proto {
		return false
	}
	if m.PortLo != 0 || m.PortHi != 0 {
		if p := o.Addr.Port(); p < m.PortLo || p > m.PortHi {
			return false
		}
	}
	return !m.Prefix.IsValid() || m.Prefix.Contains(o.Addr.Addr().Unmap())
}

func (m *InetMatch) depth() int {
	d := 1
	if m.Prefix.IsValid() {
		bits := m.Prefix.Bits()
		if m.Prefix.Addr().Is4() {
			bits += 96
		}
		d += 4 * (bits + 1)
	}
	if m.PortLo != 0 || m.PortHi != 0 {
		d += 2
	}
	if m.Proto != 0 {
		d++
	}
	return d
}

func (m *UnixMatch) match(o *UnixObject) bool {
	if m.Abstract != o.Abstract {
		return false
	}
	if m.Abstract {
		return o.Name == m.Name || (m.Prefix && strings.HasPrefix(o.Name, m.Name))
	}
	p := filepath.Clean(o.Path)
	return p == m.Path || (m.Prefix && Under(p, m.Path))
}

// Under reports whether path is prefix or lies beneath it, on a component
// boundary (/foo does not match /foobar).
func Under(path, prefix string) bool {
	if path == prefix || prefix == "/" {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

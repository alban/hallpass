// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"net/netip"
	"time"
)

// The types of the rules and events, also used by code that builds on
// any platform (the monitor in the website's demo, compiled to js/wasm).

// InetDest is an IPv4 or IPv6 destination (IPv4 unmapped).
type InetDest struct {
	Addr  netip.AddrPort
	Proto uint16 // IP protocol of the socket
}

// UnixDest is a unix socket destination: an abstract name, or a socket
// file (in events, only its last component is known).
type UnixDest struct {
	Abstract bool
	Name     string
	Path     string
}

// NetGrant is the network part of GrantOnce. The kernel keeps the first
// four Inet destinations: a sendmmsg to more stops at the fifth.
type NetGrant struct {
	Inet     []InetDest
	Abstract *string // abstract unix name, without the leading NUL
}

// UnixAnyRule allows, asks or denies every unix socket bound to a path.
// Rules on a path beat its allows and asks.
type UnixAnyRule struct {
	Deny    bool
	Ask     bool
	Expires time.Time
}

// UnixRules are a session's rules for the unix sockets bound to a path,
// but for those of Rule with Net. Inet and abstract unix destinations
// need a GrantOnce.
type UnixRules struct {
	AnyUnix []UnixAnyRule
	// OwnListeners allows connections and datagrams to the unix sockets
	// the session's members created.
	OwnListeners bool
}

// Rule allows, denies or asks about a host path: the path and everything
// below it (Tree) or that exact path only. With Net, it is about
// connections and datagrams to the unix sockets bound there, not about
// writing files. With Exec, it is about executing the programs there, and
// it cannot ask. An ask rule cuts off the allows of the paths above: what
// it matches is denied, unless a deeper allow rule or a GrantOnce allows
// it. Deny wins over both.
type Rule struct {
	Path    string // absolute and clean
	Tree    bool
	Deny    bool
	Ask     bool
	Net     bool
	Exec    bool
	Expires time.Time // zero: never (deny rules never expire)
}

// ProcRule allows, denies or asks about writes to file Name in /proc/<pid>/
// of processes named Comm outside the sandbox. An ask wins over an allow.
type ProcRule struct {
	Name, Comm string
	Deny, Ask  bool
	Expires    time.Time
}

// Event is one decision of the BPF programs. Network events (op connect
// or send) have Inet or Unix set, not Path.
type Event struct {
	PID     uint32
	Comm    string
	Op      string
	Path    string
	Inet    *InetDest
	Unix    *UnixDest
	Allowed bool
}

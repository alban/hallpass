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

// NetGrant is the network part of GrantOnce.
type NetGrant struct {
	Inet     []InetDest
	Abstract *string // abstract unix name, without the leading NUL
}

// InetRule allows, asks or denies IPv4 and IPv6 destinations. The deepest
// matching allow or ask decides, the ask on a tie: an ask stops the allows
// of shallower rules.
type InetRule struct {
	Prefix         netip.Prefix // invalid (zero): any address
	Proto          uint16       // 0: any
	PortLo, PortHi uint16       // both 0: any port
	Deny           bool
	Ask            bool
	// Depth orders allows and asks: the more specific, the deeper
	// (rules.ObjectMatch.Depth).
	Depth   uint16
	Expires time.Time
}

// AbstractRule allows, asks or denies abstract unix socket names: Name,
// or with Prefix every name starting with it. The longest name decides
// between allows and asks, the ask on a tie.
type AbstractRule struct {
	Name    string
	Prefix  bool
	Deny    bool
	Ask     bool
	Expires time.Time
}

// UnixAnyRule allows, asks or denies every unix socket. Rules on an
// address or a name beat its allows and asks.
type UnixAnyRule struct {
	Deny    bool
	Ask     bool
	Expires time.Time
}

// NetRules are a session's network rules, but for the unix sockets bound
// to a path: Rule with Net.
type NetRules struct {
	Inet     []InetRule
	Abstract []AbstractRule
	AnyUnix  []UnixAnyRule
	// OwnListeners allows loopback TCP connections to the listeners the
	// session's members started, and connections and datagrams to the unix
	// sockets they created.
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

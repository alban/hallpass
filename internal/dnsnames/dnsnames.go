// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package dnsnames names the network destinations of a session: the host
// names of the answers its processes got, mapped to the addresses those
// answers gave. Prompts show them next to the address ("connect to
// github.com (140.82.112.4:443)"); host rules match them.
//
// The answers are those hallpass relayed itself: from the session's DNS
// forwarder (internal/dnsfwd), to which the monitor redirects its queries
// to the name servers, or from systemd-resolved's varlink socket
// (Varlink). A name is shown for an address only when the session's own
// answer had it.
package dnsnames

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Port is where a datagram is a DNS query.
const Port = 53

// Servers returns the name servers of resolv.conf file path, as Go's
// resolver reads them ("nameserver" lines).
func Servers(path string) ([]netip.Addr, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for line := range strings.Lines(string(b)) {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		if a, err := netip.ParseAddr(f[1]); err == nil {
			out = append(out, a.WithZone("").Unmap())
		}
	}
	return out, nil
}

// ReverseFunc returns the names the PTR records of addr give.
type ReverseFunc func(ctx context.Context, addr netip.Addr) ([]string, error)

// HostReverse returns a reverse lookup through Go's resolver that sends
// its queries only to port 53 of servers: if resolv.conf names another
// server later, lookups fail rather than reach it.
func HostReverse(servers []netip.Addr) ReverseFunc {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || ap.Port() != Port || !slices.Contains(servers, ap.Addr().WithZone("").Unmap()) {
				return nil, fmt.Errorf("dnsnames: %s is not a name server of the session", address)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}
	return func(ctx context.Context, addr netip.Addr) ([]string, error) {
		return r.LookupAddr(ctx, addr.String())
	}
}

// Floor is how long a name stays on its addresses at least: clients
// cache answers past their TTL.
const Floor = 5 * time.Minute

// Bounds: addresses kept, names per address, and how long a reverse
// lookup may take.
const (
	maxAddrs    = 4096
	maxPerAddr  = 8
	lookupLimit = 3 * time.Second
)

// Names maps addresses to the names of a session's answers.
type Names struct {
	reverse ReverseFunc
	now     func() time.Time

	mu sync.Mutex
	// dns is whether the session got an answer (Answer).
	dns         bool
	displayOnly bool
	byAddr      map[netip.Addr][]entry // most recent first
	ptr         map[netip.Addr]ptrEntry
}

type entry struct {
	name    string
	expires time.Time
}

// New returns an empty map, filled by the answers relayed to the session
// (Answer, AnswerMsg).
func New() *Names {
	return &Names{
		now:    time.Now,
		byAddr: map[netip.Addr][]entry{},
		ptr:    map[netip.Addr]ptrEntry{},
	}
}

// addLocked records e for a, most recent first, replacing the entry of the
// same name.
func (n *Names) addLocked(a netip.Addr, e entry) {
	a = a.Unmap()
	es := n.byAddr[a]
	if _, ok := n.byAddr[a]; !ok && len(n.byAddr) >= maxAddrs {
		n.pruneLocked()
		if len(n.byAddr) >= maxAddrs {
			return
		}
	}
	es = slices.DeleteFunc(es, func(o entry) bool { return o.name == e.name })
	if len(es) >= maxPerAddr {
		es = es[:maxPerAddr-1]
	}
	n.byAddr[a] = append([]entry{e}, es...)
}

// Answer records that the session's own answer gave name the addresses
// addrs, valid for ttl (at least Floor): an answer hallpass relayed, so
// the names are those the session will use.
func (n *Names) Answer(name string, addrs []netip.Addr, ttl time.Duration) {
	name = normalize(name)
	if !validName(name) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dns = true
	exp := n.now().Add(max(ttl, Floor))
	for _, a := range addrs {
		if a.IsValid() {
			n.addLocked(a, entry{name: name, expires: exp})
		}
	}
}

// normalize returns name lowercase, without the final dot.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// Lookup returns the names of addr, most recent first.
func (n *Names) Lookup(addr netip.Addr) []string {
	addr = addr.Unmap()
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	var out []string
	for _, e := range n.byAddr[addr] {
		if now.Before(e.expires) {
			out = append(out, e.name)
		}
	}
	return out
}

// SetReverse sets the reverse lookup of Unverified, which must send its
// queries only to the session's name servers (HostReverse).
func (n *Names) SetReverse(f ReverseFunc) { n.reverse = f }

type ptrEntry struct {
	names []string
	when  time.Time
}

// maxPTR bounds the reverse lookups remembered.
const maxPTR = 1024

// Unverified returns the names the PTR records of addr give, looked up
// with the reverse lookup (SetReverse) within wait: display hints only,
// since whoever controls the address's reverse zone chooses them, never
// rule matchers. None until the session got an answer (Answer): a
// session denied DNS must not get hallpass to send queries for it (a PTR
// in a reverse zone the session's owner controls carries data out).
func (n *Names) Unverified(addr netip.Addr, wait time.Duration) []string {
	addr = addr.Unmap()
	if n.reverse == nil || !addr.IsValid() || addr.IsLoopback() || addr.IsUnspecified() {
		return nil
	}
	n.mu.Lock()
	dns := n.dns
	e, ok := n.ptr[addr]
	n.mu.Unlock()
	if !dns {
		return nil
	}
	if ok && n.now().Sub(e.when) < Floor {
		return e.names
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(wait, lookupLimit))
	defer cancel()
	names, err := n.reverse(ctx, addr)
	var out []string
	for _, name := range names {
		name = normalize(name)
		if validName(name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	if err != nil && len(out) == 0 && ctx.Err() != nil {
		return nil // not remembered: try again next time
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.ptr) >= maxPTR {
		clear(n.ptr)
	}
	n.ptr[addr] = ptrEntry{names: out, when: n.now()}
	return out
}

// SetDisplayOnly makes n's names shown in prompts but never matched by
// rules (Match): for a session that could forge the answers hallpass
// relays (a container with CAP_NET_RAW sharing the forwarder's network
// namespace).
func (n *Names) SetDisplayOnly() {
	n.mu.Lock()
	n.displayOnly = true
	n.mu.Unlock()
}

// Matches reports whether rules match n's names: not SetDisplayOnly.
func (n *Names) Matches() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return !n.displayOnly
}

// Match is Lookup, for the host rules: none when the names are display
// only (SetDisplayOnly).
func (n *Names) Match(addr netip.Addr) []string {
	if !n.Matches() {
		return nil
	}
	return n.Lookup(addr)
}

// pruneLocked forgets the expired names.
func (n *Names) pruneLocked() {
	now := n.now()
	for a, es := range n.byAddr {
		es = slices.DeleteFunc(es, func(e entry) bool { return !now.Before(e.expires) })
		if len(es) == 0 {
			delete(n.byAddr, a)
		} else {
			n.byAddr[a] = es
		}
	}
}

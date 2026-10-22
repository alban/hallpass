// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package dnsnames names the network destinations of a session: the host
// names its processes asked their DNS servers about, mapped to the
// addresses those names have. Prompts show them next to the address
// ("connect to github.com (140.82.112.4:443)"); rules still match
// addresses.
//
// The names come from the queries the session sends (QueryNames); the
// addresses from hallpass's own lookup of each name, through the host's
// resolver, so a name is shown for an address only when the name has
// that address. A content delivery network that answers the session and
// hallpass with different addresses leaves the address unnamed.
//
// hallpass must not send what the session could not: a query counts
// only when the session was allowed to send it to one of the servers
// hallpass itself looks names up with (Names.Server, HostLookup). This
// holds because the sandbox shares the host's network and resolv.conf
// (workstation); a sandbox with its own network needs its queries
// relayed instead.
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

	"golang.org/x/net/dns/dnsmessage"
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

// HostLookup returns a lookup through Go's resolver that sends its
// queries only to port 53 of servers: if resolv.conf names another
// server later, lookups fail rather than reach it.
func HostLookup(servers []netip.Addr) LookupFunc {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || !isServer(servers, ap) {
				return nil, fmt.Errorf("dnsnames: %s is not a name server of the session", address)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}
	return func(ctx context.Context, name string) ([]netip.Addr, error) {
		return r.LookupNetIP(ctx, "ip", name)
	}
}

func isServer(servers []netip.Addr, ap netip.AddrPort) bool {
	return ap.Port() == Port && slices.Contains(servers, ap.Addr().WithZone("").Unmap())
}

// QueryNames returns the names that the A, AAAA and ANY questions of DNS
// query msg ask about, without the final dot, lowercase. A response, or
// anything that is not a DNS message, gives none.
func QueryNames(msg []byte) []string {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil
	}
	var out []string
	for _, q := range qs {
		if q.Class != dnsmessage.ClassINET || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA && q.Type != dnsmessage.TypeALL) {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// Floor is how long a name stays on its addresses at least: clients
// cache answers past their TTL.
const Floor = 5 * time.Minute

// Bounds: names kept, lookups at once, and how long a lookup may take.
const (
	maxNames    = 4096
	maxLookups  = 4
	lookupLimit = 3 * time.Second
	// fresh is how long a lookup is not repeated for the same name.
	fresh = time.Minute
)

// LookupFunc returns the addresses of name, as the host resolves it.
type LookupFunc func(ctx context.Context, name string) ([]netip.Addr, error)

// Names maps addresses to the names a session asked about.
type Names struct {
	lookup  LookupFunc
	servers []netip.Addr
	now     func() time.Time
	sem     chan struct{}

	mu       sync.Mutex
	byAddr   map[netip.Addr][]entry // most recent first
	looked   map[string]time.Time   // name -> when its lookup ended
	inflight map[string]chan struct{}
}

type entry struct {
	name    string
	expires time.Time
}

// New returns an empty map whose names are looked up with lookup, which
// must send its queries only to servers (HostLookup).
func New(lookup LookupFunc, servers []netip.Addr) *Names {
	return &Names{
		lookup:   lookup,
		servers:  servers,
		now:      time.Now,
		sem:      make(chan struct{}, maxLookups),
		byAddr:   map[netip.Addr][]entry{},
		looked:   map[string]time.Time{},
		inflight: map[string]chan struct{}{},
	}
}

// Server reports whether a query the session sends to ap counts: ap is
// port 53 of one of the servers hallpass looks names up with, so its
// lookup reaches no server the session could not.
func (n *Names) Server(ap netip.AddrPort) bool {
	return isServer(n.servers, ap)
}

// Observe records that the session asked about name: hallpass looks it up,
// in the background, unless it did so recently. The caller must have
// allowed the session's query, sent to a server (Server): hallpass's
// lookup then sends nothing the session could not send itself.
func (n *Names) Observe(name string) {
	if len(name) > 253 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.inflight[name]; ok {
		return
	}
	if t, ok := n.looked[name]; ok && n.now().Sub(t) < fresh {
		return
	}
	if len(n.looked) >= maxNames {
		n.pruneLocked()
		if len(n.looked) >= maxNames {
			return
		}
	}
	done := make(chan struct{})
	n.inflight[name] = done
	go func() {
		defer close(done)
		n.sem <- struct{}{}
		ctx, cancel := context.WithTimeout(context.Background(), lookupLimit)
		addrs, err := n.lookup(ctx, name)
		cancel()
		<-n.sem
		n.mu.Lock()
		defer n.mu.Unlock()
		delete(n.inflight, name)
		now := n.now()
		n.looked[name] = now
		if err != nil {
			return
		}
		for _, a := range addrs {
			a = a.Unmap()
			es := slices.DeleteFunc(n.byAddr[a], func(e entry) bool { return e.name == name })
			n.byAddr[a] = append([]entry{{name: name, expires: now.Add(Floor)}}, es...)
		}
	}()
}

// Lookup returns the names of addr, most recent first, after waiting at
// most wait for the lookups in progress: the session connects as soon as
// its own answer comes, which may be before hallpass's.
func (n *Names) Lookup(addr netip.Addr, wait time.Duration) []string {
	addr = addr.Unmap()
	n.mu.Lock()
	var pending []chan struct{}
	for _, c := range n.inflight {
		pending = append(pending, c)
	}
	n.mu.Unlock()
	if len(pending) > 0 && wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
	loop:
		for _, c := range pending {
			select {
			case <-c:
			case <-t.C:
				break loop
			}
		}
	}
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

// pruneLocked forgets the expired names and lookups.
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
	for name, t := range n.looked {
		if now.Sub(t) >= Floor {
			delete(n.looked, name)
		}
	}
}

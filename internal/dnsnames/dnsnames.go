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
package dnsnames

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

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
	lookup LookupFunc
	now    func() time.Time
	sem    chan struct{}

	mu       sync.Mutex
	byAddr   map[netip.Addr][]entry // most recent first
	looked   map[string]time.Time   // name -> when its lookup ended
	inflight map[string]chan struct{}
}

type entry struct {
	name    string
	expires time.Time
}

// New returns an empty map whose names are looked up with lookup.
func New(lookup LookupFunc) *Names {
	return &Names{
		lookup:   lookup,
		now:      time.Now,
		sem:      make(chan struct{}, maxLookups),
		byAddr:   map[netip.Addr][]entry{},
		looked:   map[string]time.Time{},
		inflight: map[string]chan struct{}{},
	}
}

// Observe records that the session asked about name: hallpass looks it up,
// in the background, unless it did so recently. The caller must have
// allowed the session's query: hallpass's lookup then sends nothing the
// session could not send itself.
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

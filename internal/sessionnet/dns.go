// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionnet

import (
	"errors"
	"net/netip"
	"slices"
	"sync"

	"github.com/alban/hallpass/internal/dnsfwd"
	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
)

// labelForwarder labels the denials of the DNS forwarders.
const labelForwarder = "hallpass DNS forwarder"

// DNS names the destinations of a session: the monitor redirects its
// queries to its name servers to a forwarder (monitor.Config.DNSForward),
// which records the answers in Names.
type DNS struct {
	Names *dnsnames.Names
	fwd   *dnsfwd.Forwarder
	netns uint64
}

// StartDNS starts the forwarder of the session's name servers, recording
// in names. in runs a function in the session's network namespace, where
// the listeners and upstream sockets are made. warn reports what fails
// later.
func StartDNS(in dnsfwd.Dialer, servers []netip.Addr, names *dnsnames.Names, warn func(string)) (*DNS, error) {
	d := &DNS{Names: names}
	if err := in(func() (err error) {
		d.netns, err = procfs.Netns()
		return err
	}); err != nil {
		return nil, err
	}
	if d.netns == 0 {
		// The redirect checks that a socket is in the namespace of the
		// listeners.
		return nil, errors.New("no network namespace cookie (Linux 5.14)")
	}
	var aps []netip.AddrPort
	for _, s := range servers {
		aps = append(aps, netip.AddrPortFrom(s, dnsnames.Port))
	}
	var err error
	if d.fwd, err = dnsfwd.Start(in, aps, names, warn); err != nil {
		return nil, err
	}
	return d, nil
}

// Configure makes the monitor of c redirect the session's queries to d.
func (d *DNS) Configure(c *monitor.Config) {
	c.Names = d.Names
	c.Netns = d.netns
	c.DNSForward = map[netip.Addr]netip.AddrPort{}
	for _, l := range d.fwd.Listeners() {
		c.DNSForward[l.Server] = l.Addr
	}
}

// Denials returns the rules denying d's listeners: to its own session,
// which reaches them only through the redirect, and to the others of its
// network namespace (Group), whose rules may deny DNS.
func (d *DNS) Denials() []rules.Rule {
	var rs []rules.Rule
	for _, l := range d.fwd.Listeners() {
		p := l.Addr.Port()
		rs = append(rs, rules.Rule{
			Ops:     rules.OpNet,
			Object:  rules.ObjectMatch{Inet: &rules.InetMatch{Prefix: netip.PrefixFrom(l.Addr.Addr(), l.Addr.Addr().BitLen()), PortLo: p, PortHi: p}},
			Verdict: rules.Deny,
			Label:   labelForwarder,
			Set:     monitor.ProtectedSet,
		})
	}
	return rs
}

// Close stops the forwarder.
func (d *DNS) Close() {
	if d != nil {
		d.fwd.Close()
	}
}

// Group isolates the forwarders of the sessions sharing a network
// namespace (the containers of a pod, or of the node's network): a
// listener is on the loopback of all of them.
type Group struct {
	Client  string // of the denials (monitor.Decision)
	mu      sync.Mutex
	members []member
}

type member struct {
	d *DNS
	m *monitor.Monitor
}

// Join denies d's listeners to its own session, of monitor m, and to the
// other members of d's network namespace, and theirs to m, until leave.
// A neighbour that cannot be denied d's goes to warn.
func (g *Group) Join(d *DNS, m *monitor.Monitor, warn func(error)) (leave func(), err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	mine := d.Denials()
	rs := slices.Clone(mine)
	for _, o := range g.members {
		if o.d.netns == d.netns {
			rs = append(rs, o.d.Denials()...)
		}
	}
	if _, err := m.Apply(monitor.Decision{AddRules: rs, Client: g.Client}); err != nil {
		return nil, err
	}
	for _, o := range g.members {
		if o.d.netns != d.netns {
			continue
		}
		if _, err := o.m.Apply(monitor.Decision{AddRules: mine, Client: g.Client}); err != nil {
			warn(err)
		}
	}
	g.members = append(g.members, member{d, m})
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.members = slices.DeleteFunc(g.members, func(o member) bool { return o.d == d })
	}, nil
}

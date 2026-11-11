// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionnet

import (
	"errors"
	"net/netip"

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
// network namespace, whose rules may deny DNS.
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

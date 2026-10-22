// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/alban/hallpass/internal/dnsfwd"
	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/dnsredirect"
	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/netns"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
	"golang.org/x/sys/unix"
)

// labelForwarder labels the denials of the DNS forwarders of the other
// mediated containers of a network namespace.
const labelForwarder = "hallpass DNS forwarder"

// dnsState names the destinations of one container (--dns=redirect, the
// only mode of hallpass-node): its DNS queries go to a forwarder, which
// records the answers in names. Started before the container runs its
// program, closed with the session.
type dnsState struct {
	names    *dnsnames.Names
	netns    uint64 // inode of the network namespace
	w        *netns.Worker
	fwd      *dnsfwd.Forwarder
	redirect *dnsredirect.Redirect
	// rawSockets: the container has CAP_NET_RAW: its names are shown,
	// never matched by host rules.
	rawSockets bool
	// cookie is the network namespace's cookie (procfs.Netns), 0 if
	// unknown: the sockets the proxy may swap (monitor.Config.Netns).
	cookie uint64
}

// pair makes the loopback TCP pair of a swap to the proxy in the
// container's network namespace (monitor.Config.Pair): made in
// hallpass-node's own, the end installed in the workload could be
// connected again to hallpass-node's loopback (its session API) or
// leave from its pod IP. On the worker's thread, which stays in the
// container's namespace.
func (d *dnsState) pair(int) (client, server *net.TCPConn, err error) {
	err = d.w.Do(func() error {
		client, server, err = egress.Pair()
		return err
	})
	return client, server, err
}

// capNetRaw is CAP_NET_RAW's bit.
const capNetRaw = 13

// canRawSocket reports whether process pid may get CAP_NET_RAW: in its
// bounding set (a program it runs may have it; containerd's default),
// or unknown.
func canRawSocket(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return true
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, "CapBnd:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err != nil || caps&(1<<capNetRaw) != 0
		}
	}
	return true
}

// startDNS starts the forwarder of the container whose process pid is
// still in the runtime's init, in the container's network namespace,
// for the name servers of its resolv.conf as it is now, and redirects the
// queries of the container's cgroup to it. warn logs what fails later.
func startDNS(pid int, warn func(string)) (*dnsState, error) {
	cgfd, err := dnsredirect.OpenCgroup(pid)
	if err != nil {
		return nil, err
	}
	defer unix.Close(cgfd)
	servers, err := dnsnames.Servers(fmt.Sprintf("/proc/%d/root/etc/resolv.conf", pid))
	if err != nil {
		return nil, err
	}
	var ns unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/net", pid), &ns); err != nil {
		return nil, err
	}
	d := &dnsState{names: dnsnames.New(nil, nil), netns: ns.Ino}
	if d.rawSockets = canRawSocket(pid); d.rawSockets {
		// It can sniff the forwarder's queries and forge their
		// replies: its names could be any it likes.
		d.names.SetDisplayOnly()
	}
	if d.w, err = netns.Enter(pid); err != nil {
		return nil, err
	}
	if err := d.w.Do(func() (err error) {
		d.cookie, err = procfs.Netns()
		return err
	}); err != nil {
		d.close()
		return nil, err
	}
	var aps []netip.AddrPort
	for _, s := range servers {
		aps = append(aps, netip.AddrPortFrom(s, dnsnames.Port))
	}
	if len(aps) > dnsredirect.MaxRoutes {
		aps = aps[:dnsredirect.MaxRoutes]
	}
	if d.fwd, err = dnsfwd.Start(d.w.Do, aps, d.names, warn); err != nil {
		d.close()
		return nil, err
	}
	var routes []dnsredirect.Route
	for _, l := range d.fwd.Listeners() {
		routes = append(routes, dnsredirect.Route{Server: l.Server, Listener: l.Addr})
	}
	if d.redirect, err = dnsredirect.Attach(cgfd, routes); err != nil {
		d.close()
		return nil, err
	}
	return d, nil
}

// close stops the redirect, then the forwarder.
func (d *dnsState) close() {
	if d == nil {
		return
	}
	if d.redirect != nil {
		d.redirect.Close()
	}
	if d.fwd != nil {
		d.fwd.Close()
	}
	if d.w != nil {
		d.w.Close()
	}
}

// denials returns the rules denying d's forwarder to the other mediated
// containers of its network namespace: its listener is on their
// loopback too, and a container whose rules deny DNS must not resolve
// through it.
func (d *dnsState) denials() []rules.Rule {
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

// dnsNote is what the started Event says when a container gets no DNS
// names: prompts then show addresses only.
func dnsNote(err error) string {
	if errors.Is(err, dnsredirect.ErrNoCgroup2) {
		return "no DNS names: the node has no cgroup v2"
	}
	return "no DNS names: " + err.Error()
}

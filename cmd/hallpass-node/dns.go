// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/netns"
	"github.com/alban/hallpass/internal/sessionnet"
)

// dnsState names the destinations of one container: its monitor
// redirects its DNS queries to a forwarder in its network namespace.
// Started before the container runs its program, closed with the
// session.
type dnsState struct {
	*sessionnet.DNS
	w *netns.Worker // in the container's network namespace
	// rawSockets: the container has CAP_NET_RAW: its names are shown,
	// never matched by host rules.
	rawSockets bool
	leave      func() // the forwarders' group
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
// still the runtime's init, in the container's network namespace, for
// the name servers of its resolv.conf as it is now. warn logs what fails
// later.
func startDNS(pid int, warn func(string)) (*dnsState, error) {
	servers, err := dnsnames.Servers(fmt.Sprintf("/proc/%d/root/etc/resolv.conf", pid))
	if err != nil {
		return nil, err
	}
	names := dnsnames.New(nil, nil)
	d := &dnsState{rawSockets: canRawSocket(pid)}
	if d.rawSockets {
		// It can sniff the forwarder's queries and forge their
		// replies: its names could be any it likes.
		names.SetDisplayOnly()
	}
	if d.w, err = netns.Enter(pid); err != nil {
		return nil, err
	}
	if d.DNS, err = sessionnet.StartDNS(d.w.Do, servers, names, warn); err != nil {
		d.w.Close()
		return nil, err
	}
	return d, nil
}

// close leaves the forwarders' group, then stops the forwarder.
func (d *dnsState) close() {
	if d == nil {
		return
	}
	if d.leave != nil {
		d.leave()
	}
	d.DNS.Close()
	if d.w != nil {
		d.w.Close()
	}
}

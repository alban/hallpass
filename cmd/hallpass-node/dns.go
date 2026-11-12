// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

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
	// rawSockets: why the container may have CAP_NET_RAW (rawSockets),
	// or "": its names are shown, never matched by host rules.
	rawSockets string
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

// maxConfig bounds a container's OCI config.
const maxConfig = 4 << 20

// rawSockets returns why the container of bundle (a host path, the host's
// root being hostRoot) may open raw sockets, "" if it cannot: CAP_NET_RAW
// in a capability set of its OCI config (the bounding set: a program it
// runs may get it; containerd's default), or the config unknown. Not read
// from the runtime's init: with no_new_privileges off, runc installs the
// filter, and hands the listener, before it drops the capabilities.
func rawSockets(hostRoot, bundle string) string {
	spec, err := readConfig(hostRoot, bundle)
	switch {
	case err != nil:
		return fmt.Sprintf("the container may have CAP_NET_RAW (%v), it could forge its answers", err)
	case spec.Process == nil || spec.Process.Capabilities == nil:
		return "the container may have CAP_NET_RAW (no capabilities in its OCI config), it could forge its answers"
	}
	c := spec.Process.Capabilities
	for _, set := range [][]string{c.Bounding, c.Effective, c.Permitted, c.Ambient} {
		if slices.ContainsFunc(set, func(s string) bool { return strings.EqualFold(s, "CAP_NET_RAW") }) {
			return "the container has CAP_NET_RAW, it could forge its answers (drop it for host rules)"
		}
	}
	return ""
}

// readConfig reads the config.json of bundle, resolved in hostRoot: the
// runtime wrote it, but the path comes from the runtime's message.
func readConfig(hostRoot, bundle string) (*specs.Spec, error) {
	if hostRoot == "" || !filepath.IsAbs(bundle) {
		return nil, fmt.Errorf("no bundle %q in %q", bundle, hostRoot)
	}
	root, err := unix.Open(hostRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: hostRoot, Err: err}
	}
	defer unix.Close(root)
	name := filepath.Join(bundle, "config.json")
	// O_NONBLOCK: a FIFO in its place does not block the open.
	fd, err := unix.Openat2(root, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxConfig {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, maxConfig)
	}
	var spec specs.Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &spec, nil
}

// startDNS starts the forwarder of the container whose process pid is
// still the runtime's init, in the container's network namespace, for
// the name servers of its resolv.conf as it is now. raw is why its names
// are display only (rawSockets), "" if they are not. warn logs what fails
// later.
func startDNS(pid int, raw string, warn func(string)) (*dnsState, error) {
	servers, err := dnsnames.Servers(fmt.Sprintf("/proc/%d/root/etc/resolv.conf", pid))
	if err != nil {
		return nil, err
	}
	names := dnsnames.New()
	d := &dnsState{rawSockets: raw}
	if raw != "" {
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

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package dnsredirect sends the DNS queries of one container to
// forwarders (internal/dnsfwd) with cgroup sock_addr BPF programs: a
// connect or send to port 53 of a name server goes to that server's
// listener on the loopback of the container's network namespace, and the
// replies received from a listener show the server as their source, so
// the stub resolver accepts them. See bpf/dnsredirect.bpf.c.
//
// The programs run after seccomp (lite) and the LSM hooks (strict): the
// rules see the real name server, so a container denied DNS is never
// forwarded.
package dnsredirect

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Route sends the queries to Server, port 53, to Listener, a forwarder
// on 127.0.0.1 or [::1] in the container's network namespace. An IPv4
// server needs an IPv4 listener, an IPv6 one [::1].
type Route struct {
	Server   netip.Addr
	Listener netip.AddrPort
}

// MaxRoutes is the most routes one container has (its name servers).
const MaxRoutes = 16

// Redirect is the programs attached to one container's cgroup.
type Redirect struct {
	objs  dnsredirectObjects
	links []link.Link
}

// Attach loads the programs for routes and attaches them to the cgroup
// directory cgroupFD, after the cgroup's own programs and before its
// ancestors' (BPF_F_ALLOW_MULTI). They are detached by Close, or when
// this process exits.
func Attach(cgroupFD int, routes []Route) (*Redirect, error) {
	if len(routes) == 0 || len(routes) > MaxRoutes {
		return nil, fmt.Errorf("dnsredirect: %d routes, want 1 to %d", len(routes), MaxRoutes)
	}
	r := &Redirect{}
	if err := loadDnsredirectObjects(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("dnsredirect: load: %w", err)
	}
	for _, rt := range routes {
		srv, l, err := route(rt)
		if err == nil {
			err = r.objs.Routes.Update(srv, l, ebpf.UpdateNoExist)
		}
		if err == nil {
			err = r.objs.Back.Update(l, srv, ebpf.UpdateNoExist)
		}
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("dnsredirect: route %v -> %v: %w", rt.Server, rt.Listener, err)
		}
	}
	for _, a := range []struct {
		p *ebpf.Program
		t ebpf.AttachType
	}{
		{r.objs.HpDnsConnect4, ebpf.AttachCGroupInet4Connect},
		{r.objs.HpDnsConnect6, ebpf.AttachCGroupInet6Connect},
		{r.objs.HpDnsSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{r.objs.HpDnsSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
		{r.objs.HpDnsRecvmsg4, ebpf.AttachCGroupUDP4Recvmsg},
		{r.objs.HpDnsRecvmsg6, ebpf.AttachCGroupUDP6Recvmsg},
	} {
		lk, err := link.AttachRawLink(link.RawLinkOptions{Target: cgroupFD, Program: a.p, Attach: a.t})
		if err != nil {
			r.Close()
			return nil, fmt.Errorf("dnsredirect: attach %v: %w", a.t, err)
		}
		r.links = append(r.links, lk)
	}
	// The maps stay referenced by the programs.
	return r, nil
}

// route converts rt to the maps' keys and values.
func route(rt Route) (dnsredirectHpAddr6, dnsredirectHpDnsListener, error) {
	srv := addr6(rt.Server.Unmap())
	la := rt.Listener.Addr().Unmap()
	switch {
	case !rt.Server.IsValid() || rt.Server.Zone() != "":
		return srv, dnsredirectHpDnsListener{}, errors.New("invalid server")
	case rt.Server.Unmap().Is4() && la != netip.AddrFrom4([4]byte{127, 0, 0, 1}):
		return srv, dnsredirectHpDnsListener{}, errors.New("an IPv4 server needs a listener on 127.0.0.1")
	case rt.Server.Unmap().Is6() && la != netip.IPv6Loopback():
		return srv, dnsredirectHpDnsListener{}, errors.New("an IPv6 server needs a listener on [::1]")
	case rt.Listener.Port() == 0:
		return srv, dnsredirectHpDnsListener{}, errors.New("no listener port")
	}
	p := rt.Listener.Port()
	// The port in network byte order, in the low 16 bits as the kernel
	// stores it.
	return srv, dnsredirectHpDnsListener{Addr: addr6(la), Port: uint32(p>>8 | (p&0xff)<<8)}, nil
}

// addr6 is a as the programs keep it: IPv6, an IPv4 address mapped, in
// network byte order.
func addr6(a netip.Addr) dnsredirectHpAddr6 {
	b := a.As16()
	var out dnsredirectHpAddr6
	for i := range out.A {
		// The bytes as they are in memory: network order.
		out.A[i] = uint32(b[4*i]) | uint32(b[4*i+1])<<8 | uint32(b[4*i+2])<<16 | uint32(b[4*i+3])<<24
	}
	return out
}

// Close detaches and unloads the programs.
func (r *Redirect) Close() error {
	var errs []error
	for _, lk := range r.links {
		errs = append(errs, lk.Close())
	}
	r.links = nil
	errs = append(errs, r.objs.Close())
	return errors.Join(errs...)
}

// ErrNoCgroup2 is returned for a process not in a cgroup v2 hierarchy
// of its own: a node with cgroup v1 (or hybrid) has no directory per
// container to attach to.
var ErrNoCgroup2 = errors.New("no cgroup v2 directory")

// OpenCgroup opens the cgroup v2 directory of process pid, as the host
// sees it (the cgroup namespace of pid 1): a process in a container,
// such as hallpass-node, sees its own cgroup namespace and its own
// /sys/fs/cgroup. It mounts a cgroup2 file system of its own, detached,
// from a thread in pid 1's cgroup namespace, which needs CAP_SYS_ADMIN.
func OpenCgroup(pid int) (int, error) {
	type result struct {
		fd  int
		err error
	}
	done := make(chan result, 1)
	go func() {
		// The thread changes cgroup namespace: never unlocked, it exits
		// with the goroutine.
		runtime.LockOSThread()
		fd, err := openCgroup(pid)
		done <- result{fd, err}
	}()
	r := <-done
	return r.fd, r.err
}

func openCgroup(pid int) (int, error) {
	ns, err := unix.Open("/proc/1/ns/cgroup", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	err = unix.Setns(ns, unix.CLONE_NEWCGROUP)
	unix.Close(ns)
	if err != nil {
		return -1, fmt.Errorf("enter the host's cgroup namespace: %w", err)
	}
	// Read from this thread: the paths are relative to its cgroup
	// namespace.
	path, err := cgroup2Path(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return -1, err
	}
	fsfd, err := unix.Fsopen("cgroup2", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, fmt.Errorf("fsopen cgroup2: %w", err)
	}
	defer unix.Close(fsfd)
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return -1, fmt.Errorf("fsconfig cgroup2: %w", err)
	}
	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("fsmount cgroup2: %w", err)
	}
	defer unix.Close(mfd)
	fd, err := unix.Openat(mfd, "."+path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open cgroup %s: %w", path, err)
	}
	return fd, nil
}

// cgroup2Path returns the cgroup v2 path of a /proc/PID/cgroup file: its
// only line, "0::/path". More lines (cgroup v1 or hybrid), the root or
// a path outside the reader's namespace give ErrNoCgroup2.
func cgroup2Path(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		if l := strings.TrimSpace(s.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	if err := s.Err(); err != nil {
		return "", err
	}
	if len(lines) != 1 {
		return "", ErrNoCgroup2
	}
	path, ok := strings.CutPrefix(lines[0], "0::")
	if !ok || !strings.HasPrefix(path, "/") || path == "/" || strings.Contains(path, "/..") {
		return "", ErrNoCgroup2
	}
	return path, nil
}

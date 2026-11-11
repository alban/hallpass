// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

// Sorting probes. Resolvers sort the addresses of a name (RFC 6724) by
// connecting a UDP socket to each and reading the source address the
// kernel picked (getsockname), sending nothing: glibc to port 0, musl to
// 65535, Go to 53. Asked about, each would prompt, the lookup waiting
// behind it. Such a connect that no rule decides is done by the monitor
// on a copy of the socket (pidfd_getfd), after shutting its sending side
// (shutdown SHUT_WR): getsockname gives the source, and every send on
// the socket fails with EPIPE, after another connect too.

// probe emulates connect n when it looks like a sorting probe: to port 0
// or 65535 of a UDP socket, or to port 53 of an address of the session's
// DNS answers that is not a name server. It reports false when it did
// not answer n.
func (m *Monitor) probe(l *listener, n seccomp.Notif, sc seccomp.Rule, items []item) bool {
	if sc.Name != "connect" || len(items) != 1 || items[0].obj.Inet == nil || items[0].obj.Inet.Proto != unix.IPPROTO_UDP {
		return false
	}
	dst := items[0].obj.Inet.Addr
	if dst.Addr().Is6() && dst.Addr().IsLinkLocalUnicast() {
		// Its scope id is not read.
		return false
	}
	switch dst.Port() {
	case 0, 65535:
	case 53:
		a := dst.Addr().Unmap()
		if _, server := m.dnsFwd[a]; server || m.names == nil || len(m.names.Lookup(a)) == 0 {
			return false
		}
	default:
		return false
	}
	r, ok := l.n.(fdReplacer)
	if !ok {
		return false
	}
	cp, err := procfs.GetFD(int(n.PID), int(int32(n.Args[0])))
	if err != nil {
		return false
	}
	defer unix.Close(cp)
	domain, err := unix.GetsockoptInt(cp, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return false
	}
	// The fd may have been replaced since it was read.
	if p, err := unix.GetsockoptInt(cp, unix.SOL_SOCKET, unix.SO_PROTOCOL); err != nil || p != unix.IPPROTO_UDP {
		return false
	}
	var sa unix.Sockaddr
	switch {
	case domain == unix.AF_INET && dst.Addr().Is4():
		sa = &unix.SockaddrInet4{Port: int(dst.Port()), Addr: dst.Addr().As4()}
	case domain == unix.AF_INET6:
		sa = &unix.SockaddrInet6{Port: int(dst.Port()), Addr: dst.Addr().As16()}
	default:
		return false
	}
	// Shut first: no send of another thread reaches dst. An unconnected
	// socket answers ENOTCONN, shut all the same.
	if err := unix.Shutdown(cp, unix.SHUT_WR); err != nil && !errors.Is(err, unix.ENOTCONN) {
		return false
	}
	why := []Reason{{Builtin: "probe"}}
	if err := unix.Connect(cp, sa); err != nil {
		var e unix.Errno
		if !errors.As(err, &e) {
			e = unix.EIO
		}
		m.report(n, sc.Name, rules.OpConnect, objects(items), false, why)
		_ = l.n.Deny(n.ID, int32(e))
		return true
	}
	m.report(n, sc.Name, rules.OpConnect, objects(items), true, why)
	_ = r.Return(n.ID, 0)
	return true
}

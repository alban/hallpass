// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/alban/hallpass/internal/netdiag"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// netDest is where a network syscall sends: its fd, flags and the
// sockaddrs it carries.
type netDest struct {
	fd    int
	flags uint64
	addrs []procfs.MsgName
}

// netDests reads the destinations of n. A sockaddr pointer of zero, or
// of length zero, is no destination: the kernel uses the connected peer.
func netDests(n seccomp.Notif, sc seccomp.Rule) (netDest, error) {
	d := netDest{fd: int(int32(n.Args[0]))}
	switch sc.Name {
	case "connect":
		d.addrs = []procfs.MsgName{{Addr: n.Args[1], Len: uint64(uint32(n.Args[2]))}}
	case "sendto":
		d.flags = n.Args[3]
		d.addrs = []procfs.MsgName{{Addr: n.Args[4], Len: uint64(uint32(n.Args[5]))}}
	case "sendmsg":
		d.flags = n.Args[2]
		names, err := procfs.ReadMsgNames(n.PID, n.Args[1], 1, false)
		if err != nil {
			return d, err
		}
		d.addrs = names
	case "sendmmsg":
		d.flags = n.Args[3]
		vlen := min(int(uint32(n.Args[2])), procfs.UIOMaxIOV)
		names, err := procfs.ReadMsgNames(n.PID, n.Args[1], vlen, true)
		if err != nil {
			return d, err
		}
		d.addrs = names
	}
	var out []procfs.MsgName
	for _, a := range d.addrs {
		if a.Addr != 0 && a.Len != 0 {
			out = append(out, a)
		}
	}
	d.addrs = out
	return d, nil
}

// handleNet decides a connect, or a send with a destination address, or
// returns ask (see handle).
//
// In lite mode the sockaddr is read from the target's memory, which
// another thread of the target can change after the check (TOCTOU), like
// a path. In strict mode the kernel checks the address it copied.
func (m *Monitor) handleNet(l *listener, n seccomp.Notif, sc seccomp.Rule) (ask func()) {
	cont := func() {
		if err := l.n.Continue(n.ID); err != nil && !errors.Is(err, unix.ENOENT) {
			m.warn("continue: " + err.Error())
		}
	}
	d, err := netDests(n, sc)
	if err != nil {
		_ = l.n.Deny(n.ID, int32(unix.EFAULT))
		return
	}
	if len(d.addrs) == 0 {
		cont()
		return
	}
	op := rules.OpSend
	if sc.Name == "connect" {
		op = rules.OpConnect
	}
	// Unknown when the fd cannot be copied: decided on the address alone.
	si, siErr := procfs.Socket(int(n.PID), d.fd)
	if siErr == nil {
		switch {
		case si.Domain != unix.AF_INET && si.Domain != unix.AF_INET6 && si.Domain != unix.AF_UNIX:
			cont()
			return
		case op == rules.OpSend && si.Domain == unix.AF_UNIX && si.Type != unix.SOCK_DGRAM:
			// Stream and seqpacket sockets ignore the address.
			cont()
			return
		case op == rules.OpSend && si.Type == unix.SOCK_STREAM && (si.Protocol == unix.IPPROTO_TCP || si.Protocol == unix.IPPROTO_MPTCP):
			if d.flags&unix.MSG_FASTOPEN == 0 {
				// TCP ignores the address of a send.
				cont()
				return
			}
			op = rules.OpConnect
		}
	}

	root := "/"
	if m.procRoot {
		root = procfs.ProcRoot(n.PID)
	}
	var items []item
	seen := map[string]bool{}
	for _, a := range d.addrs {
		sa, ok, err := procfs.ReadSockaddr(n.PID, a.Addr, a.Len)
		if err != nil {
			_ = l.n.Deny(n.ID, int32(errnoOf(err)))
			return
		}
		if !ok && sa.Family == unix.AF_UNSPEC && sa.Inet.IsValid() && op == rules.OpSend &&
			(siErr != nil || si.Domain == unix.AF_INET) {
			// Datagram sends of AF_INET sockets take AF_UNSPEC for
			// AF_INET (AF_INET6 sockets ignore the address).
			sa.Family, ok = unix.AF_INET, true
		}
		if !ok {
			// The kernel fails it, or it reaches no peer by
			// address (AF_UNSPEC disconnects).
			continue
		}
		var obj rules.Object
		switch sa.Family {
		case unix.AF_INET, unix.AF_INET6:
			if siErr == nil && si.Domain == unix.AF_UNIX {
				continue // EINVAL
			}
			proto := uint16(si.Protocol)
			if proto == unix.IPPROTO_MPTCP {
				// Falls back to TCP: the same rules.
				proto = unix.IPPROTO_TCP
			}
			obj.Inet = &rules.InetObject{Proto: proto, Addr: sa.Inet}
		case unix.AF_UNIX:
			if siErr == nil && si.Domain != unix.AF_UNIX {
				continue // EAFNOSUPPORT
			}
			u := &rules.UnixObject{Abstract: sa.Abstract, Name: sa.Name, Type: si.Type}
			if !sa.Abstract {
				if m.kernel != nil {
					ref := 0
					if m.procRoot {
						ref = l.root
					}
					if same, err := procfs.SameView(n.PID, ref); err == nil && !same {
						m.toBPF(l, n, sc, op)
						return
					}
				}
				t, err := procfs.Resolve(n.PID, root, procfs.AtFDCWD, sa.Path, true)
				if err != nil {
					obj := rules.Object{Unix: &rules.UnixObject{Path: sa.Path}}
					m.deny(l, n, sc, op, []rules.Object{obj}, []Reason{{Builtin: "unresolvable"}})
					return
				}
				if _, err := os.Stat(filepath.Join(root, t.Path)); errors.Is(err, os.ErrNotExist) {
					continue // ENOENT
				}
				u.Path = t.Path
			}
			obj.Unix = u
		default:
			continue
		}
		var key string
		if obj.Inet != nil {
			key = obj.Inet.String()
		} else {
			key = obj.Unix.String()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, item{obj: obj, path: key})
	}
	if len(items) == 0 {
		cont()
		return
	}
	m.markOwnListeners(n, root, op, items)
	return m.decide(l, n, sc, op, items)
}

// markOwnListeners sets the OwnListener fact of the items whose listener
// (loopback TCP, or bound unix socket) a workload process holds. Lite
// detection, racy: the fd tables are read after the sock_diag dump.
// Without access to the target's network namespace, no fact.
func (m *Monitor) markOwnListeners(n seccomp.Notif, root string, op rules.Op, items []item) {
	var d *netdiag.Diag
	defer func() {
		if d != nil {
			d.Close()
		}
	}()
	diag := func() *netdiag.Diag {
		if d == nil {
			var err error
			if d, err = netdiag.Open(int(n.PID)); err != nil {
				d = nil
			}
		}
		return d
	}
	var unixSocks []netdiag.UnixSocket
	unixDone := false
	var members map[int]bool
	owned := func(cands []uint64) bool {
		if len(cands) == 0 {
			return false
		}
		if members == nil {
			members = netdiag.Descendants(m.roots())
		}
		want := map[uint64]bool{}
		for _, c := range cands {
			want[c] = true
		}
		return len(netdiag.Held(want, func(pid int) bool { return members[pid] })) == len(want)
	}
	for _, it := range items {
		switch o := it.obj; {
		case o.Inet != nil:
			if op != rules.OpConnect || o.Inet.Proto != unix.IPPROTO_TCP || !o.Inet.Addr.Addr().IsLoopback() || diag() == nil {
				continue
			}
			ls, err := d.TCPListeners(o.Inet.Addr.Port())
			if err != nil {
				continue
			}
			o.Inet.OwnListener = owned(netdiag.TCPCandidates(ls, o.Inet.Addr))
		case o.Unix != nil:
			if !unixDone {
				unixDone = true
				if diag() != nil {
					unixSocks, _ = d.UnixSockets()
				}
			}
			var dev, ino uint64
			if !o.Unix.Abstract {
				var err error
				if dev, ino, err = netdiag.SocketFile(int(n.PID), filepath.Join(root, o.Unix.Path)); err != nil {
					continue
				}
			}
			var cands []uint64
			for _, s := range unixSocks {
				if !s.Listen && s.Type != unix.SOCK_DGRAM {
					continue
				}
				if o.Unix.Abstract {
					if s.Abstract && s.Name == o.Unix.Name {
						cands = append(cands, s.Inode)
					}
				} else if !s.Abstract && s.VFSIno == ino && s.VFSDev == dev {
					cands = append(cands, s.Inode)
				}
			}
			o.Unix.OwnListener = owned(cands)
		}
	}
}

// roots returns the root process of each attached workload.
func (m *Monitor) roots() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]int, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, l.root)
	}
	return out
}

// errnoOf returns the errno of err, EFAULT if it has none.
func errnoOf(err error) unix.Errno {
	var e unix.Errno
	if errors.As(err, &e) {
		return e
	}
	return unix.EFAULT
}

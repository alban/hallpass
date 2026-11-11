// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
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
		if m.names != nil && (sc.Name == "sendmsg" || sc.Name == "sendmmsg") {
			// glibc's resolver connects its socket to the server,
			// then sends without an address: the connect was decided.
			if si, err := procfs.Socket(int(n.PID), d.fd); err == nil && si.Type == unix.SOCK_DGRAM && (m.names.Server(si.Peer) || m.isForwarder(si.Peer)) {
				for _, name := range m.queryNames(n, sc) {
					m.names.Observe(name)
				}
			}
		}
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
	if m.names != nil && op == rules.OpSend && siErr == nil && si.Type == unix.SOCK_DGRAM {
		var names []string
		for i, it := range items {
			if it.obj.Inet != nil && m.names.Server(it.obj.Inet.Addr) {
				if names == nil {
					names = m.queryNames(n, sc)
				}
				items[i].dns = names
			}
		}
	}
	m.markOwnListeners(n, root, op, items)
	if i := m.unproxied(items); i >= 0 {
		m.deny(l, n, sc, op, []rules.Object{items[i].obj}, []Reason{{Builtin: "no-proxy"}})
		return nil
	}
	m.nameItems(items)
	if len(items) == 1 && items[0].obj.Inet != nil && m.toProxy(l, n, sc, op, &items[0]) {
		return nil
	}
	return m.decide(l, n, sc, op, items)
}

// toProxy answers a connect to port 443 of a host with http rules (see
// proxiedNames), and reports true: a deny rule on the destination still
// denies it; otherwise the connection is swapped to the proxy, which
// decides each request: the address itself is not asked about. A host
// proxied for a credential only is decided as any connect, and swapped
// once allowed (it.proxy, see allow). It reports false for any other
// connect, or when it could not swap (the connect is then decided as
// usual).
func (m *Monitor) toProxy(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op, it *item) bool {
	rs := m.currentRules()
	names, byRules := m.proxiedNames(rs, it.obj.Inet)
	tcpConnect := sc.Name == "connect" && it.obj.Inet.Proto == 6
	switch {
	case names == nil:
		return false
	case !byRules:
		if tcpConnect {
			it.proxy = names
		}
		return false
	case !tcpConnect:
		// QUIC (UDP 443) or TCP Fast Open to a host with http rules
		// would go around the proxy: the client falls back to a
		// connect.
		m.deny(l, n, sc, op, []rules.Object{it.obj}, []Reason{{Builtin: "proxied-host"}})
		return true
	}
	if v, id, ok := rules.Eval(rs, rules.OpConnect, it.obj, m.now()); ok && v == rules.Deny {
		m.deny(l, n, sc, rules.OpConnect, []rules.Object{it.obj}, []Reason{{Rule: id}})
		return true
	}
	switch m.swapToProxy(l, n, sc, *it, names, Reason{Builtin: "proxy"}) {
	case swapOtherNetns:
		return false
	case swapFailed:
		// Fail closed: a host with http rules is reached through the
		// proxy or not at all (the workload could make the swap fail,
		// e.g. with RLIMIT_NOFILE, to connect directly).
		m.deny(l, n, sc, rules.OpConnect, []rules.Object{it.obj}, []Reason{{Builtin: "proxy-failed"}})
	}
	return true
}

// swapResult is what swapToProxy did.
type swapResult int

const (
	// swapped: the connect returned 0, on a socket the proxy serves.
	swapped swapResult = iota
	// swapAnswered: the connect failed as the kernel would have failed
	// it (EISCONN, EALREADY), or its thread is gone.
	swapAnswered
	// swapOtherNetns: the socket is of another network namespace than
	// the session's (one the workload made, e.g. unshare -rn): it is not
	// swapped, and its connect is decided as any other, by the rules;
	// it leaves through a relay whose own connect is mediated.
	swapOtherNetns
	// swapFailed: not swapped, nothing answered.
	swapFailed
)

// swapToProxy answers connect n of it: the workload's socket is replaced
// by one end of a loopback TCP pair whose other end the proxy serves,
// and the connect returns 0. The pair is made by Config.Pair, in the
// network namespace of the session (Config.Netns), which must be the
// socket's: a socket keeps the network namespace it was made in, so
// the end installed in the workload reaches nothing the workload's own
// sockets could not, if it is connected again. A socket connected
// already, or connecting, is answered as the kernel would (EISCONN,
// EALREADY), never swapped nor continued.
func (m *Monitor) swapToProxy(l *listener, n seccomp.Notif, sc seccomp.Rule, it item, names []string, why Reason) swapResult {
	r, ok := l.n.(fdReplacer)
	if !ok || !l.n.IDValid(n.ID) {
		return swapFailed
	}
	fd := int(int32(n.Args[0]))
	flags, err := fdFlags(int(n.PID), fd)
	if err != nil {
		return swapFailed
	}
	// Best effort: another thread can connect or close the fd after
	// this look; that only changes what the workload's own fd does.
	si, err := procfs.Socket(int(n.PID), fd)
	if err != nil {
		return swapFailed
	}
	switch {
	case si.Peer.IsValid(), si.Listening:
		_ = l.n.Deny(n.ID, int32(unix.EISCONN))
		return swapAnswered
	case si.Connecting:
		_ = l.n.Deny(n.ID, int32(unix.EALREADY))
		return swapAnswered
	case m.netns == 0 || si.Netns == 0:
		// Unknown (before Linux 5.14): fail closed.
		return swapFailed
	case si.Netns != m.netns:
		return swapOtherNetns
	case m.pair == nil:
		return swapFailed
	}
	client, server, err := m.pair(int(n.PID))
	if err != nil {
		m.warn("proxy: " + err.Error())
		return swapFailed
	}
	f, err := client.File()
	client.Close()
	if err != nil {
		server.Close()
		return swapFailed
	}
	defer f.Close()
	// Fd, each call, puts the descriptor in blocking mode: once only.
	cfd := int(f.Fd())
	// The duplicate shares the socket's flags: the workload's own.
	if err := unix.SetNonblock(cfd, flags&unix.O_NONBLOCK != 0); err != nil {
		server.Close()
		return swapFailed
	}
	var newfd uint32
	if flags&unix.O_CLOEXEC != 0 {
		newfd = unix.O_CLOEXEC
	}
	subject := buildSubject(n.PID, l.root)
	if err := r.ReplaceFD(n.ID, cfd, fd, newfd); err != nil {
		server.Close()
		if errors.Is(err, unix.ENOENT) {
			return swapAnswered
		}
		return swapFailed
	}
	if err := r.Return(n.ID, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		m.warn("proxy: " + err.Error())
	}
	m.report(n, sc.Name, rules.OpConnect, []rules.Object{it.obj}, true, []Reason{why})
	m.mu.Lock()
	p := m.proxy
	m.mu.Unlock()
	go p.Serve(server, it.obj.Inet.Addr, names, subject)
	return swapped
}

// nameItems sets the names of the inet items (InetObject.Names), for the
// host rules and the proxy: only when a rule has a host or the proxy a
// credential (whose host's connects it takes, whatever rule allows
// them), waiting at most dnsWait for the lookups in progress (the
// workload connects as soon as its own answer comes).
func (m *Monitor) nameItems(items []item) {
	m.mu.Lock()
	p := m.proxy
	m.mu.Unlock()
	if m.names == nil || !needNames(m.currentRules()) && (p == nil || !p.HasCredentials()) {
		return
	}
	for _, it := range items {
		if it.obj.Inet != nil {
			it.obj.Inet.Names = m.names.Match(it.obj.Inet.Addr.Addr(), dnsWait)
		}
	}
}

// needNames reports whether a rule of rs selects addresses by name: a
// host rule, or an http rule (its host is proxied).
func needNames(rs []rules.Rule) bool {
	return slices.ContainsFunc(rs, func(r rules.Rule) bool { return isHostRule(r) || r.Object.HTTP != nil })
}

// unproxied returns the index of an item to port 443 (TCP or UDP) that
// cannot go through the proxy although it must, or -1: the http rules or
// the credentials (Config.Credentials) of the session need its proxy and
// names its rules match, and it lacks one of them (no proxy started,
// names off or display only). Such a connection is denied rather than
// decided without the http rules, or sent with a placeholder.
func (m *Monitor) unproxied(items []item) int {
	m.mu.Lock()
	p := m.proxy
	m.mu.Unlock()
	if p != nil && m.names != nil && m.names.Matches() {
		return -1
	}
	if !m.creds && !slices.ContainsFunc(m.currentRules(), func(r rules.Rule) bool { return r.Object.HTTP != nil }) {
		return -1
	}
	return slices.IndexFunc(items, func(it item) bool {
		o := it.obj.Inet
		return o != nil && o.Addr.Port() == 443 && (o.Proto == unix.IPPROTO_TCP || o.Proto == unix.IPPROTO_UDP)
	})
}

func isHostRule(r rules.Rule) bool {
	return r.Object.Inet != nil && r.Object.Inet.Host != ""
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

// maxQuery bounds the bytes read of a DNS query: its question comes
// first.
const maxQuery = 512

// dnsWait bounds how long a prompt waits for hallpass's lookups of the
// names the workload just asked about (Names.Lookup).
const dnsWait = 500 * time.Millisecond

// queryNames returns the names the DNS queries that send n carries ask
// about (dnsnames.QueryNames). Lite mode reads them from the target's
// memory: the workload chooses them, and they are display only.
func (m *Monitor) queryNames(n seccomp.Notif, sc seccomp.Rule) []string {
	var msgs [][]byte
	switch sc.Name {
	case "sendto":
		if b := procfs.ReadData(n.PID, n.Args[1], int(min(n.Args[2], maxQuery))); b != nil {
			msgs = append(msgs, b)
		}
	case "sendmsg":
		msgs = procfs.ReadMsgData(n.PID, n.Args[1], 1, false, maxQuery)
	case "sendmmsg":
		msgs = procfs.ReadMsgData(n.PID, n.Args[1], min(int(uint32(n.Args[2])), procfs.UIOMaxIOV), true, maxQuery)
	}
	var out []string
	for _, b := range msgs {
		for _, name := range dnsnames.QueryNames(b) {
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// namesOf returns the names of the address of obj, an Inet object
// (Request.Names), or else its reverse DNS names (UnverifiedNames).
func (m *Monitor) namesOf(obj rules.Object) (names, unverified []string) {
	if m.names == nil || obj.Inet == nil {
		return nil, nil
	}
	if names = m.names.Lookup(obj.Inet.Addr.Addr(), dnsWait); len(names) > 0 {
		return names, nil
	}
	return nil, m.names.Unverified(obj.Inet.Addr.Addr(), dnsWait)
}

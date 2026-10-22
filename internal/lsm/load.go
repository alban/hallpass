// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// attachOrder lists the programs in the order Load attaches them, which is
// also the order of their link fds in FDs. task_alloc comes first, so no
// member can fork unmarked once the others run.
var attachOrder = []string{
	"hp_task_alloc", "hp_sb_alloc", "hp_sb_free", "hp_sb_kern_mount", "hp_task_kill", "hp_file_send_sigiotask",
	"hp_file_open", "hp_path_mknod", "hp_path_mkdir", "hp_path_rmdir", "hp_path_unlink",
	"hp_path_symlink", "hp_path_link", "hp_path_rename", "hp_path_truncate", "hp_bprm_check_security",
	"hp_socket_post_create", "hp_sk_free", "hp_socket_connect", "hp_socket_sendmsg",
	"hp_unix_stream_connect", "hp_unix_may_send",
}

// tracingOrder lists the tracing programs, attached after attachOrder, with
// their hook: the sys_exit tracepoint, then fexit of a kernel function
// (listenHook: the hook depends on the kernel).
var tracingOrder = []struct{ prog, hook string }{
	{"hp_sys_exit", sysExitHook},
	{"hp_listen", listenHook},
}

// listenHook stands for the function of hp_listen: __inet_listen_sk, which
// MPTCP listeners go through too, else inet_listen on kernels before 6.7.
const listenHook = "listen"

// tracingHook returns the kernel function or tracepoint of hook.
func tracingHook(kernel *btf.Spec, hook string) string {
	if hook != listenHook {
		return hook
	}
	var fn *btf.Func
	if kernel.TypeByName("__inet_listen_sk", &fn) == nil {
		return "__inet_listen_sk"
	}
	return "inet_listen"
}

func programsByName(p *hallpassPrograms) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		"hp_task_alloc": p.HpTaskAlloc, "hp_sb_alloc": p.HpSbAlloc, "hp_sb_free": p.HpSbFree,
		"hp_sb_kern_mount": p.HpSbKernMount, "hp_task_kill": p.HpTaskKill,
		"hp_file_send_sigiotask": p.HpFileSendSigiotask, "hp_file_open": p.HpFileOpen,
		"hp_path_mknod": p.HpPathMknod, "hp_path_mkdir": p.HpPathMkdir,
		"hp_path_rmdir": p.HpPathRmdir, "hp_path_unlink": p.HpPathUnlink,
		"hp_path_symlink": p.HpPathSymlink, "hp_path_link": p.HpPathLink,
		"hp_path_rename": p.HpPathRename, "hp_path_truncate": p.HpPathTruncate, "hp_bprm_check_security": p.HpBprmCheckSecurity,
		"hp_socket_post_create": p.HpSocketPostCreate, "hp_sk_free": p.HpSkFree,
		"hp_socket_connect": p.HpSocketConnect, "hp_socket_sendmsg": p.HpSocketSendmsg,
		"hp_unix_stream_connect": p.HpUnixStreamConnect, "hp_unix_may_send": p.HpUnixMaySend,
		"hp_sys_exit": p.HpSysExit, "hp_listen": p.HpListen,
	}
}

// Load loads and attaches the programs. With logAllowed, allowed operations
// are reported too, not only denials. Needs root.
func Load(logAllowed bool) (*LSM, error) {
	spec, err := loadHallpass()
	if err != nil {
		return nil, err
	}
	if err := spec.Variables["log_allowed"].Set(logAllowed); err != nil {
		return nil, err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("kernel BTF: %w", err)
	}
	listen := tracingHook(kernel, listenHook)
	spec.Programs["hp_listen"].AttachTo = listen
	if err := spec.Variables["listen_sk"].Set(listen != "inet_listen"); err != nil {
		return nil, err
	}
	var objs hallpassObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load BPF programs: %+v", ve)
		}
		return nil, fmt.Errorf("load BPF programs: %w", err)
	}
	// The links hold the programs, and the programs their maps.
	defer objs.hallpassPrograms.Close()
	l := newLSM()
	m := &objs.hallpassMaps
	l.members, l.protected, l.grants, l.rules, l.proc, l.events = m.Members, m.Protected, m.Grants, m.Rules, m.Proc, m.Events
	l.cfgs = m.Sessions
	l.inet, l.abstract = m.InetRules, m.AbstractRules
	m.OwnedSbs.Close()
	m.Listeners.Close()
	m.ListenSks.Close()
	m.Socks.Close()
	m.Scratch.Close()
	progs := programsByName(&objs.hallpassPrograms)
	for _, name := range attachOrder {
		prog := progs[name]
		if prog == nil {
			l.Close()
			return nil, fmt.Errorf("no program %s", name)
		}
		lk, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attach %s: %w", prog, err)
		}
		l.addLink(lk)
	}
	// hp_sys_exit removes each grant (GrantOnce) when its syscall returns.
	for _, t := range tracingOrder {
		prog := progs[t.prog]
		lk, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("attach %s: %w", prog, err)
		}
		l.addLink(lk)
	}
	if err := l.start(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// addLink keeps lk, and its fd for FDs.
func (l *LSM) addLink(lk link.Link) {
	l.links = append(l.links, lk)
	if f, ok := lk.(interface{ FD() int }); ok {
		l.linkFDs = append(l.linkFDs, f.FD())
	}
}

func (l *LSM) start() error {
	var err error
	l.rd, err = ringbuf.NewReader(l.events)
	return err
}

// sysExitHook names the link of hp_sys_exit, after those of attachOrder.
const sysExitHook = "sys_exit"

// hookIDs returns the kernel BTF IDs of the LSM hooks of attachOrder, then
// of the hooks of tracingOrder.
func hookIDs() ([]btf.TypeID, []string, error) {
	spec, err := loadHallpass()
	if err != nil {
		return nil, nil, err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("kernel BTF: %w", err)
	}
	ids := make([]btf.TypeID, len(attachOrder), len(attachOrder)+len(tracingOrder))
	hooks := make([]string, len(attachOrder), len(attachOrder)+len(tracingOrder))
	for i, name := range attachOrder {
		ps := spec.Programs[name]
		if ps == nil {
			return nil, nil, fmt.Errorf("no program %s", name)
		}
		fn, err := kernel.AnyTypeByName("bpf_lsm_" + ps.AttachTo)
		if err != nil {
			return nil, nil, fmt.Errorf("hook %s: %w", ps.AttachTo, err)
		}
		if ids[i], err = kernel.TypeID(fn); err != nil {
			return nil, nil, err
		}
		hooks[i] = ps.AttachTo
	}
	for _, t := range tracingOrder {
		name := tracingHook(kernel, t.hook)
		if t.hook == sysExitHook {
			name = "btf_trace_" + sysExitHook
		}
		typ, err := kernel.AnyTypeByName(name)
		if err != nil {
			return nil, nil, fmt.Errorf("hook %s: %w", t.hook, err)
		}
		id, err := kernel.TypeID(typ)
		if err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		hooks = append(hooks, tracingHook(kernel, t.hook))
	}
	return ids, hooks, nil
}

// checkLink makes sure lk attaches a BPF-LSM program to hook (BTF ID id), a
// program to the sys_exit tracepoint, or an fexit program to function hook,
// so a helper cannot hand over a link that enforces nothing. It only needs
// the link fd, no privileges.
func checkLink(lk link.Link, hook string, id btf.TypeID, fexit bool) error {
	info, err := lk.Info()
	if err != nil {
		return fmt.Errorf("link for %s: %w", hook, err)
	}
	want := ebpf.AttachLSMMac
	if fexit {
		want = ebpf.AttachTraceFExit
	}
	if hook == sysExitHook {
		if rt := info.RawTracepoint(); info.Type != link.RawTracepointType || rt == nil || rt.Name != sysExitHook {
			return fmt.Errorf("link is not attached to %s", hook)
		}
		return nil
	}
	t := info.Tracing()
	if info.Type != link.TracingType || t == nil || uint32(t.AttachType) != uint32(want) || btf.TypeID(t.TargetBtfId) != id {
		return fmt.Errorf("link is not attached to %s", hook)
	}
	return nil
}

// maps are l's maps in the order of FDs, with their types.
func (l *LSM) maps() ([]**ebpf.Map, []ebpf.MapType) {
	return []**ebpf.Map{&l.members, &l.protected, &l.grants, &l.rules, &l.proc, &l.events, &l.cfgs, &l.inet, &l.abstract},
		[]ebpf.MapType{ebpf.TaskStorage, ebpf.TaskStorage, ebpf.TaskStorage, ebpf.Hash, ebpf.Hash, ebpf.RingBuf, ebpf.Hash, ebpf.LPMTrie, ebpf.LPMTrie}
}

// FDs returns the fds that make up l, in the order FromFDs expects: the
// maps, then the links. They stay owned by l.
func (l *LSM) FDs() []int {
	var fds []int
	maps, _ := l.maps()
	for _, m := range maps {
		fds = append(fds, (*m).FD())
	}
	return append(fds, l.linkFDs...)
}

// FromFDs rebuilds an LSM from fds received from the process that loaded it
// (see FDs) and takes ownership of them. It needs no privilege: updating a
// BPF map only needs a writable fd to it.
func FromFDs(fds []int) (*LSM, error) {
	l := newLSM()
	maps, want := l.maps()
	nfds := len(want) + len(attachOrder) + len(tracingOrder)
	if len(fds) != nfds {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("got %d fds, want %d", len(fds), nfds)
	}
	ids, hooks, err := hookIDs()
	for i, fd := range fds {
		if err != nil {
			unix.Close(fd)
			continue
		}
		if i >= len(want) {
			var lk link.Link
			if lk, err = link.NewFromFD(fd); err != nil {
				err = fmt.Errorf("fd %d: %w", i, err)
				continue
			}
			l.addLink(lk)
			j := i - len(want)
			err = checkLink(lk, hooks[j], ids[j], j > len(attachOrder))
			continue
		}
		var m *ebpf.Map
		if m, err = ebpf.NewMapFromFD(fd); err != nil {
			err = fmt.Errorf("fd %d: %w", i, err)
			continue
		}
		*maps[i] = m
		if m.Type() != want[i] {
			err = fmt.Errorf("fd %d: map type %s, want %s", i, m.Type(), want[i])
		}
	}
	if err == nil {
		err = l.start()
	}
	if err == nil {
		err = l.adopt()
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// adopt reads the rules and procs already in the maps, left by a previous
// owner of the programs (the node agent before it restarted): new cookies
// must not reuse theirs, and ResumeSession takes them over.
func (l *LSM) adopt() error {
	err := adoptMap(l, l.rules, "rules", &l.stale, func(k hallpassRuleKey, v hallpassRuleVal) (uint32, nodeKey) {
		nk := nodeKey{k.Parent, cstr(k.Name[:])}
		if v.Cookie != 0 {
			l.cookies[nk] = v.Cookie
			l.next = max(l.next, v.Cookie+1)
		}
		return k.Session, nk
	})
	if err != nil {
		return err
	}
	if err := adoptMap(l, l.proc, "proc rules", &l.staleProcs, sessionOf[hallpassProcKey, hallpassProcVal]); err != nil {
		return err
	}
	var id uint32
	var cfg hallpassSessionCfg
	sit := l.cfgs.Iterate()
	for sit.Next(&id, &cfg) {
		if l.staleCfg == nil {
			l.staleCfg = map[uint32]hallpassSessionCfg{}
		}
		l.staleCfg[id] = cfg
		l.nextID = max(l.nextID, id+1)
	}
	if err := sit.Err(); err != nil {
		return fmt.Errorf("read the session settings: %w", err)
	}
	if err := adoptMap(l, l.inet, "inet rules", &l.staleInet, sessionOf[hallpassInetKey, hallpassInetVal]); err != nil {
		return err
	}
	return adoptMap(l, l.abstract, "abstract unix rules", &l.staleAbs, sessionOf[hallpassAbstractKey, hallpassAbstractVal])
}

// sessionKey is a map key with the id of its session.
type sessionKey interface {
	comparable
	session() uint32
}

func (k hallpassProcKey) session() uint32     { return k.Session }
func (k hallpassInetKey) session() uint32     { return k.Session }
func (k hallpassAbstractKey) session() uint32 { return k.Session }

// sessionOf returns the session of key k, which stale maps keep as it is.
func sessionOf[K sessionKey, V any](k K, _ V) (uint32, K) { return k.session(), k }

// adoptMap reads the entries of m into *stale, by the session and key key
// returns, and keeps new sessions ids past theirs. what names m in errors.
func adoptMap[MK, K comparable, V any](l *LSM, m *ebpf.Map, what string, stale *map[uint32]map[K]V, key func(MK, V) (uint32, K)) error {
	var mk MK
	var v V
	it := m.Iterate()
	for it.Next(&mk, &v) {
		session, k := key(mk, v)
		if *stale == nil {
			*stale = map[uint32]map[K]V{}
		}
		if (*stale)[session] == nil {
			(*stale)[session] = map[K]V{}
		}
		(*stale)[session][k] = v
		l.nextID = max(l.nextID, session+1)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("read the %s: %w", what, err)
	}
	return nil
}

// DropStale deletes the rules found by FromFDs of the sessions not resumed
// (see ResumeSession).
func (l *LSM) DropStale() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, nodes := range l.stale {
		_ = syncMap(l.rules, nodes, nil, func(k nodeKey) hallpassRuleKey { return ruleKey(id, k) })
	}
	for _, procs := range l.staleProcs {
		_ = syncMap(l.proc, procs, nil, same)
	}
	for id := range l.staleCfg {
		_ = l.cfgs.Delete(id)
	}
	for _, m := range l.staleInet {
		_ = syncMap(l.inet, m, nil, same)
	}
	for _, m := range l.staleAbs {
		_ = syncMap(l.abstract, m, nil, same)
	}
	l.stale, l.staleProcs, l.staleCfg, l.staleInet, l.staleAbs = nil, nil, nil, nil, nil
}

// Close detaches the programs: no sandbox is restricted any more.
func (l *LSM) Close() error {
	if l.rd != nil {
		l.rd.Close()
	}
	for _, lk := range l.links {
		lk.Close()
	}
	maps, _ := l.maps()
	for _, m := range maps {
		if *m != nil {
			(*m).Close()
		}
	}
	l.mu.Lock()
	ss := make([]*Session, 0, len(l.sessions))
	for _, s := range l.sessions {
		ss = append(ss, s)
	}
	l.mu.Unlock()
	for _, s := range ss {
		s.release()
	}
	return nil
}

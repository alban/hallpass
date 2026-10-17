// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package lsm is strict mode's enforcement: BPF-LSM programs that check every
// write of the sandbox against the session's rules in the kernel, on the
// object being modified, so path races and bind mounts cannot get around the
// decisions taken by the seccomp supervisor.
//
// Files are named by their path inside their filesystem (see bpf/hallpass.bpf.c),
// so a rule on a host path also covers the same files reached through another
// bind mount or mount namespace.
package lsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	rootCookie = 1 << 63
	forever    = math.MaxUint64
	nameLen    = 256
)

// Rule allows or denies a host path: the path and everything below it (Tree)
// or that exact path only.
type Rule struct {
	Path    string // absolute and clean
	Tree    bool
	Deny    bool
	Expires time.Time // zero: never (deny rules never expire)
}

// ProcRule allows or denies writes to file Name in /proc/<pid>/ of processes
// named Comm outside the sandbox.
type ProcRule struct {
	Name, Comm string
	Deny       bool
	Expires    time.Time
}

// Event is one decision of the BPF programs.
type Event struct {
	PID     uint32
	Comm    string
	Op      string
	Path    string
	Allowed bool
}

var opNames = [...]string{1: "open", "create", "mkdir", "rmdir", "unlink", "symlink", "link", "rename", "truncate"}

// kfuncs are the kernel functions bpf/hallpass.bpf.c calls. The programs do
// not load without them.
var kfuncs = []string{"bpf_path_d_path", "bpf_preempt_disable", "bpf_preempt_enable", "bpf_task_from_pid", "bpf_task_release"}

// Supported reports whether the programs can load on this kernel: its BTF
// must have every kfunc they call.
func Supported() error {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("cannot read the kernel BTF: %w", err)
	}
	var missing []string
	for _, name := range kfuncs {
		var fn *btf.Func
		if err := spec.TypeByName(name, &fn); err != nil {
			missing = append(missing, name)
		}
	}
	if missing != nil {
		return fmt.Errorf("the kernel lacks the kfuncs %s, needed by strict mode (Linux 6.12 has them)", strings.Join(missing, ", "))
	}
	return nil
}

// Active reports whether BPF-LSM programs load and run on this kernel: they
// must be supported, and bpf must be in the active LSM list, otherwise
// programs attach but are never called.
func Active() error {
	if err := Supported(); err != nil {
		return err
	}
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return fmt.Errorf("cannot read the active LSMs: %w", err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if l == "bpf" {
			return nil
		}
	}
	return fmt.Errorf("BPF-LSM is not active (%s); add bpf to the lsm= kernel parameter", strings.TrimSpace(string(b)))
}

type nodeKey struct {
	parent uint64
	name   string
}

// LSM is a loaded and attached set of programs. It enforces the rules of
// any number of sessions (see Session), each with its own members.
type LSM struct {
	members, protected, grants, rules, proc, events *ebpf.Map
	// links keep the programs attached; closing them detaches.
	links []io.Closer
	// linkFDs are the links' fds, for handing them to another process.
	linkFDs []int
	rd      *ringbuf.Reader

	mu sync.Mutex
	// cookies name the rule nodes. They are shared by all sessions, whose
	// rule keys also have the session id.
	cookies  map[nodeKey]uint64
	next     uint64
	sessions map[uint32]*Session
	nextID   uint32
	// stale are the rules and procs found in the maps by FromFDs, per
	// session, for ResumeSession; see DropStale.
	stale      map[uint32]map[nodeKey]hallpassRuleVal
	staleProcs map[uint32]map[hallpassProcKey]hallpassProcVal
	reading    bool
}

// Session is one sandbox: its members are checked against its rules only.
// Its paths are those seen by a process, its root, which can be in another
// mount namespace and chroot (a container).
type Session struct {
	l  *LSM
	id uint32
	// mountinfo is the root's; inRoot resolves paths in its root
	// directory, "" for this process's.
	mountinfo string
	inRoot    string

	mu    sync.Mutex
	nodes map[nodeKey]hallpassRuleVal
	procs map[hallpassProcKey]hallpassProcVal
	// The last rules given to Sync, for re-syncing in GrantOnce.
	lastRules []Rule
	lastProcs []ProcRule
	// once are the grants (see GrantOnce) that may still be in use.
	once   []*grant
	seq    uint64
	fn     func(Event)
	done   chan struct{}
	closed bool
}

// grant is one GrantOnce: its paths keep their rule nodes, so their cookies
// stay valid, until the grant is used up.
type grant struct {
	pidfd int
	seq   uint64
	paths []string
}

func newLSM() *LSM {
	return &LSM{
		cookies:  map[nodeKey]uint64{},
		next:     1,
		sessions: map[uint32]*Session{},
		nextID:   1,
	}
}

// attachOrder lists the programs in the order Load attaches them, which is
// also the order of their link fds in FDs. task_alloc comes first, so no
// member can fork unmarked once the others run.
var attachOrder = []string{
	"hp_task_alloc", "hp_sb_alloc", "hp_sb_free", "hp_sb_kern_mount", "hp_task_kill", "hp_file_send_sigiotask",
	"hp_file_open", "hp_path_mknod", "hp_path_mkdir", "hp_path_rmdir", "hp_path_unlink",
	"hp_path_symlink", "hp_path_link", "hp_path_rename", "hp_path_truncate",
}

func programsByName(p *hallpassPrograms) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		"hp_task_alloc": p.HpTaskAlloc, "hp_sb_alloc": p.HpSbAlloc, "hp_sb_free": p.HpSbFree,
		"hp_sb_kern_mount": p.HpSbKernMount, "hp_task_kill": p.HpTaskKill,
		"hp_file_send_sigiotask": p.HpFileSendSigiotask, "hp_file_open": p.HpFileOpen,
		"hp_path_mknod": p.HpPathMknod, "hp_path_mkdir": p.HpPathMkdir,
		"hp_path_rmdir": p.HpPathRmdir, "hp_path_unlink": p.HpPathUnlink,
		"hp_path_symlink": p.HpPathSymlink, "hp_path_link": p.HpPathLink,
		"hp_path_rename": p.HpPathRename, "hp_path_truncate": p.HpPathTruncate,
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
	m.OwnedSbs.Close()
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
		l.links = append(l.links, lk)
		if f, ok := lk.(interface{ FD() int }); ok {
			l.linkFDs = append(l.linkFDs, f.FD())
		}
	}
	// Removes each grant (GrantOnce) when its syscall returns.
	lk, err := link.AttachTracing(link.TracingOptions{Program: objs.HpSysExit})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach %s: %w", objs.HpSysExit, err)
	}
	l.links = append(l.links, lk)
	if f, ok := lk.(interface{ FD() int }); ok {
		l.linkFDs = append(l.linkFDs, f.FD())
	}
	if err := l.start(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *LSM) start() error {
	var err error
	l.rd, err = ringbuf.NewReader(l.events)
	return err
}

// sysExitHook names the link of hp_sys_exit, after those of attachOrder.
const sysExitHook = "sys_exit"

// hookIDs returns the kernel BTF IDs of the LSM hooks of attachOrder, then
// of the sys_exit tracepoint.
func hookIDs() ([]btf.TypeID, []string, error) {
	spec, err := loadHallpass()
	if err != nil {
		return nil, nil, err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("kernel BTF: %w", err)
	}
	ids := make([]btf.TypeID, len(attachOrder)+1)
	hooks := make([]string, len(attachOrder)+1)
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
	tp, err := kernel.AnyTypeByName("btf_trace_" + sysExitHook)
	if err != nil {
		return nil, nil, fmt.Errorf("tracepoint %s: %w", sysExitHook, err)
	}
	if ids[len(attachOrder)], err = kernel.TypeID(tp); err != nil {
		return nil, nil, err
	}
	hooks[len(attachOrder)] = sysExitHook
	return ids, hooks, nil
}

// checkLink makes sure lk attaches a BPF-LSM program to hook (BTF ID id), or
// a program to the sys_exit tracepoint, so a helper cannot hand over a link
// that enforces nothing. It only needs the link fd, no privileges.
func checkLink(lk link.Link, hook string, id btf.TypeID) error {
	info, err := lk.Info()
	if err != nil {
		return fmt.Errorf("link for %s: %w", hook, err)
	}
	want := ebpf.AttachLSMMac
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

// FDs returns the fds that make up l, in the order FromFDs expects: the
// maps, then the links. They stay owned by l.
func (l *LSM) FDs() []int {
	fds := []int{l.members.FD(), l.protected.FD(), l.grants.FD(), l.rules.FD(), l.proc.FD(), l.events.FD()}
	return append(fds, l.linkFDs...)
}

// FromFDs rebuilds an LSM from fds received from the process that loaded it
// (see FDs) and takes ownership of them. It needs no privilege: updating a
// BPF map only needs a writable fd to it.
func FromFDs(fds []int) (*LSM, error) {
	want := []ebpf.MapType{ebpf.TaskStorage, ebpf.TaskStorage, ebpf.TaskStorage, ebpf.Hash, ebpf.Hash, ebpf.RingBuf}
	if len(fds) != len(want)+len(attachOrder)+1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("got %d fds, want %d", len(fds), len(want)+len(attachOrder)+1)
	}
	l := newLSM()
	maps := []**ebpf.Map{&l.members, &l.protected, &l.grants, &l.rules, &l.proc, &l.events}
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
			l.links = append(l.links, lk)
			if f, ok := lk.(interface{ FD() int }); ok {
				l.linkFDs = append(l.linkFDs, f.FD())
			}
			err = checkLink(lk, hooks[i-len(want)], ids[i-len(want)])
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
	var k hallpassRuleKey
	var v hallpassRuleVal
	it := l.rules.Iterate()
	for it.Next(&k, &v) {
		nk := nodeKey{k.Parent, cstr(k.Name[:])}
		if l.stale == nil {
			l.stale = map[uint32]map[nodeKey]hallpassRuleVal{}
		}
		if l.stale[k.Session] == nil {
			l.stale[k.Session] = map[nodeKey]hallpassRuleVal{}
		}
		l.stale[k.Session][nk] = v
		if v.Cookie != 0 {
			l.cookies[nk] = v.Cookie
			l.next = max(l.next, v.Cookie+1)
		}
		l.nextID = max(l.nextID, k.Session+1)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("read the rules: %w", err)
	}
	var pk hallpassProcKey
	var pv hallpassProcVal
	pit := l.proc.Iterate()
	for pit.Next(&pk, &pv) {
		if l.staleProcs == nil {
			l.staleProcs = map[uint32]map[hallpassProcKey]hallpassProcVal{}
		}
		if l.staleProcs[pk.Session] == nil {
			l.staleProcs[pk.Session] = map[hallpassProcKey]hallpassProcVal{}
		}
		l.staleProcs[pk.Session][pk] = pv
		l.nextID = max(l.nextID, pk.Session+1)
	}
	if err := pit.Err(); err != nil {
		return fmt.Errorf("read the proc rules: %w", err)
	}
	return nil
}

// DropStale deletes the rules found by FromFDs of the sessions not resumed
// (see ResumeSession).
func (l *LSM) DropStale() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, nodes := range l.stale {
		for k := range nodes {
			_ = l.rules.Delete(ruleKey(id, k))
		}
	}
	for _, procs := range l.staleProcs {
		for k := range procs {
			_ = l.proc.Delete(k)
		}
	}
	l.stale, l.staleProcs = nil, nil
}

// Close detaches the programs: no sandbox is restricted any more.
func (l *LSM) Close() error {
	if l.rd != nil {
		l.rd.Close()
	}
	for _, lk := range l.links {
		lk.Close()
	}
	for _, m := range []*ebpf.Map{l.members, l.protected, l.grants, l.rules, l.proc, l.events} {
		if m != nil {
			m.Close()
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

// NewSession starts a session with no rules: its members may write nothing.
// Its paths are those seen by process root, or by this process if root is
// 0.
func (l *LSM) NewSession(root int) (*Session, error) {
	return l.newSession(0, root)
}

// ResumeSession is NewSession with the given id: that of a session of a
// previous owner of the programs (see FromFDs), whose members are still
// marked with it. Its rules stay in force until the first Sync.
func (l *LSM) ResumeSession(id uint32, root int) (*Session, error) {
	if id == 0 {
		return nil, errors.New("session id 0")
	}
	return l.newSession(id, root)
}

// newSession starts session id, or a new one if id is 0.
func (l *LSM) newSession(id uint32, root int) (*Session, error) {
	s := &Session{
		l:         l,
		mountinfo: "/proc/self/mountinfo",
		nodes:     map[nodeKey]hallpassRuleVal{},
		procs:     map[hallpassProcKey]hallpassProcVal{},
		done:      make(chan struct{}),
	}
	if root != 0 {
		s.mountinfo = fmt.Sprintf("/proc/%d/mountinfo", root)
		s.inRoot = fmt.Sprintf("/proc/%d/root", root)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == 0 {
		id = l.nextID
	}
	if l.sessions[id] != nil {
		return nil, fmt.Errorf("session %d exists", id)
	}
	s.id = id
	if n := l.stale[id]; n != nil {
		s.nodes = n
		delete(l.stale, id)
	}
	if p := l.staleProcs[id]; p != nil {
		s.procs = p
		delete(l.staleProcs, id)
	}
	l.sessions[id] = s
	l.nextID = max(l.nextID, id+1)
	return s, nil
}

// ID is the session's id in the kernel.
func (s *Session) ID() uint32 { return s.id }

// Close deletes the session's rules: its remaining members, if any, may
// write nothing.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.lastRules, s.lastProcs = nil, nil
	var err error
	for k := range s.nodes {
		if e := s.l.rules.Delete(ruleKey(s.id, k)); e != nil && !errors.Is(e, ebpf.ErrKeyNotExist) {
			err = e
		}
	}
	for k := range s.procs {
		if e := s.l.proc.Delete(k); e != nil && !errors.Is(e, ebpf.ErrKeyNotExist) {
			err = e
		}
	}
	s.nodes, s.procs = nil, nil
	s.releaseLocked()
	return err
}

// release forgets s without touching the maps (LSM.Close).
func (s *Session) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseLocked()
}

func (s *Session) releaseLocked() {
	if s.closed {
		return
	}
	s.closed = true
	for _, g := range s.once {
		unix.Close(g.pidfd)
	}
	s.once = nil
	s.l.mu.Lock()
	if s.l.sessions[s.id] == s {
		delete(s.l.sessions, s.id)
	}
	s.l.mu.Unlock()
	close(s.done)
}

// AddMember puts thread tid, or process tid's main thread, in the session;
// the tasks it creates from then on are members too. Its other threads are
// not, and an execve from one of them would leave the sandbox: mark the
// thread that calls execve.
func (s *Session) AddMember(tid int) error {
	fd, err := unix.PidfdOpen(tid, unix.PIDFD_THREAD)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", tid, err)
	}
	defer unix.Close(fd)
	return s.l.members.Update(uint32(fd), s.id, ebpf.UpdateAny)
}

// Protect forbids members of all sessions to signal process pid (all its
// threads).
func (l *LSM) Protect(pid int) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(fd)
	return l.protected.Update(uint32(fd), uint8(1), ebpf.UpdateAny)
}

// Events calls fn for each decision on the session's members reported by
// the programs, until the session or the LSM is closed.
func (s *Session) Events(fn func(Event)) {
	s.mu.Lock()
	s.fn = fn
	s.mu.Unlock()
	s.l.mu.Lock()
	read := !s.l.reading
	s.l.reading = true
	s.l.mu.Unlock()
	if read {
		go s.l.read()
	}
	<-s.done
}

// read dispatches the events of the ring buffer to their sessions.
func (l *LSM) read() {
	for {
		rec, err := l.rd.Read()
		if err != nil {
			return
		}
		var ev hallpassEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			continue
		}
		l.mu.Lock()
		s := l.sessions[ev.Session]
		l.mu.Unlock()
		if s == nil {
			continue
		}
		s.mu.Lock()
		fn := s.fn
		s.mu.Unlock()
		if fn == nil {
			continue
		}
		e := Event{PID: ev.Pid, Comm: cstr(ev.Comm[:]), Path: cstr(ev.Path[:]), Allowed: ev.Ret == 0}
		if int(ev.Op) < len(opNames) {
			e.Op = opNames[ev.Op]
		}
		if n := cstr(ev.Name[:]); n != "" {
			if e.Path == "" {
				// Source of a link: the hook gets no path for its directory.
				e.Path = "…"
			}
			e.Path = strings.TrimSuffix(e.Path, "/") + "/" + n
		}
		fn(e)
	}
}

func cstr(b []int8) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}

// Sync makes the kernel's rules for the session match these, translating
// paths with the current mounts. Expired rules are dropped.
func (s *Session) Sync(rules []Rule, procs []ProcRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session closed")
	}
	s.lastRules, s.lastProcs = rules, procs
	s.pruneOnce()
	_, err := s.sync()
	return err
}

// mountID is the id of the mount p is on, in the session's root.
func (s *Session) mountID(p string) uint64 {
	if s.inRoot == "" {
		return mountID(p)
	}
	return mountIDIn(s.inRoot, p)
}

// sync pushes lastRules and lastProcs, with nodes for the paths of the
// grants, and returns the mounts it used. s.mu must be held.
func (s *Session) sync() ([]mount, error) {
	rules, procs := s.lastRules, s.lastProcs
	mounts, err := readMounts(s.mountinfo)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	mono := monotonic()
	expiry := func(t time.Time) uint64 {
		if t.IsZero() {
			return forever
		}
		if !t.After(now) {
			return 0
		}
		return mono + uint64(t.Sub(now))
	}

	s.l.mu.Lock()
	defer s.l.mu.Unlock()
	nodes := map[nodeKey]hallpassRuleVal{}
	for _, r := range rules {
		exp := expiry(r.Expires)
		if exp == 0 {
			continue
		}
		for _, lc := range locate(mounts, r.Path, r.Tree, s.mountID(r.Path)) {
			k, ok := s.l.node(nodes, lc)
			if !ok {
				continue
			}
			v := nodes[k]
			switch {
			case r.Deny && r.Tree:
				v.DenyTree = 1
			case r.Deny:
				v.DenyExact = 1
			case r.Tree:
				v.AllowTree = max(v.AllowTree, exp)
			default:
				v.AllowExact = max(v.AllowExact, exp)
			}
			nodes[k] = v
		}
	}
	// The grants' nodes: they allow nothing by themselves.
	for _, g := range s.once {
		for _, p := range g.paths {
			for _, lc := range locate(mounts, p, false, s.mountID(p)) {
				s.l.node(nodes, lc)
			}
		}
	}
	for k, v := range nodes {
		if old, ok := s.nodes[k]; ok && old == v {
			continue
		}
		if err := s.l.rules.Update(ruleKey(s.id, k), v, ebpf.UpdateAny); err != nil {
			return nil, fmt.Errorf("update rule %q: %w", k.name, err)
		}
	}
	for k := range s.nodes {
		if _, ok := nodes[k]; !ok {
			if err := s.l.rules.Delete(ruleKey(s.id, k)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, err
			}
		}
	}
	s.nodes = nodes

	pm := map[hallpassProcKey]hallpassProcVal{}
	for _, r := range procs {
		exp := expiry(r.Expires)
		if exp == 0 && !r.Deny {
			continue
		}
		k := s.procKey(r.Name, r.Comm)
		v := pm[k]
		if r.Deny {
			v.Deny = 1
		} else {
			v.Allow = max(v.Allow, exp)
		}
		pm[k] = v
	}
	for k, v := range pm {
		if old, ok := s.procs[k]; ok && old == v {
			continue
		}
		if err := s.l.proc.Update(k, v, ebpf.UpdateAny); err != nil {
			return nil, err
		}
	}
	for k := range s.procs {
		if _, ok := pm[k]; !ok {
			_ = s.l.proc.Delete(k)
		}
	}
	s.procs = pm
	return mounts, nil
}

func (s *Session) procKey(name, comm string) hallpassProcKey {
	var k hallpassProcKey
	copyName(k.Name[:], name)
	copyName(k.Comm[:], comm)
	k.Session = s.id
	return k
}

// GrantOnce lets thread tid, a member blocked in a syscall that seccomp
// handed to the supervisor, write paths (exactly), and the /proc file of
// proc when its Name is set, during that syscall only: the kernel removes
// the grant when the syscall returns, even if it is restarted, and no other
// thread can use it. It must be called before the syscall is continued.
func (s *Session) GrantOnce(tid int, paths []string, proc ProcRule) error {
	fd, err := unix.PidfdOpen(tid, unix.PIDFD_THREAD)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", tid, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		unix.Close(fd)
		return errors.New("session closed")
	}
	s.pruneOnce()
	s.seq++
	g := &grant{pidfd: fd, seq: s.seq, paths: paths}
	s.once = append(s.once, g)
	mounts, err := s.sync()
	if err != nil {
		return err
	}
	v := hallpassHpGrant{Seq: g.seq}
	n := 0
	s.l.mu.Lock()
	for _, p := range paths {
		for _, lc := range locate(mounts, p, false, s.mountID(p)) {
			c, ok := s.l.cookie(lc)
			if !ok {
				continue
			}
			if n == len(v.Nodes) {
				s.l.mu.Unlock()
				return fmt.Errorf("allow once: too many paths (%d)", len(paths))
			}
			v.Nodes[n] = c
			n++
		}
	}
	s.l.mu.Unlock()
	if proc.Name != "" {
		v.Proc = s.procKey(proc.Name, proc.Comm)
	}
	return s.l.grants.Update(uint32(fd), v, ebpf.UpdateAny)
}

// pruneOnce forgets the grants the kernel has removed: their syscall
// returned, or their thread exited. s.mu must be held.
func (s *Session) pruneOnce() {
	once := s.once[:0]
	for _, g := range s.once {
		var v hallpassHpGrant
		if err := s.l.grants.Lookup(uint32(g.pidfd), &v); err == nil && v.Seq == g.seq {
			once = append(once, g)
			continue
		}
		unix.Close(g.pidfd)
	}
	clear(s.once[len(once):])
	s.once = once
}

// cookie returns the cookie of the node of lc, if it has one. l.mu must be
// held.
func (l *LSM) cookie(lc loc) (uint64, bool) {
	parent := rootCookie | uint64(lc.dev)
	c := uint64(0)
	for _, name := range strings.Split(lc.path, "/") {
		if name == "" {
			continue
		}
		if c = l.cookies[nodeKey{parent, name}]; c == 0 {
			return 0, false
		}
		parent = c
	}
	return c, c != 0
}

// node adds the nodes leading to lc to nodes and returns the key of its last
// one. Cookies are stable for the life of the LSM. l.mu must be held.
func (l *LSM) node(nodes map[nodeKey]hallpassRuleVal, lc loc) (nodeKey, bool) {
	parent := rootCookie | uint64(lc.dev)
	var comps []string
	for _, c := range strings.Split(lc.path, "/") {
		if c == "" {
			continue
		}
		if len(c) >= nameLen {
			return nodeKey{}, false // cannot exist
		}
		comps = append(comps, c)
	}
	if len(comps) == 0 {
		return nodeKey{parent, ""}, true
	}
	var k nodeKey
	for _, c := range comps {
		k = nodeKey{parent, c}
		v := nodes[k]
		if v.Cookie == 0 {
			if l.cookies[k] == 0 {
				l.cookies[k] = l.next
				l.next++
			}
			v.Cookie = l.cookies[k]
			nodes[k] = v
		}
		parent = v.Cookie
	}
	return k, true
}

func ruleKey(session uint32, k nodeKey) hallpassRuleKey {
	var rk hallpassRuleKey
	rk.Parent = k.parent
	rk.Session = session
	copyName(rk.Name[:], k.name)
	return rk
}

// copyName copies s into a NUL-padded C string, truncating as the kernel's
// bpf_probe_read_kernel_str and comm do.
func copyName(dst []int8, s string) {
	for i := 0; i < len(s) && i < len(dst)-1; i++ {
		dst[i] = int8(s[i])
	}
}

// monotonic is bpf_ktime_get_ns's clock.
func monotonic() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

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

// LSM is a loaded and attached set of programs, with its rules.
type LSM struct {
	members, protected, rules, proc, events *ebpf.Map
	// links keep the programs attached; closing them detaches.
	links []io.Closer
	// linkFDs are the links' fds, for handing them to another process.
	linkFDs []int
	rd      *ringbuf.Reader

	mountinfo string

	mu      sync.Mutex
	cookies map[nodeKey]uint64
	next    uint64
	nodes   map[nodeKey]hallpassRuleVal
	procs   map[hallpassProcKey]hallpassProcVal
}

func newLSM() *LSM {
	return &LSM{
		mountinfo: "/proc/self/mountinfo",
		cookies:   map[nodeKey]uint64{},
		next:      1,
		nodes:     map[nodeKey]hallpassRuleVal{},
		procs:     map[hallpassProcKey]hallpassProcVal{},
	}
}

// attachOrder lists the programs in the order Load attaches them, which is
// also the order of their link fds in FDs. task_alloc comes first, so no
// member can fork unmarked once the others run.
var attachOrder = []string{
	"hp_task_alloc", "hp_sb_alloc", "hp_sb_free", "hp_task_kill", "hp_file_send_sigiotask",
	"hp_file_open", "hp_path_mknod", "hp_path_mkdir", "hp_path_rmdir", "hp_path_unlink",
	"hp_path_symlink", "hp_path_link", "hp_path_rename", "hp_path_truncate",
}

func programsByName(p *hallpassPrograms) map[string]*ebpf.Program {
	return map[string]*ebpf.Program{
		"hp_task_alloc": p.HpTaskAlloc, "hp_sb_alloc": p.HpSbAlloc, "hp_sb_free": p.HpSbFree,
		"hp_task_kill": p.HpTaskKill, "hp_file_send_sigiotask": p.HpFileSendSigiotask,
		"hp_file_open": p.HpFileOpen, "hp_path_mknod": p.HpPathMknod, "hp_path_mkdir": p.HpPathMkdir,
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
	l.members, l.protected, l.rules, l.proc, l.events = m.Members, m.Protected, m.Rules, m.Proc, m.Events
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

// hookIDs returns the kernel BTF IDs of the LSM hooks of attachOrder.
func hookIDs() ([]btf.TypeID, []string, error) {
	spec, err := loadHallpass()
	if err != nil {
		return nil, nil, err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("kernel BTF: %w", err)
	}
	ids := make([]btf.TypeID, len(attachOrder))
	hooks := make([]string, len(attachOrder))
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
	return ids, hooks, nil
}

// checkLink makes sure lk attaches a BPF-LSM program to hook (BTF ID id), so
// a helper cannot hand over a link that enforces nothing. It only needs the
// link fd, no privileges.
func checkLink(lk link.Link, hook string, id btf.TypeID) error {
	info, err := lk.Info()
	if err != nil {
		return fmt.Errorf("link for %s: %w", hook, err)
	}
	t := info.Tracing()
	if info.Type != link.TracingType || t == nil || uint32(t.AttachType) != uint32(ebpf.AttachLSMMac) || btf.TypeID(t.TargetBtfId) != id {
		return fmt.Errorf("link is not attached to LSM hook %s", hook)
	}
	return nil
}

// FDs returns the fds that make up l, in the order FromFDs expects: the
// maps, then the links. They stay owned by l.
func (l *LSM) FDs() []int {
	fds := []int{l.members.FD(), l.protected.FD(), l.rules.FD(), l.proc.FD(), l.events.FD()}
	return append(fds, l.linkFDs...)
}

// FromFDs rebuilds an LSM from fds received from the process that loaded it
// (see FDs) and takes ownership of them. It needs no privilege: updating a
// BPF map only needs a writable fd to it.
func FromFDs(fds []int) (*LSM, error) {
	want := []ebpf.MapType{ebpf.TaskStorage, ebpf.TaskStorage, ebpf.Hash, ebpf.Hash, ebpf.RingBuf}
	if len(fds) != len(want)+len(attachOrder) {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("got %d fds, want %d", len(fds), len(want)+len(attachOrder))
	}
	l := newLSM()
	maps := []**ebpf.Map{&l.members, &l.protected, &l.rules, &l.proc, &l.events}
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
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Close detaches the programs: the sandbox is no longer restricted.
func (l *LSM) Close() error {
	if l.rd != nil {
		l.rd.Close()
	}
	for _, lk := range l.links {
		lk.Close()
	}
	for _, m := range []*ebpf.Map{l.members, l.protected, l.rules, l.proc, l.events} {
		if m != nil {
			m.Close()
		}
	}
	return nil
}

// AddMember puts process pid in the sandbox; the tasks it creates from then
// on are members too. Threads it already has are not.
func (l *LSM) AddMember(pid int) error {
	return l.mark(l.members, pid)
}

// Protect forbids members to signal process pid (all its threads).
func (l *LSM) Protect(pid int) error {
	return l.mark(l.protected, pid)
}

func (l *LSM) mark(m *ebpf.Map, pid int) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(fd)
	return m.Update(uint32(fd), uint8(1), ebpf.UpdateAny)
}

// Events calls fn for each decision reported by the programs, until Close.
func (l *LSM) Events(fn func(Event)) {
	for {
		rec, err := l.rd.Read()
		if err != nil {
			return
		}
		var ev hallpassEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
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

// Sync makes the kernel's rules match these, translating paths with the
// current mounts. Expired rules are dropped.
func (l *LSM) Sync(rules []Rule, procs []ProcRule) error {
	mounts, err := readMounts(l.mountinfo)
	if err != nil {
		return err
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

	l.mu.Lock()
	defer l.mu.Unlock()

	nodes := map[nodeKey]hallpassRuleVal{}
	for _, r := range rules {
		exp := expiry(r.Expires)
		if exp == 0 {
			continue
		}
		for _, lc := range locate(mounts, r.Path, r.Tree, mountID(r.Path)) {
			k, ok := l.node(nodes, lc)
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
	for k, v := range nodes {
		if old, ok := l.nodes[k]; ok && old == v {
			continue
		}
		if err := l.rules.Update(ruleKey(k), v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update rule %q: %w", k.name, err)
		}
	}
	for k := range l.nodes {
		if _, ok := nodes[k]; !ok {
			if err := l.rules.Delete(ruleKey(k)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return err
			}
		}
	}
	l.nodes = nodes

	pm := map[hallpassProcKey]hallpassProcVal{}
	for _, r := range procs {
		exp := expiry(r.Expires)
		if exp == 0 && !r.Deny {
			continue
		}
		var k hallpassProcKey
		copyName(k.Name[:], r.Name)
		copyName(k.Comm[:], r.Comm)
		v := pm[k]
		if r.Deny {
			v.Deny = 1
		} else {
			v.Allow = max(v.Allow, exp)
		}
		pm[k] = v
	}
	for k, v := range pm {
		if old, ok := l.procs[k]; ok && old == v {
			continue
		}
		if err := l.proc.Update(k, v, ebpf.UpdateAny); err != nil {
			return err
		}
	}
	for k := range l.procs {
		if _, ok := pm[k]; !ok {
			_ = l.proc.Delete(k)
		}
	}
	l.procs = pm
	return nil
}

// node adds the nodes leading to lc to nodes and returns the key of its last
// one. Cookies are stable for the life of the session.
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

func ruleKey(k nodeKey) hallpassRuleKey {
	var rk hallpassRuleKey
	rk.Parent = k.parent
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

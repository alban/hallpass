// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"fmt"
	"time"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// maxChain bounds the parent walk of a request's subject.
const maxChain = 64

// restartTTL is how long a verdict allowing a syscall covers the same
// syscall of the same thread again: a signal handler run during the syscall
// makes the kernel restart it, and seccomp notifies it again.
const restartTTL = 2 * time.Second

// request is a pending Request and the notifications waiting on it.
type request struct {
	pub     *Request
	key     string
	op      rules.Op
	obj     rules.Object
	waiters []waiter
	done    chan struct{}
	allow   bool
	why     Reason
}

type waiter struct {
	l  *listener
	id uint64
}

// item is one object of a syscall, and its decision so far.
type item struct {
	obj     rules.Object
	path    string // resolved, for the restart cache and grants
	decided bool
	why     Reason
}

// receiver receives l's notifications into journal slots and decides each
// itself, so that receiving, deciding and answering stay on one thread:
// with the kernel's synchronous wakeups, the target and the receiver then
// ping-pong on one CPU. Only a request waiting for a human moves to its own
// goroutine: it holds a goroutine and a slot, not a receiver.
func (m *Monitor) receiver(l *listener) {
	defer l.wg.Done()
	for {
		slot, ok := l.j.Take(l.hup)
		if !ok {
			return
		}
		n, err := l.n.Recv(l.j.Slot(slot))
		if errors.Is(err, unix.ENOENT) {
			// The task died before the notification was received, or
			// no task is left: then every Recv fails at once.
			l.j.Release(slot)
			select {
			case <-l.hup:
				return
			default:
				continue
			}
		}
		if err != nil {
			l.j.Release(slot)
			return
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			// As if the monitor had exited.
			_ = l.n.Deny(n.ID, int32(unix.ENOSYS))
			l.j.Release(slot)
			continue
		}
		m.busy++
		m.mu.Unlock()
		l.wg.Add(1)
		m.handleSlot(l, n, slot)
	}
}

// handleSlot handles n, received into slot, and releases the slot, or
// hands both to a goroutine if n waits for a human.
func (m *Monitor) handleSlot(l *listener, n seccomp.Notif, slot int) {
	if ask := m.handle(l, n); ask != nil {
		go func() {
			ask()
			m.release(l, n, slot)
		}()
		return
	}
	m.release(l, n, slot)
}

// release frees n's slot unless n is still waiting: the monitor closed
// before answering it, and another monitor may answer it from the journal.
func (m *Monitor) release(l *listener, n seccomp.Notif, slot int) {
	defer l.wg.Done()
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if !closed || !l.n.IDValid(n.ID) {
		l.j.Release(slot)
	}
	m.mu.Lock()
	m.busy--
	if m.busy == 0 {
		m.idle.Broadcast()
	}
	m.mu.Unlock()
}

// replay handles the notifications l's journal held when it was opened,
// received by a previous monitor that did not answer them.
func (m *Monitor) replay(l *listener) {
	for _, p := range l.j.Pending() {
		if !l.n.IDValid(p.Notif.ID) {
			// Answered, or the task died.
			l.j.Release(p.Slot)
			continue
		}
		m.mu.Lock()
		m.busy++
		m.mu.Unlock()
		l.wg.Add(1)
		go m.handleSlot(l, p.Notif, p.Slot)
	}
}

// handle decides one notified syscall, or returns ask, which asks a human
// and must run in its own goroutine.
func (m *Monitor) handle(l *listener, n seccomp.Notif) (ask func()) {
	sc, ok := seccomp.RuleFor(m.table, n.Nr)
	if !ok {
		// Not ours (the filter and the table disagree): fail closed.
		_ = l.n.Deny(n.ID, int32(unix.EPERM))
		return
	}
	if sc.Category() == seccomp.Network {
		return m.handleNet(l, n, sc)
	}
	flags, inRoot, done := m.openFlags(l, n, sc)
	if done {
		return
	}
	op := opOf(sc, flags)
	if sc.Op == "exec" {
		m.exec(l, n, sc)
		return
	}
	if m.kernel != nil {
		// Paths of a process in another mount namespace or chroot than
		// the one the rules are written for cannot be resolved here: let
		// the kernel's rules decide.
		ref := 0
		if m.procRoot {
			ref = l.root
		}
		if same, err := procfs.SameView(n.PID, ref); err == nil && !same {
			m.toBPF(l, n, sc, op)
			return
		}
	}
	root := "/"
	if m.procRoot {
		root = procfs.ProcRoot(n.PID)
	}

	var items []item
	for i, pa := range sc.Paths {
		raw, err := procfs.ReadCString(n.PID, n.Args[pa.Path])
		if err != nil {
			if m.kernel != nil {
				// The kernel's rules decide on the real inode.
				m.toBPF(l, n, sc, op)
				return
			}
			items = append(items, item{obj: rules.Object{Unknown: err}})
			continue
		}
		dirfd := int64(procfs.AtFDCWD)
		if pa.DirFD >= 0 {
			dirfd = procfs.DirFDArg(n.Args[pa.DirFD])
		}
		resolve := procfs.Resolve
		if inRoot {
			resolve = procfs.ResolveInRoot
		}
		t, err := resolve(n.PID, root, dirfd, raw, followLast(sc, n, i, flags))
		if err != nil {
			obj := rules.Object{Path: &rules.PathObject{Path: raw}}
			m.deny(l, n, sc, op, []rules.Object{obj}, []Reason{{Builtin: "unresolvable"}})
			return
		}
		it := item{path: t.Path, obj: rules.Object{Path: &rules.PathObject{Path: t.Path}}}
		switch {
		case t.Special != "":
			it.decided, it.why = true, Reason{Builtin: "special-file"}
		default:
			if tid, name, ok := procfs.PidFile(t.Path); ok {
				if m.procRoot {
					// A pid of the workload's procfs.
					tid, ok = procfs.HostTID(n.PID, tid)
				}
				if ok && m.ownProc(tid) {
					// Processes of the workload may tune each other
					// (e.g. oom_score_adj).
					it.decided, it.why = true, Reason{Builtin: "own-proc"}
				} else {
					target := rules.Task{PID: procfs.Tgid(tid), TID: tid, Comm: procfs.Comm(tid)}
					it.obj = rules.Object{Proc: &rules.ProcObject{Name: name, Target: rules.Subject{Chain: []rules.Task{target}}}}
				}
			}
		}
		items = append(items, it)
	}
	return m.decide(l, n, sc, op, items)
}

// decide decides the items of a syscall read from the target, or returns
// ask, which asks a human and must run in its own goroutine.
func (m *Monitor) decide(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op, items []item) (ask func()) {
	// The strings were read from the target's memory: make sure the
	// notification is still the same syscall of the same live task.
	if !l.n.IDValid(n.ID) {
		return
	}

	now := m.now()
	rs := m.currentRules()
	for i := range items {
		if items[i].decided {
			continue
		}
		v, id, ok := rules.Eval(rs, op, items[i].obj, now)
		if !ok || v == rules.Ask {
			continue
		}
		if v == rules.Deny {
			m.deny(l, n, sc, op, objects(items), only(len(items), i, Reason{Rule: id}))
			return
		}
		items[i].decided, items[i].why = true, Reason{Rule: id}
	}

	var undecided []int
	unknown := false
	var paths []string
	for i, it := range items {
		paths = append(paths, it.path)
		if !it.decided {
			undecided = append(undecided, i)
			unknown = unknown || it.obj.Unknown != nil
		}
	}
	if len(undecided) == 0 {
		m.allow(l, n, sc, op, items, nil)
		return
	}
	key := restartKey(n, paths)
	if !unknown && m.restarted(key) {
		for _, i := range undecided {
			items[i].decided, items[i].why = true, Reason{Builtin: "restarted"}
		}
		m.allow(l, n, sc, op, items, undecided)
		return
	}
	return func() { m.ask(l, n, sc, op, items, undecided, key, unknown) }
}

// ask decides the undecided items of a syscall, opening a request for
// each the current rules do not decide, and waiting for its verdict.
func (m *Monitor) ask(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op, items []item, undecided []int, key string, unknown bool) {
	var subject *rules.Subject
	var once []int
	for _, i := range undecided {
		r, why, decided := m.open(l, n, sc.Name, op, items[i].obj, &subject)
		if !decided {
			<-r.done
			if r.why.Died {
				return
			}
			decided, why = r.allow, r.why
		}
		if !decided {
			m.deny(l, n, sc, op, objects(items), only(len(items), i, why))
			return
		}
		items[i].decided, items[i].why = true, why
		if why.Client != "" {
			once = append(once, i)
		}
	}
	if len(once) > 0 && !unknown {
		m.allowedOnce(key)
	}
	m.allow(l, n, sc, op, items, once)
}

// open returns the pending request for obj, opening it (or joining an
// identical one) unless the current rules decide obj, in which case it
// returns allow and the reason instead.
func (m *Monitor) open(l *listener, n seccomp.Notif, syscall string, op rules.Op, obj rules.Object, subject **rules.Subject) (r *request, why Reason, allow bool) {
	if *subject == nil {
		s := buildSubject(n.PID, l.root)
		*subject = &s
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		r = &request{done: make(chan struct{}), why: Reason{Died: true}}
		close(r.done)
		return r, Reason{}, false
	}
	// The rules may have changed since the syscall was evaluated.
	if v, id, ok := rules.Eval(m.rules, op, obj, m.now()); ok && v != rules.Ask {
		return nil, Reason{Rule: id}, v == rules.Allow
	}
	key := requestKey(op, obj, **subject, n.ID)
	if r := m.byKey[key]; r != nil {
		r.waiters = append(r.waiters, waiter{l, n.ID})
		return r, Reason{}, false
	}
	m.nextReqID++
	r = &request{
		pub: &Request{
			ID:      m.nextReqID,
			Syscall: syscall,
			Op:      op,
			Objects: []rules.Object{obj},
			Subject: **subject,
		},
		key:     key,
		op:      op,
		obj:     obj,
		waiters: []waiter{{l, n.ID}},
		done:    make(chan struct{}),
	}
	m.pending[r.pub.ID] = r
	m.byKey[key] = r
	m.emitLocked(Event{Opened: r.pub})
	if !m.polling {
		m.polling = true
		go m.poll()
	}
	return r, Reason{}, false
}

// closeLocked closes r. mu must be held.
func (m *Monitor) closeLocked(r *request, allow bool, why Reason) {
	delete(m.pending, r.pub.ID)
	delete(m.byKey, r.key)
	r.allow, r.why = allow, why
	close(r.done)
	m.emitLocked(Event{Closed: &Closed{ID: r.pub.ID, Why: why}})
}

// settleLocked closes the pending requests the rules now decide. mu must
// be held.
func (m *Monitor) settleLocked() {
	now := m.now()
	for _, r := range m.pending {
		if v, id, ok := rules.Eval(m.rules, r.op, r.obj, now); ok && v != rules.Ask {
			m.closeLocked(r, v == rules.Allow, Reason{Rule: id})
		}
	}
}

// poll closes the requests whose tasks all died: the kernel does not signal
// a withdrawn notification. It runs only while requests are pending.
func (m *Monitor) poll() {
	t := time.NewTicker(pollPeriod)
	defer t.Stop()
	for range t.C {
		m.mu.Lock()
		if len(m.pending) == 0 {
			m.polling = false
			m.mu.Unlock()
			return
		}
		for _, r := range m.pending {
			alive := false
			for _, w := range r.waiters {
				if w.l.n.IDValid(w.id) {
					alive = true
					break
				}
			}
			if !alive {
				m.closeLocked(r, false, Reason{Died: true})
			}
		}
		m.mu.Unlock()
	}
}

// allow continues the syscall. once are the items allowed by a verdict or
// the restart cache: in strict mode, the kernel is granted them for this
// syscall first.
func (m *Monitor) allow(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op, items []item, once []int) {
	if m.kernel != nil {
		m.checkMounts(l)
		if len(once) > 0 {
			var paths []string
			var proc lsm.ProcRule
			for _, i := range once {
				o := items[i].obj
				switch {
				case o.Proc != nil:
					proc = lsm.ProcRule{Name: o.Proc.Name, Comm: o.Proc.Target.Chain[0].Comm}
				case o.Path != nil:
					paths = append(paths, o.Path.Path)
				}
			}
			if err := m.kernel.GrantOnce(int(n.PID), paths, proc); err != nil {
				m.warn("strict mode: allow once: " + err.Error())
			}
		}
	}
	why := make([]Reason, len(items))
	for i, it := range items {
		why[i] = it.why
	}
	m.report(n, sc.Name, op, objects(items), true, why)
	if err := l.n.Continue(n.ID); err != nil && !errors.Is(err, unix.ENOENT) {
		m.warn("continue: " + err.Error())
	}
}

func (m *Monitor) deny(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op, objs []rules.Object, why []Reason) {
	m.report(n, sc.Name, op, objs, false, why)
	_ = l.n.Deny(n.ID, int32(unix.EACCES))
}

// toBPF continues a syscall the monitor cannot see the paths of, for the
// kernel's rules to decide (strict).
func (m *Monitor) toBPF(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op) {
	m.checkMounts(l)
	m.report(n, sc.Name, op, nil, true, []Reason{{Builtin: "bpf"}})
	_ = l.n.Continue(n.ID)
}

// report emits a Decided event, if a subscriber wants them.
// exec continues an execve or execveat: what to check on exec is not
// designed yet. Its path is read for Decided events only, best effort.
//
// In strict mode, the calling thread is first made a member of the
// session: it may be one the sandbox started before it was marked (the
// container runtime's init), or a thread that is not the one marked, whose
// execve would otherwise leave the sandbox. It stays blocked meanwhile, so
// the new program never runs unmarked.
func (m *Monitor) exec(l *listener, n seccomp.Notif, sc seccomp.Rule) {
	if m.kernel != nil {
		if err := m.kernel.AddMember(int(n.PID)); err != nil {
			if l.n.IDValid(n.ID) {
				m.warn(fmt.Sprintf("strict mode: %s: %v", sc.Name, err))
			}
			_ = l.n.Deny(n.ID, int32(unix.EPERM))
			return
		}
	}
	m.mu.Lock()
	want := m.decided > 0
	m.mu.Unlock()
	var objs []rules.Object
	if want {
		pa := sc.Paths[0]
		if raw, err := procfs.ReadCString(n.PID, n.Args[pa.Path]); err == nil {
			objs = []rules.Object{{Path: &rules.PathObject{Path: raw}}}
		}
	}
	if err := l.n.Continue(n.ID); err != nil && !errors.Is(err, unix.ENOENT) {
		m.warn(fmt.Sprintf("continue %s: %v", sc.Name, err))
	}
	if want {
		m.report(n, sc.Name, 0, objs, true, []Reason{{Builtin: "execve"}})
	}
}

func (m *Monitor) report(n seccomp.Notif, syscall string, op rules.Op, objs []rules.Object, allowed bool, why []Reason) {
	m.mu.Lock()
	want := m.decided > 0
	m.mu.Unlock()
	if !want {
		return
	}
	d := &Decided{
		Time:    m.now(),
		Syscall: syscall,
		Op:      op,
		Objects: objs,
		Subject: rules.Subject{Chain: []rules.Task{{TID: int(n.PID), Exe: procfs.Exe(n.PID)}}},
		Allowed: allowed,
		Why:     why,
		Source:  SourceSeccomp,
	}
	m.mu.Lock()
	m.emitLocked(Event{Decided: d})
	m.mu.Unlock()
}

// ownProc reports whether thread tid belongs to the workload.
func (m *Monitor) ownProc(tid int) bool {
	m.mu.Lock()
	ls := m.listeners
	m.mu.Unlock()
	for _, l := range ls {
		if procfs.Descends(tid, l.root) {
			return true
		}
	}
	return false
}

// buildSubject reads thread tid and its parents up to root.
func buildSubject(tid uint32, root int) rules.Subject {
	t := rules.Task{
		PID:     procfs.Tgid(int(tid)),
		TID:     int(tid),
		Comm:    procfs.Comm(int(tid)),
		Exe:     procfs.Exe(tid),
		Cmdline: procfs.Cmdline(int(tid)),
	}
	chain := []rules.Task{t}
	pid := t.PID
	for len(chain) < maxChain && pid > 1 && pid != root {
		if pid = procfs.Parent(pid); pid <= 0 {
			break
		}
		chain = append(chain, rules.Task{PID: pid, TID: pid, Comm: procfs.Comm(pid)})
	}
	return rules.Subject{Chain: chain}
}

// requestKey coalesces concurrent requests: same op and object, from the
// same process (thread group). The prompt shows one process only, so an
// answer must not reach another one. Unreadable paths, and processes whose
// thread group is unknown, are never coalesced (id is the notification's).
func requestKey(op rules.Op, obj rules.Object, subject rules.Subject, id uint64) string {
	tgid := 0
	if len(subject.Chain) > 0 {
		tgid = subject.Chain[0].PID
	}
	switch {
	case tgid <= 0:
	case obj.Path != nil:
		return fmt.Sprintf("%d\x00%d\x00path\x00%s", tgid, op, obj.Path.Path)
	case obj.Proc != nil:
		return fmt.Sprintf("%d\x00%d\x00proc\x00%s\x00%s", tgid, op, obj.Proc.Name, obj.Proc.Target.Chain[0].Comm)
	case obj.Inet != nil:
		return fmt.Sprintf("%d\x00%d\x00inet\x00%d\x00%s", tgid, op, obj.Inet.Proto, obj.Inet.Addr)
	case obj.Unix != nil:
		return fmt.Sprintf("%d\x00%d\x00unix\x00%t\x00%s\x00%s", tgid, op, obj.Unix.Abstract, obj.Unix.Path, obj.Unix.Name)
	}
	return fmt.Sprintf("unique\x00%d", id)
}

// restartKey identifies a syscall of a thread, with what it would write.
func restartKey(n seccomp.Notif, paths []string) string {
	return fmt.Sprintf("%d %d %x %q", n.PID, n.Nr, n.Args, paths)
}

// restarted reports whether a verdict allowed this syscall very recently:
// it is the same one, restarted.
func (m *Monitor) restarted(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, t := range m.restart {
		if now.After(t) {
			delete(m.restart, k)
		}
	}
	_, ok := m.restart[key]
	return ok
}

func (m *Monitor) allowedOnce(key string) {
	m.mu.Lock()
	m.restart[key] = m.now().Add(restartTTL)
	m.mu.Unlock()
}

func objects(items []item) []rules.Object {
	out := make([]rules.Object, len(items))
	for i, it := range items {
		out[i] = it.obj
	}
	return out
}

// only returns n reasons, all empty but the i-th.
func only(n, i int, why Reason) []Reason {
	out := make([]Reason, n)
	out[i] = why
	return out
}

// openFlags returns the open flags of an open syscall n, 0 for the others,
// and whether openat2 resolves its path with RESOLVE_IN_ROOT. For openat2,
// it reads them from the target's memory, and answers n itself (done) when
// they cannot be read or carry no write intent: such an openat2 is
// continued, as the filter lets read-only openat through. In lite mode, the
// target can change them after the check, like its path; in strict mode,
// the kernel checks the opened file.
func (m *Monitor) openFlags(l *listener, n seccomp.Notif, sc seccomp.Rule) (flags uint64, inRoot, done bool) {
	switch {
	case sc.Name == "openat2":
		how, err := procfs.ReadOpenHow(n.PID, n.Args[2], n.Args[3])
		if err != nil {
			errno := unix.EFAULT
			if errors.Is(err, unix.EINVAL) {
				errno = unix.EINVAL
			}
			_ = l.n.Deny(n.ID, int32(errno))
			return 0, false, true
		}
		if how.Flags&seccomp.WriteIntentMask == 0 {
			if err := l.n.Continue(n.ID); err != nil && !errors.Is(err, unix.ENOENT) {
				m.warn("continue: " + err.Error())
			}
			return 0, false, true
		}
		return how.Flags, how.Resolve&unix.RESOLVE_IN_ROOT != 0, false
	case sc.Kind == seccomp.NotifyIfWrite:
		return n.Args[sc.FlagsArg], false, false
	}
	return 0, false, false
}

// opOf returns the operation of syscall sc, with open flags flags.
func opOf(sc seccomp.Rule, flags uint64) rules.Op {
	switch sc.Op {
	case "write":
		op := rules.OpWrite
		if sc.Name == "creat" || flags&unix.O_CREAT != 0 {
			op |= rules.OpCreate
		}
		return op
	case "create":
		return rules.OpCreate
	case "create directory":
		return rules.OpMkdir
	case "create symlink":
		return rules.OpSymlink
	case "delete":
		return rules.OpDelete
	case "link":
		return rules.OpLink
	case "rename":
		return rules.OpRename
	case "truncate":
		return rules.OpTruncate
	}
	return rules.OpAll
}

// followLast reports whether the kernel follows a symlink in the last
// component of path argument i of this syscall, with open flags flags.
func followLast(sc seccomp.Rule, n seccomp.Notif, i int, flags uint64) bool {
	switch sc.Name {
	case "openat", "open", "openat2":
		if flags&unix.O_NOFOLLOW != 0 {
			return false
		}
		return !(flags&unix.O_CREAT != 0 && flags&unix.O_EXCL != 0)
	case "creat", "truncate":
		return true
	case "linkat":
		return i == 0 && n.Args[4]&unix.AT_SYMLINK_FOLLOW != 0
	}
	return false
}

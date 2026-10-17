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

func (m *Monitor) worker(l *listener) {
	for {
		n, err := l.n.Recv()
		if errors.Is(err, unix.ENOENT) {
			// The task died before the notification was received, or
			// no task is left: then every Recv fails at once.
			select {
			case <-l.hup:
				return
			default:
				continue
			}
		}
		if err != nil {
			return
		}
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			// As if the monitor had exited.
			_ = l.n.Deny(n.ID, int32(unix.ENOSYS))
			continue
		}
		m.busy++
		m.mu.Unlock()
		m.handle(l, n)
		m.mu.Lock()
		m.busy--
		if m.busy == 0 {
			m.idle.Broadcast()
		}
		m.mu.Unlock()
	}
}

// handle decides one notified syscall.
func (m *Monitor) handle(l *listener, n seccomp.Notif) {
	sc, ok := seccomp.RuleFor(m.table, n.Nr)
	if !ok {
		// Not ours (the filter and the table disagree): fail closed.
		_ = l.n.Deny(n.ID, int32(unix.EPERM))
		return
	}
	op := opOf(sc, n)
	if sc.Op == "exec" {
		m.exec(l, n, sc)
		return
	}
	if m.kernel != nil {
		// Paths of a process in another mount namespace or chroot cannot
		// be resolved here: let the kernel's rules decide.
		if same, err := procfs.SameView(n.PID); err == nil && !same {
			m.toBPF(l, n, sc, op)
			return
		}
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
		t, err := procfs.Resolve(n.PID, dirfd, raw, followLast(sc, n, i))
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
				if m.ownProc(tid) {
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
func (m *Monitor) exec(l *listener, n seccomp.Notif, sc seccomp.Rule) {
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

// opOf returns the operation of syscall n.
func opOf(sc seccomp.Rule, n seccomp.Notif) rules.Op {
	switch sc.Op {
	case "write":
		op := rules.OpWrite
		if sc.Name == "creat" || (sc.Kind == seccomp.NotifyIfWrite && n.Args[sc.FlagsArg]&unix.O_CREAT != 0) {
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
// component of path argument i of this syscall.
func followLast(sc seccomp.Rule, n seccomp.Notif, i int) bool {
	switch sc.Name {
	case "openat", "open":
		f := n.Args[sc.FlagsArg]
		if f&unix.O_NOFOLLOW != 0 {
			return false
		}
		return !(f&unix.O_CREAT != 0 && f&unix.O_EXCL != 0)
	case "creat", "truncate":
		return true
	case "linkat":
		return i == 0 && n.Args[4]&unix.AT_SYMLINK_FOLLOW != 0
	}
	return false
}

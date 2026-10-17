// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package monitor is the mechanism of hallpass, a reference monitor for one
// workload: it mediates the workload's writes with seccomp user
// notification (lite) and BPF-LSM (strict), applies rules and verdicts,
// and reports what it cannot decide. It has no built-in policy and shows
// no prompts. See docs/devel/monitor.md.
package monitor

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// Kernel is strict mode's BPF-LSM enforcement (*lsm.LSM).
type Kernel interface {
	AddMember(pid int) error
	Sync(rules []lsm.Rule, procs []lsm.ProcRule) error
	GrantOnce(tid int, paths []string, proc lsm.ProcRule) error
	Events(fn func(lsm.Event))
}

// Notifier is a seccomp listener (*seccomp.Listener).
type Notifier interface {
	Recv(slot []byte) (seccomp.Notif, error)
	IDValid(id uint64) bool
	Continue(id uint64) error
	Deny(id uint64, errno int32) error
}

// Config configures a monitor.
type Config struct {
	Kernel Kernel // nil: lite mode
	// ProcRoot resolves each path through the calling thread's root
	// directory, /proc/<tid>/root, and reports it relative to that root:
	// for a monitor outside the workload's mount namespace, such as the
	// node agent for a container. Rule paths are then paths in that root
	// too, taken as they are: their symlinks are not resolved. False: the
	// workload shares the monitor's view (the CLI).
	ProcRoot bool
}

var (
	ErrStale       = errors.New("monitor: rules changed since IfGeneration")
	ErrClosed      = errors.New("monitor: request already closed")
	ErrUnsupported = errors.New("monitor: rule not enforceable in strict mode")
)

// Event is one thing that happened. Exactly one field is set.
type Event struct {
	Opened  *Request
	Closed  *Closed
	Rules   uint64   // the rule set changed: its new generation
	Decided *Decided // an access, once decided (EventOptions.Decided)
	// Warning reports a failure no caller can receive, e.g. the resync
	// after a mount change.
	Warning string
	// Dropped counts Decided events lost because this client was too
	// slow. Opened, Closed and Rules are never dropped.
	Dropped uint64
}

// Request is an access no rule decides, until a verdict or a rule closes
// it.
type Request struct {
	ID      uint64
	Syscall string // e.g. "renameat2"
	Op      rules.Op
	Objects []rules.Object // one for now: rename and link make one request per object
	Subject rules.Subject
	Facts   []Fact
}

// Closed reports the end of a request.
type Closed struct {
	ID  uint64 // Request.ID
	Why Reason
}

// Decided is an access the monitor decided, with or without asking.
type Decided struct {
	Time    time.Time
	Syscall string // the LSM operation when BPF decided
	Op      rules.Op
	Objects []rules.Object
	Subject rules.Subject // the requesting task only, no ancestry walk
	Allowed bool
	// Why has one entry per object; on a deny, only the denied object's
	// is set.
	Why    []Reason
	Source Source
}

// Reason says why a request was closed or an access decided. At most one
// field is set; none when BPF decided.
type Reason struct {
	Client string // a verdict from this client (Decision.Client)
	Rule   uint64 // this rule
	// Builtin is mechanism, not a rule: "special-file" (pipe, socket),
	// "own-proc" (the workload writes its own /proc files), "restarted"
	// (restart cache), "bpf" (strict: other mount namespace or unreadable
	// path, continued for BPF to decide), "unresolvable" (the path could
	// not be resolved: denied).
	Builtin string
	Died    bool // the requesting task died
}

// Source says which layer decided.
type Source int

const (
	SourceSeccomp Source = iota
	SourceLSM
)

// Decision is what a client sends to Apply.
type Decision struct {
	Verdicts     []Verdict
	AddRules     []rules.Rule
	RemoveRules  []uint64 // rules.Rule.ID
	RemoveSets   []string
	IfGeneration uint64
	Client       string // reported in Reason.Client
}

// Verdict allows or denies one request, once. In strict mode, an allow is
// a per-thread, per-syscall grant in the kernel.
type Verdict struct {
	Request uint64 // Request.ID
	Allow   bool
}

// Fact is something known about a request.
type Fact struct {
	Kind  string
	Value string
	Trust Trust
}

// Trust says where a Fact comes from.
type Trust int

const (
	TrustKernel  Trust = iota // from the kernel (notification, BPF)
	TrustRacy                 // read from process memory; may change after the read
	TrustClaimed              // written by the process itself (cmdline, comm)
)

// EventOptions selects the events of a subscription.
type EventOptions struct {
	// Decided also delivers the decided accesses (for logs, tracers).
	Decided bool
	// Done, when closed, ends the subscription: the channel is closed,
	// events not yet received are dropped.
	Done <-chan struct{}
}

// pollPeriod is how often pending requests are checked for a dead task.
var pollPeriod = time.Second

// Monitor mediates one workload.
type Monitor struct {
	kernel   Kernel
	procRoot bool
	table    []seccomp.Rule
	now      func() time.Time

	// kmu serializes kernel syncs and mount checks. It is taken before mu.
	kmu sync.Mutex

	mu         sync.Mutex
	idle       *sync.Cond // signalled when busy drops to 0
	rules      []rules.Rule
	nextRuleID uint64
	gen        uint64
	pending    map[uint64]*request
	byKey      map[string]*request
	nextReqID  uint64
	polling    bool
	restart    map[string]time.Time
	subs       []*subscriber
	decided    int // subscribers with EventOptions.Decided
	listeners  []*listener
	live       int
	busy       int // notifications being handled
	kernelOn   bool
	finished   bool
	closed     bool
}

type listener struct {
	n       Notifier
	j       *seccomp.Journal
	wg      sync.WaitGroup // receivers and handlers
	root    int
	mountFD int             // strict: /proc/<root>/mountinfo, polled for changes
	hup     <-chan struct{} // closed when no task uses the filter
}

// New returns a monitor for one workload.
func New(cfg Config) (*Monitor, error) {
	m := &Monitor{
		kernel:   cfg.Kernel,
		procRoot: cfg.ProcRoot,
		table:    seccomp.Rules(true),
		now:      time.Now,
		pending:  map[uint64]*request{},
		byKey:    map[string]*request{},
		restart:  map[string]time.Time{},
	}
	m.idle = sync.NewCond(&m.mu)
	return m, nil
}

// Attach starts mediating the processes behind seccompFD. rootPID is the
// process the filter was installed on, in the monitor's pid namespace; in
// strict mode it becomes a BPF member. The launcher must keep it from
// running untrusted code until Attach returns. Called once per listener.
// The notifications in flight are in a journal on the heap: nothing
// recovers them.
func (m *Monitor) Attach(seccompFD, rootPID int) error {
	_, err := m.AttachJournal(seccompFD, rootPID, seccomp.NewJournal(seccomp.DefaultSlots))
	return err
}

// AttachJournal is Attach with the journal of the notifications in
// flight, whose size caps them. The notifications it already holds,
// received by a previous monitor (e.g. before a crash), are handled
// first. done is closed once no task uses the listener and the monitor
// no longer uses seccompFD or j: the caller may then close them.
func (m *Monitor) AttachJournal(seccompFD, rootPID int, j *seccomp.Journal) (done <-chan struct{}, err error) {
	l := seccomp.NewListener(seccompFD)
	hup := make(chan struct{})
	go func() {
		defer close(hup)
		// No events requested: poll still reports POLLHUP and POLLERR,
		// and does not wake up for pending notifications.
		fds := []unix.PollFd{{Fd: int32(seccompFD)}}
		for {
			_, err := unix.Poll(fds, -1)
			if err == unix.EINTR {
				continue
			}
			if err != nil || fds[0].Revents != 0 {
				return
			}
		}
	}()
	return m.attach(l, rootPID, hup, j)
}

// attach is Attach for any Notifier; hup is closed when no task uses it.
func (m *Monitor) attach(n Notifier, root int, hup <-chan struct{}, j *seccomp.Journal) (<-chan struct{}, error) {
	l := &listener{n: n, j: j, root: root, mountFD: -1, hup: hup}
	m.mu.Lock()
	if m.closed || m.finished {
		m.mu.Unlock()
		return nil, errors.New("monitor: closed")
	}
	m.mu.Unlock()
	if m.kernel != nil {
		m.kmu.Lock()
		err := m.kernel.AddMember(root)
		if err == nil {
			err = m.syncLocked(m.currentRules())
		}
		if err == nil {
			l.mountFD, err = unix.Open(fmt.Sprintf("/proc/%d/mountinfo", root), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		}
		m.kmu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("strict mode: %w", err)
		}
	}
	m.mu.Lock()
	m.listeners = append(m.listeners, l)
	m.live++
	startKernel := m.kernel != nil && !m.kernelOn
	m.kernelOn = true
	m.mu.Unlock()
	if startKernel {
		go m.kernel.Events(m.kernelEvent)
	}
	m.replay(l)
	for i := 0; i < max(4, runtime.NumCPU()); i++ {
		l.wg.Add(1)
		go m.receiver(l)
	}
	done := make(chan struct{})
	go func() {
		<-hup
		m.mu.Lock()
		m.live--
		gone := m.live == 0
		m.mu.Unlock()
		go func() {
			// The journal outlives its slots in use.
			l.wg.Wait()
			close(done)
		}()
		if gone {
			m.finish()
		}
	}()
	return done, nil
}

func (m *Monitor) currentRules() []rules.Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rules
}

// Snapshot lets a client join: pending requests and the rules, at
// generation gen; then follow Events.
func (m *Monitor) Snapshot() (pending []*Request, rs []rules.Rule, gen uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.pending {
		pending = append(pending, r.pub)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].ID < pending[j].ID })
	now := m.now()
	for _, r := range m.rules {
		if !r.Expired(now) {
			rs = append(rs, r)
		}
	}
	return pending, rs, m.gen
}

// Apply is the only write entry point, and atomic: it computes the new rule
// set, syncs the kernel (strict), gives the verdicts, then closes the
// pending requests that the new rules decide. It returns the new
// generation. With IfGeneration != 0, it fails with ErrStale if the rules
// changed since that generation. A verdict on a request that is not
// pending fails with ErrClosed. If the kernel sync fails, Apply restores
// the previous rule set, gives no verdict and returns the error: the
// requests stay pending.
//
// In strict mode, the grant of an allow verdict is made by the thread
// handling the syscall, just before it continues it; a failed grant is a
// Warning, and BPF then denies the syscall.
func (m *Monitor) Apply(d Decision) (uint64, error) {
	m.kmu.Lock()
	defer m.kmu.Unlock()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, errors.New("monitor: closed")
	}
	if d.IfGeneration != 0 && d.IfGeneration != m.gen {
		gen := m.gen
		m.mu.Unlock()
		return gen, ErrStale
	}
	for _, v := range d.Verdicts {
		if m.pending[v.Request] == nil {
			gen := m.gen
			m.mu.Unlock()
			return gen, fmt.Errorf("request %d: %w", v.Request, ErrClosed)
		}
	}
	old := m.rules
	next, changed, err := m.nextRules(old, d)
	gen := m.gen
	m.mu.Unlock()
	if err != nil {
		return gen, err
	}
	if changed && m.kernel != nil {
		if err := m.syncLocked(next); err != nil {
			if err2 := m.syncLocked(old); err2 != nil {
				m.warn("strict mode: restoring the kernel's rules: " + err2.Error())
			}
			return gen, fmt.Errorf("strict mode: updating the kernel's rules: %w", err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = next
	if changed {
		m.gen++
		m.emitLocked(Event{Rules: m.gen})
	}
	for _, v := range d.Verdicts {
		// Its task may have died while the kernel was synced.
		if r := m.pending[v.Request]; r != nil {
			m.closeLocked(r, v.Allow, Reason{Client: d.Client})
		}
	}
	m.settleLocked()
	return m.gen, nil
}

// nextRules returns old with d's changes, and whether it differs. Expired
// rules are dropped. mu must be held.
func (m *Monitor) nextRules(old []rules.Rule, d Decision) ([]rules.Rule, bool, error) {
	rmID := map[uint64]bool{}
	for _, id := range d.RemoveRules {
		rmID[id] = true
	}
	rmSet := map[string]bool{}
	for _, s := range d.RemoveSets {
		rmSet[s] = true
	}
	now := m.now()
	next := make([]rules.Rule, 0, len(old)+len(d.AddRules))
	changed := len(d.AddRules) > 0
	for _, r := range old {
		if rmID[r.ID] || rmSet[r.Set] || r.Expired(now) {
			changed = true
			continue
		}
		next = append(next, r)
	}
	id := m.nextRuleID
	for _, r := range d.AddRules {
		if err := m.check(&r); err != nil {
			return nil, false, err
		}
		id++
		r.ID = id
		next = append(next, r)
	}
	m.nextRuleID = id
	return next, changed, nil
}

// check validates r and resolves its path.
func (m *Monitor) check(r *rules.Rule) error {
	o := r.Object
	n := 0
	if o.Path != nil {
		n++
	}
	if o.Proc != nil {
		n++
	}
	if o.Unknown {
		n++
	}
	if n != 1 {
		return fmt.Errorf("monitor: rule %+v: want exactly one object", *r)
	}
	if r.Ops == 0 {
		return fmt.Errorf("monitor: rule on %+v: no ops", o)
	}
	if o.Path != nil {
		if !filepath.IsAbs(o.Path.Path) {
			return fmt.Errorf("monitor: rule path %q is not absolute", o.Path.Path)
		}
		p := filepath.Clean(o.Path.Path)
		if !m.procRoot {
			if res, err := filepath.EvalSymlinks(p); err == nil {
				p = res
			}
		}
		r.Object.Path = &rules.PathMatch{Path: p, Tree: o.Path.Tree}
	}
	if m.kernel != nil {
		if _, _, err := toLSM(*r); err != nil {
			return err
		}
	}
	return nil
}

// Close stops mediating: pending requests are closed as if their tasks
// died, and subscriptions are flushed and closed. The seccomp fds stay
// open until the process exits, so no task is left waiting on a closed
// fd: their syscalls fail with ENOSYS meanwhile, as after an exit.
func (m *Monitor) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	for _, r := range m.pending {
		m.closeLocked(r, false, Reason{Died: true})
	}
	ls := m.listeners
	m.mu.Unlock()
	m.finish()
	for _, l := range ls {
		if l.mountFD >= 0 {
			unix.Close(l.mountFD)
		}
	}
	return nil
}

// finish flushes and closes the subscriptions, once the notifications in
// flight are handled: the workload is gone, or the monitor closed.
func (m *Monitor) finish() {
	m.mu.Lock()
	for m.busy > 0 {
		m.idle.Wait()
	}
	if m.finished {
		m.mu.Unlock()
		return
	}
	m.finished = true
	subs := m.subs
	m.subs = nil
	m.mu.Unlock()
	for _, s := range subs {
		s.finish()
	}
}

// warn reports a failure no caller can receive.
func (m *Monitor) warn(msg string) {
	m.mu.Lock()
	m.emitLocked(Event{Warning: msg})
	m.mu.Unlock()
}

// emitLocked sends ev to the subscribers. mu must be held.
func (m *Monitor) emitLocked(ev Event) {
	for _, s := range m.subs {
		if ev.Decided != nil && !s.decided {
			continue
		}
		s.push(ev)
	}
}

// Events subscribes a client; each call returns a new channel. Opened,
// Closed, Rules and Warning events are sent at once. Decided events are
// batched: the first after a quiet period is sent at once; later ones are
// held until 500 ms without new events, at most 2 s. All events are flushed
// before the channel is closed, when the workload is gone (all listeners
// hung up) or the monitor closed, or dropped when opts.Done is closed.
func (m *Monitor) Events(opts EventOptions) <-chan []Event {
	s := newSubscriber(opts.Decided)
	go s.run()
	m.mu.Lock()
	if m.finished {
		s.finish()
	} else {
		m.subs = append(m.subs, s)
		if opts.Decided {
			m.decided++
		}
	}
	m.mu.Unlock()
	if opts.Done != nil {
		go func() {
			<-opts.Done
			m.unsubscribe(s)
		}()
	}
	return s.ch
}

// unsubscribe stops delivering events to s.
func (m *Monitor) unsubscribe(s *subscriber) {
	m.mu.Lock()
	for i, x := range m.subs {
		if x == s {
			m.subs = append(m.subs[:i:i], m.subs[i+1:]...)
			if s.decided {
				m.decided--
			}
			break
		}
	}
	m.mu.Unlock()
	close(s.stop)
}

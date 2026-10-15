// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

func init() {
	batchQuiet = 10 * time.Millisecond
	batchMax = 50 * time.Millisecond
	pollPeriod = 20 * time.Millisecond
}

// response is what the monitor answered to a notification.
type response struct {
	id    uint64
	errno int32 // 0: continued
}

// fakeNotifier hands notifications of the test process itself to the
// monitor: their path arguments point into the test's memory.
type fakeNotifier struct {
	in    chan seccomp.Notif
	out   chan response
	mu    sync.Mutex
	dead  map[uint64]bool
	hup   chan struct{}
	alive []any // keeps path buffers alive

	orphanRecvs int // Recv calls after hup
}

func newFake() *fakeNotifier {
	return &fakeNotifier{in: make(chan seccomp.Notif), out: make(chan response, 100), dead: map[uint64]bool{}, hup: make(chan struct{})}
}

func (f *fakeNotifier) Recv() (seccomp.Notif, error) {
	select {
	case n, ok := <-f.in:
		if !ok {
			return n, unix.EBADF
		}
		return n, nil
	case <-f.hup:
		// Like the kernel once the filter has no tasks left.
		f.mu.Lock()
		f.orphanRecvs++
		f.mu.Unlock()
		return seccomp.Notif{}, unix.ENOENT
	}
}

func (f *fakeNotifier) IDValid(id uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.dead[id]
}

func (f *fakeNotifier) kill(id uint64) {
	f.mu.Lock()
	f.dead[id] = true
	f.mu.Unlock()
}

func (f *fakeNotifier) Continue(id uint64) error { f.out <- response{id, 0}; return nil }
func (f *fakeNotifier) Deny(id uint64, errno int32) error {
	f.out <- response{id, errno}
	return nil
}

var nextID uint64 = 1000

// send notifies syscall nr of the test process, with path arguments at
// the given indexes.
func (f *fakeNotifier) send(nr int, args map[int]string, extra map[int]uint64) uint64 {
	nextID++
	n := seccomp.Notif{ID: nextID, PID: uint32(os.Getpid()), Nr: int32(nr)}
	for i := range n.Args {
		n.Args[i] = uint64(procAtFDCWD())
	}
	for i, p := range args {
		b := append([]byte(p), 0)
		f.mu.Lock()
		f.alive = append(f.alive, b)
		f.mu.Unlock()
		n.Args[i] = uint64(uintptr(unsafe.Pointer(&b[0])))
	}
	for i, v := range extra {
		n.Args[i] = v
	}
	f.in <- n
	return n.ID
}

func procAtFDCWD() int64 { return unix.AT_FDCWD }

func (f *fakeNotifier) mkdir(path string) uint64 {
	return f.send(unix.SYS_MKDIRAT, map[int]string{1: path}, nil)
}

func (f *fakeNotifier) expect(t *testing.T, id uint64, errno int32) {
	t.Helper()
	select {
	case r := <-f.out:
		if r.id != id || r.errno != errno {
			t.Fatalf("response %+v, want {id:%d errno:%d}", r, id, errno)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no response for %d", id)
	}
}

func (f *fakeNotifier) expectNone(t *testing.T) {
	t.Helper()
	select {
	case r := <-f.out:
		t.Fatalf("unexpected response %+v", r)
	case <-time.After(100 * time.Millisecond):
	}
}

// fakeKernel records the rules it is given.
type fakeKernel struct {
	mu      sync.Mutex
	paths   []lsm.Rule
	procs   []lsm.ProcRule
	syncs   int
	fail    error // next Sync fails with it
	grants  [][]string
	members []int
}

func (k *fakeKernel) AddMember(pid int) error {
	k.mu.Lock()
	k.members = append(k.members, pid)
	k.mu.Unlock()
	return nil
}

func (k *fakeKernel) Sync(paths []lsm.Rule, procs []lsm.ProcRule) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.syncs++
	if err := k.fail; err != nil {
		k.fail = nil
		return err
	}
	k.paths, k.procs = paths, procs
	return nil
}

func (k *fakeKernel) GrantOnce(tid int, paths []string, proc lsm.ProcRule) error {
	k.mu.Lock()
	k.grants = append(k.grants, paths)
	k.mu.Unlock()
	return nil
}

func (k *fakeKernel) Events(fn func(lsm.Event)) {}

type fixture struct {
	m   *Monitor
	f   *fakeNotifier
	dir string
	evs <-chan []Event
}

func setup(t *testing.T, k Kernel, decided bool) *fixture {
	t.Helper()
	m, err := New(Config{Kernel: k})
	if err != nil {
		t.Fatal(err)
	}
	fx := &fixture{m: m, f: newFake(), dir: t.TempDir()}
	fx.dir, _ = filepath.EvalSymlinks(fx.dir)
	fx.evs = m.Events(EventOptions{Decided: decided})
	if err := m.attach(fx.f, os.Getpid(), fx.f.hup); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.Close()
		close(fx.f.in)
		runtime.KeepAlive(fx.f.alive)
	})
	return fx
}

// next returns the next event matching keep.
func (fx *fixture) next(t *testing.T, keep func(Event) bool) Event {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case evs, ok := <-fx.evs:
			if !ok {
				t.Fatal("events closed")
			}
			for _, ev := range evs {
				if keep(ev) {
					return ev
				}
			}
		case <-timeout:
			t.Fatal("no event")
		}
	}
}

func opened(ev Event) bool   { return ev.Opened != nil }
func isClosed(ev Event) bool { return ev.Closed != nil }

func tree(path string, v rules.Verdict) rules.Rule {
	return rules.Rule{Ops: rules.OpAll, Verdict: v, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: path, Tree: true}}}
}

func TestRules(t *testing.T) {
	fx := setup(t, nil, false)
	ok, no := filepath.Join(fx.dir, "ok"), filepath.Join(fx.dir, "no")
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(ok, rules.Allow), tree(no, rules.Deny)}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, fx.f.mkdir(ok+"/a"), 0)
	fx.f.expect(t, fx.f.mkdir(no+"/a"), int32(unix.EACCES))
}

func TestAskVerdict(t *testing.T) {
	fx := setup(t, nil, false)
	p := filepath.Join(fx.dir, "x")
	id := fx.f.mkdir(p)
	req := fx.next(t, opened).Opened
	if req.Op != rules.OpMkdir || req.Objects[0].Path.Path != p || req.Syscall != "mkdirat" {
		t.Fatalf("request %+v", req)
	}
	if req.Subject.Chain[0].PID != os.Getpid() {
		t.Fatalf("subject %+v", req.Subject)
	}
	fx.f.expectNone(t)
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, 0)
	if c := fx.next(t, isClosed).Closed; c.ID != req.ID || c.Why.Client != "test" {
		t.Fatalf("closed %+v", c)
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("second verdict: %v, want ErrClosed", err)
	}
}

func TestCoalesce(t *testing.T) {
	fx := setup(t, nil, false)
	p := filepath.Join(fx.dir, "x")
	id1 := fx.f.mkdir(p)
	req := fx.next(t, opened).Opened
	id2 := fx.f.mkdir(p)
	// The second joins the first: no new request.
	time.Sleep(50 * time.Millisecond)
	pending, _, _ := fx.m.Snapshot()
	if len(pending) != 1 {
		t.Fatalf("%d pending, want 1", len(pending))
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	got := map[uint64]int32{}
	for range 2 {
		r := <-fx.f.out
		got[r.id] = r.errno
	}
	if got[id1] != int32(unix.EACCES) || got[id2] != int32(unix.EACCES) {
		t.Fatalf("responses %v", got)
	}
}

func TestRuleSettlesPending(t *testing.T) {
	fx := setup(t, nil, false)
	sub := filepath.Join(fx.dir, "sub")
	id1 := fx.f.mkdir(sub + "/a")
	r1 := fx.next(t, opened).Opened
	id2 := fx.f.mkdir(sub + "/b")
	fx.next(t, opened)
	gen, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(sub, rules.Allow)}, Verdicts: []Verdict{{r1.ID, true}}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint64]int32{}
	for range 2 {
		r := <-fx.f.out
		got[r.id] = r.errno
	}
	if len(got) != 2 || got[id1] != 0 || got[id2] != 0 {
		t.Fatalf("responses %v", got)
	}
	_, rs, g := fx.m.Snapshot()
	if g != gen || len(rs) != 1 || rs[0].ID == 0 {
		t.Fatalf("snapshot gen %d rules %+v, want gen %d", g, rs, gen)
	}
	if _, err := fx.m.Apply(Decision{IfGeneration: gen + 1}); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	if _, err := fx.m.Apply(Decision{IfGeneration: gen, RemoveRules: []uint64{rs[0].ID}}); err != nil {
		t.Fatal(err)
	}
	if _, rs, _ := fx.m.Snapshot(); len(rs) != 0 {
		t.Fatalf("rules after removal: %+v", rs)
	}
}

func TestRemoveSet(t *testing.T) {
	fx := setup(t, nil, false)
	r := tree(fx.dir, rules.Allow)
	r.Set = "implicit"
	fx.m.Apply(Decision{AddRules: []rules.Rule{r, tree("/nonexistent", rules.Deny)}})
	fx.m.Apply(Decision{RemoveSets: []string{"implicit"}})
	_, rs, _ := fx.m.Snapshot()
	if len(rs) != 1 || rs[0].Object.Path.Path != "/nonexistent" {
		t.Fatalf("rules %+v", rs)
	}
}

func TestRestartCache(t *testing.T) {
	fx := setup(t, nil, true)
	p := filepath.Join(fx.dir, "x")
	// A restarted syscall has the same thread, number and arguments.
	b := append([]byte(p), 0)
	args := [6]uint64{uint64(procAtFDCWD()), uint64(uintptr(unsafe.Pointer(&b[0])))}
	for i := 2; i < 6; i++ {
		args[i] = uint64(procAtFDCWD())
	}
	once := func() uint64 {
		nextID++
		fx.f.in <- seccomp.Notif{ID: nextID, PID: uint32(os.Getpid()), Nr: unix.SYS_MKDIRAT, Args: args}
		return nextID
	}
	id := once()
	req := fx.next(t, opened).Opened
	fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"})
	fx.f.expect(t, id, 0)
	id = once()
	fx.f.expect(t, id, 0)
	d := fx.next(t, func(ev Event) bool { return ev.Decided != nil && ev.Decided.Why[0].Builtin == "restarted" })
	if !d.Decided.Allowed {
		t.Fatal(d.Decided)
	}
	runtime.KeepAlive(b)
}

func TestUnknownPath(t *testing.T) {
	fx := setup(t, nil, false)
	// An unreadable address.
	nextID++
	id := nextID
	fx.f.in <- seccomp.Notif{ID: id, PID: uint32(os.Getpid()), Nr: unix.SYS_MKDIRAT, Args: [6]uint64{uint64(procAtFDCWD()), 8}}
	req := fx.next(t, opened).Opened
	if req.Objects[0].Unknown == nil {
		t.Fatalf("request %+v", req)
	}
	never := rules.Rule{Ops: rules.OpAll, Verdict: rules.Deny, Object: rules.ObjectMatch{Unknown: true}}
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{never}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EACCES))
}

func TestDied(t *testing.T) {
	fx := setup(t, nil, false)
	id := fx.f.mkdir(filepath.Join(fx.dir, "x"))
	req := fx.next(t, opened).Opened
	fx.f.kill(id)
	c := fx.next(t, isClosed).Closed
	if c.ID != req.ID || !c.Why.Died {
		t.Fatalf("closed %+v", c)
	}
	fx.f.expectNone(t)
}

func TestUnresolvable(t *testing.T) {
	fx := setup(t, nil, true)
	// A relative path to a closed dirfd.
	id := fx.f.send(unix.SYS_MKDIRAT, map[int]string{1: "x"}, map[int]uint64{0: 99999})
	fx.f.expect(t, id, int32(unix.EACCES))
	d := fx.next(t, func(ev Event) bool { return ev.Decided != nil }).Decided
	if d.Allowed || d.Why[0].Builtin != "unresolvable" {
		t.Fatalf("decided %+v", d)
	}
}

func TestStrict(t *testing.T) {
	k := &fakeKernel{}
	fx := setup(t, k, false)
	if len(k.members) != 1 || k.syncs != 1 {
		t.Fatalf("members %v syncs %d", k.members, k.syncs)
	}
	ask := tree(fx.dir, rules.Ask)
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{ask}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ask rule: %v", err)
	}
	ops := tree(fx.dir, rules.Allow)
	ops.Ops = rules.OpWrite
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{ops}}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ops rule: %v", err)
	}

	a := filepath.Join(fx.dir, "a")
	id := fx.f.mkdir(a)
	req := fx.next(t, opened).Opened

	// A failed sync keeps the old rules, here and in the kernel, and the
	// request pending.
	k.fail = errors.New("boom")
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(fx.dir, rules.Allow)}, Verdicts: []Verdict{{req.ID, true}}}); err == nil {
		t.Fatal("apply: no error")
	}
	if _, rs, _ := fx.m.Snapshot(); len(rs) != 0 {
		t.Fatalf("rules after failed sync: %+v", rs)
	}
	if k.syncs != 3 || len(k.paths) != 0 {
		t.Fatalf("syncs %d paths %v", k.syncs, k.paths)
	}
	fx.f.expectNone(t)

	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, 0)
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.grants) != 1 || len(k.grants[0]) != 1 || k.grants[0][0] != a {
		t.Fatalf("grants %v", k.grants)
	}
}

func TestFlushOnHangup(t *testing.T) {
	fx := setup(t, nil, true)
	fx.m.Apply(Decision{AddRules: []rules.Rule{tree(fx.dir, rules.Allow)}})
	for i := range 5 {
		fx.f.expect(t, fx.f.mkdir(filepath.Join(fx.dir, string(rune('a'+i)))), 0)
	}
	close(fx.f.hup)
	n := 0
	for evs := range fx.evs {
		for _, ev := range evs {
			if ev.Decided != nil {
				n++
			}
		}
	}
	if n != 5 {
		t.Fatalf("%d decided events, want 5", n)
	}
	// The workers stop instead of spinning on ENOENT.
	time.Sleep(50 * time.Millisecond)
	fx.f.mu.Lock()
	defer fx.f.mu.Unlock()
	if workers := max(4, runtime.NumCPU()); fx.f.orphanRecvs > workers {
		t.Fatalf("%d Recv calls after hangup, want at most %d", fx.f.orphanRecvs, workers)
	}
}

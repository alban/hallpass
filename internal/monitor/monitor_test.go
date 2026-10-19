// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
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

func (f *fakeNotifier) Recv(slot []byte) (seccomp.Notif, error) {
	select {
	case n, ok := <-f.in:
		if !ok {
			return n, unix.EBADF
		}
		putNotif(slot, n)
		return n, nil
	case <-f.hup:
		// Like the kernel once the filter has no tasks left.
		f.mu.Lock()
		f.orphanRecvs++
		f.mu.Unlock()
		return seccomp.Notif{}, unix.ENOENT
	}
}

// putNotif writes n as the kernel's struct seccomp_notif.
func putNotif(b []byte, n seccomp.Notif) {
	binary.LittleEndian.PutUint64(b[0:], n.ID)
	binary.LittleEndian.PutUint32(b[8:], n.PID)
	binary.LittleEndian.PutUint32(b[16:], uint32(n.Nr))
	binary.LittleEndian.PutUint32(b[20:], n.Arch)
	for i, a := range n.Args {
		binary.LittleEndian.PutUint64(b[32+i*8:], a)
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

// Continue and Deny answer id: like the kernel, it is no longer valid.
func (f *fakeNotifier) Continue(id uint64) error { return f.answer(id, 0) }
func (f *fakeNotifier) Deny(id uint64, errno int32) error {
	return f.answer(id, errno)
}

func (f *fakeNotifier) answer(id uint64, errno int32) error {
	f.kill(id)
	f.out <- response{id, errno}
	return nil
}

var lastID atomic.Uint64

func init() { lastID.Store(1000) }

func newID() uint64 { return lastID.Add(1) }

// send notifies syscall nr of the test process, with path arguments at
// the given indexes.
func (f *fakeNotifier) send(nr int, args map[int]string, extra map[int]uint64) uint64 {
	n := seccomp.Notif{ID: newID(), PID: uint32(os.Getpid()), Nr: int32(nr)}
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

// openat2 notifies openat2(dirfd, path, how, size).
func (f *fakeNotifier) openat2(dirfd int, path string, how unix.OpenHow, size uint64) uint64 {
	h := &how
	f.mu.Lock()
	f.alive = append(f.alive, h)
	f.mu.Unlock()
	return f.send(unix.SYS_OPENAT2, map[int]string{1: path}, map[int]uint64{0: uint64(int64(dirfd)), 2: uint64(uintptr(unsafe.Pointer(h))), 3: size})
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
	mu        sync.Mutex
	paths     []lsm.Rule
	procs     []lsm.ProcRule
	syncs     int
	fail      error // next Sync fails with it
	grants    [][]string
	members   []int
	net       lsm.NetRules
	netGrants []lsm.NetGrant
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

func (k *fakeKernel) GrantOnce(tid int, paths []string, proc lsm.ProcRule, net lsm.NetGrant) error {
	k.mu.Lock()
	k.grants = append(k.grants, paths)
	k.netGrants = append(k.netGrants, net)
	k.mu.Unlock()
	return nil
}

func (k *fakeKernel) SyncNet(net lsm.NetRules) error {
	k.mu.Lock()
	k.net = net
	k.mu.Unlock()
	return nil
}

func (k *fakeKernel) Events(fn func(lsm.Event)) {}

type fixture struct {
	m    *Monitor
	f    *fakeNotifier
	dir  string
	evs  <-chan []Event
	done <-chan struct{} // the listener is no longer used
}

func setup(t *testing.T, k Kernel, decided bool) *fixture {
	t.Helper()
	return setupConfig(t, Config{Kernel: k}, decided)
}

func setupConfig(t *testing.T, cfg Config, decided bool) *fixture {
	t.Helper()
	return setupJournal(t, cfg, decided, seccomp.NewJournal(0))
}

func setupJournal(t *testing.T, cfg Config, decided bool, j *seccomp.Journal) *fixture {
	t.Helper()
	m, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fx := &fixture{m: m, f: newFake(), dir: t.TempDir()}
	fx.dir, _ = filepath.EvalSymlinks(fx.dir)
	fx.evs = m.Events(EventOptions{Decided: decided})
	done, err := m.attach(fx.f, os.Getpid(), fx.f.hup, j)
	if err != nil {
		t.Fatal(err)
	}
	fx.done = done
	t.Cleanup(func() {
		m.Close()
		close(fx.f.in)
		runtime.KeepAlive(fx.f.alive)
		go func() {
			<-done
			j.Close()
		}()
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

// TestPromptsDoNotBlockReceivers checks that requests waiting for a human
// do not hold receivers: with more of them than receivers, a syscall the
// rules allow is still answered.
func TestPromptsDoNotBlockReceivers(t *testing.T) {
	fx := setup(t, nil, false)
	ok := filepath.Join(fx.dir, "ok")
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(ok, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	asked := 2 * max(4, runtime.NumCPU())
	for i := 0; i < asked; i++ {
		fx.f.mkdir(filepath.Join(fx.dir, "ask"+strconv.Itoa(i)))
		fx.next(t, opened)
	}
	fx.f.expect(t, fx.f.mkdir(ok+"/a"), 0)
}

// TestEventsDone checks that closing EventOptions.Done ends a subscription
// that is not read, and stops the Decided events it asked for.
func TestEventsDone(t *testing.T) {
	fx := setup(t, nil, false)
	done := make(chan struct{})
	evs := fx.m.Events(EventOptions{Decided: true, Done: done})
	fx.f.mkdir(filepath.Join(fx.dir, "x"))
	fx.next(t, opened)
	close(done)
	timeout := time.After(5 * time.Second)
	for {
		select {
		case _, ok := <-evs:
			if !ok {
				fx.m.mu.Lock()
				n, d := len(fx.m.subs), fx.m.decided
				fx.m.mu.Unlock()
				if n != 1 || d != 0 {
					t.Fatalf("after Done: %d subscribers (want 1), %d with Decided (want 0)", n, d)
				}
				return
			}
		case <-timeout:
			t.Fatal("channel not closed after Done")
		}
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

func TestRequestKey(t *testing.T) {
	path := func(p string) rules.Object { return rules.Object{Path: &rules.PathObject{Path: p}} }
	by := func(pid int) rules.Subject { return rules.Subject{Chain: []rules.Task{{PID: pid, TID: pid + 1}}} }
	unknown := rules.Object{Unknown: errors.New("unreadable")}
	for _, tc := range []struct {
		name string
		a, b string
		same bool
	}{
		{"same process, same path", requestKey(rules.OpMkdir, path("/x"), by(10), 1), requestKey(rules.OpMkdir, path("/x"), by(10), 2), true},
		{"other process", requestKey(rules.OpMkdir, path("/x"), by(10), 1), requestKey(rules.OpMkdir, path("/x"), by(11), 2), false},
		{"other path", requestKey(rules.OpMkdir, path("/x"), by(10), 1), requestKey(rules.OpMkdir, path("/y"), by(10), 2), false},
		{"other op", requestKey(rules.OpMkdir, path("/x"), by(10), 1), requestKey(rules.OpDelete, path("/x"), by(10), 2), false},
		{"unknown process", requestKey(rules.OpMkdir, path("/x"), by(0), 1), requestKey(rules.OpMkdir, path("/x"), by(0), 2), false},
		{"no subject", requestKey(rules.OpMkdir, path("/x"), rules.Subject{}, 1), requestKey(rules.OpMkdir, path("/x"), rules.Subject{}, 2), false},
		{"unknown path", requestKey(rules.OpMkdir, unknown, by(10), 1), requestKey(rules.OpMkdir, unknown, by(10), 2), false},
	} {
		if got := tc.a == tc.b; got != tc.same {
			t.Errorf("%s: same key %v, want %v (%q, %q)", tc.name, got, tc.same, tc.a, tc.b)
		}
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

func TestProtectedSet(t *testing.T) {
	fx := setup(t, nil, false)
	p := tree("/nonexistent", rules.Deny)
	p.Set = ProtectedSet
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{p, tree(fx.dir, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	_, rs, gen := fx.m.Snapshot()
	var id uint64
	for _, r := range rs {
		if r.Set == ProtectedSet {
			id = r.ID
		}
	}
	for _, d := range []Decision{
		{RemoveSets: []string{ProtectedSet}},
		{RemoveRules: []uint64{id}},
	} {
		if _, err := fx.m.Apply(d); !errors.Is(err, ErrProtected) {
			t.Errorf("Apply(%+v): %v, want ErrProtected", d, err)
		}
	}
	allow := tree("/x", rules.Allow)
	allow.Set = ProtectedSet
	expiring := tree("/y", rules.Deny)
	expiring.Set, expiring.Expires = ProtectedSet, time.Now().Add(time.Hour)
	for _, r := range []rules.Rule{allow, expiring} {
		if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{r}}); err == nil {
			t.Errorf("Apply(add %+v) succeeded", r)
		}
	}
	if _, rs2, g := fx.m.Snapshot(); g != gen || len(rs2) != len(rs) {
		t.Fatalf("rules changed: gen %d -> %d, %+v", gen, g, rs2)
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
		id := newID()
		fx.f.in <- seccomp.Notif{ID: id, PID: uint32(os.Getpid()), Nr: unix.SYS_MKDIRAT, Args: args}
		return id
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
	id := newID()
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

// TestProcRoot resolves paths through the caller's /proc/<tid>/root, as the
// node agent does; the test process's root is "/", so the paths are the
// same. Rule paths are not symlink-resolved: they are paths in the
// workload's root, not the monitor's.
func TestProcRoot(t *testing.T) {
	fx := setupConfig(t, Config{ProcRoot: true}, true)
	ok := filepath.Join(fx.dir, "ok")
	link := filepath.Join(fx.dir, "link")
	if err := os.Symlink(ok, link); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(link, rules.Allow), tree(ok+"/no", rules.Deny)}}); err != nil {
		t.Fatal(err)
	}
	_, rs, _ := fx.m.Snapshot()
	if rs[0].Object.Path.Path != link {
		t.Errorf("rule path %s, want %s as given", rs[0].Object.Path.Path, link)
	}
	fx.f.expect(t, fx.f.mkdir(link+"/no/a"), int32(unix.EACCES))
	// The workload's own /proc files, named through its procfs.
	id := fx.f.send(unix.SYS_OPENAT, map[int]string{1: "/proc/self/oom_score_adj"}, map[int]uint64{2: unix.O_WRONLY})
	fx.f.expect(t, id, 0)
	d := fx.next(t, func(ev Event) bool { return ev.Decided != nil && ev.Decided.Syscall == "openat" }).Decided
	if !d.Allowed || d.Why[0].Builtin != "own-proc" {
		t.Fatalf("decided %+v", d)
	}
}

// TestOpenat2 checks that the monitor reads struct open_how: the filter
// cannot, and notifies every openat2.
func TestOpenat2(t *testing.T) {
	fx := setup(t, nil, true)
	ok := filepath.Join(fx.dir, "ok")
	if err := os.Mkdir(ok, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(ok, rules.Allow), tree(fx.dir+"/no", rules.Deny)}}); err != nil {
		t.Fatal(err)
	}
	const size = uint64(unsafe.Sizeof(unix.OpenHow{}))
	decided := func() *Decided {
		return fx.next(t, func(ev Event) bool { return ev.Decided != nil }).Decided
	}

	// Without write intent, as GNU tar's O_PATH|O_DIRECTORY: continued
	// silently, as a read-only openat never reaches the monitor.
	id := fx.f.openat2(unix.AT_FDCWD, fx.dir+"/no", unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY, Resolve: unix.RESOLVE_BENEATH}, size)
	fx.f.expect(t, id, 0)
	// An open_how the kernel would refuse, or cannot be read.
	fx.f.expect(t, fx.f.openat2(unix.AT_FDCWD, ok+"/f", unix.OpenHow{}, 8), int32(unix.EINVAL))
	fx.f.expect(t, fx.f.send(unix.SYS_OPENAT2, map[int]string{1: ok + "/f"}, map[int]uint64{2: 8, 3: size}), int32(unix.EFAULT))

	fx.f.expect(t, fx.f.openat2(unix.AT_FDCWD, ok+"/f", unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT}, size), 0)
	d := decided()
	if !d.Allowed || d.Syscall != "openat2" || d.Objects[0].Path.Path != ok+"/f" || d.Op&rules.OpCreate == 0 {
		t.Fatalf("decided %+v", d)
	}
	fx.f.expect(t, fx.f.openat2(unix.AT_FDCWD, fx.dir+"/no/f", unix.OpenHow{Flags: unix.O_RDWR}, size), int32(unix.EACCES))
	if d := decided(); d.Allowed || d.Op&rules.OpCreate != 0 {
		t.Fatalf("decided %+v", d)
	}

	// RESOLVE_IN_ROOT: "/no/f" and a symlink to "/no" name fx.dir/no
	// under the root fx.dir, ".." stops there.
	if err := os.Symlink("/no", filepath.Join(ok, "abs")); err != nil {
		t.Fatal(err)
	}
	root, err := unix.Open(fx.dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	for _, p := range []string{"/no/f", "ok/abs/f", "../../no/f"} {
		fx.f.expect(t, fx.f.openat2(root, p, unix.OpenHow{Flags: unix.O_WRONLY, Resolve: unix.RESOLVE_IN_ROOT}, size), int32(unix.EACCES))
		if d := decided(); d.Allowed || d.Objects[0].Path.Path != fx.dir+"/no/f" {
			t.Fatalf("%s: decided %+v", p, d)
		}
	}
	// A magic link cannot be followed in a root.
	slash, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(slash)
	fx.f.expect(t, fx.f.openat2(slash, "/proc/self/cwd/f", unix.OpenHow{Flags: unix.O_WRONLY, Resolve: unix.RESOLVE_IN_ROOT}, size), int32(unix.EACCES))
	if d := decided(); d.Allowed || d.Why[0].Builtin != "unresolvable" {
		t.Fatalf("decided %+v", d)
	}
}

func TestExecContinued(t *testing.T) {
	// No rule at all: an exec is continued anyway, even in strict mode,
	// once its task is a member.
	k := &fakeKernel{}
	fx := setup(t, k, true)
	id := fx.f.send(unix.SYS_EXECVE, map[int]string{0: "/usr/bin/true"}, nil)
	fx.f.expect(t, id, 0)
	k.mu.Lock()
	members := len(k.members)
	k.mu.Unlock()
	if members != 1 {
		t.Fatalf("%d members after execve", members)
	}
	d := fx.next(t, func(ev Event) bool { return ev.Decided != nil }).Decided
	if !d.Allowed || d.Syscall != "execve" || d.Why[0].Builtin != "execve" ||
		len(d.Objects) != 1 || d.Objects[0].Path.Path != "/usr/bin/true" {
		t.Fatalf("decided %+v", d)
	}
	id = fx.f.send(unix.SYS_EXECVEAT, map[int]string{1: "x"}, map[int]uint64{0: 99999})
	fx.f.expect(t, id, 0)
}

func TestStrict(t *testing.T) {
	k := &fakeKernel{}
	fx := setup(t, k, false)
	if len(k.members) != 0 || k.syncs != 1 {
		t.Fatalf("members %v syncs %d", k.members, k.syncs)
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

// TestStrictAsk: an ask rule inside an allowed tree goes to the kernel,
// and accesses it matches are prompted, a "once" answer granted.
func TestStrictAsk(t *testing.T) {
	k := &fakeKernel{}
	fx := setup(t, k, false)
	secret := filepath.Join(fx.dir, "secret")
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(fx.dir, rules.Allow), tree(secret, rules.Ask)}}); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	want := []lsm.Rule{{Path: fx.dir, Tree: true}, {Path: secret, Tree: true, Ask: true}}
	if fmt.Sprint(k.paths) != fmt.Sprint(want) {
		t.Errorf("kernel rules %+v, want %+v", k.paths, want)
	}
	k.mu.Unlock()

	fx.f.expect(t, fx.f.mkdir(filepath.Join(fx.dir, "a")), 0)
	b := filepath.Join(secret, "b")
	id := fx.f.mkdir(b)
	req := fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, 0)
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.grants) != 1 || len(k.grants[0]) != 1 || k.grants[0][0] != b {
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
	select {
	case <-fx.done:
	case <-time.After(5 * time.Second):
		t.Fatal("listener still in use after hangup")
	}
	// The workers stop instead of spinning on ENOENT.
	time.Sleep(50 * time.Millisecond)
	fx.f.mu.Lock()
	defer fx.f.mu.Unlock()
	if workers := max(4, runtime.NumCPU()); fx.f.orphanRecvs > workers {
		t.Fatalf("%d Recv calls after hangup, want at most %d", fx.f.orphanRecvs, workers)
	}
}

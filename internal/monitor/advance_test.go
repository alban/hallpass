// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/rules"
	"golang.org/x/sys/unix"
)

func TestParseAdvance(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		errno unix.Errno
		want  advanceQuery
	}{
		{"request?op=write&path=/usr/local/bin/**&for=10m&reason=make+install", 0,
			advanceQuery{op: rules.OpFiles, path: "/usr/local/bin", adv: Advance{Tree: true, For: 10 * time.Minute, Reason: "make install"}}},
		{"check?op=write&path=/etc/hosts", 0, advanceQuery{check: true, op: rules.OpFiles, path: "/etc/hosts"}},
		{"request?path=%2Fa%2F..%2Fb&op=write&reason=%E2%9C%93", 0, advanceQuery{op: rules.OpFiles, path: "/b", adv: Advance{Reason: "✓"}}},
		{"request?op=write&path=/**", 0, advanceQuery{op: rules.OpFiles, path: "/", adv: Advance{Tree: true}}},
		{"request?op=read&path=/a", unix.EINVAL, advanceQuery{}},
		{"request?op=write", unix.EINVAL, advanceQuery{}},
		{"request?path=/a", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=a/b", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=/a/*.go", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=/a&for=-1m", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=/a&for=soon", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=/a&path=/b", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=/a&color=red", unix.EINVAL, advanceQuery{}},
		{"request?op=write&path=/a&reason=%zz", unix.EINVAL, advanceQuery{}},
		{"grant?op=write&path=/a", unix.EINVAL, advanceQuery{}},
		{"", unix.EINVAL, advanceQuery{}},
	} {
		got, errno := parseAdvance(AdvanceDir + tc.raw)
		if errno != tc.errno || (errno == 0 && got != tc.want) {
			t.Errorf("%q: %+v, %v; want %+v, %v", tc.raw, got, errno, tc.want, tc.errno)
		}
	}
}

// advance sends an execve of AdvanceDir+query.
func (f *fakeNotifier) advance(query string) uint64 {
	return f.send(unix.SYS_EXECVE, map[int]string{0: AdvanceDir + query}, nil)
}

func TestAdvanceRequest(t *testing.T) {
	fx := setup(t, nil, false)
	dir := filepath.Join(fx.dir, "bin")
	q := "request?op=write&path=" + dir + "/**&for=10m&reason=make+install"

	// Allowed: EALREADY, and the grant the client sent with the verdict
	// covers the next request.
	id := fx.f.advance(q)
	req := fx.next(t, opened).Opened
	a := req.Advance
	if a == nil || !a.Tree || a.For != 10*time.Minute || a.Reason != "make install" ||
		req.Op != rules.OpFiles || req.Objects[0].Path.Path != dir || req.Syscall != "execve" {
		t.Fatalf("request %+v advance %+v", req, a)
	}
	fx.f.expectNone(t)
	grant := tree(dir, rules.Allow)
	grant.Expires = time.Now().Add(time.Hour)
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID, Allow: true}}, AddRules: []rules.Rule{grant}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EALREADY))
	fx.f.expect(t, fx.f.advance(q), int32(unix.EEXIST))
	fx.f.expect(t, fx.f.advance("check?op=write&path="+dir+"/sub/x"), int32(unix.EEXIST))

	// Longer than the grant: asked again. Denied: EPERM.
	id = fx.f.advance("request?op=write&path=" + dir + "/**&for=2h")
	req = fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EPERM))

	// Not answered in time: ETIMEDOUT.
	id = fx.f.advance("request?op=write&path=" + fx.dir + "/other")
	req = fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID}}, Client: "test", TimedOut: true}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.ETIMEDOUT))
}

func TestAdvanceCheck(t *testing.T) {
	fx := setup(t, nil, false)
	ok, no := filepath.Join(fx.dir, "ok"), filepath.Join(fx.dir, "no")
	tmp := filepath.Join(fx.dir, "tmp")
	temp := tree(tmp, rules.Allow)
	temp.Expires = time.Now().Add(9*time.Minute + 30*time.Second)
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(ok, rules.Allow), tree(no, rules.Deny), tree(ok+"/secret", rules.Deny), temp}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query string
		errno unix.Errno
	}{
		{"check?op=write&path=" + ok + "/a", unix.EEXIST},
		{"check?op=write&path=" + ok + "/a/**", unix.EEXIST},
		// A deny below takes part of the tree away.
		{"check?op=write&path=" + ok + "/**", unix.ENOMSG},
		{"check?op=write&path=" + no + "/x", unix.EPERM},
		{"request?op=write&path=" + no + "/x", unix.EPERM},
		{"check?op=write&path=" + fx.dir + "/x", unix.ENOMSG},
		{"check?op=write&path=" + fx.dir + "/x&for=1h", unix.ENOMSG},
		// A temporary grant covers checks for now, and requests for
		// about as long as it lasts.
		{"check?op=write&path=" + tmp + "/**", unix.EEXIST},
		{"check?op=write&path=" + tmp + "/**&for=10m", unix.EEXIST},
		{"check?op=write&path=" + tmp + "/**&for=11m", unix.ENOMSG},
		{"check?op=write", unix.EINVAL},
		{"nonsense", unix.EINVAL},
		{"check?op=write&path=/" + strings.Repeat("a", 5000), unix.ENAMETOOLONG},
	} {
		id := fx.f.advance(tc.query)
		select {
		case r := <-fx.f.out:
			if r.id != id || r.errno != int32(tc.errno) {
				t.Errorf("%.80q: errno %d, want %d (%v)", tc.query, r.errno, tc.errno, tc.errno)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%.80q: no response", tc.query)
		}
	}
}

// TestAdvanceNotSettled checks that a rule allowing the path does not
// close an advance request: only a verdict does, and a task that died.
func TestAdvanceNotSettled(t *testing.T) {
	fx := setup(t, nil, false)
	id := fx.f.advance("request?op=write&path=" + fx.dir + "/**")
	req := fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(fx.dir, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expectNone(t)
	fx.f.kill(id)
	if c := fx.next(t, isClosed).Closed; c.ID != req.ID || !c.Why.Died {
		t.Fatalf("closed %+v", c)
	}
	fx.f.expectNone(t)
}

// TestAdvanceRestarted checks that an execve restarted after a signal joins
// the pending request instead of opening a second one.
func TestAdvanceRestarted(t *testing.T) {
	fx := setup(t, nil, false)
	q := "request?op=write&path=" + fx.dir + "/x"
	first := fx.f.advance(q)
	req := fx.next(t, opened).Opened
	fx.f.kill(first)
	second := fx.f.advance(q)
	time.Sleep(50 * time.Millisecond)
	if pending, _, _ := fx.m.Snapshot(); len(pending) != 1 || pending[0].ID != req.ID {
		t.Fatalf("pending %+v", pending)
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID, Allow: true}}}); err != nil {
		t.Fatal(err)
	}
	got := map[uint64]int32{}
	for range 2 {
		select {
		case r := <-fx.f.out:
			got[r.id] = r.errno
		case <-time.After(5 * time.Second):
			t.Fatalf("responses %v", got)
		}
	}
	if got[first] != int32(unix.EALREADY) || got[second] != int32(unix.EALREADY) {
		t.Fatalf("responses %v", got)
	}
}

// TestAdvanceStrict checks that an advance request is not continued, and
// its task not made a member, in strict mode; the grant goes to the
// kernel like any rule.
func TestAdvanceStrict(t *testing.T) {
	k := &fakeKernel{}
	fx := setup(t, k, false)
	id := fx.f.advance("request?op=write&path=" + fx.dir + "/**&for=1m")
	req := fx.next(t, opened).Opened
	grant := tree(fx.dir, rules.Allow)
	grant.Expires = time.Now().Add(time.Minute)
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID, Allow: true}}, AddRules: []rules.Rule{grant}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EALREADY))
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.members) != 0 || len(k.grants) != 0 {
		t.Fatalf("members %v grants %v", k.members, k.grants)
	}
	if len(k.paths) != 1 || k.paths[0].Path != fx.dir || !k.paths[0].Tree || k.paths[0].Expires.IsZero() {
		t.Fatalf("kernel rules %+v", k.paths)
	}
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

func TestParseAdvance(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		errno unix.Errno
		want  advanceQuery
		dest  string // want.adv.Net.NetString()
	}{
		{"request?op=write&path=/usr/local/bin/**&for=10m&reason=make+install", 0,
			advanceQuery{op: rules.OpFiles, path: "/usr/local/bin", adv: Advance{Tree: true, For: 10 * time.Minute, Reason: "make install"}}, ""},
		{"check?op=write&path=/etc/hosts", 0, advanceQuery{verb: verbCheck, op: rules.OpFiles, path: "/etc/hosts"}, ""},
		{"request?path=%2Fa%2F..%2Fb&op=write&reason=%E2%9C%93", 0, advanceQuery{op: rules.OpFiles, path: "/b", adv: Advance{Reason: "✓"}}, ""},
		{"request?op=write&path=/**", 0, advanceQuery{op: rules.OpFiles, path: "/", adv: Advance{Tree: true}}, ""},
		{"request?op=exec&path=/usr/bin/make&for=1h", 0, advanceQuery{op: rules.OpExec, path: "/usr/bin/make", adv: Advance{For: time.Hour}}, ""},
		{"check?op=exec&path=/opt/tool/**", 0, advanceQuery{verb: verbCheck, op: rules.OpExec, path: "/opt/tool", adv: Advance{Tree: true}}, ""},
		{"request?op=connect&dest=tcp%3A10.1.2.3%2F8%3A443&reason=git", 0, advanceQuery{op: rules.OpNet, adv: Advance{Reason: "git"}}, "tcp:10.0.0.0/8:443"},
		{"check?op=connect&dest=%5B2001%3Adb8%3A%3A1%5D%3A53", 0, advanceQuery{verb: verbCheck, op: rules.OpNet}, "[2001:db8::1]:53"},
		{"request?op=connect&dest=*", 0, advanceQuery{op: rules.OpNet}, "*"},
		{"request?op=connect&dest=unix:/run/x/**", 0, advanceQuery{op: rules.OpNet}, "unix:/run/x/**"},
		{"request?op=connect&dest=unix:@dbus*", 0, advanceQuery{op: rules.OpNet}, "unix:@dbus*"},
		{"release?op=write&path=/a/**", 0, advanceQuery{verb: verbRelease, op: rules.OpFiles, path: "/a", adv: Advance{Tree: true}}, ""},
		{"release?op=connect&dest=udp:1.2.3.4:53", 0, advanceQuery{verb: verbRelease, op: rules.OpNet}, "udp:1.2.3.4:53"},
		{"release?op=exec&path=/a&for=1m", unix.EINVAL, advanceQuery{}, ""},
		{"release?op=exec&path=/a&reason=done", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=connect&dest=all", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=connect&dest=own-listeners", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=connect&dest=example.com:443", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=connect", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=connect&path=/a", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=connect&dest=*&path=/a", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=exec&dest=*", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=exec&path=make", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=read&path=/a", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write", unix.EINVAL, advanceQuery{}, ""},
		{"request?path=/a", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=a/b", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=/a/*.go", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=/a&for=-1m", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=/a&for=soon", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=/a&path=/b", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=/a&color=red", unix.EINVAL, advanceQuery{}, ""},
		{"request?op=write&path=/a&reason=%zz", unix.EINVAL, advanceQuery{}, ""},
		{"grant?op=write&path=/a", unix.EINVAL, advanceQuery{}, ""},
		{"", unix.EINVAL, advanceQuery{}, ""},
	} {
		got, errno := parseAdvance(AdvanceDir + tc.raw)
		dest := ""
		if got.adv.Net.IsNet() {
			dest = got.adv.Net.NetString()
		}
		got.adv.Net = rules.ObjectMatch{}
		if errno != tc.errno || (errno == 0 && (got != tc.want || dest != tc.dest)) {
			t.Errorf("%q: %+v %q, %v; want %+v %q, %v", tc.raw, got, dest, errno, tc.want, tc.dest, tc.errno)
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

// TestAdvanceNotMediated: without files mediated, nothing would enforce a
// grant: requests and checks fail with ENOSYS, without asking. The same
// for programs and network destinations.
func TestAdvanceNotMediated(t *testing.T) {
	fx := setupConfig(t, Config{Mediate: seccomp.Exec | seccomp.Connect}, false)
	for _, q := range []string{"request?op=write&path=" + fx.dir + "/**", "check?op=write&path=" + fx.dir + "/x", "release?op=write&path=" + fx.dir} {
		fx.f.expect(t, fx.f.advance(q), int32(unix.ENOSYS))
	}
	fx.f.expect(t, fx.f.advance("request?op=read&path=/x"), int32(unix.EINVAL))
	select {
	case ev := <-fx.evs:
		t.Fatalf("event %+v", ev)
	default:
	}
	fx = setupConfig(t, Config{Mediate: seccomp.Write}, false)
	for _, q := range []string{"request?op=exec&path=/usr/bin/make", "check?op=connect&dest=*:443", "release?op=connect&dest=*:443"} {
		fx.f.expect(t, fx.f.advance(q), int32(unix.ENOSYS))
	}
}

// TestAdvanceExec: a program asked for in advance; the grant is an allow
// exec rule like --allow-exec's, and covers the next request.
func TestAdvanceExec(t *testing.T) {
	fx := setup(t, nil, false)
	bin := filepath.Join(fx.dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	prog := filepath.Join(bin, "tool")
	writeExec(t, prog, "\x7fELF")
	id := fx.f.advance("request?op=exec&path=" + prog + "&for=1h&reason=build")
	req := fx.next(t, opened).Opened
	if a := req.Advance; a == nil || a.Tree || a.For != time.Hour || a.Writable || req.Op != rules.OpExec || req.Objects[0].Path.Path != prog {
		t.Fatalf("request %+v advance %+v", req, req.Advance)
	}
	g := req.Grant(time.Now().Add(time.Hour))
	if g.Ops != rules.OpExec || g.Set != AdvanceSet || g.Verdict != rules.Allow || g.Object.Path.Path != prog || g.Object.Path.Tree {
		t.Fatalf("grant %+v", g)
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID, Allow: true}}, AddRules: []rules.Rule{g}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EALREADY))
	fx.f.expect(t, fx.f.advance("check?op=exec&path="+prog), int32(unix.EEXIST))
	fx.f.expect(t, fx.f.execve(prog), 0)
	// A program grant does not cover writing it, nor its folder.
	fx.f.expect(t, fx.f.advance("check?op=write&path="+prog), int32(unix.ENOMSG))
	fx.f.expect(t, fx.f.advance("check?op=exec&path="+bin+"/**"), int32(unix.ENOMSG))

	// A folder the workload may write: said so in the request.
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{tree(fx.dir+"/w", rules.Allow), {Ops: rules.OpExec, Verdict: rules.Deny, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/no"}}}}}); err != nil {
		t.Fatal(err)
	}
	fx.f.advance("request?op=exec&path=" + fx.dir + "/w/run")
	if a := fx.next(t, opened).Opened.Advance; !a.Writable {
		t.Errorf("advance %+v", a)
	}
	fx.f.advance("request?op=exec&path=" + fx.dir + "/**")
	if a := fx.next(t, opened).Opened.Advance; !a.Writable || !a.Tree {
		t.Errorf("advance %+v", a)
	}
	fx.f.expect(t, fx.f.advance("request?op=exec&path=/no"), int32(unix.EPERM))
}

// TestAdvanceNet: network destinations asked for in advance, covered by
// the rules only when an allow covers all of them.
func TestAdvanceNet(t *testing.T) {
	fx := setup(t, nil, false)
	net := func(spec string, v rules.Verdict) rules.Rule {
		m, err := rules.ParseNet(spec)
		if err != nil {
			t.Fatal(err)
		}
		return rules.Rule{Ops: rules.OpNet, Verdict: v, Object: m}
	}
	temp := net("udp:9.9.9.9:53", rules.Allow)
	temp.Expires = time.Now().Add(10 * time.Minute)
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{
		net("10.0.0.0/8", rules.Allow), net("10.6.6.0/24", rules.Deny),
		net("192.168.0.0/16:443", rules.Allow), net("192.168.1.1", rules.Ask),
		net("172.16.0.0/12", rules.Deny), net("unix:/run/ok/**", rules.Allow), temp,
		{Ops: rules.OpConnect, Verdict: rules.Allow, Object: rules.ObjectMatch{Inet: &rules.InetMatch{Prefix: netip.MustParsePrefix("1.1.1.1/32")}}},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		query string
		errno unix.Errno
	}{
		{"check?op=connect&dest=10.1.2.3:22", unix.EEXIST},
		{"check?op=connect&dest=tcp:10.1.0.0/16", unix.EEXIST},
		// A deny inside takes part of it away.
		{"check?op=connect&dest=10.0.0.0/8", unix.ENOMSG},
		{"check?op=connect&dest=10.6.6.6:80", unix.EPERM},
		{"request?op=connect&dest=172.16.1.1:443", unix.EPERM},
		// Partly denied: asked.
		{"check?op=connect&dest=172.0.0.0/8", unix.ENOMSG},
		{"check?op=connect&dest=192.168.2.2:443", unix.EEXIST},
		{"check?op=connect&dest=192.168.2.2:80", unix.ENOMSG},
		// An ask more specific than the allow.
		{"check?op=connect&dest=192.168.1.1:443", unix.ENOMSG},
		{"check?op=connect&dest=*", unix.ENOMSG},
		{"check?op=connect&dest=udp:9.9.9.9:53", unix.EEXIST},
		{"check?op=connect&dest=udp:9.9.9.9:53&for=1h", unix.ENOMSG},
		{"check?op=connect&dest=tcp:9.9.9.9:53", unix.ENOMSG},
		// Connect only does not cover sending.
		{"check?op=connect&dest=1.1.1.1", unix.ENOMSG},
		{"check?op=connect&dest=unix:" + fx.dir, unix.ENOMSG},
		{"check?op=connect&dest=unix:@x", unix.ENOMSG},
		{"check?op=connect&dest=all", unix.EINVAL},
	} {
		fx.f.expect(t, fx.f.advance(tc.query), int32(tc.errno))
	}

	id := fx.f.advance("request?op=connect&dest=tcp%3A%5B2001%3Adb8%3A%3A1%5D%3A443&reason=push")
	req := fx.next(t, opened).Opened
	if a := req.Advance; a == nil || a.Net.NetString() != "tcp:[2001:db8::1]:443" || req.Op != rules.OpNet || len(req.Objects) != 0 || a.Reason != "push" {
		t.Fatalf("request %+v advance %+v", req, req.Advance)
	}
	g := req.Grant(time.Time{})
	if g.Ops != rules.OpNet || g.Set != AdvanceSet || g.Object.NetString() != "tcp:[2001:db8::1]:443" {
		t.Fatalf("grant %+v", g)
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{Request: req.ID, Allow: true}}, AddRules: []rules.Rule{g}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EALREADY))
	fx.f.expect(t, fx.f.advance("request?op=connect&dest=tcp:[2001:db8::1]:443"), int32(unix.EEXIST))
	fx.f.expect(t, fx.f.advance("check?op=connect&dest=[2001:db8::1]:443"), int32(unix.ENOMSG))
}

// TestAdvanceRelease: a release removes the grants of requests made in
// advance for the very same thing, and no other rule.
func TestAdvanceRelease(t *testing.T) {
	fx := setup(t, nil, false)
	dir := fx.dir
	grant := func(r rules.Rule) rules.Rule { r.Set = AdvanceSet; return r }
	conn, err := rules.ParseNet("tcp:10.0.0.0/8:443")
	if err != nil {
		t.Fatal(err)
	}
	user := tree(dir+"/user", rules.Allow)
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{
		grant(tree(dir+"/a", rules.Allow)), user,
		grant(rules.Rule{Ops: rules.OpExec, Verdict: rules.Allow, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: dir + "/a"}}}),
		grant(rules.Rule{Ops: rules.OpNet, Verdict: rules.Allow, Object: conn}),
		{Ops: rules.OpNet, Verdict: rules.Allow, Object: conn},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{grant(tree(dir, rules.Deny))}}); err == nil {
		t.Fatal("deny in the advance set")
	}
	for _, tc := range []struct {
		query string
		errno unix.Errno
	}{
		// Not the same scope.
		{"release?op=write&path=" + dir + "/a", unix.ESRCH},
		{"release?op=write&path=" + dir + "/a/b/**", unix.ESRCH},
		{"release?op=write&path=" + dir + "/user/**", unix.ESRCH},
		{"release?op=connect&dest=10.0.0.0/8:443", unix.ESRCH},
		{"release?op=write&path=" + dir + "/a/**", unix.ECANCELED},
		{"release?op=write&path=" + dir + "/a/**", unix.ESRCH},
		{"release?op=exec&path=" + dir + "/a", unix.ECANCELED},
		{"release?op=connect&dest=tcp:10.1.0.0/8:443", unix.ECANCELED},
		{"release?op=connect&dest=tcp:10.0.0.0/8:443", unix.ESRCH},
	} {
		fx.f.expect(t, fx.f.advance(tc.query), int32(tc.errno))
	}
	var released []string
	timeout := time.After(5 * time.Second)
	for len(released) < 3 {
		var evs []Event
		select {
		case evs = <-fx.evs:
		case <-timeout:
			t.Fatalf("released %q", released)
		}
		for _, ev := range evs {
			r := ev.Released
			if r == nil {
				continue
			}
			if len(r.Rules) != 1 || r.Subject.Chain[0].PID <= 0 {
				t.Fatalf("released %+v", r)
			}
			if o := r.Rules[0].Object; o.Path != nil {
				released = append(released, o.Path.Path)
			} else {
				released = append(released, o.NetString())
			}
		}
	}
	if released[0] != dir+"/a" || released[1] != dir+"/a" || released[2] != "tcp:10.0.0.0/8:443" {
		t.Errorf("released %q", released)
	}
	// The user's rules are left.
	_, rs, _ := fx.m.Snapshot()
	if len(rs) != 2 || rs[0].Set != "" || rs[1].Set != "" {
		t.Fatalf("rules %+v", rs)
	}
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

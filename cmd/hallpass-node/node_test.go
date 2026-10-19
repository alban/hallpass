// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
)

func TestParsePolicy(t *testing.T) {
	no := false
	p, err := parsePolicy("agent", policy.Spec{
		Allow:      []string{"/workspace/**", "/tmp", "/home/agent/.cache/"},
		Deny:       []string{"/var/run/secrets/**"},
		Ask:        &no,
		AskTimeout: "30s",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := &Policy{Name: "agent", Policy: policy.Policy{
		Allow:      []string{"/workspace", "/tmp", "/home/agent/.cache"},
		Deny:       []string{"/var/run/secrets"},
		AskTimeout: 30 * time.Second,
		Mediate:    seccomp.DefaultCategories,
	}}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v, want %+v", p, want)
	}

	p, err = parsePolicy("default", policy.Spec{})
	if err != nil || !p.Ask || p.AskTimeout != policy.DefaultAskTimeout {
		t.Errorf("defaults: %+v, %v", p, err)
	}

	p, err = parsePolicy("net", policy.Spec{Mediate: []string{"files", "exec", "network"}, AllowNetwork: []string{"all"}, DenyNetwork: []string{"tcp:169.254.169.254"}})
	if err != nil || p.Mediate != seccomp.AllCategories || len(p.AllowNetwork) != 1 || !p.AllowNetwork[0].AnyNet || p.DenyNetwork[0].NetString() != "tcp:169.254.169.254" {
		t.Errorf("network: %+v, %v", p, err)
	}

	for _, bad := range []policy.Spec{
		{Allow: []string{"workspace/**"}},
		{Allow: []string{"/work*/x"}},
		{Deny: []string{"/a/**/b"}},
		{AskTimeout: "soon"},
		{AskTimeout: "-1s"},
		{Mediate: []string{"dns"}},
		{Mediate: []string{}},
		{AllowNetwork: []string{"all"}},
		{Mediate: []string{"network"}, DenyNetwork: []string{"tcp:nowhere"}},
	} {
		if _, err := parsePolicy("bad", bad); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

func TestDefaultsFor(t *testing.T) {
	p, _ := parsePolicy("agent", policy.Spec{Allow: []string{"/workspace/**"}, Deny: []string{"/workspace/.git/**"}})
	rs := defaultsFor(p, metadata{Home: "/home/agent"}, seccomp.DefaultCategories, 0).Rules()
	var allow, deny []string
	for _, r := range rs {
		if r.Object.Path == nil {
			t.Errorf("network rule without network mediated: %+v", r)
			continue
		}
		if r.Verdict == rules.Allow {
			allow = append(allow, r.Object.Path.Path)
		} else {
			deny = append(deny, r.Object.Path.Path)
		}
	}
	for _, want := range []string{"/workspace", "/dev/null", "/dev/pts", "/dev/tty", "/dev/termination-log"} {
		if !slices.Contains(allow, want) {
			t.Errorf("%s not allowed: %v", want, allow)
		}
	}
	if !slices.Equal(deny, []string{"/workspace/.git"}) {
		t.Errorf("deny: %v", deny)
	}

	p, _ = parsePolicy("net", policy.Spec{Mediate: []string{"files", "network"}, AllowNetwork: []string{"unix:@x"}, DenyNetwork: []string{"tcp:*:22"}, AskNetwork: []string{"unix:@xy"}})
	var nets []string
	for _, r := range defaultsFor(p, metadata{}, p.Mediate, 0).Rules() {
		if r.Object.Path == nil {
			nets = append(nets, r.Verdict.String()+" "+r.Object.NetString())
		}
	}
	if want := []string{"allow own-listeners", "deny tcp:*:22", "allow unix:@x", "ask unix:@xy"}; !slices.Equal(nets, want) {
		t.Errorf("network rules %q, want %q", nets, want)
	}
}

// TestDefaultsForExec: in a container (here, this process's root), its
// command runs without asking, the groups of allowExec too, nothing else.
func TestDefaultsForExec(t *testing.T) {
	ls, err := filepath.EvalSymlinks("/bin/ls")
	if err != nil {
		t.Skip(err)
	}
	md := metadata{Command: "sh", Path: os.Getenv("PATH")}
	execs := func(spec policy.Spec) map[string]string {
		p, err := parsePolicy("exec", spec)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range defaultsFor(p, md, seccomp.DefaultCategories, os.Getpid()).Rules() {
			if r.Ops == rules.OpExec && r.Verdict == rules.Allow {
				out[r.Object.Path.Path] = r.Label
			}
		}
		return out
	}
	sh, _ := filepath.EvalSymlinks("/bin/sh")
	got := execs(policy.Spec{})
	if _, ok := got[sh]; len(got) != 1 || !ok {
		t.Errorf("command only: %v, want %s", got, sh)
	}
	if got := execs(policy.Spec{AllowExec: []string{"@coreutils"}}); got[ls] != "@coreutils" {
		t.Errorf("@coreutils: %s not in %v", ls, got)
	}
	// A policy's group, resolved in the container too.
	got = execs(policy.Spec{Groups: map[string][]string{"@mine": {"/bin/ls"}}, AllowExec: []string{"@mine"}})
	if len(got) != 2 || got[ls] != "@mine" {
		t.Errorf("@mine: %v, want %s", got, ls)
	}
}

type fakeCluster struct {
	selected map[string]bool
	policies map[string]*Policy
}

func (f fakeCluster) Selected(ns string) (bool, error) {
	s, ok := f.selected[ns]
	if !ok {
		return false, errors.New("unknown namespace")
	}
	return s, nil
}

func (f fakeCluster) Policy(name string) (*Policy, error) {
	if p := f.policies[name]; p != nil {
		return p, nil
	}
	return nil, errors.New("no policy")
}

func TestAdjust(t *testing.T) {
	p := &plugin{
		cluster: fakeCluster{
			selected: map[string]bool{"agents": true, "other": false},
			policies: map[string]*Policy{"agent": {Name: "agent", Policy: policy.Policy{Ask: true}}},
		},
		listenerPath: "/run/hallpass/agent.sock",
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	pod := func(ns, policy string) *api.PodSandbox {
		pod := &api.PodSandbox{Namespace: ns, Name: "p", Uid: "uid"}
		if policy != "" {
			pod.Annotations = map[string]string{PolicyAnnotation: policy}
		}
		return pod
	}
	ctr := &api.Container{Name: "c", Env: []string{"PATH=/bin", "HOME=/home/agent"}}

	for _, tc := range []struct {
		name    string
		pod     *api.PodSandbox
		adjust  bool
		wantErr bool
	}{
		{"no annotation", pod("agents", ""), false, false},
		{"namespace not selected", pod("other", "agent"), false, false},
		{"no annotation, unknown namespace", pod("new", ""), false, false},
		{"unknown namespace", pod("new", "agent"), false, true},
		{"unknown policy", pod("agents", "nope"), false, true},
		{"opted in", pod("agents", "agent"), true, false},
	} {
		adj, _, err := p.CreateContainer(t.Context(), tc.pod, ctr)
		if (err != nil) != tc.wantErr || (adj != nil) != tc.adjust {
			t.Errorf("%s: adjustment %v, err %v", tc.name, adj, err)
		}
	}

	adj, err := p.adjust(pod("agents", "agent"), ctr)
	if err != nil {
		t.Fatal(err)
	}
	s := adj.GetLinux().GetSeccompPolicy()
	if s.DefaultAction != string(specs.ActAllow) || s.ListenerPath != p.listenerPath || len(s.Flags) != 0 {
		t.Errorf("profile: %+v", s)
	}
	var md metadata
	if err := json.Unmarshal([]byte(s.ListenerMetadata), &md); err != nil {
		t.Fatal(err)
	}
	if want := (metadata{Namespace: "agents", Pod: "p", PodUID: "uid", Container: "c", Policy: "agent", Home: "/home/agent", Path: "/bin", Mediate: "files,exec"}); md != want {
		t.Errorf("metadata %+v, want %+v", md, want)
	}
	notify := false
	for _, sc := range s.Syscalls {
		if sc.Action == string(specs.ActNotify) && slices.Contains(sc.Names, "openat") {
			notify = true
		}
		if slices.Contains(sc.Names, "connect") {
			t.Errorf("connect in the profile without network mediated: %+v", sc)
		}
	}
	if !notify {
		t.Error("openat is not notified")
	}

	// A policy mediating network.
	p.cluster.(fakeCluster).policies["net"] = &Policy{Name: "net", Policy: policy.Policy{Mediate: seccomp.AllCategories}}
	if adj, err = p.adjust(pod("agents", "net"), ctr); err != nil {
		t.Fatal(err)
	}
	s = adj.GetLinux().GetSeccompPolicy()
	if err := json.Unmarshal([]byte(s.ListenerMetadata), &md); err != nil || md.Mediate != "files,exec,network" {
		t.Errorf("metadata %+v, %v", md, err)
	}
	if !slices.ContainsFunc(s.Syscalls, func(sc *api.LinuxSyscall) bool {
		return sc.Action == string(specs.ActNotify) && slices.Contains(sc.Names, "connect")
	}) {
		t.Error("connect is not notified")
	}

	// The container's own profile is kept.
	base := api.FromOCILinuxSeccomp(&specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchAARCH64, specs.ArchX86_64},
		Syscalls:      []specs.LinuxSyscall{{Names: []string{"read", "openat"}, Action: specs.ActAllow}},
	})
	p.waitKillable = true
	adj, err = p.adjust(pod("agents", "agent"), &api.Container{Name: "c", Linux: &api.LinuxContainer{SeccompPolicy: base}})
	if err != nil {
		t.Fatal(err)
	}
	s = adj.GetLinux().GetSeccompPolicy()
	if s.DefaultAction != string(specs.ActErrno) || !slices.Equal(s.Flags, []string{"SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"}) {
		t.Errorf("profile: %+v", s)
	}
	read := false
	for _, sc := range s.Syscalls {
		if sc.Action == string(specs.ActAllow) && slices.Contains(sc.Names, "read") {
			read = true
		}
	}
	if !read {
		t.Errorf("read is no longer allowed: %+v", s.Syscalls)
	}
}

func TestRecvState(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socket")
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	runc, ag := conn(fds[0]), conn(fds[1])
	defer ag.Close()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	big := make([]byte, 100<<10) // more than one read
	for i := range big {
		big[i] = 'x'
	}
	want := specs.ContainerProcessState{
		Version:  specs.Version,
		Fds:      []string{specs.SeccompFdName},
		Pid:      42,
		Metadata: `{"policy":"agent"}`,
		State:    specs.State{ID: "ctr", Annotations: map[string]string{"big": string(big)}},
	}
	b, _ := json.Marshal(want)
	go func() {
		defer runc.Close()
		_, _, _ = runc.WriteMsgUnix(b, unix.UnixRights(int(w.Fd())), nil)
	}()

	st, fd, err := recvState(ag)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if !reflect.DeepEqual(*st, want) {
		t.Errorf("state %+v", st.State.ID)
	}
	if _, err := unix.Write(fd, []byte("ok")); err != nil {
		t.Fatalf("received fd: %v", err)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "ok" {
		t.Errorf("read %q, %v", got, err)
	}
}

func TestEnvHome(t *testing.T) {
	if h := envHome([]string{"HOMEX=1", "HOME=/h"}); h != "/h" {
		t.Errorf("got %q", h)
	}
	if h := envHome(nil); h != "" {
		t.Errorf("got %q", h)
	}
}

// Until the caches sync, opted-in containers are refused and the others
// go through.
func TestAdjustNotSynced(t *testing.T) {
	p := &plugin{cluster: &kube{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctr := &api.Container{Name: "c"}
	optedIn := &api.PodSandbox{Namespace: "agents", Name: "p", Annotations: map[string]string{PolicyAnnotation: "agent"}}
	if adj, _, err := p.CreateContainer(t.Context(), optedIn, ctr); !errors.Is(err, errNotSynced) || adj != nil {
		t.Errorf("opted in: adjustment %v, err %v", adj, err)
	}
	if adj, _, err := p.CreateContainer(t.Context(), &api.PodSandbox{Namespace: "agents", Name: "q"}, ctr); err != nil || adj != nil {
		t.Errorf("not opted in: adjustment %v, err %v", adj, err)
	}
}

func TestReady(t *testing.T) {
	node := sessionapi.NewNode()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go node.Serve(ln)
	defer node.Stop()
	args := []string{"--addr", ln.Addr().String()}
	if err := cmdReady(args); err == nil {
		t.Error("ready before SetReady(true)")
	}
	node.SetReady(true)
	if err := cmdReady(args); err != nil {
		t.Errorf("not ready after SetReady(true): %v", err)
	}
	node.SetReady(false)
	if err := cmdReady(args); err == nil {
		t.Error("ready after SetReady(false)")
	}
}

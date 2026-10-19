// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/fdstore"
	"github.com/alban/hallpass/internal/launch"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/sessionapi"
)

const (
	envHelper = "HALLPASS_TEST_AGENT" // the fd-store socket
	envA      = "HALLPASS_TEST_A"
	envB      = "HALLPASS_TEST_B"
	envStrict = "HALLPASS_TEST_STRICT"
)

func TestMain(m *testing.M) {
	if launch.IsChild() {
		launch.ChildMain()
	}
	if os.Getenv(envHelper) != "" {
		helperAgent()
		return
	}
	os.Exit(m.Run())
}

var testPolicy = &Policy{Name: "p", Policy: policy.Policy{Prompt: true, PromptTimeout: time.Hour}}

func testAgent(log *slog.Logger) *agent {
	return newAgent(fakeCluster{policies: map[string]*Policy{"p": testPolicy}}, sessionapi.NewNode(), log, noRecorder{}, 8)
}

// helperAgent is an agent, killed by TestRestart: it runs a container
// that writes A, then B, then A again. It answers A with "always", then
// prints "ready" once B is pending.
func helperAgent() {
	fail := func(err error) {
		os.Stderr.WriteString("helper: " + err.Error() + "\n")
		os.Exit(1)
	}
	a := testAgent(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := a.connectStore(os.Getenv(envHelper)); err != nil {
		fail(err)
	}
	if os.Getenv(envStrict) == "1" {
		if err := a.setupStrict("strict", "/"); err != nil {
			fail(err)
		}
	}
	A, B := os.Getenv(envA), os.Getenv(envB)
	home := filepath.Dir(filepath.Dir(A))
	null, err := os.Open(os.DevNull)
	if err != nil {
		fail(err)
	}
	proc, fd, release, err := launch.Start(launch.ProcSpec{
		// A subshell writes: a child forked before the restart, which the
		// next agent does not mark again, unlike the container's root.
		Args:  []string{"/bin/sh", "-c", `(echo 1 > "$0" && echo 2 > "$1" && echo 3 > "$0"); true`, A, B},
		Env:   []string{"PATH=/usr/bin:/bin"},
		Files: []*os.File{null, os.Stderr, os.Stderr},
	})
	if err != nil {
		fail(err)
	}
	// "always" grants $HOME/one to A: not B, in $HOME/two.
	md, _ := json.Marshal(metadata{Policy: "p", Home: home, Command: "/bin/sh"})
	st := &specs.ContainerProcessState{Pid: proc.Pid, State: specs.State{ID: "c1"}, Metadata: string(md)}
	if err := a.attach(st, fd); err != nil {
		fail(err)
	}
	if err := release(); err != nil {
		fail(err)
	}
	a.mu.Lock()
	s := a.sessions["c1"]
	a.mu.Unlock()
	answered := false
	for {
		pending, _, _ := s.m.Snapshot()
		for _, r := range pending {
			p := r.Objects[0].Path.Path
			switch {
			case p == A && !answered:
				if err := s.Answer(r.ID, "always", "test"); err != nil {
					fail(err)
				}
				answered = true
			case p == B:
				// The rules granted for A may not be stored yet.
				a.persist(s)
				os.Stdout.WriteString("ready " + strconv.Itoa(proc.Pid) + "\n")
				select {}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRestart kills an agent while a request is pending, and checks that
// the next one answers it, with the rules granted before.
func TestRestart(t *testing.T) { testRestart(t, false) }

// TestRestartStrict is TestRestart in strict mode: the kernel enforces the
// restored rule for A and the "once" for B only if the next agent adopted
// the programs and resumed the session.
func TestRestartStrict(t *testing.T) {
	skip := t.Skip
	if os.Getenv("HALLPASS_REQUIRE_LSM") == "1" {
		skip = t.Fatal
	}
	if os.Geteuid() != 0 {
		skip("needs root (go test -exec sudo)")
	}
	if err := lsm.Active(); err != nil {
		skip(err)
	}
	testRestart(t, true)
}

func testRestart(t *testing.T, strict bool) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "run", "fd-store.sock")
	ln, err := fdstore.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := &fdstore.Server{UID: os.Getuid(), Log: log}
	go srv.Serve(ln)

	home := t.TempDir()
	A := filepath.Join(home, "one", "a")
	B := filepath.Join(home, "two", "b")
	for _, p := range []string{A, B} {
		if err := os.Mkdir(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The container outlives the helper: become its parent, so that the
	// next agent may read its memory despite Yama's ptrace_scope.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0)
	helper := exec.Command(os.Args[0], "-test.run=^$")
	helper.Env = append(os.Environ(), envHelper+"="+sock, envA+"="+A, envB+"="+B)
	if strict {
		helper.Env = append(helper.Env, envStrict+"=1")
	}
	helper.Stderr = os.Stderr
	out, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer helper.Process.Kill()
	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(out).ReadString('\n')
		line <- l
	}()
	var l string
	select {
	case l = <-line:
	case <-time.After(10 * time.Second):
		t.Fatal("the helper agent did not get B's request")
	}
	if !strings.HasPrefix(l, "ready ") {
		t.Fatalf("helper: %q", l)
	}
	helper.Process.Kill()
	helper.Wait()
	// The session's, and the programs' in strict mode.
	entries := 1
	if strict {
		entries = 2
	}
	if srv.Len() != entries {
		t.Fatalf("%d fd-store entries", srv.Len())
	}

	a := testAgent(log)
	if err := a.connectStore(sock); err != nil {
		t.Fatal(err)
	}
	if strict {
		if err := a.setupStrict("strict", "/"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			a.store.Delete(lsmKey)
			a.lsm.Close()
		}()
	}
	a.mu.Lock()
	s := a.sessions["c1"]
	a.mu.Unlock()
	if s == nil {
		t.Fatal("session not restored")
	}
	if strict && s.ks == nil {
		t.Fatal("strict session restored without its kernel session")
	}
	if !s.policy.Prompt || s.policy.PromptTimeout != time.Hour {
		t.Fatalf("restored policy %+v", s.policy)
	}
	var id uint64
	deadline := time.Now().Add(10 * time.Second)
	for id == 0 {
		if time.Now().After(deadline) {
			t.Fatal("B's request not replayed")
		}
		pending, _, _ := s.m.Snapshot()
		for _, r := range pending {
			if got := objectName(r.Objects[0]); got != B {
				t.Fatalf("pending %q", got)
			}
			id = r.ID
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := s.Answer(id, "once", "test"); err != nil {
		t.Fatal(err)
	}
	// The third write needs the restored rule for A.
	for {
		if b, _ := os.ReadFile(A); string(b) == "3\n" {
			break
		}
		if time.Now().After(deadline) {
			pending, _, _ := s.m.Snapshot()
			t.Fatalf("A not written again; %d pending", len(pending))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if b, _ := os.ReadFile(B); string(b) != "2\n" {
		t.Fatalf("B: %q", b)
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(l, "ready "))); err == nil {
		var ws unix.WaitStatus
		unix.Wait4(pid, &ws, 0, nil)
	}
	// The container is gone: so is its entry.
	for srv.Len() != entries-1 {
		if time.Now().After(deadline) {
			t.Fatal("fd-store entry left")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

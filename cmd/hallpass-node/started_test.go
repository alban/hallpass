// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/alban/hallpass/internal/launch"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/sessionapi"
)

// fakeRecorder keeps the Events.
type fakeRecorder struct {
	mu     sync.Mutex
	events []string // "Pod reason: msg"
}

func (f *fakeRecorder) event(md metadata, _ bool, reason, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, md.Pod+" "+reason+": "+msg)
}

func TestStartedMessage(t *testing.T) {
	for _, tc := range []struct {
		pol    Policy
		strict bool
		want   string
	}{
		{Policy{Name: "p", Policy: policy.Policy{Prompt: true}}, true, `sandboxed by hallpass (strict mode, policy "p"); answer its requests with Headlamp or ` + "`hallpass web --node`"},
		{Policy{Name: "p"}, false, `sandboxed by hallpass (lite mode, policy "p"); requests are denied without asking`},
	} {
		if got := startedMessage(&tc.pol, tc.strict); got != tc.want {
			t.Errorf("got %s\nwant %s", got, tc.want)
		}
	}
}

// TestStartedEvent: a new container's session emits a HallpassStarted
// Event on its pod.
func TestStartedEvent(t *testing.T) {
	rec := &fakeRecorder{}
	a := newAgent(fakeCluster{policies: map[string]*Policy{"p": testPolicy}}, sessionapi.NewNode(), slog.New(slog.NewTextHandler(io.Discard, nil)), rec, 8)
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	proc, fd, release, err := launch.Start(launch.ProcSpec{
		Args:  []string{"/bin/true"},
		Env:   []string{"PATH=/usr/bin:/bin"},
		Files: []*os.File{null, null, null},
	})
	if err != nil {
		t.Fatal(err)
	}
	md, _ := json.Marshal(metadata{Policy: "p", Pod: "pod1", Container: "c", Home: t.TempDir(), Command: "/bin/true"})
	st := &specs.ContainerProcessState{Pid: proc.Pid, State: specs.State{ID: "c1"}, Metadata: string(md)}
	if err := a.attach(st, fd); err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	proc.Wait()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	want := "pod1 HallpassStarted: container c: sandboxed by hallpass (lite mode, policy \"p\"); answer its requests with Headlamp"
	if len(rec.events) == 0 || !strings.HasPrefix(rec.events[0], want) {
		t.Errorf("events %q, want %q first", rec.events, want)
	}
}

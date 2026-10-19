// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakePrompter answers the prompts with keys, one per prompt; it blocks on
// a 0 key until cancelled.
type fakePrompter struct {
	keys  []byte
	shown [][]string
}

func (f *fakePrompter) Prompt(lines []string, accept string, guard, timeout time.Duration, cancel <-chan struct{}, relabel <-chan []string) byte {
	f.shown = append(f.shown, append([]string(nil), lines...))
	k := f.keys[0]
	f.keys = f.keys[1:]
	if k == 0 {
		<-cancel
	}
	return k
}

// TestTerminalWeb checks that [w] opens the web UI and asks again, and that
// a preempting function runs in place of the prompt, which comes back.
func TestTerminalWeb(t *testing.T) {
	f := &fakePrompter{keys: []byte{'w', 0, 'o'}}
	opened := make(chan struct{})
	a := &Terminal{t: f, OnWeb: func() { close(opened) }, Preempt: make(chan func())}
	ran := make(chan struct{})
	go func() {
		<-opened
		a.Preempt <- func() { close(ran) }
	}()
	if got := a.Ask(context.Background(), Request{PID: 1, Path: "/x", Waiting: 0}); got != AnswerAllowOnce {
		t.Fatalf("answer %v, want allow once", got)
	}
	<-ran
	if len(f.shown) != 3 {
		t.Fatalf("shown %d times, want 3", len(f.shown))
	}
	if keys := f.shown[0][len(f.shown[0])-1]; !strings.Contains(keys, "web UI") {
		t.Errorf("no [w] in %q", keys)
	}

	f = &fakePrompter{keys: []byte{'o'}}
	a = &Terminal{t: f}
	a.Ask(context.Background(), Request{PID: 1, Path: "/x"})
	if keys := f.shown[0][len(f.shown[0])-1]; strings.Contains(keys, "web UI") {
		t.Errorf("[w] without OnWeb: %q", keys)
	}
}

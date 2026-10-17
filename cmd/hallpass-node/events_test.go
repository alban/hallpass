// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/monitor"
)

func TestDenials(t *testing.T) {
	old := summaryPeriod
	summaryPeriod = 100 * time.Millisecond
	defer func() { summaryPeriod = old }()

	var mu sync.Mutex
	var got []string
	reports := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
	d := &denials{report: func(msg string) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, msg)
	}}

	// The first denial at once, the next ones summarized.
	d.add("write /etc/a")
	if r := reports(); len(r) != 1 || r[0] != "denied by the policy: write /etc/a" {
		t.Fatalf("first: %q", r)
	}
	for _, w := range []string{"write /etc/b", "write /etc/c", "write /etc/b", "write /etc/d", "write /etc/e", "write /etc/b", "write /etc/c"} {
		d.add(w)
	}
	time.Sleep(3 * summaryPeriod / 2)
	r := reports()
	if len(r) != 2 {
		t.Fatalf("after a period: %q", r)
	}
	if want := "denied by the policy 7 times in the last 100ms: write /etc/b (3), write /etc/c (2), write /etc/d (1) and 1 more"; r[1] != want {
		t.Errorf("summary:\n got %q\nwant %q", r[1], want)
	}

	// A quiet period ends the window: the next denial is reported at once.
	time.Sleep(2 * summaryPeriod)
	d.add("write /etc/f")
	if r := reports(); len(r) != 3 || r[2] != "denied by the policy: write /etc/f" {
		t.Fatalf("after a quiet period: %q", r)
	}

	// stop reports what is left, and nothing afterwards.
	d.add("write /etc/g")
	d.stop()
	d.add("write /etc/h")
	time.Sleep(2 * summaryPeriod)
	r = reports()
	if len(r) != 4 || !strings.Contains(r[3], "1 time in") || !strings.Contains(r[3], "/etc/g") {
		t.Errorf("stop: %q", r)
	}
}

func TestAutomatic(t *testing.T) {
	for _, tc := range []struct {
		why  monitor.Reason
		ask  bool
		want bool
	}{
		{monitor.Reason{Rule: 3}, true, true},
		{monitor.Reason{Builtin: "unresolvable"}, true, true},
		{monitor.Reason{Client: client}, false, true},
		{monitor.Reason{Client: client}, true, false}, // a timeout
		{monitor.Reason{Client: "headlamp"}, false, false},
		{monitor.Reason{Died: true}, false, false},
	} {
		if got := automatic(tc.why, tc.ask); got != tc.want {
			t.Errorf("%+v ask=%v: %v", tc.why, tc.ask, got)
		}
	}
}

func TestClean(t *testing.T) {
	if got := clean("/tmp/a\x1b[31mb\nc"); got != "/tmp/a?[31mb?c" {
		t.Errorf("got %q", got)
	}
	long := clean("/" + strings.Repeat("é", 200))
	if len(long) > 203 || !strings.HasSuffix(long, "...") || !strings.HasPrefix(long, "/é") {
		t.Errorf("long: %d bytes, %q", len(long), long[:10])
	}
}

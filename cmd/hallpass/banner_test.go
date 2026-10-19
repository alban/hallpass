// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/alban/hallpass/internal/ui"
)

func TestBanner(t *testing.T) {
	for _, tc := range []struct {
		strict bool
		asker  ui.Asker
		menu   bool
		want   string
	}{
		{false, &ui.Terminal{}, true, "hallpass: sandbox started (lite, session 42). Ctrl-] for the menu; run 'hallpass web' in another terminal for the full UI."},
		{true, &ui.Terminal{}, true, "hallpass: sandbox started (strict, session 42). Ctrl-] for the menu; run 'hallpass web' in another terminal for the full UI."},
		{false, &ui.Desktop{}, false, "hallpass: sandbox started (lite, session 42). Requests show as desktop notifications; run 'hallpass web' in another terminal for the full UI."},
		{false, ui.Remote{}, false, "hallpass: sandbox started (lite, session 42). Answer from another terminal: 'hallpass answer 42', or 'hallpass web' for the full UI."},
		{false, ui.AutoDeny{}, false, "hallpass: sandbox started (lite, session 42). Requests are denied without asking (--ask=deny)."},
		{false, ui.AutoAllow{}, false, "hallpass: sandbox started (lite, session 42). Requests are allowed without asking (--ask=allow)."},
		{false, &ui.Terminal{}, false, "hallpass: sandbox started (lite, session 42). Run 'hallpass web' in another terminal for the full UI."},
	} {
		got := banner(tc.strict, 42, tc.asker, tc.menu)
		if got != tc.want {
			t.Errorf("banner(%v, %T, %v):\n got %s\nwant %s", tc.strict, tc.asker, tc.menu, got, tc.want)
		}
		if strings.Contains(got, "\n") {
			t.Errorf("%q: more than one line", got)
		}
	}
}

// TestBannerE2E: the line is on stderr, before the command's output.
func TestBannerE2E(t *testing.T) {
	e := newEnv(t)
	c := e.cmd("echo out", "--ask=deny", "--mode=lite")
	var stdout, stderr strings.Builder
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		t.Fatalf("%v\n%s", err, stderr.String())
	}
	if want := "hallpass: sandbox started (lite, session "; !strings.HasPrefix(stderr.String(), want) {
		t.Errorf("stderr %q, want it to start with %q", stderr.String(), want)
	}
	if stdout.String() != "out\n" {
		t.Errorf("stdout %q, want only the command's", stdout.String())
	}
}

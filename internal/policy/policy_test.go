// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
	"time"
)

func newTestEngine() *Engine {
	home := "/home/u"
	return New(home, "/home/u/src/proj", append(DefaultAllows(), "/home/u/.cache/go-build"), DefaultDenies(home))
}

func TestEval(t *testing.T) {
	e := newTestEngine()
	for _, tc := range []struct {
		path string
		want Decision
	}{
		{"/home/u/src/proj/main.go", Allow},
		{"/home/u/src/proj", Allow},
		{"/home/u/src/projX/main.go", Ask}, // prefix match is per component
		{"/home/u/.cache/go-build/ab/x", Allow},
		{"/tmp/x", Allow},
		{"/dev/null", Allow},
		{"/home/u/.ssh/authorized_keys", Deny},
		{"/home/u/.ssh", Deny},
		{"/home/u/.sshx", Ask},
		{"/home/u/.bashrc", Ask},
		{"/etc/passwd", Ask},
	} {
		if got := e.Eval(tc.path); got != tc.want {
			t.Errorf("Eval(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestDenyWinsOverWorkdir(t *testing.T) {
	e := New("/home/u", "/home/u/.ssh", nil, DefaultDenies("/home/u"))
	if got := e.Eval("/home/u/.ssh/config"); got != Deny {
		t.Errorf("got %v, want Deny", got)
	}
}

func TestSessionAnswers(t *testing.T) {
	e := newTestEngine()
	e.AllowFolder("/home/u/.npm")
	if got := e.Eval("/home/u/.npm/_cacache/x"); got != Allow {
		t.Errorf("after AllowFolder: %v", got)
	}
	e.DenyPath("/home/u/.bashrc")
	if got := e.Eval("/home/u/.bashrc"); got != Deny {
		t.Errorf("after DenyPath: %v", got)
	}
	if got := e.Eval("/home/u/.profile"); got != Ask {
		t.Errorf("DenyPath leaked to sibling: %v", got)
	}

	e.AllowFolderFor("/home/u/.m2", 20*time.Millisecond)
	if got := e.Eval("/home/u/.m2/x"); got != Allow {
		t.Errorf("timed grant: %v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if got := e.Eval("/home/u/.m2/x"); got != Ask {
		t.Errorf("expired grant: %v", got)
	}
	e.AllowFolderFor("/home/u/.npm", time.Millisecond) // session grant must not shrink
	time.Sleep(5 * time.Millisecond)
	if got := e.Eval("/home/u/.npm/x"); got != Allow {
		t.Errorf("session grant shortened: %v", got)
	}
}

func TestFolderFor(t *testing.T) {
	e := newTestEngine()
	for _, tc := range []struct{ path, want string }{
		{"/home/u/other/x/y/f", "/home/u/other"},
		{"/home/u/.cache/pip/ab/f", "/home/u/.cache/pip"},
		{"/home/u/.npm/f", "/home/u/.npm"},
		{"/home/u/.local/share/app/x/f", "/home/u/.local/share/app"},
		{"/opt/tool/lib/f", "/opt/tool"},
		{"/etc/f", "/etc"},
		{"/home/u/.bashrc", ""}, // would be $HOME
		{"/f", ""},
		{"/home/u/.ssh/f", ""},    // contains a deny path
		{"/home/u/.config/x", ""}, // ~/.config contains ~/.config/gh
		{"/home/u/.config/app/x", "/home/u/.config/app"},
	} {
		if got := e.FolderFor(tc.path); got != tc.want {
			t.Errorf("FolderFor(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"strings"
	"testing"
)

func TestOrigin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmdline []string
		parents []string
		want    string
	}{
		{"empty", nil, nil, ""},
		{"plain", []string{"touch", "a.txt"}, nil, "touch a.txt"},
		{"quoted", []string{"sh", "-c", "echo evil >> ~/.bashrc"}, []string{"make", "node"},
			`sh -c 'echo evil >> ~/.bashrc' ← make ← node`},
		{"single quote", []string{"echo", "it's"}, nil, `echo "it's"`},
		{"both quotes", []string{"echo", `it's "x"`}, nil, `echo 'it'\''s "x"'`},
		{"empty arg", []string{"x", ""}, nil, `x ''`},
		{"parents only", nil, []string{"bash"}, "bash"},
		{"escape", []string{"\x1b[2Jrm", "a\nb"}, []string{"ev\x1bil"}, `'?[2Jrm' 'a?b' ← ev?il`},
		{"bidi", []string{"a\u202eb"}, nil, "'a?b'"},
		{"invalid utf8", []string{"a\xffb"}, nil, "'a?b'"},
	} {
		r := Request{Cmdline: tc.cmdline, Parents: tc.parents}
		if got := r.Origin(); got != tc.want {
			t.Errorf("%s: Origin() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestCommandTruncated(t *testing.T) {
	r := Request{Cmdline: []string{"x", strings.Repeat("é", 200), "never shown"}}
	got := r.Command()
	if !strings.HasSuffix(got, "…") || len(got) > maxCommand+len("…") || strings.Contains(got, "never") {
		t.Errorf("Command() = %q", got)
	}
	if !strings.HasPrefix(got, "x 'éé") {
		t.Errorf("Command() = %q", got)
	}
}

func TestTextNet(t *testing.T) {
	r := Request{Exe: "/usr/bin/curl", PID: 7, Op: "connect to", Path: "1.2.3.4:80", Detail: "udp", Note: "x", Scope: "1.2.3.4:80"}
	got, _ := r.Text()
	if !strings.HasPrefix(got, "curl (pid 7) wants to connect to\n  1.2.3.4:80\n  (udp, x)\n") {
		t.Errorf("Text() = %q", got)
	}
	r = Request{Exe: "sh", PID: 7, Op: "write", Path: "/a"}
	if got, _ := r.Text(); !strings.HasPrefix(got, "sh (pid 7) wants to write:\n  /a\n[o]") {
		t.Errorf("Text() = %q", got)
	}
}

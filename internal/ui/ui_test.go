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

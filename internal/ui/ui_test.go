// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"strings"
	"testing"
	"time"
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

func TestTextAdvance(t *testing.T) {
	r := Request{Exe: "/bin/sh", PID: 7, Op: "write", Path: "/w/**", Advance: true, For: 10 * time.Minute, Reason: "build\x1b[2J"}
	got, keys := r.Text()
	want := "sh (pid 7) asks in advance to write:\n  /w/**\n  for 10m\n  " + ReasonLabel + ": \"build?[2J\"\n[g] grant for 10m  [d] deny: "
	if got != want {
		t.Errorf("Text() = %q, want %q", got, want)
	}
	if len(keys) != 2 || keys["g"] != AnswerGrant || keys["d"] != AnswerDenyOnce {
		t.Errorf("keys %v", keys)
	}
	r.For, r.Reason = 0, ""
	if got, _ := r.Text(); strings.Contains(got, ReasonLabel) || !strings.Contains(got, "for the rest of the session") {
		t.Errorf("Text() = %q", got)
	}
	for d, want := range map[time.Duration]string{time.Hour: "for 1h", 90 * time.Minute: "for 1h30m", 30 * time.Second: "for 30s", time.Hour + time.Second: "for 1h0m1s"} {
		if got := (Request{For: d}).AdvanceFor(); got != want {
			t.Errorf("AdvanceFor(%v) = %q, want %q", d, got, want)
		}
	}
	if got := (Request{Reason: strings.Repeat("x", 1000)}).AdvanceReason(); len(got) > maxReason+len(`""…`) {
		t.Errorf("AdvanceReason() not truncated: %d bytes", len(got))
	}
}

func TestEffective(t *testing.T) {
	adv := Request{Advance: true, Scope: "/w"}
	for a, want := range map[Answer]Answer{
		AnswerGrant: AnswerGrant, AnswerDenyOnce: AnswerDenyOnce, AnswerTimeout: AnswerTimeout, AnswerDismissed: AnswerDismissed,
		AnswerAllowOnce: AnswerDenyOnce, AnswerAllowAlways: AnswerDenyOnce, AnswerNever: AnswerDenyOnce,
	} {
		if got := adv.Effective(a); got != want {
			t.Errorf("advance: Effective(%v) = %v, want %v", a, got, want)
		}
	}
	plain := Request{}
	for a, want := range map[Answer]Answer{
		AnswerGrant: AnswerAllowOnce, AnswerAllowTemp: AnswerAllowOnce, AnswerTimeout: AnswerTimeout, AnswerNever: AnswerNever,
	} {
		if got := plain.Effective(a); got != want {
			t.Errorf("Effective(%v) = %v, want %v", a, got, want)
		}
	}
	for _, a := range []Answer{AnswerGrant, AnswerTimeout} {
		if ParseAnswer(a.String()) != a {
			t.Errorf("ParseAnswer(%q)", a.String())
		}
	}
	if (AutoAllow{}).Ask(context.Background(), adv) != AnswerGrant || (AutoAllow{}).Ask(context.Background(), plain) != AnswerAllowOnce {
		t.Error("AutoAllow")
	}
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
	"time"
)

func TestPathGlob(t *testing.T) {
	for _, c := range []struct {
		g, p string
		want bool
	}{
		{"/**", "/", true},
		{"/**", "/a/b", true},
		{"/repos/alban/**", "/repos/alban", true},
		{"/repos/alban/**", "/repos/alban/x/y", true},
		{"/repos/alban/**", "/repos/albanx", false},
		{"/repos/*/hallpass", "/repos/alban/hallpass", true},
		{"/repos/*/hallpass", "/repos/a/b/hallpass", false},
		{"/alban/*/git-receive-pack", "/alban/hallpass/git-receive-pack", true},
		{"/alban/*.git/info/refs", "/alban/hallpass.git/info/refs", true},
		{"/a", "/a/", false},
		{"/", "/", true},
	} {
		if got := PathGlob(c.g, c.p); got != c.want {
			t.Errorf("PathGlob(%q, %q) = %v", c.g, c.p, got)
		}
	}
}

func TestHTTPRules(t *testing.T) {
	now := time.Now()
	var rs []Rule
	for i, s := range []string{
		"allow http GET https://api.github.com/**",
		"ask http POST https://api.github.com/repos/alban/*/issues/*/comments",
		"allow http GET POST https://github.com/alban/*/git-upload-pack",
		"deny http * https://api.github.com/repos/*/*/pulls/*/merge",
		"allow http * https://*.example.com/**",
	} {
		r, err := ParseSpec(s, now)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got := r.Spec(); got != s {
			t.Errorf("Spec() = %q, want %q", got, s)
		}
		if !r.Editable(now) {
			t.Errorf("%q not editable", s)
		}
		r.ID = uint64(i + 1)
		rs = append(rs, r)
	}
	for _, c := range []struct {
		method, host, path string
		v                  Verdict
		id                 uint64
		ok                 bool
	}{
		{"GET", "api.github.com", "/repos/alban/hallpass", Allow, 1, true},
		{"POST", "api.github.com", "/repos/alban/hallpass/issues/4/comments", Ask, 2, true},
		{"POST", "api.github.com", "/repos/other/hallpass/issues/4/comments", 0, 0, false},
		{"PUT", "api.github.com", "/repos/alban/hallpass/pulls/5/merge", Deny, 4, true},
		{"POST", "github.com", "/alban/hallpass/git-upload-pack", Allow, 3, true},
		{"DELETE", "github.com", "/alban/hallpass/git-upload-pack", 0, 0, false},
		{"GET", "www.example.com", "/x", Allow, 5, true},
		{"GET", "example.com", "/x", 0, 0, false},
	} {
		v, id, ok := Eval(rs, OpHTTP, Object{HTTP: &HTTPObject{Method: c.method, Host: c.host, Path: c.path}}, now)
		if v != c.v || id != c.id || ok != c.ok {
			t.Errorf("%s %s%s: %v %d %v, want %v %d %v", c.method, c.host, c.path, v, id, ok, c.v, c.id, c.ok)
		}
	}
	// An http rule is not a connect rule.
	if _, _, ok := Eval(rs, OpConnect, Object{Inet: &InetObject{Names: []string{"api.github.com"}}}, now); ok {
		t.Error("http rule matched a connect")
	}
	if !ProxiedBy(rs, []string{"x", "api.github.com"}) || !ProxiedBy(rs, []string{"a.example.com"}) || ProxiedBy(rs, []string{"objects.githubusercontent.com"}) {
		t.Error("ProxiedBy")
	}
	for _, s := range []string{
		"allow http get https://a.com/", "allow http GET http://a.com/", "allow http GET https://a.com:8443/",
		"allow http GET https://a.com/x?y=1", "allow http GET https://a.com/**/x", "allow http GET https://a.com/../x",
		"allow http GET", "allow http GET https://u@a.com/", "allow http GET * https://a.com/",
	} {
		if _, err := ParseSpec(s, now); err == nil {
			t.Errorf("%q: no error", s)
		}
	}
}

func TestHTTPCovers(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"allow http * https://api.github.com/**", "allow http GET https://api.github.com/repos/x", true},
		{"allow http GET https://api.github.com/**", "allow http * https://api.github.com/repos/x", false},
		{"allow http GET https://api.github.com/repos/*", "allow http GET https://api.github.com/repos/x", true},
		{"allow http GET https://api.github.com/repos/x", "allow http GET https://api.github.com/repos/**", false},
		{"allow http GET https://*.github.com/**", "allow http GET https://api.github.com/x", true},
		{"allow http GET https://api.github.com/**", "allow http GET https://*.github.com/x", false},
	} {
		a, _ := ParseSpec(c.a, now)
		b, _ := ParseSpec(c.b, now)
		if got := a.Covers(b); got != c.want {
			t.Errorf("%q covers %q: %v", c.a, c.b, got)
		}
	}
}

func TestHTTPOverlaps(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"GET https://a.com/repos/**", "* https://a.com/repos/*/*/pulls/*/merge", true},
		{"GET https://a.com/orgs/**", "* https://a.com/repos/*/x", false},
		{"GET https://a.com/x", "POST https://a.com/x", false},
		{"GET https://a.com/x", "GET https://b.com/x", false},
		{"GET https://*.a.com/x", "GET https://api.a.com/x", true},
		{"GET https://a.com/**", "GET https://a.com/", true},
	} {
		parse := func(s string) *HTTPMatch {
			m, u, _ := strings.Cut(s, " ")
			h, err := ParseHTTP(m, u)
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		a, b := parse(c.a), parse(c.b)
		if got := a.Overlaps(b); got != c.want || b.Overlaps(a) != c.want {
			t.Errorf("%s / %s: %v, want %v (both ways)", c.a, c.b, got, c.want)
		}
	}
}

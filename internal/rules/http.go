// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// HTTPObject is an HTTPS request through hallpass's proxy (OpHTTP).
type HTTPObject struct {
	Method string // upper case: GET, POST...
	Host   string // the TLS server name, lowercase
	Path   string // the URL path, without the query
}

// URL shows o as prompts do: "https://api.github.com/repos/x".
func (o *HTTPObject) URL() string { return "https://" + o.Host + o.Path }

// HTTPMatch is a set of HTTPS requests: methods, a host and a path glob.
type HTTPMatch struct {
	// Methods, upper case; none: any method ("*").
	Methods []string
	Host    string // lowercase; with HostSuffix, the names below it
	// HostSuffix: Host is "*.github.com".
	HostSuffix bool
	// Path is a path glob: "*" is one segment (or the rest of one), a
	// final "/**" everything below. Always absolute.
	Path string
}

// String writes m: "GET,POST https://api.github.com/**" (a rule's text
// has the methods as words: "GET POST https://...").
func (m *HTTPMatch) String() string {
	methods := "*"
	if len(m.Methods) > 0 {
		methods = strings.Join(m.Methods, ",")
	}
	host := m.Host
	if m.HostSuffix {
		host = "*." + host
	}
	return methods + " https://" + host + m.Path
}

// ParseHTTP reads the two words of an http rule: methods ("GET", "GET,POST"
// or "*") and a URL, "https://HOST/PATH", the path a glob ("*" a segment,
// a final "/**" everything below); no query, no port, no user.
func ParseHTTP(methods, url string) (*HTTPMatch, error) {
	m := &HTTPMatch{}
	if methods != "*" {
		for _, x := range strings.Split(methods, ",") {
			if x == "*" {
				return nil, fmt.Errorf("%q: * is any method, alone", methods)
			}
			if x == "" || strings.ContainsFunc(x, func(r rune) bool { return r < 'A' || r > 'Z' }) {
				return nil, fmt.Errorf("%q: want methods in upper case, comma-separated (GET,POST), or *", methods)
			}
			if !slices.Contains(m.Methods, x) {
				m.Methods = append(m.Methods, x)
			}
		}
		slices.Sort(m.Methods)
	}
	rest, ok := strings.CutPrefix(url, "https://")
	if !ok {
		return nil, fmt.Errorf("%q: want https://HOST/PATH", url)
	}
	host, path, _ := strings.Cut(rest, "/")
	path = "/" + path
	if strings.ContainsAny(host, ":@") {
		return nil, fmt.Errorf("%q: no port or user in the URL", url)
	}
	h, suffix, err := ParseHost(host)
	if err != nil {
		return nil, err
	}
	m.Host, m.HostSuffix = h, suffix
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("%q: no query or fragment in the URL", url)
	}
	for i, seg := range strings.Split(path[1:], "/") {
		if strings.Contains(seg, "**") && (seg != "**" || i != strings.Count(path, "/")-1) {
			return nil, errors.New(url + ": ** only as the last segment (/**)")
		}
		if seg == "." || seg == ".." {
			return nil, fmt.Errorf("%q: no . or .. in the path", url)
		}
	}
	m.Path = path
	return m, nil
}

func (m *HTTPMatch) match(o *HTTPObject) bool {
	if len(m.Methods) > 0 && !slices.Contains(m.Methods, o.Method) {
		return false
	}
	if m.HostSuffix {
		if !strings.HasSuffix(o.Host, "."+m.Host) {
			return false
		}
	} else if o.Host != m.Host {
		return false
	}
	return PathGlob(m.Path, o.Path)
}

// PathGlob reports whether URL path p matches glob g: "*" matches within
// one segment, a final "/**" everything below (and the path itself).
func PathGlob(g, p string) bool {
	if base, ok := strings.CutSuffix(g, "/**"); ok {
		gs, ps := segments(base), segments(p)
		return len(ps) >= len(gs) && segsMatch(gs, ps[:len(gs)])
	}
	gs, ps := segments(g), segments(p)
	return len(gs) == len(ps) && segsMatch(gs, ps)
}

func segments(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func segsMatch(gs, ps []string) bool {
	for i, g := range gs {
		if !segMatch(g, ps[i]) {
			return false
		}
	}
	return true
}

// segMatch matches one segment with "*" wildcards.
func segMatch(g, s string) bool {
	first, rest, ok := strings.Cut(g, "*")
	if !ok {
		return g == s
	}
	if !strings.HasPrefix(s, first) {
		return false
	}
	s = s[len(first):]
	for i := 0; i <= len(s); i++ {
		if segMatch(rest, s[i:]) {
			return true
		}
	}
	return false
}

// depth: a longer path deeper (a tree shallower than the same path
// exact), an exact host deeper than a suffix, methods deeper than any.
func (m *HTTPMatch) depth() int {
	d := 1 + 8*len(m.Path)
	if strings.HasSuffix(m.Path, "/**") {
		d -= 4
	}
	if !m.HostSuffix {
		d += 2
	}
	if len(m.Methods) > 0 {
		d++
	}
	return d
}

// covers reports whether m selects every request o does.
func (m *HTTPMatch) covers(o *HTTPMatch) bool {
	if len(m.Methods) > 0 && (len(o.Methods) == 0 || slices.ContainsFunc(o.Methods, func(x string) bool { return !slices.Contains(m.Methods, x) })) {
		return false
	}
	switch {
	case m.HostSuffix && o.HostSuffix:
		if o.Host != m.Host && !strings.HasSuffix(o.Host, "."+m.Host) {
			return false
		}
	case m.HostSuffix:
		if !strings.HasSuffix(o.Host, "."+m.Host) {
			return false
		}
	case o.HostSuffix || o.Host != m.Host:
		return false
	}
	// Paths: o's glob, read as a path, matched by m's; a tree only by
	// a tree.
	if strings.HasSuffix(o.Path, "/**") && !strings.HasSuffix(m.Path, "/**") {
		return false
	}
	return PathGlob(m.Path, strings.TrimSuffix(o.Path, "/**"))
}

// ProxiedBy reports whether a rule of rs has an http match whose host
// name, or a name below it, is one of names: connections to such an
// address on port 443 go through hallpass's proxy.
func ProxiedBy(rs []Rule, names []string) bool {
	for _, r := range rs {
		if h := r.Object.HTTP; h != nil {
			for _, n := range names {
				if (h.HostSuffix && strings.HasSuffix(n, "."+h.Host)) || (!h.HostSuffix && n == h.Host) {
					return true
				}
			}
		}
	}
	return false
}

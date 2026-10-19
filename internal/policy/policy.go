// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy is a sandbox's policy as people write it: with the flags
// of hallpass, in a HallpassPolicy, or in a policy file. Every source
// fills a Spec, validated the same way, and the Policy it gives builds
// the session's rules (internal/defaults).
package policy

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

// DefaultAskTimeout is a policy's askTimeout when it sets none.
const DefaultAskTimeout = 5 * time.Minute

// Spec is a policy as written. Its JSON field names are those of the spec
// of a HallpassPolicy (deploy/kubernetes/crd.yaml).
type Spec struct {
	// Allow and Deny are absolute paths: "/workspace/**" or "/workspace"
	// is the tree under /workspace.
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
	// Ask: false denies what no rule allows without asking. Default true.
	Ask *bool `json:"ask,omitempty"`
	// AskTimeout is how long a request waits for an answer before it is
	// denied, a Go duration such as "5m"; "0" waits forever. Default
	// DefaultAskTimeout.
	AskTimeout string `json:"askTimeout,omitempty"`
	// Mediate lists the mediated syscall categories: files, exec,
	// network. Default: seccomp.DefaultCategories.
	Mediate []string `json:"mediate,omitempty"`
	// AllowNetwork and DenyNetwork are network destinations
	// (rules.ParseNet syntax: "all", "tcp:10.0.0.0/8:443",
	// "unix:@name"...). They need network in Mediate. AskNetwork are
	// destinations asked about even when a less specific allow covers
	// them (10.0.0.1:22 inside an allowed 10.0.0.0/8).
	AllowNetwork []string `json:"allowNetwork,omitempty"`
	DenyNetwork  []string `json:"denyNetwork,omitempty"`
	AskNetwork   []string `json:"askNetwork,omitempty"`
}

// Policy is a validated Spec.
type Policy struct {
	Allow      []string // tree roots, absolute and clean
	Deny       []string
	Ask        bool
	AskTimeout time.Duration // 0: wait forever
	// Mediate is the mediated syscall categories.
	Mediate                               seccomp.Category
	AllowNetwork, DenyNetwork, AskNetwork []rules.ObjectMatch
}

// FieldError is an invalid field of a Spec, named as in JSON. Sources
// with other names (flags) rename Field.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Field + ": " + e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

// Validate checks s and returns it parsed, with the defaults of the
// fields it leaves unset.
func (s Spec) Validate() (Policy, error) {
	p := Policy{Ask: true, AskTimeout: DefaultAskTimeout, Mediate: seccomp.DefaultCategories}
	if s.Ask != nil {
		p.Ask = *s.Ask
	}
	if s.AskTimeout != "" {
		d, err := time.ParseDuration(s.AskTimeout)
		if err != nil || d < 0 {
			return Policy{}, &FieldError{"askTimeout", fmt.Errorf("%q: not a duration", s.AskTimeout)}
		}
		p.AskTimeout = d
	}
	var err error
	if p.Allow, err = treeRoots(s.Allow); err != nil {
		return Policy{}, &FieldError{"allow", err}
	}
	if p.Deny, err = treeRoots(s.Deny); err != nil {
		return Policy{}, &FieldError{"deny", err}
	}
	if s.Mediate != nil {
		if p.Mediate, err = seccomp.ParseCategories(strings.Join(s.Mediate, ",")); err != nil {
			return Policy{}, &FieldError{"mediate", err}
		}
		if p.Mediate == 0 {
			return Policy{}, &FieldError{"mediate", errors.New("empty (omit it for the default)")}
		}
	}
	for _, f := range []struct {
		name string
		in   []string
		out  *[]rules.ObjectMatch
	}{{"allowNetwork", s.AllowNetwork, &p.AllowNetwork}, {"denyNetwork", s.DenyNetwork, &p.DenyNetwork}, {"askNetwork", s.AskNetwork, &p.AskNetwork}} {
		if len(f.in) > 0 && p.Mediate&seccomp.Network == 0 {
			// A deny that does nothing must not look like it works.
			return Policy{}, &FieldError{f.name, errors.New("needs network in mediate")}
		}
		for _, s := range f.in {
			m, err := rules.ParseNet(s)
			if err != nil {
				return Policy{}, &FieldError{f.name, err}
			}
			*f.out = append(*f.out, m)
		}
	}
	return p, nil
}

// treeRoots turns policy paths into the roots of the trees they cover.
func treeRoots(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, p := range in {
		root := strings.TrimSuffix(p, "/**")
		if root == "" {
			root = "/"
		}
		if !path.IsAbs(root) {
			return nil, fmt.Errorf("%q: not an absolute path", p)
		}
		if strings.ContainsAny(root, "*?[") {
			return nil, fmt.Errorf("%q: only a trailing /** is supported", p)
		}
		out = append(out, path.Clean(root))
	}
	return out, nil
}

// Context is what the rules of a policy need beyond it: where it
// applies.
type Context struct {
	// Home is the sandbox's $HOME, which only flags prompts about its
	// secret stores.
	Home string
	// Workdir is the project directory, writable without asking; "" for
	// none.
	Workdir string
	// Allow are writable without asking too, before the policy's (e.g.
	// devices); Deny are denied, after the policy's.
	Allow, Deny []string
	// OwnListeners allows connections to the listeners started inside
	// the sandbox, when network is mediated.
	OwnListeners bool
	// Lexical: the paths are in another mount namespace (a container's),
	// only cleaned and not symlink-resolved (defaults.NewLexical).
	Lexical bool
}

// Defaults builds the rules of p in c.
func (p Policy) Defaults(c Context) *defaults.Defaults {
	allow := append(append([]string(nil), c.Allow...), p.Allow...)
	deny := append(append([]string(nil), p.Deny...), c.Deny...)
	build := defaults.New
	if c.Lexical {
		build = defaults.NewLexical
	}
	d := build(c.Home, c.Workdir, allow, deny)
	if c.OwnListeners {
		d.AllowOwnListeners()
	}
	for _, m := range p.AllowNetwork {
		d.AllowNet(m)
	}
	for _, m := range p.DenyNetwork {
		d.DenyNet(m)
	}
	for _, m := range p.AskNetwork {
		d.AskNet(m)
	}
	return d
}

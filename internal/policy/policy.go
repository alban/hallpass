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
	"maps"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/programs"
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
	// AllowExec and DenyExec are programs, by absolute path: "/usr/bin/make"
	// is that program only, "/opt/tools/**" every program below
	// /opt/tools. AllowExec also takes groups: "@shells", "@coreutils"
	// (programs.Names), or one of Groups. They need exec in Mediate.
	AllowExec []string `json:"allowExec,omitempty"`
	DenyExec  []string `json:"denyExec,omitempty"`
	// Groups are groups of programs, by name ("@tools"): a new group, or
	// the replacement of the built-in group of the same name. Members are
	// programs as in AllowExec, without groups. They need exec in Mediate.
	Groups map[string][]string `json:"groups,omitempty"`
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
	AllowExec, DenyExec                   []rules.PathMatch
	// AllowGroups are the program groups of AllowExec, e.g. "@shells".
	AllowGroups []string
	// Groups are the policy's own groups, sorted by name (GroupDefs).
	Groups []programs.Def
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
	if len(s.Groups) > 0 && p.Mediate&seccomp.Exec == 0 {
		return Policy{}, &FieldError{"groups", errors.New("needs exec in mediate")}
	}
	for _, name := range slices.Sorted(maps.Keys(s.Groups)) {
		if !programs.ValidName(name) {
			return Policy{}, &FieldError{"groups", fmt.Errorf("%q: not a group name (@, then lowercase letters, digits or -, 32 bytes at most)", name)}
		}
		if len(s.Groups[name]) == 0 {
			return Policy{}, &FieldError{"groups", fmt.Errorf("%s: no programs", name)}
		}
		ms, err := programPaths(s.Groups[name], nil, nil)
		if err != nil {
			return Policy{}, &FieldError{"groups", fmt.Errorf("%s: %w", name, err)}
		}
		d := programs.Def{Name: name}
		for _, m := range ms {
			if m.Tree {
				d.Members = append(d.Members, strings.TrimSuffix(m.Path, "/")+"/**")
			} else {
				d.Members = append(d.Members, m.Path)
			}
		}
		p.Groups = append(p.Groups, d)
	}
	known := p.GroupDefs()
	for _, f := range []struct {
		name   string
		in     []string
		out    *[]rules.PathMatch
		groups *[]string
	}{{"allowExec", s.AllowExec, &p.AllowExec, &p.AllowGroups}, {"denyExec", s.DenyExec, &p.DenyExec, nil}} {
		if len(f.in) > 0 && p.Mediate&seccomp.Exec == 0 {
			return Policy{}, &FieldError{f.name, errors.New("needs exec in mediate")}
		}
		if *f.out, err = programPaths(f.in, f.groups, known); err != nil {
			return Policy{}, &FieldError{f.name, err}
		}
	}
	return p, nil
}

// GroupDefs returns the program groups of p: the built-in ones, replaced
// or completed by p's own.
func (p Policy) GroupDefs() []programs.Def {
	return programs.Merge(p.Groups)
}

// programPaths turns policy program paths into path matches: a path is
// that program, a trailing /** every program below. With groups not nil,
// the names of groups ("@shells", one of known) go to it.
func programPaths(in []string, groups *[]string, known []programs.Def) ([]rules.PathMatch, error) {
	var out []rules.PathMatch
	for _, p := range in {
		if strings.HasPrefix(p, "@") {
			switch {
			case groups == nil:
				return nil, fmt.Errorf("%q: groups are for allowing only", p)
			case !slices.ContainsFunc(known, func(d programs.Def) bool { return d.Name == p }):
				names := make([]string, len(known))
				for i, d := range known {
					names[i] = d.Name
				}
				return nil, fmt.Errorf("%q: unknown group (known: %s)", p, strings.Join(names, ", "))
			}
			if !slices.Contains(*groups, p) {
				*groups = append(*groups, p)
			}
			continue
		}
		root, tree := strings.CutSuffix(p, "/**")
		if tree && root == "" {
			root = "/"
		}
		if !path.IsAbs(root) {
			return nil, fmt.Errorf("%q: not an absolute path", p)
		}
		if strings.ContainsAny(root, "*?[") {
			return nil, fmt.Errorf("%q: only a trailing /** is supported", p)
		}
		out = append(out, rules.PathMatch{Path: path.Clean(root), Tree: tree})
	}
	return out, nil
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
	// Execs are programs allowed to run without asking (absolute paths,
	// exact), before the policy's: the command.
	Execs []string
	// Groups are the program groups, resolved as the sandbox finds them:
	// for the policy's AllowGroups, and offered by prompts.
	Groups []programs.Group
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
	for _, e := range c.Execs {
		d.AllowExec(e, false)
	}
	for _, m := range p.AllowExec {
		d.AllowExec(m.Path, m.Tree)
	}
	d.SetGroups(c.Groups)
	for _, g := range p.AllowGroups {
		d.AllowGroup(g)
	}
	for _, m := range p.DenyExec {
		d.DenyExec(m.Path, m.Tree)
	}
	return d
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

// defaultAskTimeout is a policy's askTimeout when it sets none.
const defaultAskTimeout = 5 * time.Minute

// PolicySpec is the spec of a HallpassPolicy (deploy/kubernetes/crd.yaml).
type PolicySpec struct {
	// Allow and Deny are container paths: "/workspace/**" or "/workspace"
	// is the tree under /workspace.
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`
	// Ask: false denies what no rule allows without asking. Default true.
	Ask *bool `json:"ask,omitempty"`
	// AskTimeout is how long a request waits for an answer before it is
	// denied, e.g. "5m". Default 5m.
	AskTimeout string `json:"askTimeout,omitempty"`
	// Mediate lists the mediated syscall categories: files, exec,
	// network. Default: files and exec.
	Mediate []string `json:"mediate,omitempty"`
	// AllowNetwork and DenyNetwork are network destinations
	// (rules.ParseNet syntax: "all", "tcp:10.0.0.0/8:443",
	// "unix:@name"...). They need network in Mediate.
	AllowNetwork []string `json:"allowNetwork,omitempty"`
	DenyNetwork  []string `json:"denyNetwork,omitempty"`
}

// Policy is a validated PolicySpec.
type Policy struct {
	Name       string
	Allow      []string // cleaned tree roots
	Deny       []string
	Ask        bool
	AskTimeout time.Duration
	// Mediate is the categories of the filters the plugin installs; a
	// session uses its filter's (metadata.Mediate).
	Mediate                   seccomp.Category
	AllowNetwork, DenyNetwork []rules.ObjectMatch
}

// parsePolicy validates spec, the HallpassPolicy name.
func parsePolicy(name string, spec PolicySpec) (*Policy, error) {
	p := &Policy{Name: name, Ask: true, AskTimeout: defaultAskTimeout, Mediate: seccomp.DefaultCategories}
	if spec.Ask != nil {
		p.Ask = *spec.Ask
	}
	if spec.AskTimeout != "" {
		d, err := time.ParseDuration(spec.AskTimeout)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("policy %s: askTimeout %q: not a positive duration", name, spec.AskTimeout)
		}
		p.AskTimeout = d
	}
	var err error
	if p.Allow, err = treeRoots(spec.Allow); err != nil {
		return nil, fmt.Errorf("policy %s: allow: %w", name, err)
	}
	if p.Deny, err = treeRoots(spec.Deny); err != nil {
		return nil, fmt.Errorf("policy %s: deny: %w", name, err)
	}
	if spec.Mediate != nil {
		if p.Mediate, err = seccomp.ParseCategories(strings.Join(spec.Mediate, ",")); err != nil {
			return nil, fmt.Errorf("policy %s: mediate: %w", name, err)
		}
		if p.Mediate == 0 {
			return nil, fmt.Errorf("policy %s: mediate: empty (omit it for the default)", name)
		}
	}
	for _, f := range []struct {
		name string
		in   []string
		out  *[]rules.ObjectMatch
	}{{"allowNetwork", spec.AllowNetwork, &p.AllowNetwork}, {"denyNetwork", spec.DenyNetwork, &p.DenyNetwork}} {
		if len(f.in) > 0 && p.Mediate&seccomp.Network == 0 {
			// A deny that does nothing must not look like it works.
			return nil, fmt.Errorf("policy %s: %s needs network in mediate", name, f.name)
		}
		for _, s := range f.in {
			m, err := rules.ParseNet(s)
			if err != nil {
				return nil, fmt.Errorf("policy %s: %s: %w", name, f.name, err)
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

// containerAllows are written by ordinary containers and hold nothing to
// protect, on top of defaults.DefaultAllows: the container's terminals
// (its /dev/pts is its own devpts instance) and the file kubelet reads
// the termination message from.
func containerAllows() []string {
	out := defaults.DefaultAllows()
	out = append(out, defaults.TTYAllows("")...)
	return append(out, "/dev/pts", "/dev/termination-log")
}

// defaultsFor builds the rules of a container under p whose filter
// mediates cats; home is the container's $HOME, which only flags prompts
// about its secret stores.
func defaultsFor(p *Policy, home string, cats seccomp.Category) *defaults.Defaults {
	if home == "" || !path.IsAbs(home) {
		home = "/root"
	}
	allow := append(containerAllows(), p.Allow...)
	d := defaults.NewLexical(home, "", allow, p.Deny)
	if cats&seccomp.Network != 0 {
		d.AllowOwnListeners()
	}
	for _, m := range p.AllowNetwork {
		d.AllowNet(m)
	}
	for _, m := range p.DenyNetwork {
		d.DenyNet(m)
	}
	return d
}

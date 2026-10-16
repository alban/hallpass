// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/defaults"
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
}

// Policy is a validated PolicySpec.
type Policy struct {
	Name       string
	Allow      []string // cleaned tree roots
	Deny       []string
	Ask        bool
	AskTimeout time.Duration
}

// parsePolicy validates spec, the HallpassPolicy name.
func parsePolicy(name string, spec PolicySpec) (*Policy, error) {
	p := &Policy{Name: name, Ask: true, AskTimeout: defaultAskTimeout}
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

// defaultsFor builds the rules of a container under p; home is the
// container's $HOME, which only flags prompts about its secret stores.
func defaultsFor(p *Policy, home string) *defaults.Defaults {
	if home == "" || !path.IsAbs(home) {
		home = "/root"
	}
	allow := append(containerAllows(), p.Allow...)
	return defaults.NewLexical(home, "", allow, p.Deny)
}

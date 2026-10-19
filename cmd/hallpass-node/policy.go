// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/seccomp"
)

// Policy is a validated HallpassPolicy. Its Mediate is the categories of
// the filters the plugin installs; a session uses its filter's
// (metadata.Mediate). Saved sessions keep it as JSON (see saved): the
// embedded fields are inlined.
type Policy struct {
	Name string
	policy.Policy
}

// parsePolicy validates spec, the HallpassPolicy name.
func parsePolicy(name string, spec policy.Spec) (*Policy, error) {
	p, err := spec.Validate()
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", name, err)
	}
	return &Policy{Name: name, Policy: p}, nil
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
	return p.Defaults(policy.Context{
		Home:         home,
		Allow:        containerAllows(),
		OwnListeners: cats&seccomp.Network != 0,
		Lexical:      true,
	})
}

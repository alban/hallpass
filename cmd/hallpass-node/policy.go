// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/programs"
	"github.com/alban/hallpass/internal/rules"
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
// mediates cats; md.Home is the container's $HOME, which only flags
// prompts about its secret stores. pid is a process of the container
// (0: none), in whose root the programs of exec rules are looked up.
func defaultsFor(p *Policy, md metadata, cats seccomp.Category, pid int) *defaults.Defaults {
	home := md.Home
	if home == "" || !path.IsAbs(home) {
		home = "/root"
	}
	c := policy.Context{
		Home:         home,
		Allow:        containerAllows(),
		OwnListeners: cats&seccomp.Network != 0,
		Lexical:      true,
	}
	pol := p.Policy
	if cats&seccomp.Exec != 0 && pid > 0 {
		pathEnv := md.Path
		if pathEnv == "" {
			pathEnv = defaultPath
		}
		f := containerFinder(pid, pathEnv)
		// The container's own command (args[0]) may run any number of
		// times without asking; groups only when the policy names them.
		if e, ok := f.Look(md.Command); ok {
			c.Execs = append(c.Execs, e)
		}
		c.Groups = f.Groups(pol.GroupDefs())
		// The rules match resolved paths: /bin/sh is /usr/bin/dash in
		// many images.
		pol.AllowExec = inContainer(pid, pol.AllowExec)
		pol.DenyExec = inContainer(pid, pol.DenyExec)
	}
	return pol.Defaults(c)
}

// defaultPath is the $PATH of a container that sets none.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// inContainer resolves the paths of ms in the root of process pid; a path
// that cannot be resolved is kept.
func inContainer(pid int, ms []rules.PathMatch) []rules.PathMatch {
	out := make([]rules.PathMatch, len(ms))
	for i, m := range ms {
		out[i] = m
		if t, err := procfs.Resolve(uint32(pid), procfs.ProcRoot(uint32(pid)), procfs.AtFDCWD, m.Path, true); err == nil && t.Special == "" {
			out[i].Path = t.Path
		}
	}
	return out
}

// containerFinder finds programs in the root of process pid, looked up
// in pathEnv as the container's runtime and shells do; symlinks resolve
// inside that root.
func containerFinder(pid int, pathEnv string) programs.Finder {
	root := procfs.ProcRoot(uint32(pid))
	return programs.Finder{
		Root: root,
		Path: pathEnv,
		Resolve: func(p string) (string, error) {
			t, err := procfs.Resolve(uint32(pid), root, procfs.AtFDCWD, p, true)
			if err != nil {
				return "", err
			}
			if t.Special != "" {
				return "", fmt.Errorf("%s: not a regular path (%s)", p, t.Special)
			}
			return t.Path, nil
		},
	}
}

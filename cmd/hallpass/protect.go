// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sync"

	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

// Labels of the protected rules, shown with them.
const (
	labelSockets = "hallpass sessions"
	labelWeb     = "hallpass web UI"
)

// protectedRules returns the denials that no answer or rule lifts
// (monitor.ProtectedSet): the sandbox must not reach the clients that
// answer for it. With files mediated, no write to sockDir (the session
// sockets, the registered web ports); with the network, no connection to
// the session sockets nor to the web UI's ports.
func protectedRules(mediate seccomp.Category, sockDir string, ports []uint16) []rules.Rule {
	var rs []rules.Rule
	if mediate&seccomp.Files != 0 {
		rs = append(rs, rules.Rule{
			Ops:     rules.OpFiles,
			Object:  rules.ObjectMatch{Path: &rules.PathMatch{Path: sockDir, Tree: true}},
			Verdict: rules.Deny,
			Label:   labelSockets,
			Set:     monitor.ProtectedSet,
		})
	}
	if mediate&seccomp.Network == 0 {
		return rs
	}
	rs = append(rs, rules.Rule{
		Ops:     rules.OpNet,
		Object:  rules.ObjectMatch{Unix: &rules.UnixMatch{Path: sockDir, Prefix: true}},
		Verdict: rules.Deny,
		Label:   labelSockets,
		Set:     monitor.ProtectedSet,
	})
	return append(rs, portRules(ports)...)
}

// portRules denies connections to ports, at any address and with any
// protocol.
func portRules(ports []uint16) []rules.Rule {
	var rs []rules.Rule
	for _, p := range ports {
		rs = append(rs, rules.Rule{
			Ops:     rules.OpNet,
			Object:  rules.ObjectMatch{Inet: &rules.InetMatch{PortLo: p, PortHi: p}},
			Verdict: rules.Deny,
			Label:   labelWeb,
			Set:     monitor.ProtectedSet,
		})
	}
	return rs
}

// portGuard adds the protected rules of the registered web ports to a
// monitor, once per port.
type portGuard struct {
	m    *monitor.Monitor
	mu   sync.Mutex
	done map[uint16]bool
}

// protect denies the ports not denied yet.
func (g *portGuard) protect(ports []uint16) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	var add []uint16
	for _, p := range ports {
		if !g.done[p] {
			add = append(add, p)
		}
	}
	if len(add) == 0 {
		return nil
	}
	if _, err := g.m.Apply(monitor.Decision{AddRules: portRules(add), Client: "hallpass"}); err != nil {
		return fmt.Errorf("protecting the web UI's ports %v: %w", add, err)
	}
	for _, p := range add {
		g.done[p] = true
	}
	return nil
}

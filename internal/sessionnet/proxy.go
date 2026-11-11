// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package sessionnet is the network side of a session, the same for
// hallpass and hallpass-node: the HTTPS proxy of its http rules and
// credentials, deciding with the session's monitor, and the DNS
// forwarder its queries are redirected to. The callers add where the
// credentials come from, how the proxy's CA is trusted, and the network
// namespace.
package sessionnet

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
)

// caLife bounds a session CA's validity: longer than any session.
const caLife = 365 * 24 * time.Hour

// Hosts returns the hosts of the http rules of rs and of creds, once
// each: the proxied hosts, fixed for the session (its CA's name
// constraints).
func Hosts(rs []rules.Rule, creds []egress.Credential) []egress.Host {
	var out []egress.Host
	add := func(h egress.Host) {
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	for _, r := range rs {
		if h := r.Object.HTTP; h != nil {
			add(egress.Host{Name: h.Host, Suffix: h.HostSuffix})
		}
	}
	for _, c := range creds {
		for _, h := range c.Hosts {
			add(h)
		}
	}
	return out
}

// NewCA makes the CA of a session for hosts (Hosts).
func NewCA(name string, hosts []egress.Host) (*egress.CA, error) {
	return egress.NewCA(name, hosts, caLife)
}

// Proxy is what a session's proxy needs besides its monitor.
type Proxy struct {
	CA *egress.CA
	// Roots verify the servers: hallpass's own, never the workload's;
	// nil: the system's.
	Roots       *x509.CertPool
	Credentials []egress.Credential
	// Dial connects to a server; nil: a plain TCP dial.
	Dial func(ctx context.Context, a netip.AddrPort) (net.Conn, error)
	Warn func(string)
	// Leak reports a request refused because it carried a credential
	// to another host (LeakMessage).
	Leak func(owner any, r egress.Request, credential string)
}

// StartProxy hands m the proxy p, whose requests m decides
// (monitor.DecideHTTP).
func StartProxy(m *monitor.Monitor, p Proxy) *egress.Proxy {
	ep := &egress.Proxy{
		CA:    p.CA,
		Roots: p.Roots,
		Decide: func(ctx context.Context, owner any, r egress.Request) (bool, string) {
			return m.DecideHTTP(ctx, owner, rules.HTTPObject{Method: r.Method, Host: r.Host, Path: r.Path})
		},
		Dial:        p.Dial,
		Warn:        p.Warn,
		Credentials: p.Credentials,
		Leak:        p.Leak,
	}
	m.SetProxy(ep)
	return ep
}

// LeakMessage says what a leak the proxy refused was (Proxy.Leak).
func LeakMessage(owner any, r egress.Request, credential string) string {
	who := ""
	if s, ok := owner.(rules.Subject); ok && len(s.Chain) > 0 {
		who = fmt.Sprintf("%s (pid %d) ", s.Chain[0].Comm, s.Chain[0].PID)
	}
	return fmt.Sprintf("%ssent the %s credential to %s, not one of its hosts (%s %s)", who, credential, r.Host, r.Method, r.URL())
}

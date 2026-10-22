// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/egress/profiles"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
)

// caLife bounds the session CA's validity: longer than any session.
const caLife = 90 * 24 * time.Hour

// httpHosts returns the hosts of the http rules of rs: the proxied hosts,
// fixed for the session (the CA's name constraints).
func httpHosts(rs []rules.Rule) []egress.Host {
	var out []egress.Host
	for _, r := range rs {
		if h := r.Object.HTTP; h != nil {
			e := egress.Host{Name: h.Host, Suffix: h.HostSuffix}
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// credentials are the credentials of a session, ready for the proxy.
type credentials struct {
	list  []egress.Credential
	hosts []egress.Host
	env   []string // KEY=value, set in the sandbox
	vars  []string // removed from the sandbox's environment
}

// loadCredentials reads the profiles names (built in, or config:NAME in
// dir) and their values, which stay in memory: a placeholder for the
// sandbox.
func loadCredentials(dir string, names []string) (*credentials, error) {
	c := &credentials{}
	for _, name := range names {
		p, err := profiles.Load(dir, name)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		value, err := p.Source.Get(ctx)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("credential %s: %w", name, err)
		}
		ec := egress.Credential{Name: name, Value: value}
		shown := value
		if p.Mask {
			if ec.Placeholder, err = p.Shape.Placeholder(); err != nil {
				return nil, err
			}
			shown = ec.Placeholder
		}
		for _, h := range p.Hosts {
			host, suffix, err := rules.ParseHost(h)
			if err != nil {
				return nil, fmt.Errorf("credential %s: %w", name, err)
			}
			eh := egress.Host{Name: host, Suffix: suffix}
			ec.Hosts = append(ec.Hosts, eh)
			if !slices.Contains(c.hosts, eh) {
				c.hosts = append(c.hosts, eh)
			}
		}
		for _, k := range slices.Sorted(maps.Keys(p.Env)) {
			c.env = append(c.env, k+"="+strings.ReplaceAll(p.Env[k], "{placeholder}", shown))
		}
		c.vars = append(c.vars, p.Strip...)
		if p.Source.Kind == "env" {
			// The value's own variable never reaches the sandbox.
			c.vars = append(c.vars, p.Source.Arg)
		}
		c.list = append(c.list, ec)
	}
	return c, nil
}

// strip removes the credentials' variables from environ.
func (c *credentials) strip(environ []string) []string {
	return slices.DeleteFunc(environ, func(kv string) bool {
		k, _, _ := strings.Cut(kv, "=")
		return slices.Contains(c.vars, k)
	})
}

// startProxy makes the session's CA for the hosts of the http rules and
// of the credentials, writes the trust bundles in the session directory
// (which the sandbox cannot write), hands m the proxy, and returns the
// environment naming the bundles, and what removes them.
func startProxy(m *monitor.Monitor, hosts []egress.Host, creds *credentials, warn func(string)) (env []string, stop func(), err error) {
	for _, h := range creds.hosts {
		if !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	ca, err := egress.NewCA("hallpass session "+strconv.Itoa(os.Getpid()), hosts, caLife)
	if err != nil {
		return nil, nil, err
	}
	system, err := egress.SystemBundle()
	if err != nil {
		return nil, nil, fmt.Errorf("the system's CA bundle: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, nil, err
	}
	dir := filepath.Join(sessionapi.SocketDir(), strconv.Itoa(os.Getpid())+".trust")
	if env, err = egress.WriteTrust(dir, system, ca); err != nil {
		return nil, nil, err
	}
	p := &egress.Proxy{
		CA:    ca,
		Roots: roots,
		Decide: func(ctx context.Context, owner any, r egress.Request) (bool, string) {
			return m.DecideHTTP(ctx, owner, rules.HTTPObject{Method: r.Method, Host: r.Host, Path: r.Path})
		},
		Warn:        func(s string) { warn("hallpass: " + s) },
		Credentials: creds.list,
		Leak: func(owner any, r egress.Request, name string) {
			who := ""
			if s, ok := owner.(rules.Subject); ok && len(s.Chain) > 0 {
				who = fmt.Sprintf("%s (pid %d) ", s.Chain[0].Comm, s.Chain[0].PID)
			}
			warn(fmt.Sprintf("hallpass: blocked: %ssent the %s credential to %s, not one of its hosts (%s %s)", who, name, r.Host, r.Method, r.URL()))
		},
	}
	m.SetProxy(p)
	return env, func() { os.RemoveAll(dir) }, nil
}

// httpFlags adds the --allow-http, --ask-http and --deny-http requests
// ("GET,POST https://host/path") and the --credential profiles to spec,
// as a rule file of their own. Without connect in spec's mediate, the
// first of them is refused here, by its flag's name: the rule file's
// error would name neither.
func httpFlags(spec *policy.Spec, allow, ask, deny, creds []string) error {
	mediate := seccomp.DefaultCategories
	if spec.Mediate != nil {
		// A parse error is Validate's to report.
		mediate, _ = seccomp.ParseCategories(strings.Join(spec.Mediate, ","))
	}
	if mediate != 0 && mediate&seccomp.Connect == 0 {
		for _, f := range []struct {
			name string
			vals []string
		}{{"credential", creds}, {"allow-http", allow}, {"ask-http", ask}, {"deny-http", deny}} {
			if len(f.vals) > 0 {
				return fmt.Errorf("--%s %s: needs connect in --mediate (--mediate=%s)", f.name, f.vals[0], mediate|seccomp.Connect)
			}
		}
	}
	var text strings.Builder
	for _, c := range creds {
		text.WriteString("credential " + c + "\n")
	}
	for _, l := range []struct {
		verdict string
		vals    []string
	}{{"allow", allow}, {"ask", ask}, {"deny", deny}} {
		for _, v := range l.vals {
			methods, url, ok := strings.Cut(strings.TrimSpace(v), " ")
			if !ok {
				return fmt.Errorf("--%s-http %q: want METHODS URL (GET https://api.github.com/**)", l.verdict, v)
			}
			m, err := rules.ParseHTTP(methods, strings.TrimSpace(url))
			if err != nil {
				return fmt.Errorf("--%s-http: %w", l.verdict, err)
			}
			r := rules.Rule{Verdict: rules.Allow, Ops: rules.OpHTTP, Object: rules.ObjectMatch{HTTP: m}}
			switch l.verdict {
			case "ask":
				r.Verdict = rules.Ask
			case "deny":
				r.Verdict = rules.Deny
			}
			text.WriteString(r.Spec() + "\n")
		}
	}
	if text.Len() > 0 {
		spec.RuleFiles = append(spec.RuleFiles, policy.RuleFile{Name: "--allow-http", Text: text.String()})
	}
	return nil
}

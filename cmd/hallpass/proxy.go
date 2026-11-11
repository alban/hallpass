// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/egress/profiles"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/sessionnet"
)

// startProxy makes the session's CA for hosts, writes the trust bundles
// in the session directory (which the sandbox cannot write), hands m the
// proxy, and returns the environment naming the bundles, and what
// removes them.
func startProxy(m *monitor.Monitor, hosts []egress.Host, creds *profiles.Session, warn func(string)) (env []string, stop func(), err error) {
	ca, err := sessionnet.NewCA("hallpass session "+strconv.Itoa(os.Getpid()), hosts)
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
	sessionnet.StartProxy(m, sessionnet.Proxy{
		CA:          ca,
		Roots:       roots,
		Credentials: creds.Credentials,
		Warn:        func(s string) { warn("hallpass: " + s) },
		Leak: func(owner any, r egress.Request, name string) {
			warn("hallpass: blocked: " + sessionnet.LeakMessage(owner, r, name))
		},
	})
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

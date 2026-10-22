// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/rules"
)

// TestTrust: a container with http rules gets its CA's directory mounted
// read-only and the tools' variables; its session's bundle gets the
// container's roots and the CA; the directory goes with the session.
func TestTrust(t *testing.T) {
	trustRoot = t.TempDir()
	ts := trustStore{upstream: x509.NewCertPool()}
	adj := &api.ContainerAdjustment{}
	if err := ts.prepare("c1", []egress.Host{{Name: "api.github.com"}}, nil, adj); err != nil {
		t.Fatal(err)
	}
	if len(adj.Mounts) != 1 || adj.Mounts[0].Destination != trustMount || adj.Mounts[0].Source != filepath.Join(trustRoot, "c1") ||
		!strings.Contains(strings.Join(adj.Mounts[0].Options, ","), "ro") {
		t.Errorf("mounts %v", adj.Mounts)
	}
	env := map[string]string{}
	for _, kv := range adj.Env {
		env[kv.Key] = kv.Value
	}
	if env["SSL_CERT_FILE"] != trustMount+"/ca-bundle.pem" || env["NODE_EXTRA_CA_CERTS"] != trustMount+"/ca.pem" {
		t.Errorf("env %v", env)
	}
	if err := ts.prepare("../x", nil, nil, adj); err == nil {
		t.Error("a path as an id")
	}
	// Without DNS names, no proxy.
	if _, err := ts.start("c1", os.Getpid(), nil, nil, nil, nil); err == nil {
		t.Error("a proxy without names")
	}
	if p, err := ts.start("c2", os.Getpid(), nil, nil, nil, nil); p != nil || err != nil {
		t.Errorf("no CA: %v %v", p, err)
	}
	// With names (a dnsState of the test's own namespace), the bundle
	// gets this process's roots.
	if err := ts.prepare("c3", []egress.Host{{Name: "api.github.com"}}, nil, &api.ContainerAdjustment{}); err != nil {
		t.Fatal(err)
	}
	decide := func(context.Context, any, egress.Request) (bool, string) { return false, "" }
	if _, err := containerRoots(os.Getpid()); err != nil {
		t.Skipf("no roots on this host: %v", err)
	}
	p, err := ts.start("c3", os.Getpid(), &dnsState{}, decide, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The servers are verified with hallpass-node's roots, never the
	// container's.
	if p.Roots != ts.upstream {
		t.Error("the proxy verifies the servers with other roots")
	}
	b, _ := os.ReadFile(filepath.Join(trustRoot, "c3", "ca-bundle.pem"))
	if p == nil || strings.Count(string(b), "BEGIN CERTIFICATE") < 2 || !strings.HasSuffix(string(b), string(p.CA.PEM())) {
		t.Errorf("bundle of %d certificates", strings.Count(string(b), "BEGIN CERTIFICATE"))
	}
	ts.remove("c3")
	if _, err := os.Stat(filepath.Join(trustRoot, "c3")); !os.IsNotExist(err) {
		t.Errorf("directory left: %v", err)
	}
}

// TestContainerRoots: the image's bundle is read inside its root (an
// absolute symlink does not reach the node's files), only as a regular
// file, and only its certificates are kept.
func TestContainerRoots(t *testing.T) {
	ca, err := egress.NewCA("test", []egress.Host{{Name: "x.test"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.pem")
	if err := os.WriteFile(outside, append([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), ca.PEM()...), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func(t *testing.T, setup func(root string)) ([]byte, error) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "etc/ssl/certs"), 0o755); err != nil {
			t.Fatal(err)
		}
		setup(root)
		fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		return rootsIn(fd)
	}
	bundle := func(root string) string { return filepath.Join(root, "etc/ssl/certs/ca-certificates.crt") }
	b, err := read(t, func(root string) {
		if err := os.WriteFile(bundle(root), append([]byte("junk\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), ca.PEM()...), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	if err != nil || string(b) != string(ca.PEM()) {
		t.Errorf("certificates alone: %q %v", b, err)
	}
	if b, err := read(t, func(root string) {
		if err := os.Symlink(outside, bundle(root)); err != nil {
			t.Fatal(err)
		}
	}); err == nil {
		t.Errorf("an absolute symlink read the node's file: %q", b)
	}
	if _, err := read(t, func(root string) {
		if err := unix.Mkfifo(bundle(root), 0o644); err != nil {
			t.Fatal(err)
		}
	}); err == nil || !strings.Contains(err.Error(), "regular") {
		t.Errorf("a FIFO: %v", err)
	}
}

// TestCredentials: a policy's credential takes its value from a Secret
// of the pod's namespace; the container gets the placeholder in the
// profile's variable, loses the stripped ones, and gets the trust mount.
// Without access to the Secret, the container is refused.
func TestCredentials(t *testing.T) {
	trustRoot = t.TempDir()
	spec := policy.Spec{Mediate: []string{"write", "connect"}, Rules: "credential gh",
		Credentials: map[string]policy.CredentialSource{"gh": {SecretRef: &policy.SecretRef{Name: "gh-token", Key: "token"}}}}
	pol, err := parsePolicy("ci", spec)
	if err != nil {
		t.Fatal(err)
	}
	p := &plugin{
		cluster: fakeCluster{
			selected: map[string]bool{"ci": true, "other": true},
			policies: map[string]*Policy{"ci": pol},
			secrets:  map[string]string{"ci/gh-token/token": "ghp_value"},
		},
		listenerPath: "/run/hallpass/agent.sock",
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		trust:        &trustStore{},
	}
	pod := &api.PodSandbox{Namespace: "ci", Name: "p", Uid: "uid", Annotations: map[string]string{PolicyAnnotation: "ci"}}
	adj, _, err := p.CreateContainer(t.Context(), pod, &api.Container{Id: "c1", Name: "c"})
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, kv := range adj.Env {
		env[kv.Key] = kv.Value
	}
	if tok := env["GH_TOKEN"]; !strings.HasPrefix(tok, "ghp_") || tok == "ghp_value" || len(tok) != 40 {
		t.Errorf("GH_TOKEN %q", tok)
	}
	if env["SSL_CERT_FILE"] == "" || len(adj.Mounts) != 1 {
		t.Errorf("trust: %v %v", env, adj.Mounts)
	}
	stripped := false
	for _, kv := range adj.Env {
		if kv.Key == "-GITHUB_TOKEN" || (kv.Key == "GITHUB_TOKEN" && kv.Value == "") {
			stripped = true
		}
	}
	if !stripped {
		t.Errorf("GITHUB_TOKEN not removed: %v", adj.Env)
	}
	p.trust.mu.Lock()
	pt := p.trust.cas["c1"]
	p.trust.mu.Unlock()
	if pt == nil || len(pt.creds) != 1 || pt.creds[0].Value != "ghp_value" || pt.creds[0].Placeholder != env["GH_TOKEN"] {
		t.Errorf("pending %+v", pt)
	}
	// Another namespace has no such Secret (or no grant): refused.
	pod.Namespace = "other"
	if _, _, err := p.CreateContainer(t.Context(), pod, &api.Container{Id: "c2", Name: "c"}); err == nil {
		t.Error("created without the Secret")
	}
	// Policies: a credential line needs its secretRef, and the other way
	// round.
	for _, bad := range []policy.Spec{
		{Mediate: []string{"connect"}, Rules: "credential gh"},
		{Mediate: []string{"connect"}, Credentials: map[string]policy.CredentialSource{"gh": {SecretRef: &policy.SecretRef{Name: "a", Key: "b"}}}},
		{Mediate: []string{"connect"}, Rules: "credential nope", Credentials: map[string]policy.CredentialSource{"nope": {SecretRef: &policy.SecretRef{Name: "a", Key: "b"}}}},
	} {
		if _, err := parsePolicy("bad", bad); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
}

// TestNoProxyRules: without a proxy, port 443 is denied, whatever the
// connect rules allow, and other ports are not.
func TestNoProxyRules(t *testing.T) {
	all, err := rules.ParseNet("all")
	if err != nil {
		t.Fatal(err)
	}
	rs := append(noProxyRules(), rules.Rule{Ops: rules.OpNet, Object: all, Verdict: rules.Allow})
	for addr, want := range map[string]rules.Verdict{"140.82.112.3:443": rules.Deny, "140.82.112.3:22": rules.Allow} {
		for _, proto := range []uint16{6, 17} {
			obj := rules.Object{Inet: &rules.InetObject{Proto: proto, Addr: netip.MustParseAddrPort(addr)}}
			if v, _, _ := rules.Eval(rs, rules.OpConnect, obj, time.Now()); v != want {
				t.Errorf("%d %s: %v, want %v", proto, addr, v, want)
			}
		}
	}
}

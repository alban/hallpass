// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/egress"
	"github.com/alban/hallpass/internal/netns"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/sessionnet"
)

// trustRoot holds a directory per container with http rules, on the
// host's tmpfs (the agent's hostPath): its CA bundles, bind-mounted
// read-only at trustMount in the container. A variable for the tests.
var trustRoot = "/run/hallpass/trust"

// trustMount is where a container finds its bundles.
const trustMount = "/run/hallpass-trust"

// trustStore keeps the CAs made when the containers are created, until
// their sessions start (CreateContainer, then agent.attach).
type trustStore struct {
	// upstream verifies the servers the proxies connect to: hallpass-node's
	// own roots (--upstream-roots), never a container's, which its image
	// chooses: an image trusting its own CA would get the credentials put
	// on the wire for a server it controls. nil: no proxy can start.
	upstream *x509.CertPool

	mu  sync.Mutex
	cas map[string]*pendingTrust
}

// pendingTrust is what a container's proxy needs, from its creation to
// its session: its CA, its credentials (their values in memory only).
type pendingTrust struct {
	ca    *egress.CA
	creds []egress.Credential
}

// prepare makes the CA of container id for the hosts of rs and creds
// (sessionnet.Hosts), and its directory, with the CA alone for now (the
// bundle gets the container's own roots when its session starts, see
// start), and adds to adj the read-only mount of the directory and the
// variables naming the bundles. creds are put on the wire by the proxy.
func (t *trustStore) prepare(id string, rs []rules.Rule, creds []egress.Credential, adj *api.ContainerAdjustment) error {
	if id == "" || strings.ContainsAny(id, "/.") {
		return fmt.Errorf("container id %q", id)
	}
	ca, err := sessionnet.NewCA("hallpass container "+id, sessionnet.Hosts(rs, creds))
	if err != nil {
		return err
	}
	dir := filepath.Join(trustRoot, id)
	if _, err := egress.WriteTrust(dir, nil, ca); err != nil {
		return err
	}
	// The container may run as any user: the files are 0644, the
	// directory readable.
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	t.mu.Lock()
	if t.cas == nil {
		t.cas = map[string]*pendingTrust{}
	}
	t.cas[id] = &pendingTrust{ca: ca, creds: creds}
	t.mu.Unlock()
	adj.AddMount(&api.Mount{Source: dir, Destination: trustMount, Type: "bind", Options: []string{"rbind", "ro", "nosuid", "nodev", "noexec"}})
	for _, v := range egress.TrustEnv {
		f := trustMount + "/ca-bundle.pem"
		if v.Extra {
			f = trustMount + "/ca.pem"
		}
		adj.AddEnv(v.Name, f)
	}
	return nil
}

// containerBundles are where a container image keeps its roots.
var containerBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// start makes the proxy of container id, whose process pid is still the
// runtime's init: the container's bundle gets the certificates of its
// image's own bundle, so that it trusts what it trusted, and the CA; the
// servers are verified with t.upstream. nil without a CA (no http rules,
// or an agent restarted since the container was created).
func (t *trustStore) start(id string, pid int, dns *dnsState) (*sessionnet.Proxy, error) {
	t.mu.Lock()
	pt := t.cas[id]
	delete(t.cas, id)
	t.mu.Unlock()
	if pt == nil {
		return nil, nil
	}
	ca := pt.ca
	if dns == nil {
		return nil, errors.New("http rules need DNS names (no cgroup v2?)")
	}
	if t.upstream == nil {
		return nil, errors.New("hallpass-node has no roots to verify the servers (--upstream-roots)")
	}
	roots, err := containerRoots(pid)
	if err != nil {
		return nil, err
	}
	if _, err := egress.WriteTrust(filepath.Join(trustRoot, id), roots, ca); err != nil {
		return nil, err
	}
	return &sessionnet.Proxy{
		CA:          ca,
		Roots:       t.upstream,
		Credentials: pt.creds,
		// Servers are reached from the pod's network namespace:
		// NetworkPolicy applies as if the container connected. A thread
		// per dial: a slow server must not hold the DNS forwarder's.
		Dial: func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
			var c net.Conn
			dial := func() (err error) {
				var d net.Dialer
				c, err = d.DialContext(ctx, "tcp", a.String())
				return err
			}
			err := netns.Run(pid, dial)
			if errors.Is(err, os.ErrNotExist) {
				// The first process is gone: the forwarder's thread.
				err = dns.w.Do(dial)
			}
			return c, err
		},
	}, nil
}

// noProxyRules deny port 443 to a session whose policy has http rules
// but which has no proxy (it could not start, or the agent restarted
// since): its http rules would not apply, and connections to their hosts
// would be decided by the connect rules alone. Fail closed.
func noProxyRules() []rules.Rule {
	var rs []rules.Rule
	for _, n := range []string{"tcp:*:443", "udp:*:443"} {
		m, err := rules.ParseNet(n)
		if err != nil {
			panic(err)
		}
		rs = append(rs, rules.Rule{Ops: rules.OpNet, Object: m, Verdict: rules.Deny, Label: "no HTTPS proxy", Set: defaults.Set})
	}
	return rs
}

// loadRoots returns the roots in PEM file, or the system's if "".
func loadRoots(file string) (*x509.CertPool, error) {
	if file == "" {
		return x509.SystemCertPool()
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: no certificate", file)
	}
	return pool, nil
}

// maxBundle bounds the size of a container's CA bundle.
const maxBundle = 8 << 20

// containerRoots returns the certificates of the first CA bundle of
// containerBundles found in the root of process pid, as PEM. The image
// chooses those files: they are opened inside its root (an absolute
// symlink there must not reach the node's files through /proc/PID/root),
// must be regular files of at most maxBundle bytes (not a FIFO, nor
// /dev/zero), and only what parses as a certificate is kept: the bundle
// is written back where the container reads it.
func containerRoots(pid int) ([]byte, error) {
	root, err := unix.Open(fmt.Sprintf("/proc/%d/root", pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(root)
	return rootsIn(root)
}

// rootsIn is containerRoots in the directory root, a descriptor.
func rootsIn(root int) ([]byte, error) {
	for _, b := range containerBundles {
		fd, err := unix.Openat2(root, strings.TrimPrefix(b, "/"), &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			continue
		}
		f := os.NewFile(uintptr(fd), b)
		out, err := readCerts(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("the container's %s: %w", b, err)
		}
		return out, nil
	}
	return nil, errors.New("no CA bundle in the container's image")
}

// readCerts reads a PEM bundle from f, a regular file, and returns its
// certificates alone, encoded again.
func readCerts(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBundle+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBundle {
		return nil, errors.New("larger than 8 MiB")
	}
	var out []byte
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			continue
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})...)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate")
	}
	return out, nil
}

// remove removes the trust directory of container id.
func (t *trustStore) remove(id string) {
	t.mu.Lock()
	delete(t.cas, id)
	t.mu.Unlock()
	if id != "" && !strings.ContainsAny(id, "/.") {
		os.RemoveAll(filepath.Join(trustRoot, id))
	}
}

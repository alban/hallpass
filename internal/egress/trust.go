// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"os"
	"path/filepath"
)

// systemBundles are where distributions keep their roots in one file.
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora, RHEL
	"/etc/ssl/ca-bundle.pem",                            // openSUSE
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora, RHEL
	"/etc/ssl/cert.pem",                                 // Alpine, macOS
}

// SystemBundle returns the roots the programs of the host trust: the file
// SSL_CERT_FILE names, else the distribution's bundle.
func SystemBundle() ([]byte, error) {
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		return os.ReadFile(f)
	}
	var err error
	for _, f := range systemBundles {
		var b []byte
		if b, err = os.ReadFile(f); err == nil {
			return b, nil
		}
	}
	return nil, err
}

// TrustEnv are the variables naming a CA bundle, per tool, and whether the
// file must be a whole bundle (the tool's roots are replaced) or the CA
// alone (added to the tool's own roots).
var TrustEnv = []struct {
	Name  string
	Extra bool
}{
	{"SSL_CERT_FILE", false},                      // OpenSSL, Go, Python's ssl
	{"CURL_CA_BUNDLE", false},                     // curl
	{"GIT_SSL_CAINFO", false},                     // git over HTTPS
	{"REQUESTS_CA_BUNDLE", false},                 // Python requests, az
	{"AWS_CA_BUNDLE", false},                      // aws (botocore)
	{"CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE", false}, // gcloud
	{"NODE_EXTRA_CA_CERTS", true},                 // Node.js
}

// WriteTrust writes, in dir (made 0700 if missing), the bundle of the
// system's roots and the CA (ca-bundle.pem), and the CA alone (ca.pem),
// and returns the environment naming them (TrustEnv).
func WriteTrust(dir string, system []byte, ca *CA) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	bundle := filepath.Join(dir, "ca-bundle.pem")
	alone := filepath.Join(dir, "ca.pem")
	b := append(append(append([]byte{}, system...), '\n'), ca.PEM()...)
	if err := os.WriteFile(bundle, b, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(alone, ca.PEM(), 0o644); err != nil {
		return nil, err
	}
	var env []string
	for _, v := range TrustEnv {
		f := bundle
		if v.Extra {
			f = alone
		}
		env = append(env, v.Name+"="+f)
	}
	return env, nil
}

// Covers reports whether p can terminate TLS for name (monitor.Proxy).
func (p *Proxy) Covers(name string) bool { return p.CA.Covers(name) }

// Injects reports whether p has a credential for name: its connections
// go through p even without http rules (monitor.Proxy).
func (p *Proxy) Injects(name string) bool {
	for i := range p.Credentials {
		if p.Credentials[i].forHost(name) {
			return true
		}
	}
	return false
}

// HasCredentials reports whether p has a credential for any host: the
// names of the addresses connected to are needed (monitor.Proxy).
func (p *Proxy) HasCredentials() bool { return len(p.Credentials) > 0 }

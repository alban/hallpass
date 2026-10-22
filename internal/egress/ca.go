// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Host is a host name the proxy terminates TLS for: Name, or with Suffix
// the names below it.
type Host struct {
	Name   string
	Suffix bool
}

func (h Host) matches(name string) bool {
	if h.Suffix {
		return strings.HasSuffix(name, "."+h.Name)
	}
	return name == h.Name
}

// CA is a certificate authority made for one session: its key lives in
// memory only, and X.509 name constraints limit it to the proxied hosts,
// so even leaked it could sign for nothing else.
type CA struct {
	hosts []Host
	cert  *x509.Certificate
	der   []byte
	key   *ecdsa.PrivateKey
	life  time.Duration

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// NewCA makes a CA for hosts, valid for life (the session's at most). name
// is its common name, e.g. "hallpass session 12345".
func NewCA(name string, hosts []Host, life time.Duration) (*CA, error) {
	if len(hosts) == 0 {
		return nil, errors.New("egress: a CA for no host")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var permitted []string
	for _, h := range hosts {
		if h.Suffix {
			// A leading dot: the names below, not the name.
			permitted = append(permitted, "."+h.Name)
		} else {
			permitted = append(permitted, h.Name)
		}
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: name, Organization: []string{"hallpass"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(life),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         permitted,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{hosts: hosts, cert: cert, der: der, key: key, life: life, leaves: map[string]*tls.Certificate{}}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// PEM is the CA's certificate, for the trust bundles.
func (c *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
}

// Covers reports whether the CA may sign for name.
func (c *CA) Covers(name string) bool {
	for _, h := range c.hosts {
		if h.matches(name) {
			return true
		}
	}
	return false
}

// Leaf returns a certificate for name, signed by the CA, made once.
func (c *CA) Leaf(name string) (*tls.Certificate, error) {
	if !c.Covers(name) {
		return nil, fmt.Errorf("egress: %q is not a proxied host", name)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if l := c.leaves[name]; l != nil {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     c.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	l := &tls.Certificate{Certificate: [][]byte{der, c.der}, PrivateKey: key}
	if len(c.leaves) > 4096 {
		clear(c.leaves)
	}
	c.leaves[name] = l
	return l, nil
}

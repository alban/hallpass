// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream is an HTTPS server for host, its certificate from its own CA,
// echoing the method, path and the Host it got.
func upstream(t *testing.T, host string) (netip.AddrPort, *x509.CertPool) {
	t.Helper()
	ca, err := NewCA("upstream", []Host{{Name: host}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf(host)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(200 * time.Millisecond)
		}
		if e := r.Header.Get("X-Echo"); e != "" {
			w.Header().Set("X-Echoed", e)
		}
		a := r.Header.Get("Authorization")
		if a != "" {
			w.Header().Set("X-Auth", a)
		}
		io.WriteString(w, r.Method+" "+r.Host+" "+r.URL.RequestURI())
		if a != "" {
			io.WriteString(w, " auth="+a)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	return netip.MustParseAddrPort(srv.Listener.Addr().String()), roots
}

type decision struct {
	mu    sync.Mutex
	seen  []Request
	leaks []string
}

func (d *decision) decide(_ context.Context, owner any, r Request) (bool, string) {
	d.mu.Lock()
	d.seen = append(d.seen, r)
	d.mu.Unlock()
	if owner != "sandbox" {
		return false, "wrong owner"
	}
	return r.Method == "GET", "a rule"
}

// session starts a proxy for api.example.test and returns a client for a
// connection to dst, as the sandbox would make one, trusting the session
// CA and naming the server sni.
func session(t *testing.T, dst netip.AddrPort, roots *x509.CertPool, names []string, sni string, creds ...Credential) (*http.Client, *decision, *CA) {
	t.Helper()
	ca, err := NewCA("hallpass session", []Host{{Name: "api.example.test"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	d := &decision{}
	p := &Proxy{CA: ca, Decide: d.decide, Roots: roots, Warn: func(s string) { t.Log(s) }, Credentials: creds,
		Leak: func(owner any, r Request, name string) {
			d.mu.Lock()
			d.leaks = append(d.leaks, name+" "+r.URL())
			d.mu.Unlock()
		}}
	trust := x509.NewCertPool()
	trust.AddCert(ca.cert)
	c := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			client, server, err := Pair()
			if err != nil {
				return nil, err
			}
			go p.Serve(server, dst, names, "sandbox")
			tc := tls.Client(client, &tls.Config{ServerName: sni, RootCAs: trust})
			return tc, tc.HandshakeContext(ctx)
		},
	}, Timeout: 10 * time.Second}
	t.Cleanup(c.CloseIdleConnections)
	return c, d, ca
}

func TestProxy(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	c, d, _ := session(t, dst, roots, []string{"api.example.test"}, "api.example.test")
	resp, err := c.Get("https://api.example.test/repos/x?per_page=1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "GET api.example.test /repos/x?per_page=1" {
		t.Errorf("GET: %d %q", resp.StatusCode, b)
	}
	// Denied: 403, never sent.
	resp, err = c.Post("https://api.example.test/repos/x/issues", "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || !strings.Contains(string(b), "denied: POST https://api.example.test/repos/x/issues") {
		t.Errorf("POST: %d %q", resp.StatusCode, b)
	}
	d.mu.Lock()
	if len(d.seen) != 2 || d.seen[0] != (Request{"GET", "api.example.test", "/repos/x"}) {
		t.Errorf("decided %+v", d.seen)
	}
	d.mu.Unlock()
}

// TestProxyHost: a Host other than the TLS server name is refused.
func TestProxyHost(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	c, d, _ := session(t, dst, roots, []string{"api.example.test"}, "api.example.test")
	req, _ := http.NewRequest("GET", "https://api.example.test/x", nil)
	req.Host = "evil.example.test"
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	d.mu.Lock()
	defer d.mu.Unlock()
	if resp.StatusCode != http.StatusMisdirectedRequest || len(d.seen) != 0 {
		t.Errorf("Host mismatch: %d, decided %v", resp.StatusCode, d.seen)
	}
}

// TestProxySNI: a server name that is not a name of the address, or that
// the CA does not cover, fails the handshake.
func TestProxySNI(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	for _, c := range []struct {
		names []string
		sni   string
	}{
		{[]string{"other.example.test"}, "api.example.test"},
		{[]string{"api.example.test", "evil.test"}, "evil.test"},
	} {
		cl, _, _ := session(t, dst, roots, c.names, c.sni)
		if resp, err := cl.Get("https://" + c.sni + "/"); err == nil {
			resp.Body.Close()
			t.Errorf("%v %s: served", c.names, c.sni)
		}
	}
}

// TestProxyUpstreamVerified: the server's certificate must be valid for
// the name: a server with a certificate from an unknown CA is refused.
func TestProxyUpstreamVerified(t *testing.T) {
	dst, _ := upstream(t, "api.example.test")
	c, _, _ := session(t, dst, x509.NewCertPool(), []string{"api.example.test"}, "api.example.test")
	resp, err := c.Get("https://api.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("unverified upstream: %d", resp.StatusCode)
	}
}

// TestCAConstraints: the session CA cannot sign for other names, and a
// certificate it signed for another name would not verify anyway.
func TestCAConstraints(t *testing.T) {
	ca, err := NewCA("s", []Host{{Name: "api.example.test"}, {Name: "example.org", Suffix: true}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"evil.test", "example.org", "api.example.test.evil"} {
		if _, err := ca.Leaf(n); err == nil {
			t.Errorf("signed for %s", n)
		}
	}
	if _, err := ca.Leaf("www.example.org"); err != nil {
		t.Error(err)
	}
	// Forge a leaf for evil.test with the CA's key, bypassing Leaf.
	ca.hosts = append(ca.hosts, Host{Name: "evil.test"})
	l, err := ca.Leaf("evil.test")
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(l.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "evil.test"}); err == nil {
		t.Error("a certificate outside the name constraints verified")
	}
}

func TestPair(t *testing.T) {
	c, s, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer s.Close()
	go c.Write([]byte("ping\n"))
	if l, _ := bufio.NewReader(s).ReadString('\n'); l != "ping\n" {
		t.Errorf("%q", l)
	}
}

// TestProxyHalfClose: a client that shuts its writing side down after
// its request (shutdown(SHUT_WR)) still gets the answer, then the proxy
// closes the connection.
func TestProxyHalfClose(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	ca, err := NewCA("hallpass session", []Host{{Name: "api.example.test"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	d := &decision{}
	p := &Proxy{CA: ca, Decide: d.decide, Roots: roots, Warn: func(s string) { t.Log(s) }}
	client, server, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	served := make(chan struct{})
	go func() {
		p.Serve(server, dst, []string{"api.example.test"}, "sandbox")
		close(served)
	}()
	trust := x509.NewCertPool()
	trust.AddCert(ca.cert)
	tc := tls.Client(client, &tls.Config{ServerName: "api.example.test", RootCAs: trust})
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(tc, "GET /slow HTTP/1.1\r\nHost: api.example.test\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(tc)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "GET api.example.test /slow" {
		t.Errorf("GET: %d %q", resp.StatusCode, b)
	}
	if n, err := br.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Errorf("after the answer: %d, %v; want the connection closed", n, err)
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return")
	}
}

// TestProxyHalfCloseBody: a request whose body is complete when the
// sandbox shuts its writing side down gets its answer; one cut short
// by the EOF ends the connection, rather than waiting for the rest
// forever.
func TestProxyHalfCloseBody(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	ca, err := NewCA("hallpass session", []Host{{Name: "api.example.test"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	d := &decision{}
	p := &Proxy{CA: ca, Decide: d.decide, Roots: roots, Warn: func(s string) { t.Log(s) }}
	trust := x509.NewCertPool()
	trust.AddCert(ca.cert)
	for _, tc := range []struct {
		name, body string
		answer     bool
	}{
		{"complete", "0123456789", true},
		{"cut", "01234", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server, err := Pair()
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			served := make(chan struct{})
			go func() {
				p.Serve(server, dst, []string{"api.example.test"}, "sandbox")
				close(served)
			}()
			c := tls.Client(client, &tls.Config{ServerName: "api.example.test", RootCAs: trust})
			c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(c, "GET /slow HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 10\r\n\r\n"+tc.body); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(c), nil)
			if tc.answer {
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 || string(b) != "GET api.example.test /slow" {
					t.Errorf("GET: %d %q", resp.StatusCode, b)
				}
			} else if err == nil && resp.StatusCode == 200 {
				t.Errorf("a request cut short got an answer: %d", resp.StatusCode)
			}
			select {
			case <-served:
			case <-time.After(5 * time.Second):
				t.Error("Serve did not return")
			}
		})
	}
}

// TestCredentials: the placeholder in a request to the credential's host
// becomes the value, in a header or inside Basic authorization; in a
// request to another host, the request is refused and reported, never
// decided.
func TestCredentials(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	const ph, value = "ghp_PLACEHOLDERPLACEHOLDERPLACEHOLDER1", "ghp_REALVALUE"
	get := func(c *http.Client, auth string) (int, string) {
		req, _ := http.NewRequest("GET", "https://api.example.test/user", nil)
		req.Header.Set("Authorization", auth)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	own := Credential{Name: "gh", Hosts: []Host{{Name: "api.example.test"}}, Placeholder: ph, Value: value}
	c, _, _ := session(t, dst, roots, []string{"api.example.test"}, "api.example.test", own)
	if code, b := get(c, "token "+ph); code != 200 || !strings.HasSuffix(b, "auth=token "+value) {
		t.Errorf("header: %d %q", code, b)
	}
	// A response header echoing the value gets the placeholder back.
	req0, _ := http.NewRequest("GET", "https://api.example.test/user", nil)
	req0.Header.Set("Authorization", "token "+ph)
	resp0, err := c.Do(req0)
	if err != nil {
		t.Fatal(err)
	}
	resp0.Body.Close()
	if got := resp0.Header.Get("X-Auth"); got != "token "+ph {
		t.Errorf("echoed authorization %q", got)
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+ph))
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+value))
	if code, b := get(c, basic); code != 200 || !strings.HasSuffix(b, "auth="+want) {
		t.Errorf("basic: %d %q", code, b)
	}
	// Another header keeps the placeholder.
	req, _ := http.NewRequest("GET", "https://api.example.test/user", nil)
	req.Header.Set("X-Echo", ph)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("X-Echoed"); got != ph {
		t.Errorf("X-Echo became %q", got)
	}
	// The same credential, for another host only: a leak.
	other := own
	other.Hosts = []Host{{Name: "other.example.test"}}
	c, d, _ := session(t, dst, roots, []string{"api.example.test"}, "api.example.test", other)
	for _, auth := range []string{"token " + ph, basic, "token " + value} {
		if code, b := get(c, auth); code != 403 || !strings.Contains(b, "carries the gh credential") {
			t.Errorf("%s to another host: %d %q", auth, code, b)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.leaks) != 3 || d.leaks[0] != "gh https://api.example.test/user" || len(d.seen) != 0 {
		t.Errorf("leaks %q, decided %v", d.leaks, d.seen)
	}
}

// TestProxyPaths: a path a server could normalise to another one than
// the rules saw is refused, never decided.
func TestProxyPaths(t *testing.T) {
	dst, roots := upstream(t, "api.example.test")
	c, d, _ := session(t, dst, roots, []string{"api.example.test"}, "api.example.test")
	for _, p := range []string{"/repos/me/x/../../orgs/secret", "/repos/./x", "/repos//x", "/repos/a%2Fb", "/repos/a%5cb", "/repos/%2e%2e/orgs"} {
		resp, err := c.Get("https://api.example.test" + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	resp, err := c.Get("https://api.example.test/repos/x/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("a trailing slash: %d", resp.StatusCode)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.seen) != 1 {
		t.Errorf("decided %v", d.seen)
	}
}

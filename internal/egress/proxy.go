// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package egress is hallpass's HTTPS proxy for the hosts that have http
// rules: it terminates the sandbox's TLS with a certificate of the
// session's CA, decides each request (method, host, path) like any other
// access, and sends the allowed ones to the server the sandbox connected
// to, over TLS verified against the system's roots. The supervisor hands
// it the connections it swapped in for the sandbox's own (see
// internal/monitor); other hosts never reach it.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Request is one HTTPS request of the sandbox.
type Request struct {
	Method string
	Host   string // the TLS server name, which the Host header equals
	Path   string // without the query
}

// URL shows r as prompts do.
func (r Request) URL() string { return "https://" + r.Host + r.Path }

// Decide decides a request of the connection whose owner is c (what Serve
// was given): allow, or deny with a reason for the error page. It blocks
// while a person is asked, until ctx ends.
type Decide func(ctx context.Context, c any, r Request) (allow bool, why string)

// Proxy serves the swapped connections of one session.
type Proxy struct {
	CA     *CA
	Decide Decide
	// Roots verify the servers; nil: the system's.
	Roots *x509.CertPool
	// Dial connects to a server's address; nil: a plain TCP dial.
	Dial func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
	// Warn logs what fails.
	Warn func(string)
}

// Serve serves conn, the proxy's end of a connection the sandbox opened
// to dst, an address with names (most recent first): the TLS server name
// must be one of them, and one the CA covers. owner is passed to Decide.
// It returns when the connection ends.
func (p *Proxy) Serve(conn net.Conn, dst netip.AddrPort, names []string, owner any) {
	defer conn.Close()
	tc := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// HTTP/1.1 only: each request is decided, and so seen, on its own.
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sni := strings.ToLower(strings.TrimSuffix(h.ServerName, "."))
			if !slices.Contains(names, sni) {
				// The name must be one the sandbox's DNS gave this
				// address: no proxied host's certificate for another
				// server.
				return nil, fmt.Errorf("server name %q is not a name of %v", h.ServerName, dst.Addr())
			}
			return p.CA.Leaf(sni)
		},
	})
	tc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		p.warn("TLS from the sandbox to %v: %v", dst, err)
		return
	}
	tc.SetDeadline(time.Time{})
	sni := tc.ConnectionState().ServerName
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))

	upstream := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dial := p.Dial
			if dial == nil {
				dial = func(ctx context.Context, a netip.AddrPort) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "tcp", a.String())
				}
			}
			raw, err := dial(ctx, dst)
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: p.Roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
			if err := c.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			return c, nil
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
	defer upstream.CloseIdleConnections()
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host = "https", sni
			r.Out.Host = sni
		},
		Transport: upstream,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.warn("%s https://%s%s: %v", r.Method, sni, r.URL.Path, err)
			http.Error(w, "hallpass: the server could not be reached: "+err.Error(), http.StatusBadGateway)
		},
	}
	hc := &halfClosed{Conn: tc, wake: make(chan struct{})}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != http.NoBody {
			// An EOF before the body's end is the sandbox's, not a
			// half-close after its request: returned, not held.
			hc.setBodyPending(true)
			r.Body = &bodyEnd{ReadCloser: r.Body, hc: hc}
		}
		host := strings.ToLower(r.Host)
		if hp, err := netip.ParseAddrPort(host); err == nil {
			host = hp.Addr().String()
		} else if h, port, ok := strings.Cut(host, ":"); ok && port == "443" {
			host = h
		}
		if host != sni {
			// One connection, one server: the Host must be the TLS one.
			http.Error(w, fmt.Sprintf("hallpass: Host %q is not the TLS server name %q", r.Host, sni), http.StatusMisdirectedRequest)
			return
		}
		if !upperToken(r.Method) {
			// The rules name methods in upper case; a server may take
			// "post" for POST.
			http.Error(w, fmt.Sprintf("hallpass: refused: method %q: want upper-case letters", r.Method), http.StatusMethodNotAllowed)
			return
		}
		req := Request{Method: r.Method, Host: sni, Path: r.URL.Path}
		if req.Path == "" {
			req.Path = "/"
		}
		if !canonical(r) {
			// The rules match the path as written: a server that
			// normalises /a/../b, //b or an encoded / would serve
			// another path than the one decided.
			http.Error(w, "hallpass: refused: "+r.Method+" "+req.URL()+": the path has a . or .. segment, an empty segment, or an encoded / or \\", http.StatusBadRequest)
			return
		}
		allow, why := p.Decide(r.Context(), owner, req)
		if !allow {
			http.Error(w, "hallpass: denied: "+r.Method+" "+req.URL()+": "+why, http.StatusForbidden)
			return
		}
		rp.ServeHTTP(w, r)
	})
	l := &oneConn{c: hc, done: make(chan struct{})}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: time.Minute,
		IdleTimeout:       5 * time.Minute,
		ConnState: func(_ net.Conn, s http.ConnState) {
			hc.setActive(s == http.StateActive)
			if s == http.StateClosed || s == http.StateHijacked {
				l.Close()
			}
		},
		ErrorLog: nil,
	}
	_ = srv.Serve(l)
	srv.Close()
}

func (p *Proxy) warn(format string, args ...any) {
	if p.Warn != nil {
		p.Warn("egress: " + fmt.Sprintf(format, args...))
	}
}

// canonical reports whether r's path is in canonical form: absolute, no
// "." or ".." segment, no empty segment, no encoded "/" or "\".
func canonical(r *http.Request) bool {
	p := r.URL.Path
	if p == "" || p == "/" {
		return true
	}
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	raw := strings.ToLower(r.URL.EscapedPath())
	if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") {
		return false
	}
	segs := strings.Split(strings.TrimSuffix(p[1:], "/"), "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return false
		}
	}
	return true
}

// oneConn is a listener for one connection: Accept returns it, then waits
// until the listener is closed.
type oneConn struct {
	c    net.Conn
	once sync.Once
	mu   sync.Mutex
	used bool
	done chan struct{}
}

func (l *oneConn) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.c, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }

// halfClosed is the sandbox's connection as the HTTP server reads it: an
// EOF while a request is active (the sandbox shut its writing side down,
// shutdown(SHUT_WR), and waits for the answer) is held until the request
// is done, rather than cancelling it (net/http's background read); then,
// or when idle already, it is returned, and the server closes the
// connection. The shutdown is not passed on upstream: the upstream
// connections are pooled, not one per sandbox connection. An EOF while
// the request's body is still to be read is returned at once: the
// request is cut short, nothing is waiting for an answer.
type halfClosed struct {
	net.Conn
	mu       sync.Mutex
	active   bool
	pending  bool // the active request's body is not read to its end
	eof      bool
	deadline time.Time
	wake     chan struct{} // closed, and replaced, when the above change
}

func (c *halfClosed) Read(b []byte) (int, error) {
	c.mu.Lock()
	eof := c.eof
	c.mu.Unlock()
	if !eof {
		n, err := c.Conn.Read(b)
		if !errors.Is(err, io.EOF) {
			return n, err
		}
		c.mu.Lock()
		c.eof = true
		c.mu.Unlock()
		if n > 0 {
			return n, nil
		}
	}
	for {
		c.mu.Lock()
		active, pending, d, wake := c.active, c.pending, c.deadline, c.wake
		c.mu.Unlock()
		if !active || pending {
			return 0, io.EOF
		}
		if d.IsZero() {
			<-wake
			continue
		}
		left := time.Until(d)
		if left <= 0 {
			// net/http's abortPendingRead, once the request is done,
			// or a timeout.
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(left)
		select {
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
}

func (c *halfClosed) change(f func()) {
	c.mu.Lock()
	f()
	close(c.wake)
	c.wake = make(chan struct{})
	c.mu.Unlock()
}

func (c *halfClosed) setActive(a bool) {
	c.change(func() {
		c.active = a
		if !a {
			c.pending = false
		}
	})
}

func (c *halfClosed) setBodyPending(p bool) { c.change(func() { c.pending = p }) }

// bodyEnd tells halfClosed when a request's body is read to its end.
type bodyEnd struct {
	io.ReadCloser
	hc *halfClosed
}

func (b *bodyEnd) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.hc.setBodyPending(false)
	}
	return n, err
}

func (c *halfClosed) SetReadDeadline(t time.Time) error {
	c.change(func() { c.deadline = t })
	return c.Conn.SetReadDeadline(t)
}

func (c *halfClosed) SetDeadline(t time.Time) error {
	c.change(func() { c.deadline = t })
	return c.Conn.SetDeadline(t)
}

func (c *halfClosed) Close() error {
	c.setActive(false)
	return c.Conn.Close()
}

// ErrNoHost is returned by Pair for a listener it could not make.
var ErrNoHost = errors.New("egress: no loopback")

// Pair makes a connected pair of TCP sockets on the loopback: the
// sandbox gets one end in place of its own socket (a unix socket pair
// would fail its TCP socket options), the proxy the other. It checks that
// the accepted peer is its own client, not another local process racing
// for the port.
func Pair() (client *net.TCPConn, server *net.TCPConn, err error) {
	for range 4 {
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrNoHost, err)
		}
		c, err := net.DialTCP("tcp4", nil, l.Addr().(*net.TCPAddr))
		if err != nil {
			l.Close()
			return nil, nil, err
		}
		l.SetDeadline(time.Now().Add(5 * time.Second))
		s, err := l.AcceptTCP()
		l.Close()
		if err != nil {
			c.Close()
			return nil, nil, err
		}
		if s.RemoteAddr().String() == c.LocalAddr().String() {
			return c, s, nil
		}
		// Another process connected first: try again.
		s.Close()
		c.Close()
	}
	return nil, nil, errors.New("egress: the loopback pair was raced")
}

// upperToken reports whether m is made of upper-case ASCII letters, as
// the methods rules name (and those of RFC 9110) are.
func upperToken(m string) bool {
	return m != "" && !strings.ContainsFunc(m, func(r rune) bool { return r < 'A' || r > 'Z' })
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/egress"
	"golang.org/x/sys/unix"
)

// httpsHelper asks the name server about localhost (so that hallpass
// names 127.0.0.1), then sends GET and POST requests to
// https://localhost/PATH over IPv4, trusting SSL_CERT_FILE, and prints
// each status and body: args are the server and the path.
func httpsHelper(args []string) int {
	if len(args) != 2 {
		fmt.Println("https: want server path")
		return 1
	}
	if code := dnsQuery(args[0], "localhost"); code != 0 {
		return code
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", addr)
		},
	}}
	for _, m := range []string{"GET", "POST"} {
		req, _ := http.NewRequest(m, "https://localhost"+args[1], strings.NewReader("x"))
		resp, err := c.Do(req)
		if err != nil {
			fmt.Printf("%s=%v\n", m, err)
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("%s=%d %s\n", m, resp.StatusCode, strings.SplitN(string(b), "\n", 2)[0])
	}
	return 0
}

// swapHelper asks the name server (args[0]) about localhost, then
// connects TCP sockets to 127.0.0.1:443 and prints what each became:
// "proxy" (swapped: its peer is the pair's, not port 443), "direct", or
// the connect's error. args[1] "again": one socket connected twice;
// "netns": a socket made here, then one made by a child in a new user
// and network namespace, which connects both (Go cannot unshare a user
// namespace: it has threads); "nonblock": a non-blocking socket, then
// whether it is still non-blocking.
func swapHelper(args []string) int {
	if len(args) != 2 {
		fmt.Println("swap: want server again|listen|netns|nonblock")
		return 1
	}
	if args[1] != "netns-child" {
		if code := dnsQuery(args[0], "localhost"); code != 0 {
			return code
		}
	}
	sa := &unix.SockaddrInet4{Port: 443, Addr: [4]byte{127, 0, 0, 1}}
	conn := func(label string, fd int) {
		if err := unix.Connect(fd, sa); err != nil {
			fmt.Printf("%s=%v\n", label, err)
			return
		}
		peer, _ := unix.Getpeername(fd)
		if p, ok := peer.(*unix.SockaddrInet4); ok && p.Port == 443 {
			fmt.Printf("%s=direct\n", label)
			return
		}
		fmt.Printf("%s=proxy\n", label)
	}
	sock := func() int {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Println("socket:", err)
			os.Exit(1)
		}
		return fd
	}
	switch args[1] {
	case "again":
		fd := sock()
		conn("first", fd)
		conn("second", fd)
	case "listen":
		fd := sock()
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			fmt.Println("bind:", err)
			return 1
		}
		if err := unix.Listen(fd, 1); err != nil {
			fmt.Println("listen:", err)
			return 1
		}
		conn("listening", fd)
	case "netns":
		before := os.NewFile(uintptr(sock()), "before")
		c := exec.Command("/proc/self/exe", args[0], "netns-child")
		c.Env = os.Environ()
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		c.ExtraFiles = []*os.File{before}
		c.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		}
		if err := c.Run(); err != nil {
			fmt.Println("child:", err)
			return 1
		}
	case "netns-child":
		conn("before", 3)
		conn("after", sock())
	case "nonblock":
		fd := sock()
		if err := unix.SetNonblock(fd, true); err != nil {
			fmt.Println("nonblock:", err)
			return 1
		}
		conn("nonblock", fd)
		if fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil || fl&unix.O_NONBLOCK == 0 {
			fmt.Printf("flags %#o %v: O_NONBLOCK lost\n", fl, err)
		}
	}
	return 0
}

// dnsQuery sends an A query for name to port 53 of server with sendto,
// as musl does (a write on a connected socket is not seen).
func dnsQuery(server, name string) int {
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		fmt.Println("dns:", err)
		return 1
	}
	defer c.Close()
	dst, err := net.ResolveUDPAddr("udp4", server+":53")
	if err != nil {
		fmt.Println("dns:", err)
		return 1
	}
	// A minimal query: ID 7, RD, one question, name, A, IN.
	q := []byte{0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(append(q, byte(len(l))), l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	if _, err := c.WriteTo(q, dst); err != nil {
		fmt.Println("dns:", err)
		return 1
	}
	return 0
}

// TestProxy: with an http rule for localhost, the sandbox's HTTPS
// connections to it go through hallpass's proxy: an allowed request gets
// the server's answer, another a 403 from hallpass, and the server never
// sees it. The server's certificate is verified with hallpass's roots
// (SSL_CERT_FILE here); the sandbox trusts the session CA through the
// variables hallpass sets.
func TestProxy(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("binds port 443")
	}
	servers, _ := dnsnames.Servers("/etc/resolv.conf")
	if len(servers) == 0 || !servers[0].Is4() {
		t.Skipf("no IPv4 name server in /etc/resolv.conf: %v", servers)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:443")
	if err != nil {
		t.Skipf("port 443: %v", err)
	}
	ca, err := egress.NewCA("test upstream", []egress.Host{{Name: "localhost"}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("localhost")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 10)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path
		fmt.Fprintf(w, "upstream %s %s\n", r.Method, r.URL.Path)
	}), TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}}}
	go srv.ServeTLS(l, "", "")
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca.PEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := x509.SystemCertPool(); err != nil {
		t.Skip(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			script := fmt.Sprintf(`HALLPASS_E2E_HELPER=https "$HP_SELF" %s /repos/x`, servers[0])
			cmd := e.cmd(script, "--prompt=deny", "--mediate=write,exec,connect", "--allow-connect=udp:"+servers[0].String()+":53",
				"--allow-http=GET https://localhost/repos/**", "--mode="+mode)
			cmd.Env = append(cmd.Env, "HP_SELF="+self, "SSL_CERT_FILE="+caFile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out)
			}
			o := string(out)
			if !strings.Contains(o, "GET=200 upstream GET /repos/x\n") || !strings.Contains(o, "POST=403 hallpass: denied: POST https://localhost/repos/x") {
				t.Errorf("output:\n%s", o)
			}
			select {
			case s := <-seen:
				if s != "GET /repos/x" {
					t.Errorf("the server got %s", s)
				}
			default:
				t.Error("the server got nothing")
			}
			select {
			case s := <-seen:
				t.Errorf("the server also got %s", s)
			default:
			}
		})
	}
}

// TestProxySwapChecks: a connect on a socket swapped already, or
// listening, fails with
// EISCONN, as the kernel's would, instead of being swapped again; a
// socket of a network namespace the workload made is not swapped (its
// pair would be in the session's namespace), one made before the
// unshare still is; a non-blocking socket stays non-blocking once
// swapped.
func TestProxySwapChecks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	servers, _ := dnsnames.Servers("/etc/resolv.conf")
	if len(servers) == 0 || !servers[0].Is4() {
		t.Skipf("no IPv4 name server in /etc/resolv.conf: %v", servers)
	}
	ns := servers[0].String()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			for _, c := range []struct{ arg, want string }{
				{"again", "first=proxy\nsecond=transport endpoint is already connected\n"},
				{"listen", "listening=transport endpoint is already connected\n"},
				{"netns", "before=proxy\n"},
				{"nonblock", "nonblock=proxy\n"},
			} {
				e := newEnv(t)
				script := fmt.Sprintf(`HALLPASS_E2E_HELPER=swap "$HP_SELF" %s %s`, ns, c.arg)
				cmd := e.cmd(script, "--prompt=deny", "--mediate=write,exec,connect", "--allow-connect=udp:"+ns+":53",
					"--allow-http=GET https://localhost/**", "--allow-userns", "--mode="+mode)
				cmd.Env = append(cmd.Env, "HP_SELF="+self)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("%s: hallpass: %v\n%s", c.arg, err, out)
				}
				o := string(out)
				if !strings.Contains(o, c.want) {
					t.Errorf("%s: output lacks %q:\n%s", c.arg, c.want, o)
				}
				if strings.Contains(o, "O_NONBLOCK lost") {
					t.Errorf("%s: the swapped socket is blocking:\n%s", c.arg, o)
				}
				if c.arg == "netns" && (strings.Contains(o, "after=proxy") || !strings.Contains(o, "after=")) {
					t.Errorf("netns: a socket of the new namespace was swapped:\n%s", o)
				}
			}
		})
	}
}

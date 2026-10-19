// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/web"
)

const webUsage = `usage: hallpass web [--listen ADDR] [--open] [--node ADDR]

Serves a web page to follow every hallpass session of this user and answer
their requests, on 127.0.0.1. It prints a one-time pairing link; press Enter
for a new one.

With --node, it follows the sessions of a Kubernetes node agent instead,
through a port-forward (see docs/kubernetes/answer.md):

  kubectl -n hallpass-system port-forward pod/hallpass-node-xxxxx 7323
  hallpass web --node 127.0.0.1:7323

EXPERIMENTAL: the page is protected by a cookie, which a sandboxed agent
could read from the browser profile to answer its own requests. Sessions
that mediate the network (--mediate=files,exec,network) deny their
sandbox connections to this port; others do not. See docs/devel/web.md.
`

func webMain(argv []string) int {
	fs := flag.NewFlagSet("hallpass web", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), webUsage+"\nflags:\n"); fs.PrintDefaults() }
	listen := fs.String("listen", "127.0.0.1:0", "listen on `addr`, a loopback address (port 0: random)")
	open := fs.Bool("open", false, "open the pairing link with xdg-open (puts the token on a command line)")
	node := fs.String("node", "", "follow the sessions of the hallpass-node agent at `addr` (host:port)")
	if err := fs.Parse(argv); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	ln, err := web.Listen(*listen)
	if err != nil {
		return fail(err)
	}
	s := web.New()
	if *node != "" {
		s, err = web.NewNode(*node)
		if err != nil {
			ln.Close()
			return fail(err)
		}
	}
	defer s.Close()
	base := "http://" + ln.Addr().String()
	pairURL := func() string { return base + "/pair?token=" + s.NewToken() }

	// The sessions that mediate the network deny their sandboxes
	// connections to these ports.
	unregister, err := sessionapi.RegisterPorts(protectPorts(ln.Addr(), *node))
	if err != nil {
		fmt.Fprintf(os.Stderr, "hallpass web: registering the port with the sessions: %v; sandboxes can connect to it\n", err)
		unregister = func() {}
	}
	defer unregister()

	fmt.Fprintln(os.Stderr, "hallpass web: EXPERIMENTAL, see docs/devel/web.md#security.")
	fmt.Fprintf(os.Stderr, "hallpass web: serving %s\n", base)
	u := pairURL()
	fmt.Fprintf(os.Stderr, "Open this link once to pair your browser (Enter: a new link):\n  %s\n", u)
	if *open {
		if err := exec.Command("xdg-open", u).Start(); err != nil {
			fmt.Fprintf(os.Stderr, "hallpass web: xdg-open: %v\n", err)
		}
	}
	go func() {
		in := bufio.NewScanner(os.Stdin)
		for in.Scan() {
			fmt.Fprintf(os.Stderr, "  %s\n", pairURL())
		}
	}()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	// Stop cleanly, so that the port is unregistered.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sig
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(err)
	}
	return 0
}

// protectPorts returns the ports the sandboxes must not connect to: the
// web UI's, and with --node a loopback port-forward to the node agent's
// session API, which needs no pairing.
func protectPorts(web net.Addr, node string) []uint16 {
	var out []uint16
	if a, ok := web.(*net.TCPAddr); ok {
		out = append(out, uint16(a.Port))
	}
	if host, port, err := net.SplitHostPort(node); err == nil {
		ip := net.ParseIP(host)
		if p, err := strconv.ParseUint(port, 10, 16); err == nil && p != 0 && (host == "localhost" || ip != nil && ip.IsLoopback()) {
			out = append(out, uint16(p))
		}
	}
	return out
}

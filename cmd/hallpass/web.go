// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/web"
)

const webUsage = `usage: hallpass web [--listen ADDR] [--open] [--node ADDR]

Serves a web page to follow every hallpass session of this user and answer
their requests, on 127.0.0.1. Open the address it prints: the page shows a
pairing code, and hallpass web asks you on its terminal to confirm it.

With --node, it follows the sessions of a Kubernetes node agent instead,
through a port-forward (see docs/kubernetes/answer.md):

  kubectl -n hallpass-system port-forward pod/hallpass-node-xxxxx 7323
  hallpass web --node 127.0.0.1:7323

EXPERIMENTAL: a sandboxed agent can connect to the page too, and pair if
you confirm its code instead of your browser's. Sessions that mediate the
network (--mediate=files,exec,network) deny their sandbox connections to
this port; others do not. See docs/devel/web.md.
`

func webMain(argv []string) int {
	fs := flag.NewFlagSet("hallpass web", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), webUsage+"\nflags:\n"); fs.PrintDefaults() }
	listen := fs.String("listen", "127.0.0.1:0", "listen on `addr`, a loopback address (port 0: random)")
	open := fs.Bool("open", false, "open the page with xdg-open")
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
	s.Confirm = lineConfirm(os.Stdin)
	s.Warn = func(msg string) { fmt.Fprintf(os.Stderr, "hallpass web: %s\n", msg) }
	u := "http://" + ln.Addr().String() + "/"

	// The sessions that mediate the network deny their sandboxes
	// connections to these ports.
	unregister, err := sessionapi.RegisterPorts(protectPorts(ln.Addr(), *node))
	if err != nil {
		fmt.Fprintf(os.Stderr, "hallpass web: registering the port with the sessions: %v; sandboxes can connect to it\n", err)
		unregister = func() {}
	}
	defer unregister()

	fmt.Fprintln(os.Stderr, "hallpass web: EXPERIMENTAL, see docs/devel/web.md#security.")
	fmt.Fprintf(os.Stderr, "hallpass web: open %s, then confirm its pairing code here.\n", u)
	if *open {
		c := exec.Command("xdg-open", u)
		if err := c.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "hallpass web: xdg-open: %v\n", err)
		} else {
			go func() { _ = c.Wait() }()
		}
	}
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

// typeahead is how long after a question lines are taken as typed before
// it.
const typeahead = 500 * time.Millisecond

// lineConfirm returns a web.Server.Confirm asking on stderr and reading
// the answer, a line, from in.
func lineConfirm(in io.Reader) func(context.Context, string) bool {
	lines := make(chan string)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	var mu sync.Mutex
	return func(ctx context.Context, code string) bool {
		mu.Lock()
		defer mu.Unlock()
		// Lines typed before the question are not answers to it: drop
		// those waiting, and those read right after (still buffered).
		for drained := false; !drained; {
			select {
			case _, ok := <-lines:
				drained = !ok
			default:
				drained = true
			}
		}
		asked := time.Now()
		fmt.Fprintf(os.Stderr, "Pair the browser showing %s? [y/n] ", code)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					fmt.Fprintln(os.Stderr, "\nhallpass web: no input to confirm on: pairing refused")
					return false
				}
				if time.Since(asked) < typeahead {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(l)) {
				case "y", "yes":
					fmt.Fprintln(os.Stderr, "hallpass web: paired")
					return true
				case "n", "no":
					return false
				}
				fmt.Fprintf(os.Stderr, "Pair the browser showing %s? [y/n] ", code)
			case <-ctx.Done():
				fmt.Fprintf(os.Stderr, "\nhallpass web: %v\n", context.Cause(ctx))
				return false
			}
		}
	}
}

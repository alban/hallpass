// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/alban/hallpass/internal/web"
)

const webUsage = `usage: hallpass web [--listen ADDR] [--open]

Serves a web page to follow every hallpass session of this user and answer
their requests, on 127.0.0.1. It prints a one-time pairing link; press Enter
for a new one.

EXPERIMENTAL: the page is protected by a cookie, which a sandboxed agent
could read from the browser profile to answer its own requests. See
docs/devel/web.md.
`

func webMain(argv []string) int {
	fs := flag.NewFlagSet("hallpass web", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), webUsage+"\nflags:\n"); fs.PrintDefaults() }
	listen := fs.String("listen", "127.0.0.1:0", "listen on `addr`, a loopback address (port 0: random)")
	open := fs.Bool("open", false, "open the pairing link with xdg-open (puts the token on a command line)")
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
	defer s.Close()
	base := "http://" + ln.Addr().String()
	pairURL := func() string { return base + "/pair?token=" + s.NewToken() }

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
	if err := srv.Serve(ln); err != nil {
		return fail(err)
	}
	return 0
}

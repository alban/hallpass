// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/ui"
	"github.com/alban/hallpass/internal/web"
)

// sessionWeb is the session's own web UI: the internal/web server, for
// this session only, started on the first "open" (Ctrl-] w, or a click on
// a request's notification) on a random loopback port.
type sessionWeb struct {
	mu  sync.Mutex
	srv *web.Server
	hs  *http.Server
	url string
	// unregister removes the port from the protected ports.
	unregister func()
}

// openWeb starts the session's web UI if needed, lets one browser pair, and
// opens the page with xdg-open.
func (s *session) openWeb() {
	u, err := s.startWeb()
	if err != nil {
		go s.notice(fmt.Sprintf("hallpass: web UI: %v", err))
		return
	}
	s.web.srv.AllowPairing()
	where := "here"
	if _, ok := s.cfg.Asker.(*ui.Desktop); ok {
		where = "in the notification"
	}
	msg := fmt.Sprintf("hallpass: web UI at %s: confirm its pairing code %s", u, where)
	c := exec.Command("xdg-open", u)
	// Its own session: the browser it may start must neither get the
	// program's terminal nor its hangup. Not waited for: reap reaps it.
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		msg += fmt.Sprintf(" (xdg-open: %v)", err)
	} else {
		_ = c.Process.Release()
	}
	// Not while promptMu is held, by a desktop request clicked on.
	go s.notice(msg)
}

// startWeb starts the session's web UI if needed, and returns its URL.
func (s *session) startWeb() (string, error) {
	w := &s.web
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hs != nil {
		return w.url, nil
	}
	ln, err := web.Listen("127.0.0.1:0")
	if err != nil {
		return "", err
	}
	// Registered as hallpass web does: the sessions that mediate the
	// network deny their sandboxes connections to the port.
	ports := protectPorts(ln.Addr(), "")
	unregister, err := sessionapi.RegisterPorts(ports)
	if err != nil {
		go s.notice(fmt.Sprintf("hallpass: web UI: registering the port with the sessions: %v; their sandboxes can connect to it", err))
		unregister = func() {}
	}
	// This sandbox now, before the page opens, not when the watch sees
	// the file.
	if s.ports != nil {
		if err := s.ports.protect(ports); err != nil {
			unregister()
			ln.Close()
			return "", err
		}
	}
	w.unregister = unregister
	w.srv = web.NewSession(os.Getpid())
	w.srv.Confirm = s.confirmPair
	w.srv.Warn = func(msg string) { go s.notice("hallpass: " + msg) }
	w.hs = &http.Server{Handler: w.srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	w.url = "http://" + ln.Addr().String() + "/"
	go func() { _ = w.hs.Serve(ln) }()
	return w.url, nil
}

// closeWeb stops the session's web UI, if started.
func (s *session) closeWeb() {
	w := &s.web
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hs != nil {
		_ = w.hs.Close()
		w.srv.Close()
		w.unregister()
	}
}

// confirmPair asks the user to confirm the pairing code shown by the
// browser, where the sandbox can neither see nor answer: a desktop
// notification of its own, or the terminal's overlay.
func (s *session) confirmPair(ctx context.Context, code string) bool {
	if d, ok := s.cfg.Asker.(*ui.Desktop); ok {
		return d.Confirm(ctx, "hallpass: pair a browser",
			fmt.Sprintf("Pair the browser showing <b>%s</b>?\nOnly if the web page shows the same code.", code),
			"Pair", "Cancel")
	}
	if s.cfg.TTY == nil || !lockCtx(ctx, &s.promptMu) {
		return false
	}
	defer s.promptMu.Unlock()
	var timeout time.Duration
	if dl, ok := ctx.Deadline(); ok {
		if timeout = time.Until(dl); timeout <= 0 {
			return false
		}
	}
	lines := []string{
		fmt.Sprintf(" hallpass: pair the browser showing %s?", code),
		" Only if the web page shows the same code.   [y] pair   [n] cancel",
	}
	k := s.cfg.TTY.Prompt(lines, "yYnN\x1b\x03", typeahead, timeout, ctx.Done(), nil)
	return k == 'y' || k == 'Y'
}

// lockCtx locks mu, unless ctx ends first.
func lockCtx(ctx context.Context, mu *sync.Mutex) bool {
	locked := make(chan struct{})
	go func() {
		mu.Lock()
		close(locked)
	}()
	select {
	case <-locked:
		return true
	case <-ctx.Done():
		go func() {
			<-locked
			mu.Unlock()
		}()
		return false
	}
}

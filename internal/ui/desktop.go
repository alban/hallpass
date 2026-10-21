// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ui

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/alban/hallpass"
)

const (
	notifDest = "org.freedesktop.Notifications"
	notifPath = "/org/freedesktop/Notifications"
	notifIfc  = "org.freedesktop.Notifications"
)

// Desktop prompts via org.freedesktop.Notifications. It reuses one
// notification id (replaces_id) for the whole session, so a burst of requests
// updates a single notification instead of stacking many. timeout == 0 waits
// forever.
type Desktop struct {
	conn    *dbus.Conn
	timeout time.Duration
	icon    string

	// OnWeb, when set before the first Ask, adds an "Open web UI" button to
	// requests' notifications, and is called in its own goroutine when the
	// user clicks it, with the activation token the service sent for it, if
	// any. The request stays asked.
	OnWeb func(token string)

	// The bus's signals, sent to each listener (see listen).
	lmu       sync.Mutex
	listeners map[chan *dbus.Signal]struct{}
	closed    bool

	mu      sync.Mutex
	replace uint32

	// yield, while Ask shows a request, asks it to hide the request until
	// the channel sent is closed (see Confirm). quiet hides requests (see
	// SetQuiet); quietCh is closed when it changes.
	ymu     sync.Mutex
	yield   chan chan struct{}
	quiet   bool
	quietCh chan struct{}
}

// reopenAfterClick is how long after a click on "Open web UI" a request's
// notification is shown again if it closes: notification services may close
// it on click despite "resident", which must not dismiss the request.
const reopenAfterClick = 2 * time.Second

// logoIcon writes the logo where the notification service can read it and
// returns its URI, or a themed icon name if that fails.
func logoIcon() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		dir = filepath.Join(dir, "hallpass")
		p := filepath.Join(dir, "logo.svg")
		if err = os.MkdirAll(dir, 0o700); err == nil {
			if err = os.WriteFile(p, hallpass.Logo, 0o644); err == nil {
				return (&url.URL{Scheme: "file", Path: p}).String()
			}
		}
	}
	return "dialog-question"
}

// NewDesktop connects to the session bus. It fails if no notification service
// with action support is reachable, so callers can fall back.
func NewDesktop(timeout time.Duration) (*Desktop, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, fmt.Errorf("session bus: %w", err)
	}
	var caps []string
	err = conn.Object(notifDest, notifPath).Call(notifIfc+".GetCapabilities", 0).Store(&caps)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("notification service: %w", err)
	}
	hasActions := false
	for _, c := range caps {
		if c == "actions" {
			hasActions = true
		}
	}
	if !hasActions {
		conn.Close()
		return nil, fmt.Errorf("notification service does not support actions")
	}

	d := &Desktop{conn: conn, timeout: timeout, icon: logoIcon(), listeners: map[chan *dbus.Signal]struct{}{}, quietCh: make(chan struct{})}
	// Only from the name's owner: on GNOME, it forwards to gnome-shell,
	// which broadcasts the same signals itself, with the same ids.
	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(notifDest),
		dbus.WithMatchObjectPath(notifPath),
		dbus.WithMatchInterface(notifIfc),
	); err != nil {
		conn.Close()
		return nil, err
	}
	signals := make(chan *dbus.Signal, 64)
	conn.Signal(signals)
	go d.dispatch(signals)
	return d, nil
}

// dispatch sends the bus's signals to the listeners, until the connection
// closes.
func (d *Desktop) dispatch(signals <-chan *dbus.Signal) {
	for sig := range signals {
		d.lmu.Lock()
		for l := range d.listeners {
			select {
			case l <- sig:
			default:
			}
		}
		d.lmu.Unlock()
	}
	d.lmu.Lock()
	defer d.lmu.Unlock()
	d.closed = true
	for l := range d.listeners {
		close(l)
		delete(d.listeners, l)
	}
}

// listen returns the signals received from now on, until stop is called,
// or the connection closes (the channel is closed then).
func (d *Desktop) listen() (sigs <-chan *dbus.Signal, stop func()) {
	c := make(chan *dbus.Signal, 64)
	d.lmu.Lock()
	defer d.lmu.Unlock()
	if d.closed {
		close(c)
		return c, func() {}
	}
	d.listeners[c] = struct{}{}
	return c, func() {
		d.lmu.Lock()
		defer d.lmu.Unlock()
		delete(d.listeners, c)
	}
}

func (d *Desktop) notify(replace uint32, summary, body string, actions []string, hints map[string]dbus.Variant) (uint32, error) {
	var id uint32
	err := d.conn.Object(notifDest, notifPath).Call(
		notifIfc+".Notify", 0,
		"hallpass", replace, d.icon, summary, body, actions, hints, int32(0),
	).Store(&id)
	return id, err
}

func (d *Desktop) closeNotification(id uint32) {
	d.conn.Object(notifDest, notifPath).Call(notifIfc+".CloseNotification", 0, id)
}

// Ask shows (or replaces) the session's notification and blocks for an
// answer, or until ctx ends.
func (d *Desktop) Ask(ctx context.Context, r Request) Answer {
	d.mu.Lock()
	defer d.mu.Unlock()

	body := fmt.Sprintf("<b>%s</b> (pid %d) %s\n%s",
		html.EscapeString(sanitize(baseName(r.Exe))), r.PID, html.EscapeString(r.Wants()), html.EscapeString(r.Target()))
	if r.Warn != "" {
		body += fmt.Sprintf("\n<b><span foreground=\"#cc0000\">[!] %s</span></b>",
			html.EscapeString(sanitize(r.Warn)))
	}
	if d := r.Details(); d != "" {
		body += "\n(" + html.EscapeString(d) + ")"
	}
	if o := r.Origin(); o != "" {
		body += "\nby: " + html.EscapeString(o)
	}
	// GNOME Shell shows at most three buttons; the other answers need the
	// web UI, the terminal or `hallpass answer`.
	onWeb := d.OnWeb
	var actions []string
	switch {
	case r.Advance:
		body += "\n" + html.EscapeString(r.AdvanceFor())
		if s := r.AdvanceReason(); s != "" {
			body += "\n<i>" + html.EscapeString(ReasonLabel) + ":</i> " + html.EscapeString(s)
		}
		actions = []string{"grant", "Grant", "deny", "Deny"}
		if onWeb != nil {
			actions = append(actions, "web", "Open web UI")
		}
	case r.Group != "":
		// A program: its group is the likelier lasting answer; "once" is
		// in the web UI when it is on.
		body += "\n\nAllow the group: " + html.EscapeString(sanitize(r.Group))
		actions = []string{"group", "Allow group", "deny", "Deny"}
		if onWeb != nil {
			actions = append(actions, "web", "Open web UI")
		} else {
			actions = append([]string{"once", "Allow once"}, actions...)
		}
	case onWeb != nil:
		actions = []string{"once", "Allow once", "deny", "Deny", "web", "Open web UI"}
	case r.Scope != "":
		actions = []string{"once", "Allow once"}
		body += fmt.Sprintf("\n\nAllow for %v: %s", TempGrant, html.EscapeString(sanitize(r.Scope)))
		actions = append(actions, "temp", fmt.Sprintf("Allow %v", TempGrant))
		actions = append(actions, "deny", "Deny")
	default:
		actions = []string{"once", "Allow once", "deny", "Deny", "never", "Never"}
	}
	if r.Waiting > 0 {
		body += fmt.Sprintf("\n(%d more waiting)", r.Waiting)
	}
	hints := map[string]dbus.Variant{
		// Critical notifications stay on screen until answered.
		"urgency": dbus.MakeVariant(byte(2)),
	}
	if onWeb != nil {
		// Opening the web UI keeps the notification (resident), so that
		// the request stays answerable here too.
		hints["resident"] = dbus.MakeVariant(true)
	}

	// Listen before showing it, so a fast click cannot be missed.
	sigs, stop := d.listen()
	defer stop()

	yield := make(chan chan struct{}, 1)
	d.ymu.Lock()
	d.yield = yield
	quiet, quietCh := d.quiet, d.quietCh
	d.ymu.Unlock()
	defer func() {
		d.ymu.Lock()
		d.yield = nil
		d.ymu.Unlock()
	}()
	// hidden, while a confirmation shows, is closed once it is answered.
	var hidden <-chan struct{}
	// id is the notification shown, 0 while hidden or quiet.
	var id uint32
	replace := d.replace
	refresh := func() error {
		switch want := hidden == nil && !quiet; {
		case want && id == 0:
			n, err := d.notify(replace, "hallpass", body, actions, hints)
			if err != nil {
				return err
			}
			id, d.replace, replace = n, n, 0
		case !want && id != 0:
			d.closeNotification(id)
			id = 0
		}
		return nil
	}
	if refresh() != nil {
		return AnswerDismissed
	}
	closeShown := func() {
		if id != 0 {
			d.closeNotification(id)
		}
	}

	var deadline <-chan time.Time
	if d.timeout > 0 {
		t := time.NewTimer(d.timeout)
		defer t.Stop()
		deadline = t.C
	}
	var reopenUntil time.Time
	// The service sends it right before the action it is for.
	var token string
	for {
		select {
		case <-quietCh:
			d.ymu.Lock()
			quiet, quietCh = d.quiet, d.quietCh
			d.ymu.Unlock()
			if refresh() != nil {
				return AnswerDismissed
			}
		case h := <-yield:
			if hidden == nil {
				hidden = h
				_ = refresh()
			}
		case <-hidden:
			hidden = nil
			if refresh() != nil {
				return AnswerDismissed
			}
		case sig, ok := <-sigs:
			if !ok {
				return AnswerDismissed
			}
			if id == 0 {
				// Signals about the notifications closed by refresh.
				continue
			}
			if t, ok := activationToken(sig, id); ok {
				token = t
				continue
			}
			key, ok := forNotification(sig, id)
			switch {
			case !ok:
			case key == "default":
				// A body click: no answer.
			case key == "web" && onWeb != nil:
				go onWeb(token)
				reopenUntil = time.Now().Add(reopenAfterClick)
			case key != "":
				if onWeb != nil {
					d.closeNotification(id) // resident
				}
				return ParseAnswer(key)
			case time.Now().Before(reopenUntil):
				// Closed by the click, despite "resident".
				reopenUntil = time.Time{}
				id = 0
				if refresh() != nil {
					return AnswerDismissed
				}
			default:
				return AnswerDismissed
			}
		case <-deadline:
			closeShown()
			return AnswerTimeout
		case <-ctx.Done():
			closeShown()
			return AnswerDismissed
		}
	}
}

// SetQuiet sets whether requests are shown: not while the user follows them
// elsewhere, in a web page. A request asked meanwhile waits for an answer
// from there, or for SetQuiet(false) to show it.
func (d *Desktop) SetQuiet(quiet bool) {
	d.ymu.Lock()
	defer d.ymu.Unlock()
	if d.quiet == quiet {
		return
	}
	d.quiet = quiet
	close(d.quietCh)
	d.quietCh = make(chan struct{})
}

// Confirm shows a notification of its own with yes and no buttons, and
// reports whether the user clicked yes before ctx ends. Unlike Ask, it does
// not replace the request's notification; but notification services show
// one critical notification at a time (GNOME queues the others), so the
// request's is hidden meanwhile, and shown again afterwards.
func (d *Desktop) Confirm(ctx context.Context, summary, body, yes, no string) bool {
	done := make(chan struct{})
	defer close(done)
	d.ymu.Lock()
	if d.yield != nil {
		select {
		case d.yield <- done:
		default:
		}
	}
	d.ymu.Unlock()
	hints := map[string]dbus.Variant{"urgency": dbus.MakeVariant(byte(2))}
	sigs, stop := d.listen()
	defer stop()
	id, err := d.notify(0, summary, body, []string{"yes", yes, "no", no}, hints)
	if err != nil {
		return false
	}
	for {
		select {
		case sig, ok := <-sigs:
			if !ok {
				return false
			}
			if key, ok := forNotification(sig, id); ok && key != "default" {
				return key == "yes"
			}
		case <-ctx.Done():
			d.closeNotification(id)
			return false
		}
	}
}

// activationToken interprets an ActivationToken signal about notification
// id: the token, for the window the action opens to get the focus (Wayland's
// XDG_ACTIVATION_TOKEN, X11's DESKTOP_STARTUP_ID).
func activationToken(sig *dbus.Signal, id uint32) (string, bool) {
	if sig.Name != notifIfc+".ActivationToken" || len(sig.Body) < 2 {
		return "", false
	}
	if got, _ := sig.Body[0].(uint32); got != id {
		return "", false
	}
	t, ok := sig.Body[1].(string)
	return t, ok
}

// forNotification interprets an ActionInvoked or NotificationClosed signal
// about notification id: the action's key, or "" if it closed. ok is false
// for other signals.
func forNotification(sig *dbus.Signal, id uint32) (key string, ok bool) {
	if len(sig.Body) < 2 {
		return "", false
	}
	if got, _ := sig.Body[0].(uint32); got != id {
		return "", false
	}
	switch sig.Name {
	case notifIfc + ".ActionInvoked":
		key, _ := sig.Body[1].(string)
		return key, key != ""
	case notifIfc + ".NotificationClosed":
		return "", true
	}
	return "", false
}

// Close releases the bus connection.
func (d *Desktop) Close() error { return d.conn.Close() }

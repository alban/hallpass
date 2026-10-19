// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

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

	// OnDefault, when set before the first Ask, is called in its own
	// goroutine when the user clicks the body of a request's notification
	// (its "default" action). The request stays asked.
	OnDefault func()

	// The bus's signals, sent to each listener (see listen).
	lmu       sync.Mutex
	listeners map[chan *dbus.Signal]struct{}
	closed    bool

	mu      sync.Mutex
	replace uint32
}

// reopenAfterClick is how long after a body click a request's notification
// is shown again if it closes: notification services close non-resident
// notifications on click, which must not dismiss the request.
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

	d := &Desktop{conn: conn, timeout: timeout, icon: logoIcon(), listeners: map[chan *dbus.Signal]struct{}{}}
	if err := conn.AddMatchSignal(
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
		html.EscapeString(sanitize(baseName(r.Exe))), r.PID, html.EscapeString(r.Wants()), html.EscapeString(sanitize(r.Path)))
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
	// GNOME Shell shows at most three buttons; "always" and "never" need
	// the terminal or `hallpass answer`.
	var actions []string
	switch {
	case r.Advance:
		body += "\n" + html.EscapeString(r.AdvanceFor())
		if s := r.AdvanceReason(); s != "" {
			body += "\n<i>" + html.EscapeString(ReasonLabel) + ":</i> " + html.EscapeString(s)
		}
		actions = []string{"grant", "Grant", "deny", "Deny"}
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
	onDefault := d.OnDefault
	if onDefault != nil {
		// A body click opens the web UI: keep the notification (resident),
		// so that the request stays answerable here too.
		actions = append([]string{"default", "Open the web UI"}, actions...)
		hints["resident"] = dbus.MakeVariant(true)
	}

	// Listen before showing it, so a fast click cannot be missed.
	sigs, stop := d.listen()
	defer stop()
	id, err := d.notify(d.replace, "hallpass", body, actions, hints)
	if err != nil {
		return AnswerDismissed
	}
	d.replace = id

	var deadline <-chan time.Time
	if d.timeout > 0 {
		t := time.NewTimer(d.timeout)
		defer t.Stop()
		deadline = t.C
	}
	var reopenUntil time.Time
	for {
		select {
		case sig, ok := <-sigs:
			if !ok {
				return AnswerDismissed
			}
			key, ok := forNotification(sig, id)
			switch {
			case !ok:
			case key == "default":
				if onDefault != nil {
					go onDefault()
					reopenUntil = time.Now().Add(reopenAfterClick)
				}
			case key != "":
				if onDefault != nil {
					d.closeNotification(id) // resident
				}
				return ParseAnswer(key)
			case time.Now().Before(reopenUntil):
				// Closed by the body click, despite "resident".
				reopenUntil = time.Time{}
				if id, err = d.notify(0, "hallpass", body, actions, hints); err != nil {
					return AnswerDismissed
				}
				d.replace = id
			default:
				return AnswerDismissed
			}
		case <-deadline:
			d.closeNotification(id)
			return AnswerTimeout
		case <-ctx.Done():
			d.closeNotification(id)
			return AnswerDismissed
		}
	}
}

// Confirm shows a notification of its own with yes and no buttons, and
// reports whether the user clicked yes before ctx ends. Unlike Ask, it does
// not replace the request's notification, and can show beside it.
func (d *Desktop) Confirm(ctx context.Context, summary, body, yes, no string) bool {
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

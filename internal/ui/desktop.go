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
	signals chan *dbus.Signal
	icon    string

	mu      sync.Mutex
	replace uint32
}

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

	d := &Desktop{conn: conn, timeout: timeout, signals: make(chan *dbus.Signal, 64), icon: logoIcon()}
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(notifPath),
		dbus.WithMatchInterface(notifIfc),
	); err != nil {
		conn.Close()
		return nil, err
	}
	conn.Signal(d.signals)
	return d, nil
}

// Ask shows (or replaces) the session's notification and blocks for an
// answer, or until ctx ends.
func (d *Desktop) Ask(ctx context.Context, r Request) Answer {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Drop signals about earlier prompts (and other applications) before
	// showing the new one, so a fast click cannot be discarded.
	d.drain()

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

	var id uint32
	err := d.conn.Object(notifDest, notifPath).Call(
		notifIfc+".Notify", 0,
		"hallpass", d.replace, d.icon, "hallpass", body, actions, hints, int32(0),
	).Store(&id)
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
	for {
		select {
		case sig, ok := <-d.signals:
			if !ok {
				return AnswerDismissed
			}
			if a, done := match(sig, id); done {
				return a
			}
		case <-deadline:
			d.conn.Object(notifDest, notifPath).Call(notifIfc+".CloseNotification", 0, id)
			return AnswerTimeout
		case <-ctx.Done():
			d.conn.Object(notifDest, notifPath).Call(notifIfc+".CloseNotification", 0, id)
			return AnswerDismissed
		}
	}
}

func (d *Desktop) drain() {
	for {
		select {
		case <-d.signals:
		default:
			return
		}
	}
}

// match interprets an ActionInvoked or NotificationClosed signal for id.
func match(sig *dbus.Signal, id uint32) (Answer, bool) {
	if len(sig.Body) < 2 {
		return 0, false
	}
	if got, _ := sig.Body[0].(uint32); got != id {
		return 0, false
	}
	switch sig.Name {
	case notifIfc + ".ActionInvoked":
		key, _ := sig.Body[1].(string)
		if key == "default" {
			// Body clicked: keep waiting.
			return 0, false
		}
		return ParseAnswer(key), true
	case notifIfc + ".NotificationClosed":
		return AnswerDismissed, true
	}
	return 0, false
}

// Close releases the bus connection.
func (d *Desktop) Close() error { return d.conn.Close() }

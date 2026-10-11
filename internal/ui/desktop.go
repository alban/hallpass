// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"fmt"
	"html"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
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

	mu      sync.Mutex
	replace uint32
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

	d := &Desktop{conn: conn, timeout: timeout, signals: make(chan *dbus.Signal, 64)}
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

// Ask shows (or replaces) the session's notification and blocks for an answer.
func (d *Desktop) Ask(r Request) Answer {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Drop signals about earlier prompts (and other applications) before
	// showing the new one, so a fast click cannot be discarded.
	d.drain()

	body := fmt.Sprintf("<b>%s</b> (pid %d) wants to %s:\n%s",
		html.EscapeString(baseName(r.Exe)), r.PID, r.Op, html.EscapeString(r.Path))
	actions := []string{"once", "Allow once"}
	if r.Folder != "" {
		body += fmt.Sprintf("\n\nAllow folder: %s", html.EscapeString(r.Folder))
		actions = append(actions, "folder", "Allow folder")
	}
	actions = append(actions, "deny", "Deny")
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
		"hallpass", d.replace, "dialog-question", "hallpass", body, actions, hints, int32(0),
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
		switch key, _ := sig.Body[1].(string); key {
		case "once":
			return AnswerAllowOnce, true
		case "folder":
			return AnswerAllowFolder, true
		case "deny":
			return AnswerDeny, true
		default:
			// "default" action (body clicked): keep waiting.
			return 0, false
		}
	case notifIfc + ".NotificationClosed":
		return AnswerDismissed, true
	}
	return 0, false
}

// Close releases the bus connection.
func (d *Desktop) Close() error { return d.conn.Close() }

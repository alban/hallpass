// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bufio"
	"context"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeNotifications is a notification service on a private session bus.
type fakeNotifications struct {
	conn *dbus.Conn

	mu     sync.Mutex
	next   uint32
	shown  chan notification
	closed chan uint32
}

type notification struct {
	id, replaces uint32
	summary      string
	actions      []string
	hints        map[string]dbus.Variant
}

func (f *fakeNotifications) GetCapabilities() ([]string, *dbus.Error) {
	return []string{"actions", "body", "body-markup"}, nil
}

func (f *fakeNotifications) Notify(_ string, replaces uint32, _, summary, _ string, actions []string, hints map[string]dbus.Variant, _ int32) (uint32, *dbus.Error) {
	f.mu.Lock()
	id := replaces
	if id == 0 {
		f.next++
		id = f.next
	}
	f.mu.Unlock()
	f.shown <- notification{id, replaces, summary, actions, hints}
	return id, nil
}

func (f *fakeNotifications) CloseNotification(id uint32) *dbus.Error {
	f.closed <- id
	return nil
}

func (f *fakeNotifications) emit(t *testing.T, name string, args ...any) {
	t.Helper()
	if err := f.conn.Emit(notifPath, notifIfc+"."+name, args...); err != nil {
		t.Fatal(err)
	}
}

// newFakeDesktop starts a session bus with a fake notification service,
// and returns a Desktop connected to it.
func newFakeDesktop(t *testing.T) (*Desktop, *fakeNotifications) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("no dbus-daemon")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", strings.TrimSpace(addr))

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f := &fakeNotifications{conn: conn, shown: make(chan notification, 8), closed: make(chan uint32, 8)}
	if err := conn.Export(f, notifPath, notifIfc); err != nil {
		t.Fatal(err)
	}
	if reply, err := conn.RequestName(notifDest, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("RequestName: %v %v", reply, err)
	}
	d, err := NewDesktop(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, f
}

func recv[T any](t *testing.T, c <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-c:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("no %s", what)
		panic("unreachable")
	}
}

func TestDesktopBodyClick(t *testing.T) {
	d, f := newFakeDesktop(t)
	clicked := make(chan struct{}, 4)
	d.OnDefault = func() { clicked <- struct{}{} }
	answer := make(chan Answer, 1)
	go func() {
		answer <- d.Ask(context.Background(), Request{Exe: "/bin/sh", PID: 42, Path: "/home/u/.bashrc"})
	}()

	n := recv(t, f.shown, "notification")
	if !slices.Contains(n.actions, "default") || n.hints["resident"].Value() != true {
		t.Errorf("actions %v hints %v: want a default action, resident", n.actions, n.hints)
	}
	f.emit(t, "ActionInvoked", n.id, "default")
	recv(t, clicked, "OnDefault")
	// gnome-shell, behind GNOME's proxy owning the name, broadcasts the
	// same signals itself: not a second click.
	shell, err := dbus.ConnectSessionBus()
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()
	if err := shell.Emit(notifPath, notifIfc+".ActionInvoked", n.id, "default"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-clicked:
		t.Fatal("OnDefault called again for a signal from another sender")
	case <-time.After(200 * time.Millisecond):
	}
	// The service closes the notification after the click: it comes back.
	f.emit(t, "NotificationClosed", n.id, uint32(2))
	n2 := recv(t, f.shown, "notification shown again")
	if n2.replaces != 0 || n2.id == n.id {
		t.Errorf("shown again as %+v", n2)
	}
	select {
	case a := <-answer:
		t.Fatalf("answered %v after a body click", a)
	default:
	}

	// A pairing confirmation shows on its own, without replacing it: the
	// request's is hidden meanwhile (GNOME shows one critical notification
	// at a time), then shown again.
	confirmed := make(chan bool, 1)
	go func() { confirmed <- d.Confirm(context.Background(), "pair", "482 913", "Pair", "Cancel") }()
	c := recv(t, f.shown, "confirmation")
	if c.replaces != 0 || c.id == n2.id || c.summary != "pair" {
		t.Errorf("confirmation %+v", c)
	}
	if id := recv(t, f.closed, "request hidden"); id != n2.id {
		t.Errorf("closed %d, want the request's %d", id, n2.id)
	}
	f.emit(t, "NotificationClosed", n2.id, uint32(3))
	f.emit(t, "ActionInvoked", c.id, "yes")
	if !recv(t, confirmed, "confirmation answer") {
		t.Error("confirmation: want yes")
	}
	n2 = recv(t, f.shown, "request shown again")
	if n2.replaces != 0 || n2.summary != "hallpass" {
		t.Errorf("request shown again as %+v", n2)
	}
	select {
	case a := <-answer:
		t.Fatalf("answered %v after the confirmation", a)
	default:
	}

	f.emit(t, "ActionInvoked", n2.id, "once")
	if a := recv(t, answer, "answer"); a != AnswerAllowOnce {
		t.Errorf("answer %v", a)
	}
	if id := recv(t, f.closed, "close"); id != n2.id {
		t.Errorf("closed %d, want the resident %d", id, n2.id)
	}

	// Closed by the user, not right after a click: dismissed.
	go func() {
		answer <- d.Ask(context.Background(), Request{Exe: "/bin/sh", PID: 42, Path: "/home/u/.profile"})
	}()
	n3 := recv(t, f.shown, "notification")
	f.emit(t, "NotificationClosed", n3.id, uint32(2))
	if a := recv(t, answer, "answer"); a != AnswerDismissed {
		t.Errorf("answer %v", a)
	}
}

func TestDesktopConfirm(t *testing.T) {
	d, f := newFakeDesktop(t)
	ctx, cancel := context.WithCancel(context.Background())
	confirmed := make(chan bool, 1)
	go func() { confirmed <- d.Confirm(ctx, "pair", "482 913", "Pair", "Cancel") }()
	c := recv(t, f.shown, "confirmation")
	f.emit(t, "ActionInvoked", c.id, "default") // a body click is no answer
	cancel()
	if recv(t, confirmed, "confirmation answer") {
		t.Error("confirmed after ctx ended")
	}
	if id := recv(t, f.closed, "close"); id != c.id {
		t.Errorf("closed %d, want %d", id, c.id)
	}

	go func() { confirmed <- d.Confirm(context.Background(), "pair", "482 913", "Pair", "Cancel") }()
	c = recv(t, f.shown, "confirmation")
	f.emit(t, "ActionInvoked", c.id, "no")
	if recv(t, confirmed, "confirmation answer") {
		t.Error("confirmed after no")
	}

	// Without OnDefault, no default action.
	go d.Ask(ctx, Request{Exe: "/bin/sh", PID: 42, Path: "/home/u/.bashrc"})
	if n := recv(t, f.shown, "notification"); slices.Contains(n.actions, "default") {
		t.Errorf("actions %v", n.actions)
	}
}

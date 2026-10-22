// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package netns runs functions in another process's network namespace:
// the sockets they make stay in it, wherever they are used from. Entering
// needs CAP_SYS_ADMIN over the namespace (setns(2)).
package netns

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// Worker is an OS thread in a network namespace, running functions.
type Worker struct {
	reqs chan func()
	done chan struct{}
}

// ErrClosed is returned by Do after Close.
var ErrClosed = errors.New("netns: worker closed")

// Enter returns a worker in the network namespace of pid.
func Enter(pid int) (*Worker, error) {
	ns, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	w := &Worker{reqs: make(chan func()), done: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		// The thread changes namespace: never unlocked, it exits with
		// the goroutine.
		runtime.LockOSThread()
		err := unix.Setns(ns, unix.CLONE_NEWNET)
		unix.Close(ns)
		if err != nil {
			started <- fmt.Errorf("enter the network namespace of %d: %w", pid, err)
			return
		}
		started <- nil
		for {
			select {
			case f := <-w.reqs:
				f()
			case <-w.done:
				return
			}
		}
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	return w, nil
}

// Do runs f in the worker's namespace and returns its error.
func (w *Worker) Do(f func() error) error {
	errc := make(chan error, 1)
	select {
	case w.reqs <- func() { errc <- f() }:
		return <-errc
	case <-w.done:
		return ErrClosed
	}
}

// Close stops the worker. Sockets it made stay usable.
func (w *Worker) Close() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

// Run runs f in the network namespace of pid, once.
func Run(pid int, f func() error) error {
	w, err := Enter(pid)
	if err != nil {
		return err
	}
	defer w.Close()
	return w.Do(f)
}

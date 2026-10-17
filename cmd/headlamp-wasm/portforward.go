// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// pfConn is a net.Conn over a Kubernetes port-forward WebSocket for one
// port, in the channel.k8s.io protocols (v1 to v4 are the same for
// port-forward): each message starts with a channel byte, 0 for the data
// and 1 for the errors of the first port. The first message on each
// channel is the port number, 2 bytes little-endian.
type pfConn struct {
	send   func([]byte) error // sends one WebSocket message
	hangup func()             // closes the WebSocket; may be nil

	mu     sync.Mutex
	cond   *sync.Cond
	queue  [][]byte
	seen   [2]bool // the port header was read on channel 0, 1
	err    error   // set once closed: reads return it after the queue
	closed bool
}

func newPFConn(send func([]byte) error) *pfConn {
	c := &pfConn{send: send}
	c.cond = sync.NewCond(&c.mu)
	return c
}

var errPortHeader = errors.New("port-forward: short port header")

// deliver handles a message received on the WebSocket. It never blocks:
// it runs in the browser's event loop.
func (c *pfConn) deliver(msg []byte) {
	if len(msg) == 0 {
		return
	}
	ch, data := msg[0], msg[1:]
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch > 1 || c.closed {
		return
	}
	if !c.seen[ch] {
		if len(data) < 2 {
			c.closeLocked(errPortHeader)
			return
		}
		c.seen[ch] = true
		data = data[2:]
		c.cond.Broadcast()
	}
	if len(data) == 0 {
		return
	}
	if ch == 1 {
		c.closeLocked(errors.New("port-forward: " + string(data)))
		return
	}
	c.queue = append(c.queue, append([]byte(nil), data...))
	c.cond.Broadcast()
}

// closeWithError ends the connection, e.g. when the WebSocket closes:
// reads return err once the data received is consumed.
func (c *pfConn) closeWithError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked(err)
}

func (c *pfConn) closeLocked(err error) {
	if c.closed {
		return
	}
	c.closed = true
	c.err = err
	c.cond.Broadcast()
}

func (c *pfConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.queue) == 0 && !c.closed {
		c.cond.Wait()
	}
	if len(c.queue) == 0 {
		return 0, c.err
	}
	n := copy(b, c.queue[0])
	if n == len(c.queue[0]) {
		c.queue = c.queue[1:]
	} else {
		c.queue[0] = c.queue[0][n:]
	}
	return n, nil
}

func (c *pfConn) Write(b []byte) (int, error) {
	// Wait for the port header: the WebSocket is open and the stream to
	// the port set up.
	c.mu.Lock()
	for !c.seen[0] && !c.closed {
		c.cond.Wait()
	}
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if err := c.send(append([]byte{0}, b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *pfConn) Close() error {
	c.closeWithError(io.EOF)
	if c.hangup != nil {
		c.hangup()
	}
	return nil
}

type pfAddr struct{}

func (pfAddr) Network() string { return "port-forward" }
func (pfAddr) String() string  { return "port-forward" }

func (c *pfConn) LocalAddr() net.Addr                { return pfAddr{} }
func (c *pfConn) RemoteAddr() net.Addr               { return pfAddr{} }
func (c *pfConn) SetDeadline(t time.Time) error      { return nil }
func (c *pfConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pfConn) SetWriteDeadline(t time.Time) error { return nil }

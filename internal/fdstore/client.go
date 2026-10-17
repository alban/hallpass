// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package fdstore

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"
)

// Client is a connection to a Server. Its methods may be called
// concurrently. After an error other than a refused request, the
// connection is unusable: dial again.
type Client struct {
	mu sync.Mutex
	c  *net.UnixConn
}

// Dial connects to the server at path.
func Dial(path string) (*Client, error) {
	c, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return nil, err
	}
	return &Client{c: c}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.c.Close() }

// Alive reports whether the server is still connected, without waiting.
func (c *Client) Alive() bool {
	raw, err := c.c.SyscallConn()
	if err != nil {
		return false
	}
	alive := false
	_ = raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLRDHUP}}
		n, err := unix.Poll(fds, 0)
		alive = err == nil && (n == 0 || fds[0].Revents&(unix.POLLRDHUP|unix.POLLHUP|unix.POLLERR) == 0)
	})
	return alive
}

// Put stores fds as entry key, replacing it. fds stay the caller's: the
// server keeps its own copies.
func (c *Client) Put(key string, fds []int) error {
	if len(fds) == 0 {
		return errors.New("fdstore: put without fds")
	}
	return c.call(header{Op: opPut, Key: key}, fds)
}

// Delete removes entry key, if any.
func (c *Client) Delete(key string) error {
	return c.call(header{Op: opDelete, Key: key}, nil)
}

// RequestError is a request the server refused.
type RequestError struct{ Msg string }

func (e *RequestError) Error() string { return "fdstore: " + e.Msg }

func (c *Client) call(h header, fds []int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := send(c.c, h, fds); err != nil {
		return err
	}
	r, rfds, err := recv(c.c)
	CloseAll(rfds)
	if err != nil {
		return err
	}
	if r.Op != opReply {
		return fmt.Errorf("fdstore: unexpected %q", r.Op)
	}
	if r.Err != "" {
		return &RequestError{r.Err}
	}
	return nil
}

// List returns the entries. Their fds are the caller's.
func (c *Client) List() ([]Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := send(c.c, header{Op: opList}, nil); err != nil {
		return nil, err
	}
	var es []Entry
	fail := func(err error) ([]Entry, error) {
		for _, e := range es {
			CloseAll(e.FDs)
		}
		return nil, err
	}
	for {
		h, fds, err := recv(c.c)
		if err != nil {
			CloseAll(fds)
			return fail(err)
		}
		switch h.Op {
		case opEntry:
			es = append(es, Entry{Key: h.Key, FDs: fds})
		case opEnd:
			CloseAll(fds)
			return es, nil
		default:
			CloseAll(fds)
			return fail(fmt.Errorf("fdstore: unexpected %q", h.Op))
		}
	}
}

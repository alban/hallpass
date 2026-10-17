// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package fdstore keeps file descriptors for another process, so that they
// survive its crash or upgrade: the hallpass node agent stores there the
// seccomp listeners it mediates and their journals, and takes them back
// when it starts.
//
// The protocol runs over a SOCK_SEQPACKET unix socket, one JSON header per
// message, with the fds attached (SCM_RIGHTS):
//
//	put {key} + fds    replace the entry key; its old fds are closed
//	delete {key}       remove the entry key and close its fds
//	list               the entries, one "entry" {key} + fds each, then "end"
//
// put and delete are answered with a reply {err}. Only root may connect.
package fdstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"golang.org/x/sys/unix"
)

// MaxFDs is the most fds of an entry: the kernel's SCM_MAX_FD.
const MaxFDs = 253

// maxMsg bounds a header.
const maxMsg = 4096

const (
	opPut    = "put"
	opDelete = "delete"
	opList   = "list"
	opEntry  = "entry"
	opEnd    = "end"
	opReply  = "reply"
)

type header struct {
	Op  string `json:"op"`
	Key string `json:"key,omitempty"`
	Err string `json:"err,omitempty"`
}

// Entry is a stored entry. Its fds are the receiver's, to close.
type Entry struct {
	Key string
	FDs []int
}

func send(c *net.UnixConn, h header, fds []int) error {
	if len(fds) > MaxFDs {
		return fmt.Errorf("fdstore: %d fds, at most %d", len(fds), MaxFDs)
	}
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(b) > maxMsg {
		return fmt.Errorf("fdstore: header of %d bytes, at most %d", len(b), maxMsg)
	}
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	_, _, err = c.WriteMsgUnix(b, oob, nil)
	if errors.Is(err, unix.EPIPE) || errors.Is(err, unix.ECONNRESET) {
		return ErrClosed
	}
	return err
}

// recv reads one message. The fds are the caller's, even on an error.
func recv(c *net.UnixConn) (header, []int, error) {
	buf := make([]byte, maxMsg+1)
	oob := make([]byte, unix.CmsgSpace(MaxFDs*4))
	n, oobn, flags, _, err := c.ReadMsgUnix(buf, oob)
	var fds []int
	if oobn > 0 {
		msgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
		if perr != nil && err == nil {
			err = perr
		}
		for _, m := range msgs {
			if r, err := unix.ParseUnixRights(&m); err == nil {
				fds = append(fds, r...)
			}
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, unix.ECONNRESET) || err == nil && n == 0 {
		// An empty message is SOCK_SEQPACKET's end of connection; a
		// reset, a close with our messages unread.
		return header{}, fds, ErrClosed
	}
	if err != nil {
		return header{}, fds, err
	}
	if n > maxMsg || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		return header{}, fds, errors.New("fdstore: message truncated")
	}
	var h header
	if err := json.Unmarshal(buf[:n], &h); err != nil {
		return header{}, fds, fmt.Errorf("fdstore: %w", err)
	}
	return h, fds, nil
}

// ErrClosed is the end of the connection.
var ErrClosed = errors.New("fdstore: connection closed")

// CloseAll closes fds.
func CloseAll(fds []int) {
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package fdstore

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"golang.org/x/sys/unix"
)

// Server holds the entries.
type Server struct {
	// UID is the only peer uid accepted (0: root).
	UID int
	Log *slog.Logger

	mu      sync.Mutex
	entries map[string][]int
}

// Listen creates the socket at path. Its directory is made root-only.
func Listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
}

// Serve accepts connections until ln is closed.
func (s *Server) Serve(ln *net.UnixListener) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if err := s.serveConn(c); err != nil && !errors.Is(err, ErrClosed) {
				s.Log.Warn("fd-store client", "err", err)
			}
		}()
	}
}

// Len returns the number of entries.
func (s *Server) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *Server) serveConn(c *net.UnixConn) error {
	uid, err := peerUID(c)
	if err != nil {
		return err
	}
	if uid != s.UID {
		return fmt.Errorf("peer uid %d refused", uid)
	}
	for {
		h, fds, err := recv(c)
		if err != nil {
			CloseAll(fds)
			return err
		}
		var rerr error
		switch h.Op {
		case opPut:
			rerr = s.put(h.Key, fds)
		case opDelete:
			CloseAll(fds)
			s.put(h.Key, nil)
		case opList:
			CloseAll(fds)
			if err := s.list(c); err != nil {
				return err
			}
			continue
		default:
			CloseAll(fds)
			rerr = fmt.Errorf("unknown op %q", h.Op)
		}
		r := header{Op: opReply}
		if rerr != nil {
			r.Err = rerr.Error()
		}
		if err := send(c, r, nil); err != nil {
			return err
		}
	}
}

// put replaces entry key by fds, or deletes it if fds is empty.
func (s *Server) put(key string, fds []int) error {
	if key == "" {
		CloseAll(fds)
		return errors.New("no key")
	}
	s.mu.Lock()
	old := s.entries[key]
	if len(fds) == 0 {
		delete(s.entries, key)
	} else {
		if s.entries == nil {
			s.entries = map[string][]int{}
		}
		s.entries[key] = fds
	}
	n := len(s.entries)
	s.mu.Unlock()
	CloseAll(old)
	s.Log.Debug("fd-store", "key", key, "fds", len(fds), "entries", n)
	return nil
}

// list sends the entries. They stay stored: a client that crashes while
// receiving them loses nothing.
func (s *Server) list(c *net.UnixConn) error {
	s.mu.Lock()
	keys := make([]string, 0, len(s.entries))
	for k := range s.entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type entry struct {
		key string
		fds []int
	}
	var es []entry
	for _, k := range keys {
		// Dup'ed: a put or delete may close the stored fds meanwhile.
		var fds []int
		for _, fd := range s.entries[k] {
			d, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				s.mu.Unlock()
				CloseAll(fds)
				for _, e := range es {
					CloseAll(e.fds)
				}
				return err
			}
			fds = append(fds, d)
		}
		es = append(es, entry{k, fds})
	}
	s.mu.Unlock()
	var err error
	for _, e := range es {
		if err == nil {
			err = send(c, header{Op: opEntry, Key: e.key}, e.fds)
		}
		CloseAll(e.fds)
	}
	if err != nil {
		return err
	}
	return send(c, header{Op: opEnd}, nil)
}

func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return -1, err
	}
	if cerr != nil {
		return -1, cerr
	}
	return int(cred.Uid), nil
}

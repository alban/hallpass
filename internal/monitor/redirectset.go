// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import "sync"

// maxRedirected bounds the sockets remembered as redirected. Past it,
// the oldest is forgotten: its replies keep the listener as their
// source, which resolvers drop (DNS fails on that socket, nothing more).
const maxRedirected = 4096

// redirectSet are the sockets redirected to a forwarder: inode, and
// SO_COOKIE, as an inode is reused once its socket is closed.
type redirectSet struct {
	mu     sync.Mutex
	cookie map[uint64]uint64
	order  [][2]uint64 // inode, cookie; oldest first
}

func (s *redirectSet) add(ino, cookie uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookie == nil {
		s.cookie = map[uint64]uint64{}
	}
	if c, ok := s.cookie[ino]; ok && c == cookie {
		return
	}
	s.cookie[ino] = cookie
	s.order = append(s.order, [2]uint64{ino, cookie})
	for len(s.order) > maxRedirected {
		if s.cookie[s.order[0][0]] == s.order[0][1] {
			delete(s.cookie, s.order[0][0])
		}
		s.order = s.order[1:]
	}
}

// has reports whether a socket of inode ino may be redirected.
func (s *redirectSet) has(ino uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cookie[ino]
	return ok
}

// is reports whether the socket of inode ino and cookie was redirected;
// an older socket of the inode is forgotten.
func (s *redirectSet) is(ino, cookie uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cookie[ino]
	if ok && c != cookie {
		delete(s.cookie, ino)
	}
	return ok && c == cookie
}

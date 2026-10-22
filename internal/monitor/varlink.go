// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// fdReplacer is a Notifier that can install a descriptor in the target
// (*seccomp.Listener).
type fdReplacer interface {
	ReplaceFD(id uint64, fd, target int, newfdFlags uint32) error
	Return(id uint64, val int64) error
}

// Bounds of the varlink relay: connections at once, and the size of a
// message followed (a larger one is relayed, no longer followed).
const (
	maxRelays     = 64
	maxVarlinkMsg = 1 << 20
	// relayIdle closes a relayed connection idle this long: a workload
	// holding connections must not keep others from being relayed.
	relayIdle = 5 * time.Minute
)

// relayed reports whether the allowed connect n, to items, is to the
// resolved varlink socket and was relayed (answered) by relayResolve.
func (m *Monitor) relayed(l *listener, n seccomp.Notif, sc seccomp.Rule, items []item) bool {
	if m.resolve == "" || sc.Name != "connect" || len(items) != 1 {
		return false
	}
	u := items[0].obj.Unix
	if u == nil || u.Abstract || u.Type != unix.SOCK_STREAM || u.Path != m.resolve {
		return false
	}
	r, ok := l.n.(fdReplacer)
	return ok && m.relayResolve(r, n)
}

// relayResolve answers connect n, to systemd-resolved's varlink socket:
// the monitor connects to resolved itself, installs one end of a socket
// pair at the target's descriptor (as dup2 would), answers 0, and relays
// the messages both ways, recording the names resolved answers
// (dnsnames.Varlink). glibc's nss-resolve sends no DNS query the monitor
// could see: this is where Fedora's programs resolve names.
//
// resolved sees the monitor's credentials: those of the user (lite), or
// root. Only this socket is relayed, after the rules allowed the connect,
// and only when the target's path is the monitor's socket (same inode).
// It returns false, having answered nothing, when it cannot relay: the
// connect is then continued as usual (no names).
//
// The target's socket options are lost (set on the socket replaced), and
// a non-blocking connect succeeds at once.
func (m *Monitor) relayResolve(r fdReplacer, n seccomp.Notif) bool {
	fd := int(int32(n.Args[0]))
	var mine, theirs unix.Stat_t
	if unix.Stat(m.resolve, &mine) != nil || unix.Stat(fmt.Sprintf("/proc/%d/root%s", n.PID, m.resolve), &theirs) != nil ||
		mine.Dev != theirs.Dev || mine.Ino != theirs.Ino {
		return false
	}
	flags, err := fdFlags(int(n.PID), fd)
	if err != nil {
		return false
	}
	if m.relays.Add(1) > maxRelays {
		m.relays.Add(-1)
		return false
	}
	ok := false
	defer func() {
		if !ok {
			m.relays.Add(-1)
		}
	}()
	up, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: m.resolve, Net: "unix"})
	if err != nil {
		return false
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		up.Close()
		return false
	}
	defer unix.Close(pair[1])
	if flags&unix.O_NONBLOCK != 0 {
		if err := unix.SetNonblock(pair[1], true); err != nil {
			unix.Close(pair[0])
			up.Close()
			return false
		}
	}
	var newfd uint32
	if flags&unix.O_CLOEXEC != 0 {
		newfd = unix.O_CLOEXEC
	}
	if err := r.ReplaceFD(n.ID, pair[1], fd, newfd); err != nil {
		unix.Close(pair[0])
		up.Close()
		// ENOENT: the target is gone, nothing to answer.
		return errors.Is(err, unix.ENOENT)
	}
	f := os.NewFile(uintptr(pair[0]), "varlink")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		// The target has its end: it sees the connection closed.
		up.Close()
		_ = r.Return(n.ID, 0)
		return true
	}
	if err := r.Return(n.ID, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		m.warn("varlink relay: " + err.Error())
	}
	ok = true
	go func() {
		defer m.relays.Add(-1)
		relayVarlink(c.(*net.UnixConn), up, dnsnames.NewVarlink(m.names))
	}()
	return true
}

// relayVarlink copies the messages of client to server and back until
// both are done, following them with v before passing them on: a name
// is recorded before the client reads its answer.
func relayVarlink(client, server *net.UnixConn, v *dnsnames.Varlink) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	pump := func(dst, src *net.UnixConn, follow func([]byte)) {
		defer wg.Done()
		defer dst.CloseWrite()
		var acc []byte
		buf := make([]byte, 64<<10)
		for {
			src.SetReadDeadline(time.Now().Add(relayIdle))
			k, err := src.Read(buf)
			if k > 0 {
				mu.Lock()
				if !v.Done() {
					acc = append(acc, buf[:k]...)
					for {
						i := bytes.IndexByte(acc, 0)
						if i < 0 {
							break
						}
						follow(acc[:i])
						acc = acc[i+1:]
					}
					if len(acc) > maxVarlinkMsg {
						v.Stop()
					}
				}
				if v.Done() {
					acc = nil
				}
				mu.Unlock()
				if _, err := dst.Write(buf[:k]); err != nil {
					src.CloseRead()
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					// Idle, or broken: both ways end.
					client.Close()
					server.Close()
				}
				return
			}
		}
	}
	wg.Add(2)
	go pump(server, client, v.Call)
	go pump(client, server, v.Reply)
	wg.Wait()
	client.Close()
	server.Close()
}

// fdFlags returns the open flags of descriptor fd of pid, O_CLOEXEC
// included (/proc/PID/fdinfo).
func fdFlags(pid, fd int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return 0, err
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, "flags:"); ok {
			f, err := strconv.ParseUint(strings.TrimSpace(v), 8, 32)
			return int(f), err
		}
	}
	return 0, errors.New("fdinfo: no flags")
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Protected ports: the TCP ports of the clients that answer for the
// sessions (hallpass web), which no sandbox may connect to. A client
// registers them in the socket directory, in web-<pid>.port (one port per
// line), for as long as it runs. Each session reads the registered ports
// when it starts, then watches the directory with inotify, and denies its
// sandbox every connection to them when it mediates the network.
//
// The directory is this user's (0700), and the sessions deny their
// sandboxes writes to it: only unsandboxed processes of the user register
// ports. A file is trusted if it is a regular file of this user and its
// pid is alive.

const (
	portPrefix = "web-"
	portSuffix = ".port"
	// maxPortFile bounds what is read of a port file.
	maxPortFile = 4096
)

// RegisterPorts registers ports as protected until unregister is called
// or this process exits. Files left by processes that exited are removed.
func RegisterPorts(ports []uint16) (unregister func(), err error) {
	dir := SocketDir()
	if err := ensureSocketDir(dir); err != nil {
		return nil, err
	}
	removeStalePorts(dir)
	var b strings.Builder
	for _, p := range ports {
		fmt.Fprintf(&b, "%d\n", p)
	}
	pid := os.Getpid()
	tmp := filepath.Join(dir, fmt.Sprintf(".%s%d.tmp", portPrefix, pid))
	path := filepath.Join(dir, fmt.Sprintf("%s%d%s", portPrefix, pid, portSuffix))
	_ = os.Remove(tmp)
	// O_EXCL: no symlink followed. The rename makes the file appear
	// complete, for the sessions watching.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = f.WriteString(b.String())
	if err2 := f.Close(); err == nil {
		err = err2
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

// ProtectedPorts returns the ports registered by running processes.
func ProtectedPorts() []uint16 {
	dir := SocketDir()
	ents, _ := os.ReadDir(dir)
	var out []uint16
	for _, e := range ents {
		if _, ok := portFilePID(e.Name()); ok {
			out = append(out, readPorts(filepath.Join(dir, e.Name()))...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// WatchPorts calls fn with the ports of each registration made from now
// on, from one goroutine, until stop returns. The socket directory must
// exist (Listen creates it). Call ProtectedPorts after WatchPorts to miss
// no registration.
func WatchPorts(fn func([]uint16)) (stop func(), err error) {
	dir := SocketDir()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	if _, err := unix.InotifyAddWatch(fd, dir, unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_ONLYDIR); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inotify %s: %w", dir, err)
	}
	// Non-blocking: reads go through the runtime poller, and Close
	// unblocks them.
	f := os.NewFile(uintptr(fd), "inotify")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
		for {
			n, err := f.Read(buf)
			if err != nil {
				return
			}
			for off := 0; off+unix.SizeofInotifyEvent <= n; {
				ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[off]))
				end := off + unix.SizeofInotifyEvent + int(ev.Len)
				if end > n {
					break
				}
				name := strings.TrimRight(string(buf[off+unix.SizeofInotifyEvent:end]), "\x00")
				off = end
				if _, ok := portFilePID(name); !ok {
					continue
				}
				if ports := readPorts(filepath.Join(dir, name)); len(ports) > 0 {
					fn(ports)
				}
			}
		}
	}()
	return func() {
		f.Close()
		wg.Wait()
	}, nil
}

// portFilePID returns the pid of a port file's name.
func portFilePID(name string) (int, bool) {
	s, ok := strings.CutPrefix(name, portPrefix)
	if !ok {
		return 0, false
	}
	if s, ok = strings.CutSuffix(s, portSuffix); !ok {
		return 0, false
	}
	pid, err := strconv.Atoi(s)
	return pid, err == nil && pid > 0
}

// alive reports whether process pid exists.
func alive(pid int) bool {
	return !errors.Is(unix.Kill(pid, 0), unix.ESRCH)
}

// readPorts reads a port file, if its process is alive and it is a
// regular file of this user; nil otherwise.
func readPorts(path string) []uint16 {
	pid, _ := portFilePID(filepath.Base(path))
	if !alive(pid) {
		return nil
	}
	// O_NONBLOCK: a FIFO in its place does not block us.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Getuid() {
		return nil
	}
	var out []uint16
	sc := bufio.NewScanner(io.LimitReader(f, maxPortFile))
	for sc.Scan() {
		p, err := strconv.ParseUint(strings.TrimSpace(sc.Text()), 10, 16)
		if err == nil && p != 0 {
			out = append(out, uint16(p))
		}
	}
	return out
}

// removeStalePorts removes the port files of processes that exited.
func removeStalePorts(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if pid, ok := portFilePID(e.Name()); ok && !alive(pid) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alban/hallpass/internal/procfs"
	"golang.org/x/sys/unix"
)

// SocketDir returns the directory holding per-session answer sockets.
func SocketDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hallpass")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("hallpass-%d", os.Getuid()))
}

// SocketPath returns the answer socket of the session supervised by pid.
func SocketPath(pid int) string {
	return filepath.Join(SocketDir(), strconv.Itoa(pid)+".sock")
}

// Socket serves prompts to `hallpass answer` clients over a unix socket. It is
// the fallback when no desktop is available (ssh) and the agent owns the
// terminal. One client is served at a time.
type Socket struct {
	ln      *net.UnixListener
	path    string
	timeout time.Duration
	conns   chan *net.UnixConn

	mu     sync.Mutex
	client *net.UnixConn
	rd     *bufio.Reader
	seq    uint64
}

// NewSocket listens on SocketPath(os.Getpid()).
func NewSocket(timeout time.Duration) (*Socket, error) {
	dir := SocketDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := SocketPath(os.Getpid())
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	s := &Socket{ln: ln, path: path, timeout: timeout, conns: make(chan *net.UnixConn)}
	go s.accept()
	return s, nil
}

// Path returns the socket path.
func (s *Socket) Path() string { return s.path }

func (s *Socket) accept() {
	for {
		c, err := s.ln.AcceptUnix()
		if err != nil {
			return
		}
		if err := checkPeer(c); err != nil {
			fmt.Fprintf(c, "ERROR %s\n", err)
			c.Close()
			continue
		}
		s.conns <- c
	}
}

// checkPeer rejects clients that could be the sandbox answering its own
// prompts: the peer must be the same user and must not run under any seccomp
// filter (every sandboxed process runs under hallpass's filter, and filters
// cannot be removed).
func checkPeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if int(cred.Uid) != os.Getuid() {
		return errors.New("peer is a different user")
	}
	if procfs.SeccompMode(int(cred.Pid)) != 0 {
		return errors.New("peer runs under a seccomp filter (sandboxed processes cannot answer)")
	}
	return nil
}

// wireRequest is the JSON line sent to clients. Replies are "<id> <answer>";
// replies carrying a stale id (for a prompt that already timed out) are
// ignored.
type wireRequest struct {
	ID      uint64   `json:"id"`
	Exe     string   `json:"exe"`
	PID     uint32   `json:"pid"`
	Op      string   `json:"op"`
	Path    string   `json:"path"`
	Scope   string   `json:"scope,omitempty"`
	Never   string   `json:"never,omitempty"`
	Waiting int      `json:"waiting,omitempty"`
	Cmdline []string `json:"cmdline,omitempty"`
	Parents []string `json:"parents,omitempty"`
}

// Ask sends the request to the connected client, waiting for one to connect if
// needed, and returns its answer.
func (s *Socket) Ask(r Request) Answer {
	s.mu.Lock()
	defer s.mu.Unlock()

	var deadline time.Time
	var expired <-chan time.Time
	if s.timeout > 0 {
		deadline = time.Now().Add(s.timeout)
		t := time.NewTimer(s.timeout)
		defer t.Stop()
		expired = t.C
	}

	s.seq++
	id := s.seq
	for {
		if s.client == nil {
			select {
			case c := <-s.conns:
				s.client, s.rd = c, bufio.NewReader(c)
			case <-expired:
				return AnswerDismissed
			}
		}
		line, _ := json.Marshal(wireRequest{
			ID: id, Exe: r.Exe, PID: r.PID, Op: r.Op, Path: r.Path, Scope: r.Scope, Never: r.Never, Waiting: r.Waiting,
			Cmdline: r.Cmdline, Parents: r.Parents,
		})
		_ = s.client.SetDeadline(deadline)
		if _, err := fmt.Fprintf(s.client, "PROMPT %s\n", line); err != nil {
			s.drop()
			continue
		}
		ans, err := s.readReply(id)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				fmt.Fprintln(s.client, "TIMEOUT")
				_ = s.client.SetDeadline(time.Time{})
				return AnswerDismissed
			}
			s.drop()
			continue
		}
		_ = s.client.SetDeadline(time.Time{})
		if a := ParseAnswer(ans); r.Valid(a) {
			return a
		}
		// A scoped grant without a scope: the narrowest allow.
		return AnswerAllowOnce
	}
}

// readReply reads lines until one answers prompt id.
func (s *Socket) readReply(id uint64) (string, error) {
	for {
		line, err := s.rd.ReadString('\n')
		if err != nil {
			return "", err
		}
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == strconv.FormatUint(id, 10) {
			return f[1], nil
		}
	}
}

func (s *Socket) drop() {
	if s.client != nil {
		s.client.Close()
	}
	s.client, s.rd = nil, nil
}

// Close stops serving and removes the socket.
func (s *Socket) Close() error {
	s.mu.Lock()
	s.drop()
	s.mu.Unlock()
	err := s.ln.Close()
	_ = os.Remove(s.path)
	return err
}

// RunClient connects to a session's answer socket and relays prompts between
// it and the terminal (in, out) until the session ends.
func RunClient(path string, in *os.File, out *os.File) error {
	c, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	defer c.Close()
	fmt.Fprintf(out, "Connected to %s. Waiting for prompts...\n", path)

	srv := bufio.NewReader(c)
	user := bufio.NewReader(in)
	for {
		line, err := srv.ReadString('\n')
		if err != nil {
			fmt.Fprintln(out, "Session ended.")
			return nil
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ERROR "):
			return errors.New(strings.TrimPrefix(line, "ERROR "))
		case line == "TIMEOUT":
			fmt.Fprintln(out, "  (timed out, denied)")
			continue
		case !strings.HasPrefix(line, "PROMPT "):
			continue
		}
		var r wireRequest
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "PROMPT ")), &r); err != nil {
			return err
		}
		fmt.Fprintf(out, "\n%s (pid %d) wants to %s:\n  %s\n", baseName(r.Exe), r.PID, r.Op, r.Path)
		if o := (Request{Cmdline: r.Cmdline, Parents: r.Parents}).Origin(); o != "" {
			fmt.Fprintf(out, "  by: %s\n", o)
		}
		if r.Waiting > 0 {
			fmt.Fprintf(out, "  (%d more waiting)\n", r.Waiting)
		}
		keys := map[string]Answer{"o": AnswerAllowOnce, "d": AnswerDenyOnce, "n": AnswerNever}
		fmt.Fprint(out, "[o] allow once  ")
		if r.Scope != "" {
			fmt.Fprintf(out, "[t] allow %s for %v  [a] always  ", r.Scope, TempGrant)
			keys["t"], keys["a"] = AnswerAllowTemp, AnswerAllowAlways
		}
		fmt.Fprint(out, "[d] deny  [n] never")
		if r.Never != "" {
			fmt.Fprintf(out, " (%s)", r.Never)
		}
		fmt.Fprint(out, ": ")
		ans, err := user.ReadString('\n')
		if err != nil {
			return nil
		}
		reply := AnswerDismissed
		if a, ok := keys[strings.ToLower(strings.TrimSpace(ans))]; ok {
			reply = a
		}
		fmt.Fprintf(c, "%d %s\n", r.ID, reply)
	}
}

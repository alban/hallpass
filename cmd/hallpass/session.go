// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/launch"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/tty"
	"github.com/alban/hallpass/internal/ui"
	"golang.org/x/sys/unix"
)

// sessionConfig describes one sandboxed session.
type sessionConfig struct {
	Args        []string // command to run
	Dir         string   // working directory of the command
	Defaults    *defaults.Defaults
	Asker       ui.Asker
	AllowUserns bool
	Log         io.Writer // JSON lines, one per mediated syscall; nil disables
	// TTY, when set, is the pseudo-terminal the command runs on (for
	// terminal prompts); otherwise it inherits hallpass's stdio.
	TTY *tty.Term
	// LSM, when set, is strict mode: the kernel enforces the rules on the
	// sandbox.
	LSM *lsm.LSM
	// Env is added to the sandbox's environment (KEY=value).
	Env []string
	// WaitAll keeps supervising after the command exits, until every
	// process of the sandbox has exited (the notify fd reports POLLHUP,
	// Linux 5.9+) or the user stops waiting.
	WaitAll bool
	// Timeout is how long a request waits for an answer (0: forever),
	// reported to the session's clients.
	Timeout time.Duration
	// Mediate is the syscall categories mediated (--mediate).
	Mediate seccomp.Category
}

// session is hallpass as a client of the monitor: it asks the user about
// the requests and logs the decisions.
type session struct {
	cfg   sessionConfig
	m     *monitor.Monitor
	start time.Time

	// promptMu serializes what is shown to the user: prompts, the menu,
	// notices.
	promptMu sync.Mutex
	menuOpen atomic.Bool
	wait     *waiter

	// curMu guards the request asked about, and how to take its prompt
	// down.
	curMu     sync.Mutex
	curID     uint64
	curCancel context.CancelFunc
	// curMore sends the prompt shown its count of waiting requests.
	curMore chan int
}

// runSession starts the command under the monitor, until it exits, and
// returns its exit status (128+signal when killed).
func runSession(cfg sessionConfig) (int, error) {
	var kernel monitor.Kernel
	if cfg.LSM != nil {
		ks, err := cfg.LSM.NewSession(0)
		if err != nil {
			return 0, err
		}
		defer ks.Close()
		if err := ks.Mediate(cfg.Mediate&seccomp.Files != 0, cfg.Mediate&seccomp.Network != 0); err != nil {
			return 0, err
		}
		kernel = ks
	}
	m, err := monitor.New(monitor.Config{Kernel: kernel})
	if err != nil {
		return 0, err
	}
	defer m.Close()
	if _, err := m.Apply(monitor.Decision{AddRules: cfg.Defaults.Rules(), Client: "hallpass"}); err != nil {
		return 0, err
	}
	s := &session{cfg: cfg, m: m, start: time.Now(), wait: &waiter{stop: make(chan struct{})}}
	// Other clients (`hallpass answer`, `hallpass web`) follow and answer
	// on the session's socket.
	srv, err := sessionapi.Listen(m, s)
	if err != nil {
		return 0, fmt.Errorf("session socket: %w", err)
	}
	defer srv.Close()
	// The socket directory exists now: the kernel's rules need it.
	protected := protectedRules(cfg.Mediate, sessionapi.SocketDir(), nil)
	if _, err := m.Apply(monitor.Decision{AddRules: protected, Client: "hallpass"}); err != nil {
		return 0, err
	}
	if cfg.Mediate&seccomp.Network != 0 {
		// The web UIs' ports, registered before the sandbox starts, and
		// while it runs.
		g := &portGuard{m: m, done: map[uint16]bool{}}
		stop, err := sessionapi.WatchPorts(func(ports []uint16) {
			if err := g.protect(ports); err != nil {
				s.notice("hallpass: " + err.Error())
			}
		})
		if err != nil {
			return 0, err
		}
		defer stop()
		if err := g.protect(sessionapi.ProtectedPorts()); err != nil {
			return 0, err
		}
	}
	if _, remote := cfg.Asker.(ui.Remote); remote {
		fmt.Fprintf(os.Stderr, "hallpass: answer from another terminal with: hallpass answer %d\n", os.Getpid())
	}

	spec := launch.ProcSpec{
		Args:        cfg.Args,
		Dir:         cfg.Dir,
		Env:         append(append(os.Environ(), "HALLPASS=1"), cfg.Env...),
		Files:       []*os.File{os.Stdin, os.Stdout, os.Stderr},
		AllowUserns: cfg.AllowUserns,
		Mediate:     cfg.Mediate,
	}
	if cfg.TTY != nil {
		sl := cfg.TTY.Slave()
		spec.Files = []*os.File{sl, sl, sl}
		// New session with the pty as controlling terminal, so Ctrl-C,
		// Ctrl-Z and job control work inside.
		spec.Setsid, spec.Setctty = true, true
	}
	if cfg.LSM != nil {
		if err := cfg.LSM.Protect(os.Getpid()); err != nil {
			return 0, fmt.Errorf("protect the supervisor: %w", err)
		}
	}

	// Ctrl-C and Ctrl-\ are for the sandboxed program, which shares our
	// process group and terminal: catch and drop them here. (signal.Ignore
	// would be inherited across exec; caught signals are reset to default.)
	// Termination requests are forwarded. Once the command has exited and
	// only its background processes are left (--wait=all), Ctrl-C and
	// termination requests stop the waiting instead.
	drop := make(chan os.Signal, 4)
	signal.Notify(drop, syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Stop(drop)
	go func() {
		for sig := range drop {
			if sig == syscall.SIGINT && s.wait.active.Load() {
				s.wait.Stop()
			}
		}
	}()
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(fwd)

	if cfg.TTY != nil {
		if err := cfg.TTY.Start(filepath.Base(cfg.Args[0])); err != nil {
			return 0, fmt.Errorf("terminal: %w", err)
		}
	}
	// Processes of the sandbox whose parent exits are reparented to us,
	// not to init: we stay their ancestor, which Yama's default
	// ptrace_scope=1 requires for reading their syscall arguments from
	// /proc/<pid>/mem. Without it, every write of a daemonized process was
	// denied as unreadable. We reap them, and the command, in reap.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("prctl(PR_SET_CHILD_SUBREAPER): %w", err)
	}
	sigchld := make(chan os.Signal, 1)
	signal.Notify(sigchld, syscall.SIGCHLD)
	defer signal.Stop(sigchld)
	proc, listenerFD, release, err := launch.Start(spec)
	if proc == nil {
		return 0, err
	}
	mainDone := make(chan unix.WaitStatus, 1)
	go reap(proc.Pid, sigchld, mainDone)
	waitMain := func() int { return exitStatus(<-mainDone) }
	if cfg.TTY != nil {
		cfg.TTY.CloseSlave()
	}
	if err != nil {
		return waitMain(), err
	}

	if err := m.Attach(listenerFD, proc.Pid); err != nil {
		_ = proc.Kill()
		release()
		waitMain()
		return 1, err
	}
	gone := make(chan struct{})
	go s.prompts(m.Events(monitor.EventOptions{}), gone)
	logged := make(chan struct{})
	if cfg.Log != nil {
		_, audit := cfg.Asker.(ui.AutoAllow)
		go logEvents(m.Events(monitor.EventOptions{Decided: true}), cfg.Log, audit, logged)
	} else {
		close(logged)
	}
	if cfg.TTY != nil {
		cfg.TTY.SetMenu(s.menu)
	}
	if err := release(); err != nil {
		_ = proc.Kill()
		waitMain()
		return 1, err
	}

	go func() {
		for sig := range fwd {
			if s.wait.active.Load() {
				s.wait.Stop()
				continue
			}
			_ = proc.Signal(sig)
		}
	}()

	code := waitMain()
	if cfg.WaitAll {
		s.waitAll(gone)
	}
	// Background processes left by the command keep the filter; their
	// mediated syscalls now fail with ENOSYS (fail closed).
	m.Close()
	<-logged
	return code, nil
}

// notice prints a line for the user, outside any prompt.
func (s *session) notice(msg string) {
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	if s.cfg.TTY != nil {
		// The terminal is in raw mode.
		fmt.Fprint(os.Stderr, "\r\n"+msg+"\r\n")
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

// waiter is --wait=all's state: active once the command has exited and
// hallpass supervises its background processes; stop ends that early.
type waiter struct {
	active atomic.Bool
	once   sync.Once
	stop   chan struct{}
}

// Stop stops waiting for the background processes.
func (w *waiter) Stop() { w.once.Do(func() { close(w.stop) }) }

// waitAll returns once no process uses the seccomp filter any more (gone
// is closed), or the user stops waiting. Meanwhile the monitor goes on
// deciding, and we on asking and logging.
func (s *session) waitAll(gone <-chan struct{}) {
	// Most commands leave nothing behind: say nothing in that case.
	select {
	case <-gone:
		return
	case <-time.After(200 * time.Millisecond):
	}
	s.wait.active.Store(true)
	how := "SIGTERM"
	if s.cfg.TTY != nil {
		how = "Ctrl-] then s"
	}
	s.notice("hallpass: the command exited; still supervising its background processes (" + how + " to stop)")
	select {
	case <-gone:
	case <-s.wait.stop:
		s.notice("hallpass: stopped waiting; the remaining processes' writes now fail")
	}
}

// reap reaps every child: the command (main, whose status goes to mainDone)
// and the processes of the sandbox reparented to us as subreaper. It owns
// waiting for children: nothing else may wait for them (no cmd.Wait).
func reap(main int, sigchld <-chan os.Signal, mainDone chan<- unix.WaitStatus) {
	for {
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil || pid <= 0 {
				break
			}
			if pid == main {
				mainDone <- ws
			}
		}
		<-sigchld
	}
}

// exitStatus is the shell's view of ws: the exit code, or 128+signal.
func exitStatus(ws unix.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

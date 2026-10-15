// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package supervisor runs the sandboxed command (see package launch) and
// mediates its intercepted syscalls.
package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alban/hallpass/internal/launch"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/tty"
	"github.com/alban/hallpass/internal/ui"
	"golang.org/x/sys/unix"
)

// Config describes one sandboxed session.
type Config struct {
	Args        []string // command to run
	Dir         string   // working directory of the command
	Policy      *policy.Engine
	Asker       ui.Asker
	AllowUserns bool
	Log         io.Writer // JSON lines, one per mediated syscall; nil disables
	// TTY, when set, is the pseudo-terminal the command runs on (for
	// terminal prompts); otherwise it inherits hallpass's stdio.
	TTY *tty.Term
	// LSM, when set, is strict mode: the kernel enforces the policy on the
	// sandbox, and the supervisor keeps its rules in sync with the answers.
	LSM *lsm.LSM
	// Env is added to the sandbox's environment (KEY=value).
	Env []string
	// WaitAll keeps supervising after the command exits, until every
	// process of the sandbox has exited (the notify fd reports POLLHUP,
	// Linux 5.9+) or the user stops waiting.
	WaitAll bool
}

// syncPeriod is how often strict mode rules are re-translated, to follow
// mounts appearing or disappearing.
const syncPeriod = 5 * time.Second

// maxParents bounds the parent chain shown in prompts.
const maxParents = 4

// Run starts the command under the seccomp filter, mediates its syscalls until
// it exits, and returns its exit status (128+signal when killed).
func Run(cfg Config) (int, error) {
	spec := launch.ProcSpec{
		Args:        cfg.Args,
		Dir:         cfg.Dir,
		Env:         append(append(os.Environ(), "HALLPASS=1"), cfg.Env...),
		Files:       []*os.File{os.Stdin, os.Stdout, os.Stderr},
		AllowUserns: cfg.AllowUserns,
	}
	if cfg.TTY != nil {
		s := cfg.TTY.Slave()
		spec.Files = []*os.File{s, s, s}
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
	wt := &waiter{stop: make(chan struct{})}
	drop := make(chan os.Signal, 4)
	signal.Notify(drop, syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Stop(drop)
	go func() {
		for sig := range drop {
			if sig == syscall.SIGINT && wt.active.Load() {
				wt.Stop()
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

	s := &session{
		cfg:      cfg,
		rules:    seccomp.Rules(cfg.AllowUserns),
		listener: seccomp.NewListener(listenerFD),
		inflight: map[string]*pending{},
		restart:  map[string]time.Time{},
		root:     proc.Pid,
		wait:     wt,
	}
	if cfg.Log != nil {
		s.logEnc = json.NewEncoder(cfg.Log)
	}
	if cfg.TTY != nil {
		cfg.TTY.SetMenu(s.menu)
	}

	if cfg.LSM != nil {
		err := cfg.LSM.AddMember(proc.Pid)
		if err == nil {
			err = s.syncKernel()
		}
		if err != nil {
			_ = proc.Kill()
			release()
			waitMain()
			return 1, fmt.Errorf("strict mode: %w", err)
		}
		done := make(chan struct{})
		defer close(done)
		go s.kernelEvents()
		go s.periodicSync(done)
	}
	if err := release(); err != nil {
		_ = proc.Kill()
		waitMain()
		return 1, err
	}

	workers := max(4, runtime.NumCPU())
	for i := 0; i < workers; i++ {
		go s.worker()
	}

	go func() {
		for sig := range fwd {
			if wt.active.Load() {
				wt.Stop()
				continue
			}
			_ = proc.Signal(sig)
		}
	}()

	code := waitMain()
	if cfg.WaitAll {
		s.waitAll()
	}
	// Background processes left by the command keep the filter; once we
	// exit, their mediated syscalls fail with ENOSYS (fail closed).
	return code, nil
}

type session struct {
	cfg      Config
	rules    []seccomp.Rule
	listener *seccomp.Listener
	root     int // pid of the sandboxed command

	logMu  sync.Mutex
	logEnc *json.Encoder

	// promptMu serializes prompts: one visible question at a time.
	promptMu sync.Mutex
	// inflight coalesces concurrent requests for the same path.
	inflightMu sync.Mutex
	inflight   map[string]*pending
	waiting    int

	// restart holds the syscalls just allowed once (see restartKey), with
	// until when a restart of them is allowed without asking.
	restartMu sync.Mutex
	restart   map[string]time.Time

	// neverUnknown: the user answered "never" to an unreadable path.
	neverUnknown atomic.Bool

	menuOpen atomic.Bool
	wait     *waiter
}

type pending struct {
	done          chan struct{}
	allowed, once bool
}

func (s *session) worker() {
	for {
		n, err := s.listener.Recv()
		if err != nil {
			return
		}
		s.handle(n)
	}
}

// handle decides one intercepted syscall.
func (s *session) handle(n seccomp.Notif) {
	rule, ok := seccomp.RuleFor(s.rules, n.Nr)
	if !ok {
		// Not ours (the filter and the table disagree): fail closed.
		s.listener.Deny(n.ID, int32(unix.EPERM))
		return
	}
	if s.cfg.LSM != nil {
		// Paths of a process in another mount namespace or chroot cannot
		// be resolved here: let the kernel's rules decide, without asking.
		if same, err := procfs.SameView(n.PID); err == nil && !same {
			s.log(logEntry{PID: n.PID, Syscall: rule.Name, Decision: "continue", Reason: "lsm: other mount namespace or root"})
			_ = s.listener.Continue(n.ID)
			return
		}
	}

	type target struct {
		path    string
		special string
	}
	var targets []target
	var ask []subject
	for i, pa := range rule.Paths {
		raw, err := procfs.ReadCString(n.PID, n.Args[pa.Path])
		if err != nil {
			if s.cfg.LSM != nil {
				// The kernel's rules decide on the real inode.
				s.log(logEntry{PID: n.PID, Syscall: rule.Name, Decision: "continue", Reason: "lsm: unreadable path: " + err.Error()})
				_ = s.listener.Continue(n.ID)
				return
			}
			ask = append(ask, s.unknownSubject(n.ID, err))
			continue
		}
		dirfd := int64(procfs.AtFDCWD)
		if pa.DirFD >= 0 {
			dirfd = procfs.DirFDArg(n.Args[pa.DirFD])
		}
		t, err := procfs.Resolve(n.PID, dirfd, raw, followLast(rule, n, i))
		if err != nil {
			s.deny(n, rule, raw, "unresolvable path: "+err.Error())
			return
		}
		targets = append(targets, target{t.Path, t.Special})
	}

	// The strings were read from the target's memory: make sure the
	// notification is still the same syscall of the same live task.
	if !s.listener.IDValid(n.ID) {
		return
	}

	exe := ""
	for _, t := range targets {
		if t.special != "" {
			continue
		}
		if tid, name, ok := procfs.PidFile(t.path); ok {
			// Processes of the sandbox may tune each other (e.g.
			// oom_score_adj); other processes are asked about.
			if procfs.Descends(tid, s.root) {
				continue
			}
			k := policy.ProcKey{Name: name, Comm: procfs.Comm(tid)}
			switch s.cfg.Policy.EvalProc(k) {
			case policy.Deny:
				s.deny(n, rule, t.path, "policy")
				return
			case policy.Ask:
				ask = append(ask, s.procSubject(t.path, k))
			}
			continue
		}
		switch s.cfg.Policy.Eval(t.path) {
		case policy.Deny:
			s.deny(n, rule, t.path, "policy")
			return
		case policy.Ask:
			ask = append(ask, s.fileSubject(t.path))
		}
	}

	var cmdline, parents []string
	unknown := false
	for _, sub := range ask {
		unknown = unknown || sub.unknown
	}
	var paths []string
	for _, t := range targets {
		paths = append(paths, t.path)
	}
	key := restartKey(n, paths)
	restarted := len(ask) > 0 && !unknown && s.restarted(key)
	var once []subject
	for _, sub := range ask {
		if restarted {
			once = append(once, sub)
			continue
		}
		if exe == "" {
			exe = procfs.Exe(n.PID)
			cmdline = procfs.Cmdline(int(n.PID))
			parents = procfs.Ancestors(int(n.PID), s.root, maxParents)
		}
		sub.req.Exe, sub.req.PID, sub.req.Op = exe, n.PID, rule.Op
		sub.req.Cmdline, sub.req.Parents = cmdline, parents
		allowed, o := s.ask(sub)
		if !allowed {
			if sub.unknown {
				s.deny(n, rule, "", "user: unknown path")
			} else {
				s.deny(n, rule, sub.req.Path, "user")
			}
			return
		}
		if o {
			once = append(once, sub)
		}
	}
	if len(once) > 0 && !unknown && !restarted {
		s.allowedOnce(key)
	}

	reason := "policy"
	if len(ask) > 0 {
		reason = "user"
		if _, ok := s.cfg.Asker.(ui.AutoAllow); ok {
			reason = "audit" // would have been asked
		}
		if unknown {
			reason += ": unknown path"
		}
		if restarted {
			reason += ": restarted"
		}
	}
	path := ""
	if len(targets) > 0 {
		path = targets[len(targets)-1].path
	}
	s.log(logEntry{PID: n.PID, Exe: exe, Syscall: rule.Name, Path: path, Decision: "allow", Reason: reason})
	if s.cfg.LSM != nil && len(once) > 0 {
		s.grantOnce(n, once)
	}
	if err := s.listener.Continue(n.ID); err != nil && !errors.Is(err, unix.ENOENT) {
		fmt.Fprintf(os.Stderr, "hallpass: continue: %v\n", err)
	}
}

func (s *session) deny(n seccomp.Notif, rule seccomp.Rule, path, reason string) {
	s.log(logEntry{PID: n.PID, Syscall: rule.Name, Path: path, Decision: "deny", Reason: reason})
	_ = s.listener.Deny(n.ID, int32(unix.EACCES))
}

// followLast reports whether the kernel follows a symlink in the last
// component of path argument i of this syscall.
func followLast(rule seccomp.Rule, n seccomp.Notif, i int) bool {
	switch rule.Name {
	case "openat", "open":
		f := n.Args[rule.FlagsArg]
		if f&unix.O_NOFOLLOW != 0 {
			return false
		}
		return !(f&unix.O_CREAT != 0 && f&unix.O_EXCL != 0)
	case "creat", "truncate":
		return true
	case "linkat":
		return i == 0 && n.Args[4]&unix.AT_SYMLINK_FOLLOW != 0
	}
	return false
}

// ask returns whether the user allows sub, and whether only this once.
// Concurrent identical requests share one prompt; queued prompts are
// re-evaluated after each answer so a scoped grant settles them without
// asking again.
func (s *session) ask(sub subject) (allowed, once bool) {
	req := sub.req
	s.inflightMu.Lock()
	if p, ok := s.inflight[sub.key]; ok {
		s.inflightMu.Unlock()
		<-p.done
		return p.allowed, p.once
	}
	p := &pending{done: make(chan struct{})}
	s.inflight[sub.key] = p
	s.waiting++
	s.inflightMu.Unlock()

	s.promptMu.Lock()
	s.inflightMu.Lock()
	s.waiting--
	req.Waiting = s.waiting
	s.inflightMu.Unlock()

	switch sub.eval() {
	case policy.Allow:
		p.allowed = true
	case policy.Deny:
		p.allowed = false
	default:
		a := s.cfg.Asker.Ask(req)
		if !req.Valid(a) {
			a = ui.AnswerAllowOnce
		}
		switch a {
		case ui.AnswerAllowOnce:
			p.allowed, p.once = true, true
		case ui.AnswerAllowTemp:
			sub.grant(ui.TempGrant)
			p.allowed = true
		case ui.AnswerAllowAlways:
			sub.grant(0)
			p.allowed = true
		case ui.AnswerNever:
			sub.never()
		}
		if s.cfg.LSM != nil {
			// Before the waiting syscalls are continued.
			s.syncOrWarn()
		}
	}
	s.promptMu.Unlock()

	s.inflightMu.Lock()
	delete(s.inflight, sub.key)
	s.inflightMu.Unlock()
	close(p.done)
	return p.allowed, p.once
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/seccomp"
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
}

// Run starts the command under the seccomp filter, mediates its syscalls until
// it exits, and returns its exit status (128+signal when killed).
func Run(cfg Config) (int, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("socketpair: %w", err)
	}
	parentSock := pair[0]
	childSock := os.NewFile(uintptr(pair[1]), "hallpass-child-sock")

	cmd := exec.Command("/proc/self/exe", append([]string{"--"}, cfg.Args...)...)
	cmd.Args[0] = "hallpass-child"
	cmd.Dir = cfg.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{childSock} // fd 3 in the child
	cmd.Env = append(os.Environ(),
		childEnvSentinel+"=1",
		childEnvFD+"=3",
		"HALLPASS=1",
	)
	if cfg.AllowUserns {
		cmd.Env = append(cmd.Env, childEnvUserns+"=1")
	}

	// Ctrl-C and Ctrl-\ are for the sandboxed program, which shares our
	// process group and terminal: catch and drop them here. (signal.Ignore
	// would be inherited across exec; caught signals are reset to default.)
	// Termination requests are forwarded.
	drop := make(chan os.Signal, 4)
	signal.Notify(drop, syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Stop(drop)
	go func() {
		for range drop {
		}
	}()
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(fwd)

	if err := cmd.Start(); err != nil {
		childSock.Close()
		unix.Close(parentSock)
		return 0, err
	}
	childSock.Close()

	listenerFD, err := recvFD(parentSock)
	unix.Close(parentSock)
	if err != nil {
		// The child printed why it failed before exiting.
		_ = cmd.Wait()
		return exitCode(cmd.ProcessState), fmt.Errorf("sandbox setup failed")
	}
	unix.SetNonblock(listenerFD, false)

	s := &session{
		cfg:      cfg,
		rules:    seccomp.Rules(cfg.AllowUserns),
		listener: seccomp.NewListener(listenerFD),
		inflight: map[string]*pending{},
	}
	if cfg.Log != nil {
		s.logEnc = json.NewEncoder(cfg.Log)
	}

	workers := max(4, runtime.NumCPU())
	for i := 0; i < workers; i++ {
		go s.worker()
	}

	go func() {
		for sig := range fwd {
			_ = cmd.Process.Signal(sig)
		}
	}()

	_ = cmd.Wait()
	// Background processes left by the command keep the filter; once we
	// exit, their mediated syscalls fail with ENOSYS (fail closed).
	return exitCode(cmd.ProcessState), nil
}

func exitCode(ps *os.ProcessState) int {
	if ps == nil {
		return 1
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

type session struct {
	cfg      Config
	rules    []seccomp.Rule
	listener *seccomp.Listener

	logMu  sync.Mutex
	logEnc *json.Encoder

	// promptMu serializes prompts: one visible question at a time.
	promptMu sync.Mutex
	// inflight coalesces concurrent requests for the same path.
	inflightMu sync.Mutex
	inflight   map[string]*pending
	waiting    int
}

type pending struct {
	done    chan struct{}
	allowed bool
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

type logEntry struct {
	Time     string `json:"time"`
	PID      uint32 `json:"pid"`
	Exe      string `json:"exe,omitempty"`
	Syscall  string `json:"syscall"`
	Path     string `json:"path,omitempty"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

func (s *session) log(e logEntry) {
	if s.logEnc == nil {
		return
	}
	e.Time = time.Now().Format(time.RFC3339Nano)
	s.logMu.Lock()
	_ = s.logEnc.Encode(e)
	s.logMu.Unlock()
}

// handle decides one intercepted syscall.
func (s *session) handle(n seccomp.Notif) {
	rule, ok := seccomp.RuleFor(s.rules, n.Nr)
	if !ok {
		// Not ours (the filter and the table disagree): fail closed.
		s.listener.Deny(n.ID, int32(unix.EPERM))
		return
	}

	type target struct {
		path    string
		special string
	}
	var targets []target
	for i, pa := range rule.Paths {
		raw, err := procfs.ReadCString(n.PID, n.Args[pa.Path])
		if err != nil {
			s.deny(n, rule, "", "unreadable path: "+err.Error())
			return
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

	var ask []string
	for _, t := range targets {
		if t.special != "" {
			continue
		}
		switch s.cfg.Policy.Eval(t.path) {
		case policy.Deny:
			s.deny(n, rule, t.path, "policy")
			return
		case policy.Ask:
			ask = append(ask, t.path)
		}
	}

	exe := ""
	for _, p := range ask {
		if exe == "" {
			exe = procfs.Exe(n.PID)
		}
		if !s.ask(ui.Request{Exe: exe, PID: n.PID, Op: rule.Op, Path: p}) {
			s.deny(n, rule, p, "user")
			return
		}
	}

	reason := "policy"
	if len(ask) > 0 {
		reason = "user"
	}
	path := ""
	if len(targets) > 0 {
		path = targets[len(targets)-1].path
	}
	s.log(logEntry{PID: n.PID, Exe: exe, Syscall: rule.Name, Path: path, Decision: "allow", Reason: reason})
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

// ask returns whether the user allows writing req.Path. Concurrent requests
// for the same path share one prompt; queued prompts are re-evaluated after
// each answer so an "Allow folder" settles them without asking again.
func (s *session) ask(req ui.Request) bool {
	s.inflightMu.Lock()
	if p, ok := s.inflight[req.Path]; ok {
		s.inflightMu.Unlock()
		<-p.done
		return p.allowed
	}
	p := &pending{done: make(chan struct{})}
	s.inflight[req.Path] = p
	s.waiting++
	s.inflightMu.Unlock()

	s.promptMu.Lock()
	s.inflightMu.Lock()
	s.waiting--
	req.Waiting = s.waiting
	s.inflightMu.Unlock()

	switch s.cfg.Policy.Eval(req.Path) {
	case policy.Allow:
		p.allowed = true
	case policy.Deny:
		p.allowed = false
	default:
		req.Folder = s.cfg.Policy.FolderFor(req.Path)
		switch s.cfg.Asker.Ask(req) {
		case ui.AnswerAllowOnce:
			p.allowed = true
		case ui.AnswerAllowFolder:
			s.cfg.Policy.AllowFolder(req.Folder)
			p.allowed = true
		case ui.AnswerAllowFolderTemp:
			s.cfg.Policy.AllowFolderFor(req.Folder, ui.TempGrant)
			p.allowed = true
		case ui.AnswerDeny:
			s.cfg.Policy.DenyPath(req.Path)
		}
	}
	s.promptMu.Unlock()

	s.inflightMu.Lock()
	delete(s.inflight, req.Path)
	s.inflightMu.Unlock()
	close(p.done)
	return p.allowed
}

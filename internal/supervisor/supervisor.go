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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
}

// onceTTL is how long the kernel allows a path after "allow once": long
// enough for the syscall being continued to reach the LSM hook.
const onceTTL = 2 * time.Second

// syncPeriod is how often strict mode rules are re-translated, to follow
// mounts appearing or disappearing.
const syncPeriod = 5 * time.Second

// maxParents bounds the parent chain shown in prompts.
const maxParents = 4

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
	if cfg.TTY != nil {
		s := cfg.TTY.Slave()
		cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
		// New session with the pty as controlling terminal, so Ctrl-C,
		// Ctrl-Z and job control work inside.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	}
	cmd.ExtraFiles = []*os.File{childSock} // fd 3 in the child
	cmd.Env = append(os.Environ(),
		childEnvSentinel+"=1",
		childEnvFD+"=3",
		"HALLPASS=1",
	)
	cmd.Env = append(cmd.Env, cfg.Env...)
	if cfg.AllowUserns {
		cmd.Env = append(cmd.Env, childEnvUserns+"=1")
	}
	if cfg.LSM != nil {
		cmd.Env = append(cmd.Env, childEnvWait+"=1")
		if err := cfg.LSM.Protect(os.Getpid()); err != nil {
			childSock.Close()
			unix.Close(parentSock)
			return 0, fmt.Errorf("protect the supervisor: %w", err)
		}
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

	if cfg.TTY != nil {
		if err := cfg.TTY.Start(); err != nil {
			childSock.Close()
			unix.Close(parentSock)
			return 0, fmt.Errorf("terminal: %w", err)
		}
	}
	// Processes of the sandbox whose parent exits are reparented to us,
	// not to init: we stay their ancestor, which Yama's default
	// ptrace_scope=1 requires for reading their syscall arguments from
	// /proc/<pid>/mem. Without it, every write of a daemonized process was
	// denied as unreadable. We reap them, and the command, in reap.
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		childSock.Close()
		unix.Close(parentSock)
		return 0, fmt.Errorf("prctl(PR_SET_CHILD_SUBREAPER): %w", err)
	}
	sigchld := make(chan os.Signal, 1)
	signal.Notify(sigchld, syscall.SIGCHLD)
	defer signal.Stop(sigchld)
	if err := cmd.Start(); err != nil {
		childSock.Close()
		unix.Close(parentSock)
		return 0, err
	}
	mainDone := make(chan unix.WaitStatus, 1)
	go reap(cmd.Process.Pid, sigchld, mainDone)
	waitMain := func() int { return exitStatus(<-mainDone) }
	childSock.Close()
	if cfg.TTY != nil {
		cfg.TTY.CloseSlave()
	}

	listenerFD, err := recvFD(parentSock)
	if err != nil {
		unix.Close(parentSock)
		// The child printed why it failed before exiting.
		return waitMain(), fmt.Errorf("sandbox setup failed")
	}
	unix.SetNonblock(listenerFD, false)

	s := &session{
		cfg:      cfg,
		rules:    seccomp.Rules(cfg.AllowUserns),
		listener: seccomp.NewListener(listenerFD),
		inflight: map[string]*pending{},
		root:     cmd.Process.Pid,
	}
	if cfg.Log != nil {
		s.logEnc = json.NewEncoder(cfg.Log)
	}
	if cfg.TTY != nil {
		cfg.TTY.SetMenu(s.menu)
	}

	if cfg.LSM != nil {
		err := cfg.LSM.AddMember(cmd.Process.Pid)
		if err == nil {
			err = s.syncKernel()
		}
		if err == nil {
			_, err = unix.Write(parentSock, []byte{1})
		}
		if err != nil {
			unix.Close(parentSock)
			_ = cmd.Process.Kill()
			waitMain()
			return 1, fmt.Errorf("strict mode: %w", err)
		}
		done := make(chan struct{})
		defer close(done)
		go s.kernelEvents()
		go s.periodicSync(done)
	}
	unix.Close(parentSock)

	workers := max(4, runtime.NumCPU())
	for i := 0; i < workers; i++ {
		go s.worker()
	}

	go func() {
		for sig := range fwd {
			_ = cmd.Process.Signal(sig)
		}
	}()

	code := waitMain()
	// Background processes left by the command keep the filter; once we
	// exit, their mediated syscalls fail with ENOSYS (fail closed).
	return code, nil
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

	// Strict mode: "allow once" answers, as short-lived exact rules.
	onceMu   sync.Mutex
	once     []lsm.Rule
	onceProc []lsm.ProcRule

	// neverUnknown: the user answered "never" to an unreadable path.
	neverUnknown atomic.Bool

	menuOpen atomic.Bool
}

// menu shows the session's rules over the program's screen (Ctrl-]), until
// a key is pressed. Prompts wait meanwhile.
func (s *session) menu() {
	if !s.menuOpen.CompareAndSwap(false, true) {
		return
	}
	defer s.menuOpen.Store(false)
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	mode := "lite"
	if s.cfg.LSM != nil {
		mode = "strict"
	}
	deny, allow := s.cfg.Policy.Summary()
	w := s.cfg.TTY.Width() - 1
	lines := []string{fmt.Sprintf(" hallpass, %s mode: the rules of this session", mode)}
	lines = append(lines, wrapList(" Denied:   ", deny, w)...)
	lines = append(lines, wrapList(" Writable: ", allow, w)...)
	lines = append(lines, " Anything else is asked. A folder covers everything below it.   [any key] close")
	keys := make([]byte, 0, 255)
	for k := 1; k < 256; k++ {
		keys = append(keys, byte(k))
	}
	s.cfg.TTY.Prompt(lines, string(keys), 0, 0)
}

// wrapList lays out items after prefix, comma-separated, in lines of at
// most width columns, continuation lines indented like the first item.
func wrapList(prefix string, items []string, width int) []string {
	indent := strings.Repeat(" ", len(prefix))
	var lines []string
	line := prefix
	for i, it := range items {
		if i < len(items)-1 {
			it += ","
		}
		if line != prefix && line != indent && len(line)+1+len(it) > width {
			lines = append(lines, line)
			line = indent
		}
		if line != prefix && line != indent {
			line += " "
		}
		line += it
	}
	return append(lines, line)
}

// syncKernel pushes the policy's current rules and the pending "allow once"
// answers to the kernel.
func (s *session) syncKernel() error {
	now := time.Now()
	s.onceMu.Lock()
	once := s.once[:0]
	for _, r := range s.once {
		if r.Expires.After(now) {
			once = append(once, r)
		}
	}
	s.once = once
	onceProc := s.onceProc[:0]
	for _, r := range s.onceProc {
		if r.Expires.After(now) {
			onceProc = append(onceProc, r)
		}
	}
	s.onceProc = onceProc
	rules := append([]lsm.Rule(nil), once...)
	procs := append([]lsm.ProcRule(nil), onceProc...)
	s.onceMu.Unlock()

	for _, r := range s.cfg.Policy.Rules() {
		rules = append(rules, lsm.Rule{Path: r.Path, Tree: r.Tree, Deny: r.Deny, Expires: r.Expires})
	}
	for _, r := range s.cfg.Policy.ProcRules() {
		procs = append(procs, lsm.ProcRule{Name: r.Name, Comm: r.Comm, Deny: r.Deny, Expires: r.Expires})
	}
	return s.cfg.LSM.Sync(rules, procs)
}

func (s *session) syncOrWarn() {
	if err := s.syncKernel(); err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: strict mode: updating the kernel's rules: %v\n", err)
	}
}

func (s *session) periodicSync(done <-chan struct{}) {
	t := time.NewTicker(syncPeriod)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s.syncOrWarn()
		}
	}
}

// kernelEvents logs the decisions of the BPF programs: denials (also of
// operations the seccomp filter does not see, e.g. through io_uring).
func (s *session) kernelEvents() {
	s.cfg.LSM.Events(func(e lsm.Event) {
		d := "deny"
		if e.Allowed {
			d = "allow"
		}
		s.log(logEntry{PID: e.PID, Exe: e.Comm, Syscall: e.Op, Path: e.Path, Decision: d, Reason: "lsm"})
	})
}

// allowOnce lets the kernel allow exactly path for a moment, for the
// syscall about to be continued.
func (s *session) allowOnce(path string) {
	s.onceMu.Lock()
	s.once = append(s.once, lsm.Rule{Path: path, Expires: time.Now().Add(onceTTL)})
	s.onceMu.Unlock()
}

func (s *session) allowProcOnce(k policy.ProcKey) {
	s.onceMu.Lock()
	s.onceProc = append(s.onceProc, lsm.ProcRule{Name: k.Name, Comm: k.Comm, Expires: time.Now().Add(onceTTL)})
	s.onceMu.Unlock()
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
		if exe == "" {
			exe = procfs.Exe(n.PID)
			cmdline = procfs.Cmdline(int(n.PID))
			parents = procfs.Ancestors(int(n.PID), s.root, maxParents)
		}
		sub.req.Exe, sub.req.PID, sub.req.Op = exe, n.PID, rule.Op
		sub.req.Cmdline, sub.req.Parents = cmdline, parents
		if !s.ask(sub) {
			if sub.unknown {
				s.deny(n, rule, "", "user: unknown path")
			} else {
				s.deny(n, rule, sub.req.Path, "user")
			}
			return
		}
		if sub.unknown {
			unknown = true
		}
	}

	reason := "policy"
	if unknown {
		reason = "user: unknown path"
	} else if len(ask) > 0 {
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

// subject is something the user is asked about: a file path, or a kind of
// write to another process's /proc files.
type subject struct {
	key   string // coalesces concurrent identical requests
	req   ui.Request
	eval  func() policy.Decision
	grant func(ttl time.Duration) // covers req.Scope; 0: rest of the session
	never func()
	once  func() // strict mode: let the kernel allow it this time
	// unknown: the path could not be read (see unknownSubject).
	unknown bool
}

func (s *session) fileSubject(path string) subject {
	p := s.cfg.Policy
	folder := p.FolderFor(path)
	warn := p.Warn(path)
	if warn != "" {
		warn += " — secret store"
	}
	return subject{
		key:   path,
		req:   ui.Request{Path: path, Scope: folder, Never: "this path", Warn: warn},
		eval:  func() policy.Decision { return p.Eval(path) },
		grant: func(ttl time.Duration) { p.AllowFolderFor(folder, ttl) },
		never: func() { p.DenyPath(path) },
		once:  func() { s.allowOnce(path) },
	}
}

func (s *session) procSubject(path string, k policy.ProcKey) subject {
	p := s.cfg.Policy
	what := fmt.Sprintf("%s of %q processes outside the sandbox", k.Name, k.Comm)
	return subject{
		key:   "\x00proc\x00" + k.Name + "\x00" + k.Comm,
		req:   ui.Request{Path: path, Scope: what, Never: what},
		eval:  func() policy.Decision { return p.EvalProc(k) },
		grant: func(ttl time.Duration) { p.AllowProcFor(k, ttl) },
		never: func() { p.DenyProc(k) },
		once:  func() { s.allowProcOnce(k) },
	}
}

// unknownSubject asks about a syscall whose path hallpass could not read.
// Only lite mode gets here. Allowing it skips every rule, including the
// denies, and a process can make its path unreadable on purpose: so only
// "once" is offered, never a lasting grant, and the prompt is not shared
// with other syscalls.
func (s *session) unknownSubject(id uint64, err error) subject {
	return subject{
		key: fmt.Sprintf("\x00unknown\x00%d", id),
		req: ui.Request{
			Path:  "(unknown path)",
			Never: "all unknown paths",
			Warn:  "Unknown path — hallpass could not read it (" + err.Error() + ")",
		},
		eval: func() policy.Decision {
			if s.neverUnknown.Load() {
				return policy.Deny
			}
			return policy.Ask
		},
		grant:   func(time.Duration) {},
		never:   func() { s.neverUnknown.Store(true) },
		once:    func() {},
		unknown: true,
	}
}

// ask returns whether the user allows sub. Concurrent identical requests
// share one prompt; queued prompts are re-evaluated after each answer so a
// scoped grant settles them without asking again.
func (s *session) ask(sub subject) bool {
	req := sub.req
	s.inflightMu.Lock()
	if p, ok := s.inflight[sub.key]; ok {
		s.inflightMu.Unlock()
		<-p.done
		return p.allowed
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
			p.allowed = true
			if s.cfg.LSM != nil {
				sub.once()
			}
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
	return p.allowed
}

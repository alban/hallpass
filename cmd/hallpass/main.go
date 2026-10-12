// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Command hallpass runs a command (typically an AI agent CLI) so that writes
// outside its project directory need the user's approval.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/config"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/privsep"
	"github.com/alban/hallpass/internal/supervisor"
	"github.com/alban/hallpass/internal/tty"
	"github.com/alban/hallpass/internal/ui"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const usageText = `Usage:
  hallpass [flags] [--] [command [args...]]   run command (default: $SHELL)
  hallpass answer [PID]                       answer prompts from this terminal
  hallpass policy [flags]                     print the rules these flags give

In the program's terminal, press Ctrl-] to show the current rules.

Flags:
`

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	if supervisor.IsChild() {
		supervisor.ChildMain()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == privsep.HelperArg {
		os.Exit(privsep.HelperMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "answer" {
		os.Exit(answerMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "policy" {
		os.Exit(runMain(os.Args[2:], true))
	}
	os.Exit(runMain(os.Args[1:], false))
}

// runMain runs a sandboxed command, or with printPolicy prints the rules
// the same flags would give it.
func runMain(argv []string, printPolicy bool) int {
	fs := flag.NewFlagSet("hallpass", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	var (
		workdir     string
		allow, deny listFlag
		ask         string
		timeout     time.Duration
		allowUserns bool
		logPath     string
		mode        string
		escalate    string
	)
	fs.StringVar(&workdir, "C", "", "project `dir`, writable without asking (default: current directory)")
	fs.StringVar(&workdir, "workdir", "", "same as -C")
	fs.Var(&allow, "allow", "`path` also writable without asking (repeatable)")
	fs.Var(&deny, "deny", "`path` always denied (repeatable, wins over --allow)")
	fs.StringVar(&ask, "ask", "auto", "how to ask: auto | term | desktop | answer | deny")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "deny unanswered prompts after `duration` (0: wait forever)")
	fs.BoolVar(&allowUserns, "allow-userns", false, "let the sandbox create user/mount namespaces (weakens lite mode; always on in strict mode)")
	fs.StringVar(&logPath, "log", "", "append one JSON line per mediated syscall to `file`")
	fs.StringVar(&mode, "mode", "lite", "lite (seccomp only, no root needed) | strict (the kernel enforces the answers with BPF-LSM; root needed to load it)")
	fs.StringVar(&escalate, "escalate", "", "strict mode, when not root: how to run the loader as root: "+strings.Join(privsep.Tools, " | ")+" (default: the saved choice, else ask on a terminal, else auto)")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	cfgDir, err := config.Dir()
	if err != nil {
		return fail(err)
	}

	args := fs.Args()
	if len(args) == 0 {
		sh := os.Getenv("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		args = []string{sh}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fail(err)
	}
	if workdir == "" {
		if workdir, err = os.Getwd(); err != nil {
			return fail(err)
		}
	}
	if workdir, err = filepath.Abs(workdir); err != nil {
		return fail(err)
	}
	if st, err := os.Stat(workdir); err != nil || !st.IsDir() {
		return fail(fmt.Errorf("workdir %s: not a directory", workdir))
	}
	if filepath.Clean(workdir) == filepath.Clean(home) || workdir == "/" {
		return fail(fmt.Errorf("refusing to use %s as the workdir: everything under it would be writable", workdir))
	}
	for _, l := range []listFlag{allow, deny} {
		for i, p := range l {
			if l[i], err = filepath.Abs(p); err != nil {
				return fail(err)
			}
		}
	}

	// The sandbox must not change what hallpass runs next time, outside it.
	deny = append(deny, cfgDir)
	engine := policy.New(home, workdir,
		append(policy.DefaultAllows(), allow...),
		deny)
	if printPolicy {
		engine.SetTmpdir(filepath.Join(os.TempDir(), "hallpass-*"))
		for _, l := range engine.Describe() {
			fmt.Println(l)
		}
		return 0
	}
	// A private $TMPDIR, so tools that honour it (mktemp, compilers, ...)
	// work without asking and without sharing /tmp.
	tmpdir, err := os.MkdirTemp("", "hallpass-")
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := os.Remove(tmpdir); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "hallpass: kept %s: not empty\n", tmpdir)
		}
	}()
	engine.SetTmpdir(tmpdir)

	var strict *lsm.LSM
	switch mode {
	case "lite":
	case "strict":
		// The supervisor runs as the sandbox's user: forbid it ptrace,
		// pidfd_getfd, /proc/<pid>/mem and fd access to us, before any
		// fd worth stealing exists. (Root keeps them, for the loader.)
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			return fail(fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", err))
		}
		if err := lsm.Active(); err != nil {
			return fail(err)
		}
		if os.Geteuid() != 0 {
			if escalate, err = escalateTool(escalate, cfgDir); err != nil {
				return fail(err)
			}
		}
		if strict, err = privsep.Load(escalate, false); err != nil {
			return fail(err)
		}
		defer strict.Close()
		// The kernel enforces the rules, whatever namespaces the
		// sandbox builds (e.g. an agent working on a container runtime).
		allowUserns = true
	default:
		return fail(fmt.Errorf("unknown --mode %q (want lite or strict)", mode))
	}

	asker, pty, err := newAsker(ask, timeout)
	if err != nil {
		return fail(err)
	}
	defer asker.Close()

	var logw io.Writer
	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		logw = f
	}

	code, err := supervisor.Run(supervisor.Config{
		Args:        args,
		Dir:         workdir,
		Policy:      engine,
		Asker:       asker,
		AllowUserns: allowUserns,
		Log:         logw,
		TTY:         pty,
		LSM:         strict,
		Env:         []string{"TMPDIR=" + tmpdir},
	})
	if pty != nil {
		pty.Close() // restore the terminal before printing anything
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

// newAsker picks how to ask. "auto" prefers the terminal overlay (works
// locally and over ssh, and keeps the question next to the agent), then the
// desktop, then `hallpass answer`.
func newAsker(mode string, timeout time.Duration) (ui.Asker, *tty.Term, error) {
	switch mode {
	case "deny":
		return ui.AutoDeny{}, nil, nil
	case "term":
		return newTermAsker(timeout)
	case "desktop":
		d, err := ui.NewDesktop(timeout)
		return d, nil, err
	case "answer":
		s, err := newSocketAsker(timeout)
		return s, nil, err
	case "auto":
		if tty.Available() {
			return newTermAsker(timeout)
		}
		if d, err := ui.NewDesktop(timeout); err == nil {
			return d, nil, nil
		}
		s, err := newSocketAsker(timeout)
		return s, nil, err
	}
	return nil, nil, fmt.Errorf("unknown --ask mode %q", mode)
}

func newTermAsker(timeout time.Duration) (ui.Asker, *tty.Term, error) {
	if !tty.Available() {
		return nil, nil, errors.New("--ask=term needs stdin and stdout to be a terminal")
	}
	t, err := tty.Open()
	if err != nil {
		return nil, nil, err
	}
	return ui.NewTerminal(t, timeout), t, nil
}

func newSocketAsker(timeout time.Duration) (ui.Asker, error) {
	s, err := ui.NewSocket(timeout)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "hallpass: no desktop prompt; answer from another terminal with: hallpass answer %d\n", os.Getpid())
	return s, nil
}

func answerMain(argv []string) int {
	var path string
	switch len(argv) {
	case 0:
		matches, _ := filepath.Glob(filepath.Join(ui.SocketDir(), "*.sock"))
		switch len(matches) {
		case 0:
			return fail(errors.New("no hallpass session is waiting for answers"))
		case 1:
			path = matches[0]
		default:
			return fail(fmt.Errorf("several sessions; pick one: hallpass answer PID (%s)", strings.Join(matches, " ")))
		}
	case 1:
		var pid int
		if _, err := fmt.Sscanf(argv[0], "%d", &pid); err != nil {
			return fail(fmt.Errorf("bad PID %q", argv[0]))
		}
		path = ui.SocketPath(pid)
	default:
		return fail(errors.New("usage: hallpass answer [PID]"))
	}
	if err := ui.RunClient(path, os.Stdin, os.Stdout); err != nil {
		return fail(err)
	}
	return 0
}

// escalateTool resolves --escalate: the flag, else the saved choice, else
// ask on a terminal, else auto.
func escalateTool(flagValue, cfgDir string) (string, error) {
	if flagValue != "" && flagValue != "ask" {
		if !privsep.Valid(flagValue) {
			return "", fmt.Errorf("unknown --escalate %q (want one of %s)", flagValue, strings.Join(privsep.Tools, ", "))
		}
		return flagValue, nil
	}
	cfg, err := config.Load(cfgDir)
	if err != nil {
		return "", err
	}
	saved := cfg.Get("escalate")
	if saved != "" && !privsep.Valid(saved) {
		return "", fmt.Errorf("%s: unknown escalate value %q (want one of %s)", cfg.Path(), saved, strings.Join(privsep.Tools, ", "))
	}
	if flagValue == "" && saved != "" && saved != "ask" {
		return saved, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if flagValue == "ask" || saved == "ask" {
			return "", errors.New("--escalate=ask needs a terminal on stdin")
		}
		return "auto", nil
	}
	tool, remember, err := privsep.Choose(os.Stdin, os.Stderr)
	if err != nil {
		return "", err
	}
	switch {
	case remember:
		err = cfg.Set("escalate", tool)
		if err == nil {
			fmt.Fprintf(os.Stderr, "hallpass: saved in %s; change it with --escalate=ask\n", cfg.Path())
		}
	case saved != "" && saved != "ask":
		// "Ask next time" replaces the saved choice.
		err = cfg.Set("escalate", "ask")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: saving the choice: %v\n", err)
	}
	return tool, nil
}

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "hallpass: %v\n", err)
	return 1
}

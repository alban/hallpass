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

	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/supervisor"
	"github.com/alban/hallpass/internal/ui"
)

const usageText = `Usage:
  hallpass [flags] [--] [command [args...]]   run command (default: $SHELL)
  hallpass answer [PID]                       answer prompts from this terminal

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
	if len(os.Args) > 1 && os.Args[1] == "answer" {
		os.Exit(answerMain(os.Args[2:]))
	}
	os.Exit(runMain(os.Args[1:]))
}

func runMain(argv []string) int {
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
	)
	fs.StringVar(&workdir, "C", "", "project `dir`, writable without asking (default: current directory)")
	fs.StringVar(&workdir, "workdir", "", "same as -C")
	fs.Var(&allow, "allow", "`path` also writable without asking (repeatable)")
	fs.Var(&deny, "deny", "`path` always denied (repeatable, wins over --allow)")
	fs.StringVar(&ask, "ask", "auto", "how to ask: auto | desktop | answer | deny")
	fs.DurationVar(&timeout, "timeout", 30*time.Second, "deny unanswered prompts after `duration` (0: wait forever)")
	fs.BoolVar(&allowUserns, "allow-userns", false, "let the sandbox create user/mount namespaces (weakens lite mode)")
	fs.StringVar(&logPath, "log", "", "append one JSON line per mediated syscall to `file`")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
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

	engine := policy.New(home, workdir,
		append(policy.DefaultAllows(), allow...),
		append(policy.DefaultDenies(home), deny...))

	asker, err := newAsker(ask, timeout)
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
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func newAsker(mode string, timeout time.Duration) (ui.Asker, error) {
	switch mode {
	case "deny":
		return ui.AutoDeny{}, nil
	case "desktop":
		return ui.NewDesktop(timeout)
	case "answer":
		return newSocketAsker(timeout)
	case "auto":
		if d, err := ui.NewDesktop(timeout); err == nil {
			return d, nil
		}
		return newSocketAsker(timeout)
	}
	return nil, fmt.Errorf("unknown --ask mode %q", mode)
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

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "hallpass: %v\n", err)
	return 1
}

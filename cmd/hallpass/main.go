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
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/config"
	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/launch"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/privsep"
	"github.com/alban/hallpass/internal/programs"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/tty"
	"github.com/alban/hallpass/internal/ui"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const usageText = `Usage:
  hallpass [flags] [--] [command [args...]]   run command (default: $SHELL)
  hallpass answer [PID]                       answer prompts from this terminal
  hallpass web [--listen ADDR] [--open]       follow and answer sessions in a browser (experimental)
  hallpass policy [flags]                     print the rules these flags give

In the program's terminal, press Ctrl-] to show the current rules.

Flags:
`

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	if launch.IsChild() {
		launch.ChildMain()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == privsep.HelperArg {
		os.Exit(privsep.HelperMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "answer" {
		os.Exit(answerMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "web" {
		os.Exit(webMain(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "policy" {
		os.Exit(runMain(os.Args[2:], true))
	}
	os.Exit(runMain(os.Args[1:], false))
}

// options are the flags of a run.
type options struct {
	workdir     string
	ask         string
	timeout     time.Duration
	allowUserns bool
	logPath     string
	mode        string
	escalate    string
	noImplicit  bool
	allowTTY    bool
	wait        string
	// policy is the policy the flags give (--allow, --deny, --mediate,
	// --allow-net...).
	policy policy.Policy
	// deny is denied on top of policy: hallpass's own config and binary.
	deny []string
	args []string // command to run
}

// flagNames are the flags filling the fields of a policy.Spec.
var flagNames = map[string]string{
	"allow":        "--allow",
	"deny":         "--deny",
	"askTimeout":   "--timeout",
	"mediate":      "--mediate",
	"allowNetwork": "--allow-net",
	"denyNetwork":  "--deny-net",
	"askNetwork":   "--ask-net",
	"allowExec":    "--allow-exec",
	"denyExec":     "--deny-exec",
	"groups":       "--group",
}

// parseFlags parses and checks argv. When it returns ok == false, the run
// ends with exit code code.
func parseFlags(argv []string, printPolicy bool) (o options, code int, ok bool) {
	fs := flag.NewFlagSet("hallpass", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	var allow, deny listFlag
	fs.StringVar(&o.workdir, "C", "", "project `dir`, writable without asking (default: current directory)")
	fs.StringVar(&o.workdir, "workdir", "", "same as -C")
	fs.Var(&allow, "allow", "`path` also writable without asking (repeatable)")
	fs.Var(&deny, "deny", "`path` always denied (repeatable, wins over --allow)")
	fs.BoolVar(&o.noImplicit, "no-implicit", false, "allowed without asking: only the --allow paths and --allow-exec programs (no project dir, $TMPDIR, devices, terminal or implicit program groups; the command still runs)")
	fs.BoolVar(&o.allowTTY, "allow-tty", true, "the session's own terminal (/dev/tty, its /dev/pts/N) is writable without asking; --no-implicit turns it off unless given explicitly")
	fs.StringVar(&o.ask, "ask", "auto", "how to ask: auto | term | desktop | answer | deny | allow (allow and log: audit)")
	fs.DurationVar(&o.timeout, "timeout", 30*time.Second, "deny unanswered prompts after `duration` (0: wait forever)")
	fs.BoolVar(&o.allowUserns, "allow-userns", false, "let the sandbox create user/mount namespaces (weakens lite mode; always on in strict mode)")
	fs.StringVar(&o.logPath, "log", "", "append one JSON line per mediated syscall to `file`")
	fs.StringVar(&o.mode, "mode", "lite", "lite (seccomp only, no root needed) | strict (the kernel enforces the answers with BPF-LSM; root needed to load it)")
	fs.StringVar(&o.escalate, "escalate", "", "strict mode, when not root: how to run the loader as root: "+strings.Join(privsep.Tools, " | ")+" (default: the saved choice, else ask on a terminal, else auto)")
	fs.StringVar(&o.wait, "wait", "main", "exit when the main process exits (main), or keep supervising its background processes until they all exit (all)")
	mediate := fs.String("mediate", seccomp.DefaultCategories.String(), "comma-separated `categories` of syscalls to mediate: files, exec, network (network is experimental)")
	var allowNet, denyNet, askNet listFlag
	fs.Var(&allowNet, "allow-net", "network `destination` allowed without asking (repeatable; needs --mediate with network): all, [tcp:|udp:]ADDR[/N][:PORT[-PORT]] (ADDR * for any, IPv6 in brackets), unix:/path, unix:/dir/**, unix:@name, unix:@prefix*")
	fs.Var(&denyNet, "deny-net", "network `destination` always denied (repeatable, same syntax, wins over --allow-net)")
	fs.Var(&askNet, "ask-net", "network `destination` asked about even inside a less specific --allow-net (repeatable, same syntax; a more specific --allow-net still allows)")
	var allowExec, denyExec listFlag
	fs.Var(&allowExec, "allow-exec", "`program` allowed to run without asking (repeatable, comma-separated): a name looked up in $PATH, a path, dir/** for every program below dir, or a group of programs: "+strings.Join(programs.Names(), ", "))
	fs.Var(&denyExec, "deny-exec", "`program` never allowed to run (repeatable, comma-separated, same syntax but no groups, wins over --allow-exec)")
	var groupFlags listFlag
	fs.Var(&groupFlags, "group", "`@name=program,...`: a group of programs, offered in prompts and allowed by --allow-exec=@name (repeatable; programs as in --allow-exec, without groups); replaces the built-in group of the same name")
	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return o, 0, false
		}
		return o, 2, false
	}
	var err error
	spec := o.spec(allow, deny, *mediate, allowNet, denyNet, askNet)
	spec.AllowExec, spec.DenyExec = programPaths(allowExec), programPaths(denyExec)
	if spec.Groups, err = groupSpecs(groupFlags); err != nil {
		return o, fail(err), false
	}
	if o.policy, err = spec.Validate(); err != nil {
		var fe *policy.FieldError
		if errors.As(err, &fe) {
			fe.Field = flagNames[fe.Field]
		}
		return o, fail(err), false
	}
	if o.noImplicit {
		explicit := false
		fs.Visit(func(f *flag.Flag) { explicit = explicit || f.Name == "allow-tty" })
		if !explicit {
			o.allowTTY = false
		}
	}
	if o.wait != "main" && o.wait != "all" {
		return o, fail(fmt.Errorf("unknown --wait %q (want main or all)", o.wait)), false
	}
	if o.wait == "all" && !printPolicy && !kernelAtLeast(5, 9) {
		return o, fail(errors.New("--wait=all needs Linux 5.9 or later (POLLHUP on the seccomp notify fd)")), false
	}
	o.args = fs.Args()
	if len(o.args) == 0 {
		sh := os.Getenv("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		o.args = []string{sh}
	}
	return o, 0, true
}

// spec is the policy.Spec of the flags. Relative --allow and --deny paths
// are relative to the current directory.
func (o *options) spec(allow, deny []string, mediate string, allowNet, denyNet, askNet []string) policy.Spec {
	abs := func(l []string) []string {
		out := make([]string, 0, len(l))
		for _, p := range l {
			if a, err := filepath.Abs(p); err == nil {
				p = a
			}
			out = append(out, p)
		}
		return out
	}
	ask := o.ask != "deny"
	return policy.Spec{
		Allow:        abs(allow),
		Deny:         abs(deny),
		Ask:          &ask,
		AskTimeout:   o.timeout.String(),
		Mediate:      strings.Split(mediate, ","),
		AllowNetwork: allowNet,
		DenyNetwork:  denyNet,
		AskNetwork:   askNet,
	}
}

// programPaths turns --allow-exec and --deny-exec values, each a
// comma-separated list, into absolute paths: a name without a slash is
// looked up in $PATH (kept as is when it is not found, for Validate to
// refuse), a relative path is relative to the current directory, a
// @group is kept as is.
func programPaths(l []string) []string {
	out := make([]string, 0, len(l))
	for _, v := range l {
		for _, p := range strings.Split(v, ",") {
			if p == "" {
				continue
			}
			if !strings.Contains(p, "/") && !strings.HasPrefix(p, "@") {
				if lp, err := exec.LookPath(p); err == nil {
					p = lp
				}
			}
			if strings.Contains(p, "/") {
				if a, err := filepath.Abs(p); err == nil {
					p = a
				}
			}
			out = append(out, p)
		}
	}
	return out
}

// groupSpecs turns --group values, "@name=program,...", into a policy's
// groups; the programs as with programPaths. A group given twice gets
// the programs of both.
func groupSpecs(l []string) (map[string][]string, error) {
	if len(l) == 0 {
		return nil, nil
	}
	out := map[string][]string{}
	for _, v := range l {
		name, progs, ok := strings.Cut(v, "=")
		if !ok {
			return nil, fmt.Errorf("--group: %q: want @name=program,...", v)
		}
		out[name] = append(out[name], programPaths([]string{progs})...)
	}
	return out, nil
}

// runMain runs a sandboxed command, or with printPolicy prints the rules
// the same flags would give it.
func runMain(argv []string, printPolicy bool) int {
	o, code, ok := parseFlags(argv, printPolicy)
	if !ok {
		return code
	}

	cfgDir, err := config.Dir()
	if err != nil {
		return fail(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fail(err)
	}
	if err := o.resolvePaths(home, cfgDir); err != nil {
		return fail(err)
	}
	engine := o.buildPolicy(home)
	if printPolicy {
		o.printRules(engine)
		return 0
	}

	var env []string
	if !o.noImplicit {
		tmpdir, cleanup, err := privateTmpdir()
		if err != nil {
			return fail(err)
		}
		defer cleanup()
		engine.SetTmpdir(tmpdir)
		env = append(env, "TMPDIR="+tmpdir)
	}

	strict, err := o.loadStrict(cfgDir)
	if err != nil {
		return fail(err)
	}
	if strict != nil {
		defer strict.Close()
	}

	asker, pty, err := newAsker(o.ask, o.timeout)
	if err != nil {
		return fail(err)
	}
	defer asker.Close()
	if o.allowTTY {
		allowOwnTTY(engine, pty)
	}

	logw, closeLog, err := openLog(o.logPath)
	if err != nil {
		return fail(err)
	}
	defer closeLog()

	code, err = runSession(sessionConfig{
		Args:        o.args,
		Dir:         o.workdir,
		Defaults:    engine,
		Asker:       asker,
		AllowUserns: o.allowUserns,
		Log:         logw,
		TTY:         pty,
		LSM:         strict,
		Env:         env,
		WaitAll:     o.wait == "all",
		Timeout:     o.timeout,
		Mediate:     o.policy.Mediate,
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

// resolvePaths makes the workdir absolute, checks it, and adds the paths
// always denied.
func (o *options) resolvePaths(home, cfgDir string) error {
	var err error
	if o.workdir == "" {
		if o.workdir, err = os.Getwd(); err != nil {
			return err
		}
	}
	if o.workdir, err = filepath.Abs(o.workdir); err != nil {
		return err
	}
	if st, err := os.Stat(o.workdir); err != nil || !st.IsDir() {
		return fmt.Errorf("workdir %s: not a directory", o.workdir)
	}
	if filepath.Clean(o.workdir) == filepath.Clean(home) || o.workdir == "/" {
		if !o.noImplicit {
			return fmt.Errorf("refusing to use %s as the workdir: everything under it would be writable", o.workdir)
		}
	}

	// The sandbox must not change what hallpass runs next time, outside it.
	o.deny = append(o.deny, cfgDir)
	// Nor overwrite the hallpass binary itself: a later strict run would
	// execute the tampered copy as root, and any run would execute
	// unsandboxing code. Deny it like the config, even when it sits inside
	// the workdir (e.g. go build ./cmd/hallpass).
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		o.deny = append(o.deny, exe)
	}
	return nil
}

// buildPolicy returns the rules of o, before the session's own $TMPDIR and
// terminal are known.
func (o *options) buildPolicy(home string) *defaults.Defaults {
	c := policy.Context{Home: home, Deny: o.deny}
	if o.policy.Mediate&seccomp.Exec != 0 {
		// The command is named on the command line: it is explicit, kept
		// with --no-implicit. Groups are allowed by --allow-exec=@name, a
		// "group" answer, or implicitly (programs.Implicit).
		c.Execs = lookPrograms(o.workdir, o.args[:1])
		c.Groups = programs.Finder{Path: os.Getenv("PATH"), Resolve: filepath.EvalSymlinks}.Groups(o.policy.GroupDefs())
	}
	if !o.noImplicit {
		c.Workdir = o.workdir
		c.Allow = defaults.DefaultAllows()
		c.OwnListeners = o.policy.Mediate&seccomp.Network != 0
		if o.policy.Mediate&seccomp.Exec != 0 {
			c.AllowGroups = programs.Implicit()
		}
	}
	return o.policy.Defaults(c)
}

// lookPrograms returns the absolute paths of the programs names, as the
// sandbox finds them: names without a slash in $PATH, relative paths
// from dir. Programs not found are left out.
func lookPrograms(dir string, names []string) []string {
	var out []string
	for _, n := range names {
		p := n
		if !strings.Contains(n, "/") {
			var err error
			if p, err = exec.LookPath(n); err != nil {
				continue
			}
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		out = append(out, p)
	}
	return out
}

// printRules prints engine's rules, with placeholders for the $TMPDIR and
// terminal a run would get.
func (o *options) printRules(engine *defaults.Defaults) {
	if !o.noImplicit {
		engine.SetTmpdir(filepath.Join(os.TempDir(), "hallpass-*"))
	}
	if o.allowTTY {
		for _, p := range defaults.TTYAllows("/dev/pts/N") {
			engine.AllowDevice(p)
		}
	}
	// What a session would add when it starts.
	rs := append(engine.Rules(), protectedRules(o.policy.Mediate, sessionapi.SocketDir(), sessionapi.ProtectedPorts())...)
	for _, l := range engine.Describe(rs) {
		fmt.Println(l)
	}
}

// privateTmpdir creates a private $TMPDIR, so tools that honour it (mktemp,
// compilers, ...) work without asking and without sharing /tmp. cleanup
// removes it if empty.
func privateTmpdir() (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "hallpass-")
	if err != nil {
		return "", nil, err
	}
	return dir, func() {
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "hallpass: kept %s: not empty\n", dir)
		}
	}, nil
}

// loadStrict loads the BPF-LSM programs in strict mode; nil in lite mode.
func (o *options) loadStrict(cfgDir string) (*lsm.LSM, error) {
	switch o.mode {
	case "lite":
		return nil, nil
	case "strict":
	default:
		return nil, fmt.Errorf("unknown --mode %q (want lite or strict)", o.mode)
	}
	// The supervisor runs as the sandbox's user: forbid it ptrace,
	// pidfd_getfd, /proc/<pid>/mem and fd access to us, before any
	// fd worth stealing exists. (Root keeps them, for the loader.)
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return nil, fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", err)
	}
	if err := lsm.Active(); err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		var err error
		if o.escalate, err = escalateTool(o.escalate, cfgDir); err != nil {
			return nil, err
		}
	}
	strict, err := privsep.Load(o.escalate, false)
	if err != nil {
		return nil, err
	}
	// The kernel enforces the rules, whatever namespaces the
	// sandbox builds (e.g. an agent working on a container runtime).
	o.allowUserns = true
	return strict, nil
}

// allowOwnTTY makes the program's own terminal writable without asking;
// other /dev/pts/N (another session) stay asked.
func allowOwnTTY(engine *defaults.Defaults, pty *tty.Term) {
	pts := ""
	if pty != nil {
		pts = pty.SlavePath()
	}
	for _, p := range defaults.TTYAllows(pts) {
		engine.AllowDevice(p)
	}
}

// openLog opens the --log file for appending; a nil writer without one.
func openLog(path string) (io.Writer, func(), error) {
	if path == "" {
		return nil, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// kernelAtLeast reports whether the running kernel is at least major.minor;
// true when the release cannot be parsed, to not refuse unknown kernels.
func kernelAtLeast(major, minor int) bool {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return true
	}
	var ma, mi int
	if _, err := fmt.Sscanf(unix.ByteSliceToString(u.Release[:]), "%d.%d", &ma, &mi); err != nil {
		return true
	}
	return ma > major || (ma == major && mi >= minor)
}

// newAsker picks how to ask. "auto" prefers the terminal overlay (works
// locally and over ssh, and keeps the question next to the agent), then the
// desktop, then `hallpass answer`.
func newAsker(mode string, timeout time.Duration) (ui.Asker, *tty.Term, error) {
	switch mode {
	case "deny":
		return ui.AutoDeny{}, nil, nil
	case "allow":
		return ui.AutoAllow{}, nil, nil
	case "term":
		return newTermAsker(timeout)
	case "desktop":
		d, err := ui.NewDesktop(timeout)
		return d, nil, err
	case "answer":
		return newRemoteAsker(timeout), nil, nil
	case "auto":
		if tty.Available() {
			return newTermAsker(timeout)
		}
		if d, err := ui.NewDesktop(timeout); err == nil {
			return d, nil, nil
		}
		return newRemoteAsker(timeout), nil, nil
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

// newRemoteAsker shows nothing: `hallpass answer` or `hallpass web` answer
// on the session socket (runSession prints how).
func newRemoteAsker(timeout time.Duration) ui.Asker {
	return ui.Remote{Timeout: timeout}
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

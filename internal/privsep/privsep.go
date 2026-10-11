// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package privsep gets strict mode's BPF programs loaded without running
// hallpass as root: a short-lived helper (hallpass itself, started through
// sudo, pkexec, ..., or by the user as root with --escalate=manual) loads and
// attaches them, hands the map and link fds to the unprivileged supervisor,
// and exits. Updating the maps afterwards only needs the fds.
//
// The fds travel over a socketpair of the supervisor. The helper is passed the
// supervisor's pid and the fd number of one end, and takes a copy of that end
// with pidfd_getfd(2): unlike inherited fds this works whatever the escalation
// tool closes (sudo closes fds >= 3, run0 starts the command from systemd),
// and no socket appears in the filesystem. pidfd_getfd needs ptrace access,
// which root has even to a non-dumpable process, unless
// kernel.yama.ptrace_scope is 3.
package privsep

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/alban/hallpass/internal/lsm"
	"golang.org/x/sys/unix"
)

// HelperArg is the first argument of the helper process.
const HelperArg = "--internal-load"

// maxFDs bounds the fds received: the maps and one link per program.
const maxFDs = 64

// Tools lists the accepted --escalate values.
var Tools = []string{"auto", "pkexec", "sudo", "run0", "doas", "su", "manual", "none"}

// Load returns strict mode's programs, loaded and attached. As root they
// are loaded in this process; otherwise through a helper started with tool.
func Load(tool string, logAllowed bool) (*lsm.LSM, error) {
	if os.Geteuid() == 0 {
		return lsm.Load(logAllowed)
	}
	if tool == "auto" {
		tool = pickTool()
	}
	if tool == "none" || tool == "" {
		return nil, errors.New("strict mode needs root to load its BPF programs: run hallpass as root or pass --escalate=sudo|pkexec|run0|doas|su|manual")
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])

	args := []string{exe, HelperArg, strconv.Itoa(os.Getpid()), strconv.Itoa(pair[1])}
	if logAllowed {
		args = append(args, "--log-allowed")
	}
	if tool == "manual" {
		fds, err := manual(args, pair[0], os.Stdin, os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("loading strict mode: %w", err)
		}
		return lsm.FromFDs(fds)
	}
	argv, err := command(tool, args)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	// The tool may ask for a password on the terminal.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("loading strict mode with %s: %w", argv[0], err)
	}
	fds, err := receive(pair[0])
	if err != nil {
		return nil, fmt.Errorf("loading strict mode with %s: %w", argv[0], err)
	}
	return lsm.FromFDs(fds)
}

// pickTool prefers pkexec in a graphical session (its prompt does not need
// the terminal), then the usual terminal tools.
func pickTool() string {
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		if _, err := exec.LookPath("pkexec"); err == nil {
			return "pkexec"
		}
	}
	for _, t := range []string{"sudo", "run0", "doas"} {
		if _, err := exec.LookPath(t); err == nil {
			return t
		}
	}
	return ""
}

// manual asks the user to run the helper as root themselves (from another
// terminal, a root shell, over ssh...), and waits for them to press Enter.
func manual(args []string, sock int, in io.Reader, out io.Writer) ([]int, error) {
	fmt.Fprintf(out, "hallpass: strict mode needs root to load its BPF programs. As root, run:\n\n    %s\n\nthen press Enter here. ", shellQuote(args))
	r := bufio.NewReader(in)
	for {
		if _, err := r.ReadString('\n'); err != nil {
			return nil, fmt.Errorf("waiting for Enter: %w", err)
		}
		fds, err := receive(sock)
		if !errors.Is(err, errNothing) {
			return fds, err
		}
		fmt.Fprint(out, "hallpass: nothing received yet; run the command above as root, then press Enter. ")
	}
}

// shellQuote quotes args for a POSIX shell.
func shellQuote(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}

// command returns the command line running args as root with tool. All
// state is in args: these tools reset the environment.
func command(tool string, args []string) ([]string, error) {
	switch tool {
	case "pkexec", "run0", "doas":
		return append([]string{tool}, args...), nil
	case "sudo":
		return append([]string{"sudo", "--"}, args...), nil
	case "su":
		return []string{"su", "-c", shellQuote(args), "root"}, nil
	}
	return nil, fmt.Errorf("unknown --escalate tool %q (want one of %s)", tool, strings.Join(Tools, ", "))
}

var errNothing = errors.New("the helper sent nothing")

// receive reads the helper's message, already queued on sock.
func receive(sock int) ([]int, error) {
	buf := make([]byte, 256)
	oob := make([]byte, unix.CmsgSpace(4*maxFDs))
	n, oobn, flags, _, err := unix.Recvmsg(sock, buf, oob, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
	if errors.Is(err, unix.EAGAIN) {
		return nil, errNothing
	}
	if err != nil {
		return nil, err
	}
	var fds []int
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for i := range scms {
		f, err := unix.ParseUnixRights(&scms[i])
		if err == nil {
			fds = append(fds, f...)
		}
	}
	if flags&unix.MSG_CTRUNC != 0 || string(buf[:n]) != "ok" {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, fmt.Errorf("bad message from the helper: %q", buf[:n])
	}
	return fds, nil
}

// HelperMain is the helper process: hallpass HelperArg PID FD [--log-allowed].
func HelperMain(args []string) int {
	if err := helper(args); err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: loading strict mode: %v\n", err)
		return 1
	}
	return 0
}

func helper(args []string) error {
	if len(args) < 2 || len(args) > 3 || (len(args) == 3 && args[2] != "--log-allowed") {
		return errors.New("usage: hallpass " + HelperArg + " PID FD [--log-allowed]")
	}
	pid, err := strconv.Atoi(args[0])
	if err != nil || pid <= 0 {
		return fmt.Errorf("bad pid %q", args[0])
	}
	fd, err := strconv.Atoi(args[1])
	if err != nil || fd < 0 {
		return fmt.Errorf("bad fd %q", args[1])
	}
	if os.Geteuid() != 0 {
		return errors.New("the helper must run as root")
	}

	// The pidfd pins the process: its pid cannot be reused while it exists,
	// so the checks below are about the process the pidfd refers to if it
	// still exists after them.
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(pidfd)
	if err := checkTarget(pid); err != nil {
		return err
	}
	sock, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("pidfd_getfd: %w (is kernel.yama.ptrace_scope 3?)", err)
		}
		return fmt.Errorf("pidfd_getfd: %w", err)
	}
	defer unix.Close(sock)
	if err := checkSocket(sock, pid); err != nil {
		return err
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return fmt.Errorf("process %d is gone: %w", pid, err)
	}

	l, err := lsm.Load(len(args) == 3)
	if err != nil {
		return err
	}
	// Exiting without Close: the supervisor's copies keep everything.
	return unix.Sendmsg(sock, []byte("ok"), unix.UnixRights(l.FDs()...), nil, 0)
}

// checkTarget makes sure pid is a hallpass run by the user who invoked the
// escalation tool, when the tool says who that is.
func checkTarget(pid int) error {
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	exe, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return err
	}
	if !os.SameFile(self, exe) {
		return fmt.Errorf("process %d is not running this hallpass binary", pid)
	}
	want, ok := invoker()
	if !ok {
		return nil
	}
	got, err := realUID(pid)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("process %d belongs to uid %d, not to the invoking user (uid %d)", pid, got, want)
	}
	return nil
}

// invoker returns the uid of the user who ran the escalation tool.
func invoker() (int, bool) {
	for _, v := range []string{"PKEXEC_UID", "SUDO_UID"} { // run0 sets SUDO_UID too
		if s := os.Getenv(v); s != "" {
			if uid, err := strconv.Atoi(s); err == nil {
				return uid, true
			}
		}
	}
	if name := os.Getenv("DOAS_USER"); name != "" {
		if u, err := user.Lookup(name); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil {
				return uid, true
			}
		}
	}
	return 0, false
}

func realUID(pid int) (int, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "Uid:" {
			return strconv.Atoi(f[1])
		}
	}
	return 0, fmt.Errorf("no Uid in /proc/%d/status", pid)
}

// checkSocket makes sure sock is an end of a socketpair created by pid.
func checkSocket(sock, pid int) error {
	if d, err := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_DOMAIN); err != nil || d != unix.AF_UNIX {
		return errors.New("fd is not a unix socket")
	}
	if t, err := unix.GetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_TYPE); err != nil || t != unix.SOCK_SEQPACKET {
		return errors.New("fd is not a SOCK_SEQPACKET socket")
	}
	cred, err := unix.GetsockoptUcred(sock, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return err
	}
	if int(cred.Pid) != pid {
		return fmt.Errorf("socket peer is pid %d, not %d", cred.Pid, pid)
	}
	return nil
}

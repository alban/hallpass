// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package launch is hallpass's local launcher: it starts a command with the
// seccomp filter installed, paused before its exec until the caller has
// attached the filter's listener to a monitor.
//
// hallpass re-executes itself as a small child stub (ChildMain) that
// installs the filter, hands the listener fd back over a socketpair, waits
// for the go byte, and execs the real command.
package launch

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// Environment variables used to pass state to the re-executed child stub.
const (
	childEnvSentinel = "_HALLPASS_CHILD"
	childEnvFD       = "_HALLPASS_SOCK_FD"
	childEnvUserns   = "_HALLPASS_ALLOW_USERNS"
	childEnvMediate  = "_HALLPASS_MEDIATE"
)

// ProcSpec describes the command to start.
type ProcSpec struct {
	Args []string // argv[0] is looked up in PATH
	Dir  string
	Env  []string
	// Files are the child's fds 0, 1, 2, ...; Setsid/Setctty as in
	// syscall.SysProcAttr (the TTY case, with fd 0 as the terminal).
	Files   []*os.File
	Setsid  bool
	Setctty bool
	// Whether new user and mount namespaces are allowed (lite mode
	// refuses them, see seccomp.Rules).
	AllowUserns bool
	// Mediate is the syscall categories notified (--mediate); 0:
	// seccomp.DefaultCategories.
	Mediate seccomp.Category
}

// Start starts spec paused before its first exec, with the seccomp filter
// installed. The caller attaches seccompFD and proc.Pid to a monitor, then
// calls release to let the child exec. The caller owns waiting for proc.
// When the child fails to set up the filter, Start returns an error with
// proc still set, to be waited for: the child printed why.
func Start(spec ProcSpec) (proc *os.Process, seccompFD int, release func() error, err error) {
	if len(spec.Files) < 3 {
		return nil, -1, nil, errors.New("launch: Files must have at least stdin, stdout and stderr")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, -1, nil, fmt.Errorf("socketpair: %w", err)
	}
	parentSock := pair[0]
	childSock := os.NewFile(uintptr(pair[1]), "hallpass-child-sock")
	defer childSock.Close()

	cmd := exec.Command("/proc/self/exe", append([]string{"--"}, spec.Args...)...)
	cmd.Args[0] = "hallpass-child"
	cmd.Dir = spec.Dir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = spec.Files[0], spec.Files[1], spec.Files[2]
	cmd.ExtraFiles = append(append([]*os.File{}, spec.Files[3:]...), childSock)
	if spec.Setsid || spec.Setctty {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: spec.Setsid, Setctty: spec.Setctty, Ctty: 0}
	}
	cmd.Env = append(append([]string{}, spec.Env...),
		childEnvSentinel+"=1",
		childEnvFD+"="+strconv.Itoa(len(spec.Files)),
	)
	if spec.AllowUserns {
		cmd.Env = append(cmd.Env, childEnvUserns+"=1")
	}
	if spec.Mediate == 0 {
		spec.Mediate = seccomp.DefaultCategories
	}
	cmd.Env = append(cmd.Env, childEnvMediate+"="+spec.Mediate.String())
	if err := cmd.Start(); err != nil {
		unix.Close(parentSock)
		return nil, -1, nil, err
	}
	childSock.Close()

	fd, err := recvFD(parentSock)
	if err != nil {
		unix.Close(parentSock)
		return cmd.Process, -1, nil, errors.New("sandbox setup failed")
	}
	unix.SetNonblock(fd, false)
	release = func() error {
		defer unix.Close(parentSock)
		if _, err := unix.Write(parentSock, []byte{1}); err != nil {
			return fmt.Errorf("release the sandbox: %w", err)
		}
		return nil
	}
	return cmd.Process, fd, release, nil
}

// IsChild reports whether this process is the re-executed child stub.
func IsChild() bool { return os.Getenv(childEnvSentinel) != "" }

func init() {
	// Strict mode marks the child by pid, which is its thread group leader:
	// exec from the main thread so the task that runs the command is the
	// one marked (an exec from another thread would take over the leader's
	// pid with an unmarked task). Package init runs on the main thread.
	if IsChild() {
		runtime.LockOSThread()
	}
}

// ChildMain is the entry point for the re-executed child. It must run before
// the Go runtime starts extra work on behalf of the program. It never returns
// on success: it execs the target command.
func ChildMain() {
	fdStr := os.Getenv(childEnvFD)
	fd, err := strconv.Atoi(fdStr)
	if err != nil {
		fatal("child: bad %s=%q", childEnvFD, fdStr)
	}

	// argv for the real command follows "--".
	args := childArgs()
	if len(args) == 0 {
		fatal("child: no command")
	}

	exe, err := exec.LookPath(args[0])
	if err != nil {
		fatal("child: %v", err)
	}

	cats, err := seccomp.ParseCategories(os.Getenv(childEnvMediate))
	if err != nil || cats == 0 {
		fatal("child: bad %s=%q", childEnvMediate, os.Getenv(childEnvMediate))
	}

	// From here on, stay on one OS thread: install the filter and exec from
	// the same thread so the per-thread filter survives into the new image.
	seccomp.LockThread()

	listenerFD, err := seccomp.Install(seccomp.Select(seccomp.Rules(os.Getenv(childEnvUserns) == "1"), cats))
	if err != nil {
		fatal("child: install filter: %v", err)
	}

	if err := sendFD(fd, listenerFD); err != nil {
		fatal("child: send listener fd: %v", err)
	}
	_ = unix.Close(listenerFD)
	// Exec only once the parent has attached the listener (and, in strict
	// mode, made us a member).
	var b [1]byte
	if n, err := unix.Read(fd, b[:]); n != 1 || err != nil {
		fatal("child: the supervisor did not start the sandbox")
	}
	_ = unix.Close(fd)

	// Scrub our bookkeeping from the environment before exec.
	env := cleanEnv()
	if err := unix.Exec(exe, args, env); err != nil {
		fatal("child: exec %s: %v", exe, err)
	}
}

// childArgs returns the target command, which follows the first "--".
func childArgs() []string {
	for i, a := range os.Args {
		if a == "--" {
			return os.Args[i+1:]
		}
	}
	return nil
}

// cleanEnv drops hallpass's private variables before exec.
func cleanEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "_HALLPASS_") {
			continue
		}
		env = append(env, kv)
	}
	return env
}

// sendFD passes a single fd over a unix socket using SCM_RIGHTS.
func sendFD(sock, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(sock, []byte{0}, rights, nil, 0)
}

// recvFD receives a single fd sent with SCM_RIGHTS.
func recvFD(sock int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
	if err != nil {
		return -1, err
	}
	scms, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}
	if len(scms) == 0 {
		return -1, fmt.Errorf("no control message")
	}
	fds, err := unix.ParseUnixRights(&scms[0])
	if err != nil {
		return -1, err
	}
	if len(fds) == 0 {
		return -1, fmt.Errorf("no fd in control message")
	}
	return fds[0], nil
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "hallpass: "+format+"\n", a...)
	os.Exit(127)
}

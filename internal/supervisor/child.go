// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package supervisor runs the sandboxed child and mediates its intercepted
// syscalls. In lite mode hallpass re-executes itself as a small child stub
// (ChildMain) that installs the seccomp filter, hands the resulting listener fd
// back to the parent over a socketpair, and execs the real target. The parent
// then runs the notification loop.
package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// Environment variables used to pass state to the re-executed child stub.
const (
	childEnvSentinel = "_HALLPASS_CHILD"
	childEnvFD       = "_HALLPASS_SOCK_FD"
	childEnvUserns   = "_HALLPASS_ALLOW_USERNS"
	childEnvWait     = "_HALLPASS_WAIT"
)

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

	// From here on, stay on one OS thread: install the filter and exec from
	// the same thread so the per-thread filter survives into the new image.
	seccomp.LockThread()

	listenerFD, err := seccomp.Install(seccomp.Rules(os.Getenv(childEnvUserns) == "1"))
	if err != nil {
		fatal("child: install filter: %v", err)
	}

	if err := sendFD(fd, listenerFD); err != nil {
		fatal("child: send listener fd: %v", err)
	}
	_ = unix.Close(listenerFD)
	if os.Getenv(childEnvWait) == "1" {
		// Strict mode: exec only once the supervisor has made us a member.
		var b [1]byte
		if n, err := unix.Read(fd, b[:]); n != 1 || err != nil {
			fatal("child: the supervisor did not start the sandbox")
		}
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

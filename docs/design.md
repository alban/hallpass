# How it works

hallpass wraps a command and puts it, and everything it starts, under a sandbox. Writes inside the project directory go through without asking; writes anywhere else are mediated. It combines two kernel mechanisms, one per mode.

## Why from the kernel

Any program you run can write wherever your user can. Some have their own permission prompts and sandboxes, such as AI agent CLIs, but those are enforced by the program itself and configured by files it can often write. hallpass is enforced by the kernel, from outside the program, so it does not depend on the program being well-behaved. It complements the program's own controls rather than replacing them.

## Security model

hallpass is a proof of concept. It is meant to catch **honest mistakes**: a wrong path, an overeager install script, a command run in the wrong directory, by the program or anything it starts, even when the program skips its own prompts.

What it protects:

- Writes outside the project, in both modes: paused and asked, or denied by your rules. The sandbox cannot change hallpass itself (its binary and config are denied), nor answer its own prompts: it cannot see the terminal prompt, and the session socket refuses sandboxed clients.
- In strict mode, also against a process that deliberately races the check (TOCTOU), or hides the target behind symlinks, bind mounts or other mount namespaces: the kernel checks the real file.

What it does not protect:

- Reads: a program can read your secrets, and send them away (the network is not mediated by default).
- Writes done for the sandbox by a service outside it (`systemd-run --user`, a container daemon, D-Bus): `connect` is only mediated with the experimental `--mediate=...,network`. Running a client of such a service (`systemd-run`, `docker`) is asked about, but programs are matched by path only (see [Programs](#programs)), and a process can talk to the service without its client. This is why hallpass does not contain a hostile program today.
- Permissions, owners, extended attributes and timestamps.
- In lite mode, a deliberate TOCTOU race.
- Your answers: an `always` on a broad folder allows everything under it. The `by:` line of a prompt is set by the process and proves nothing.

The details are in [Limitations](#limitations).

## Lite mode: seccomp user notification

Lite mode is unprivileged. A seccomp filter pauses the syscalls that modify the filesystem — write-intent `open`, create, delete, rename, link, `truncate`, `mknod` — and hands them to the hallpass supervisor through a notification file descriptor. The supervisor resolves the path, applies the policy and, if needed, asks you. Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

This is what lets hallpass *ask* instead of just failing the call. It is best effort: because the allowed syscall is re-executed by the kernel, a malicious multi-threaded process can change the path between the check and the kernel acting on it (a TOCTOU race). Strict mode closes that.

In practice lite mode is still useful, because that gap only matters against a process *deliberately* racing the check. Most escapes are accidents — a wrong path, an overeager script, a command run in the wrong directory — not adversarial races, and lite mode catches those reliably. Strict mode closes the TOCTOU race so filesystem enforcement also holds against a deliberate racer.

Neither mode contains a hostile agent today: programs are matched by path only, and `connect` is not mediated by default, so a sandboxed process can still ask a service outside the sandbox (`systemd-run --user`, a container daemon, the systemd or D-Bus socket) to write for it. See [Limitations](#limitations).

## Strict mode: BPF-LSM

Strict mode builds on lite mode rather than replacing it: the seccomp supervisor still pauses writes and asks you interactively, and the workload waits for your answer. The BPF-LSM program is an added enforcement layer, not a silent pre-configured policy.

Strict mode exists to close the TOCTOU race that lite mode is inherently exposed to. With seccomp user notification the kernel re-executes the *allowed* syscall after the supervisor's check, resolving the path a second time. A malicious multi-threaded process can swap what the path points at in that window, so the file the supervisor approved is not the file the kernel acts on. No seccomp-based tool can fully close this; the check and the action are two separate steps.

<video src="../assets/demos/strict.mp4" poster="../assets/demos/strict.png" controls muted playsinline aria-label="a racer flips one byte of a path between a project file and ~/.bashrc while it opens it: it writes to ~/.bashrc under lite mode, and never under strict mode"></video>

*A process flips one byte of the path it opens, between a file in the project and `~/.bashrc`. Lite mode lets the write through in under a second; strict mode never does ([source](https://github.com/alban/hallpass/blob/main/demos/strict/race/main.go)).*

Strict mode adds an eBPF program on the kernel's LSM hooks, which run at the moment of the action, on the real file (inode) the kernel is about to modify — after any symlink, bind mount, mount-namespace or rename trick has already been resolved. There is no second resolution to race, so the same bypasses that defeat lite mode (symlink races, bind mounts, other mount namespaces) do not apply. `io_uring`, which performs I/O without the syscalls seccomp sees, is refused in both modes (`io_uring_setup` fails with `EPERM`). Your answers to the prompts are pushed to the kernel before the paused syscall continues, so the enforcement and the question stay in sync.

Overlayfs is the exception: it writes to its lower and upper layers with the kernel's internal calls (copy-up, create, unlink, rename), which skip the path hooks. An overlay mounted by a sandboxed process with a protected directory as its upper layer would write there unchecked, so the LSM denies sandboxed processes mounting overlayfs; fuse-overlayfs, which goes through the normal hooks, still works. Overlays set up outside the sandbox, such as a container's root, are used normally: the files opened through the overlay are checked, and the layer accesses behind them are not checked a second time.

Only loading the BPF programs needs root. hallpass starts a short-lived copy of itself as root, which loads and attaches the programs, hands their file descriptors back to the unprivileged supervisor and exits. The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it. See [Strict mode](workstation/strict.md) for how the root step is run.

## Network (experimental)

With `--mediate=files,exec,network` (or `mediate` in a [HallpassPolicy](kubernetes/policies.md)), connections and sends to an address are mediated like writes. Destinations are IPv4/IPv6 addresses and ports (TCP, UDP), unix socket files and abstract unix names; IPv4-mapped IPv6 addresses are shown and matched as IPv4. Names are not shown: there is no DNS mediation.

- Lite mode pauses `connect`, `sendto` with an address, `sendmsg` and `sendmmsg` (a message with no address continues at once; `MSG_FASTOPEN` counts as a connection). The supervisor reads the address from the process's memory, so a racing thread can change it after the check (TOCTOU), as with paths.
- Strict mode adds the LSM hooks `socket_connect` and `socket_sendmsg`, which see the address the kernel copied, and `unix_stream_connect` and `unix_may_send`, which see the peer socket: a unix socket file is matched by inode, whatever path reached it. The question is still asked at seccomp time; a "once" answer becomes a one-shot grant for that thread.

The only destination allowed without asking is a loopback or unix listener started inside the sandbox, such as a test server. Lite mode finds the listener's owner with `NETLINK_SOCK_DIAG` and the sandboxed processes' file descriptors (racy); strict mode records the listeners sandboxed processes create, and forgets them when the socket is freed.

## Programs

With `exec` in `--mediate` (the default, also in a [HallpassPolicy](kubernetes/policies.md)), running a program is mediated like a write: a program no rule allows is asked about. Only the command given to hallpass is allowed by default; groups of common programs (`@shells`, `@coreutils`, `@search`, `@git`, `@busybox`, or groups of your own, `--group` or a policy's `groups`) are allowed by name, or from a prompt about one of their programs. See [Programs](workstation/usage.md#programs) for the rules and answers.

- Lite mode pauses `execve` and `execveat` (already paused to add new processes to the session in strict mode). The supervisor reads the path from the process's memory, resolves it like a write's (symlinks followed, in the process's root and working directory), and reads the `#!` line of a script, and of its interpreter, as the kernel does: the script and each interpreter must be allowed. A denied exec fails with `EACCES`. A path that is not an executable file is let through: the kernel fails it, as when a shell tries each `$PATH` directory.
- Strict mode adds the LSM hook `bprm_check_security`, which the kernel calls with the file it is about to execute: the program, then each `#!` interpreter or `binfmt_misc` handler. The rule is matched on that file, whatever path, symlink or bind mount reached it, so swapping the path after the check does not help. The question is still asked at seccomp time; a "once" answer becomes a one-shot grant for the files of that `execve`.

Exec rules are about which programs start, not what they do: an allowed interpreter runs any code it is given (`python3 -c`, `bash -c`, `node -e`), the dynamic loader runs any program it is given (`ld.so /path/to/program`), and a copy of a program under an allowed path runs. They make an agent's use of an unexpected tool visible, they do not contain it. Rules on the arguments are planned.

## Prompts

Prompts are designed not to overwhelm you: one question at a time, concurrent requests of a process for the same path coalesced, and pending requests settled by a new rule. See [Answers and rules](answers/index.md#prompts-that-dont-flood-you).

## Limitations

hallpass is a proof of concept. It mediates filesystem writes and the programs run
(by path only), and mediates `connect` only when network mediation is enabled. By default, a sandboxed process can therefore reach
a service that acts on its behalf *outside* the sandbox, and so write anywhere
that service can, without a prompt. For example `systemd-run --user`, or
`docker`/`podman run` talking to a daemon, or a process connecting directly to
the systemd or D-Bus session socket. Running those clients is asked about, but
an allowed interpreter can connect to the socket itself. Network mediation asks about those
connections, but an `always` on such a socket allows the escape again;
treat the current build as "ask me about
honest mistakes", not "contain a hostile agent".

Program mediation, in both modes:

- An allowed interpreter (`python3`, `node`, a shell) runs any code it is given, and the dynamic loader (`ld.so /path/to/program`) runs a program without executing it.
- A program copied or downloaded to a path an allow covers runs. The project directory is writable, not executable by default.
- When several commands are one binary (busybox, uutils coreutils), installed as symlinks, allowing one allows all: rules match the resolved path, and telling the commands apart needs `argv[0]`. Hard links and copies have paths of their own.
- A program run from a file descriptor (`execveat` with `AT_EMPTY_PATH`, for example a `memfd`) gives lite mode no path to read: it asks about it as an unknown path ("once" only). Strict mode matches the rules on the file the descriptor is open on, without asking, and always denies a file with no path at all (a `memfd`).
- `binfmt_misc` handlers (qemu, Wine) are not seen by lite mode, which only reads `#!` lines: they run. Strict mode checks them in the kernel but never asks about them: they need an allow rule.
- In Kubernetes, the container's command (its `args[0]`) is allowed for good, with any arguments and any number of times.

Network mediation, in both modes:

- Sockets inherited from outside the sandbox, or received with `SCM_RIGHTS`, are already connected: their traffic is not asked about.
- Only IPv4, IPv6 and unix sockets are mediated; other families (netlink, packet, vsock...) are not.
- A UDP socket bound inside the sandbox is not a listener: sending to it is asked.
- Answers cover one destination; there are no answers for a subnet or a folder of sockets yet (use `--allow-net`).

In both modes, only writes and program executions are mediated: reading files, secrets included, is not restricted. `chmod`, `chown`, extended attributes and timestamps are not mediated yet.

### Lite mode

Lite mode is best effort:

- Only writes (write-intent `open`, create, delete, rename, link, `truncate`, `mknod`) and program executions are mediated.
- Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so a malicious multi-threaded process can change the path between the check and the kernel acting on it (TOCTOU). Strict mode (BPF-LSM) closes this.
- `openat2` passes its flags in memory (`struct open_how`), which the seccomp filter cannot read: every `openat2` reaches hallpass, which reads the flags and lets the read-only ones through. A malicious process can change the flags after the check, as it can change the path. Strict mode closes this too.
- Pre-existing hard links to protected files are not detected.
- Programs: the path is read from memory after the check (TOCTOU), as for writes, and the `binfmt_misc` handlers the kernel runs for other formats (qemu, Wine) are not checked.
- Network: the destination address is read from memory after the check (TOCTOU), and a listener inherited from outside the sandbox counts as started inside it.

### Strict mode

- The supervisor holds writable fds of the BPF maps, so the user running hallpass can put any process, including other users', under the policy or under signal protection. Choosing an escalation tool is the administrator's consent to that.
- If the supervisor dies, the programs are detached. Seccomp then fails the sandbox's mediated syscalls closed, but nothing else is enforced on processes left behind.
- When the helper runs without a recognised escalation tool in its environment (`--escalate=manual`, or `su`, which clears `SUDO_UID`/`PKEXEC_UID`/`DOAS_USER`), it cannot tell which user invoked it and only checks that the target runs the same hallpass binary.
- `kernel.yama.ptrace_scope=3` prevents the helper from fetching the socket (`pidfd_getfd`); run hallpass as root instead.
- Sandboxed processes cannot mount overlayfs (for example rootless podman or buildah with the native overlay driver): overlayfs writes to its layers without going through the hooks hallpass checks. fuse-overlayfs works.
- Network: listeners created before the BPF programs were loaded are not known as started inside the sandbox, and their connections are asked about. A one-shot grant holds a few destinations per thread.
- Programs: the `binfmt_misc` handlers are checked like `#!` interpreters, but not asked about at seccomp time: they need an allow.

### Kubernetes

See [Kubernetes limitations](kubernetes/index.md#limitations).

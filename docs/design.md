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

- Reads: a program can read your secrets, and send them away (the network is not mediated).
- Writes done for the sandbox by a service outside it (`systemd-run --user`, a container daemon, D-Bus): `connect` and `execve` are not mediated yet. This is why hallpass does not contain a hostile program today.
- Permissions, owners, extended attributes and timestamps.
- In lite mode, a deliberate TOCTOU race.
- Your answers: an `always` on a broad folder allows everything under it. The `by:` line of a prompt is set by the process and proves nothing.

The details are in [Limitations](#limitations).

## Lite mode: seccomp user notification

Lite mode is unprivileged. A seccomp filter pauses the syscalls that modify the filesystem — write-intent `open`, create, delete, rename, link, `truncate`, `mknod` — and hands them to the hallpass supervisor through a notification file descriptor. The supervisor resolves the path, applies the policy and, if needed, asks you. Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

This is what lets hallpass *ask* instead of just failing the call. It is best effort: because the allowed syscall is re-executed by the kernel, a malicious multi-threaded process can change the path between the check and the kernel acting on it (a TOCTOU race). Strict mode closes that.

In practice lite mode is still useful, because that gap only matters against a process *deliberately* racing the check. Most escapes are accidents — a wrong path, an overeager script, a command run in the wrong directory — not adversarial races, and lite mode catches those reliably. Strict mode closes the TOCTOU race so filesystem enforcement also holds against a deliberate racer.

Neither mode contains a hostile agent today: `execve` and `connect` are not mediated, so a sandboxed process can still ask a service outside the sandbox (`systemd-run --user`, a container daemon, the systemd or D-Bus socket) to write for it. See [Limitations](#limitations).

## Strict mode: BPF-LSM

Strict mode builds on lite mode rather than replacing it: the seccomp supervisor still pauses writes and asks you interactively, and the workload waits for your answer. The BPF-LSM program is an added enforcement layer, not a silent pre-configured policy.

Strict mode exists to close the TOCTOU race that lite mode is inherently exposed to. With seccomp user notification the kernel re-executes the *allowed* syscall after the supervisor's check, resolving the path a second time. A malicious multi-threaded process can swap what the path points at in that window, so the file the supervisor approved is not the file the kernel acts on. No seccomp-based tool can fully close this; the check and the action are two separate steps.

<video src="../assets/demos/strict.mp4" poster="../assets/demos/strict.png" controls muted playsinline aria-label="a racer flips one byte of a path between a project file and ~/.bashrc while it opens it: it writes to ~/.bashrc under lite mode, and never under strict mode"></video>

*A process flips one byte of the path it opens, between a file in the project and `~/.bashrc`. Lite mode lets the write through in under a second; strict mode never does ([source](https://github.com/alban/hallpass/blob/main/demos/strict/race/main.go)).*

Strict mode adds an eBPF program on the kernel's LSM hooks, which run at the moment of the action, on the real file (inode) the kernel is about to modify — after any symlink, bind mount, mount-namespace or rename trick has already been resolved. There is no second resolution to race, so the same bypasses that defeat lite mode (symlink races, bind mounts, other mount namespaces) do not apply. `io_uring`, which performs I/O without the syscalls seccomp sees, is refused in both modes (`io_uring_setup` fails with `EPERM`). Your answers to the prompts are pushed to the kernel before the paused syscall continues, so the enforcement and the question stay in sync.

Overlayfs is the exception: it writes to its lower and upper layers with the kernel's internal calls (copy-up, create, unlink, rename), which skip the path hooks. An overlay mounted by a sandboxed process with a protected directory as its upper layer would write there unchecked, so the LSM denies sandboxed processes mounting overlayfs; fuse-overlayfs, which goes through the normal hooks, still works. Overlays set up outside the sandbox, such as a container's root, are used normally: the files opened through the overlay are checked, and the layer accesses behind them are not checked a second time.

Only loading the BPF programs needs root. hallpass starts a short-lived copy of itself as root, which loads and attaches the programs, hands their file descriptors back to the unprivileged supervisor and exits. The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it. See [Strict mode](workstation/strict.md) for how the root step is run.

## Prompts

Prompts are designed not to overwhelm you: one question at a time, concurrent requests of a process for the same path coalesced, and pending requests settled by a new rule. See [Answers and rules](answers/index.md#prompts-that-dont-flood-you).

## Limitations

hallpass is a proof of concept. It mediates filesystem writes; it does not yet mediate
`execve` or `connect`, in either mode. A sandboxed process can therefore reach
a service that acts on its behalf *outside* the sandbox, and so write anywhere
that service can, without a prompt. For example `systemd-run --user`, or
`docker`/`podman run` talking to a daemon, or a process connecting directly to
the systemd or D-Bus session socket. These are trivial, known escapes until
`connect`/`execve` policy exists; treat the current build as "ask me about
honest mistakes", not "contain a hostile agent".

In both modes, only writes are mediated: reading files, secrets included, is not restricted. `chmod`, `chown`, extended attributes and timestamps are not mediated yet.

### Lite mode

Lite mode is best effort:

- Only writes are mediated (write-intent `open`, create, delete, rename, link, `truncate`, `mknod`).
- Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so a malicious multi-threaded process can change the path between the check and the kernel acting on it (TOCTOU). Strict mode (BPF-LSM) closes this.
- `openat2` passes its flags in memory (`struct open_how`), which the seccomp filter cannot read: every `openat2` reaches hallpass, which reads the flags and lets the read-only ones through. A malicious process can change the flags after the check, as it can change the path. Strict mode closes this too.
- Pre-existing hard links to protected files are not detected.
- Network and `execve` policy are not implemented yet (see above).

### Strict mode

- The supervisor holds writable fds of the BPF maps, so the user running hallpass can put any process, including other users', under the policy or under signal protection. Choosing an escalation tool is the administrator's consent to that.
- If the supervisor dies, the programs are detached. Seccomp then fails the sandbox's mediated syscalls closed, but nothing else is enforced on processes left behind.
- When the helper runs without a recognised escalation tool in its environment (`--escalate=manual`, or `su`, which clears `SUDO_UID`/`PKEXEC_UID`/`DOAS_USER`), it cannot tell which user invoked it and only checks that the target runs the same hallpass binary.
- `kernel.yama.ptrace_scope=3` prevents the helper from fetching the socket (`pidfd_getfd`); run hallpass as root instead.
- Sandboxed processes cannot mount overlayfs (for example rootless podman or buildah with the native overlay driver): overlayfs writes to its layers without going through the hooks hallpass checks. fuse-overlayfs works.

### Kubernetes

See [Kubernetes limitations](kubernetes/index.md#limitations).

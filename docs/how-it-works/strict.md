# Strict mode: BPF-LSM

Strict mode builds on [lite mode](lite.md) rather than replacing it: the seccomp supervisor still pauses writes and asks you interactively, and the workload waits for your answer. The BPF-LSM programs are an added enforcement layer, not a silent pre-configured policy. To run it, see [Strict mode](../workstation/strict.md) on a workstation, or [Strict mode](../kubernetes/install.md#strict-mode) in Kubernetes.

## Why: TOCTOU

Strict mode exists to close the TOCTOU race that lite mode is inherently exposed to. With seccomp user notification the kernel re-executes the *allowed* syscall after the supervisor's check, resolving the path a second time. A malicious multi-threaded process can swap what the path points at in that window, so the file the supervisor approved is not the file the kernel acts on. No seccomp-based tool can fully close this; the check and the action are two separate steps.

<video src="../../assets/demos/strict.mp4" poster="../../assets/demos/strict.png" controls muted playsinline aria-label="a racer flips one byte of a path between a project file and ~/.bashrc while it opens it: it writes to ~/.bashrc under lite mode, and never under strict mode"></video>

*A process flips one byte of the path it opens, between a file in the project and `~/.bashrc`. Lite mode lets the write through in under a second; strict mode never does ([source](https://github.com/alban/hallpass/blob/main/demos/strict/race/main.go)).*

## The LSM hooks

Strict mode adds eBPF programs on the kernel's LSM hooks, which run at the moment of the action, on the real file (inode) the kernel is about to modify — after any symlink, bind mount, mount-namespace or rename trick has already been resolved. There is no second resolution to race, so the same bypasses that defeat lite mode (symlink races, bind mounts, other mount namespaces) do not apply. The hooks of each category are listed in [Files](files.md), [Network](network.md) and [Programs](exec.md).

The programs only check the tasks of a sandbox (its *members*), each against the rules of its session. One set of programs serves every session of the host: in Kubernetes, every mediated container of the node.

- A file is named by its path inside its filesystem, from the filesystem's root, without crossing mounts. The supervisor translates its rules to these names with the session's `/proc/<pid>/mountinfo`, so a rule follows the files whichever bind mount or mount namespace they are reached through. It translates them again when the session's mounts change, before continuing the next syscall.
- Your answers to the prompts are pushed to the kernel before the paused syscall continues, so the enforcement and the question stay in sync. A rule (`temp`, `always`...) goes to the rule maps; a "once" answer becomes a one-shot grant for the paused thread, which the kernel drops when the syscall returns (a `sys_exit` tracepoint).
- The kernel reports its decisions to the supervisor through a ring buffer: denials, and allowed operations when they are logged.

Maps shared by all categories:

| Map | Key → value | Relation | Written by |
|---|---|---|---|
| `members` | task → its session | 1:1, per task | the supervisor, for each thread that calls `execve`, before the program runs; the BPF program (`task_alloc`), for the tasks a member creates |
| `sessions` | session → its settings: the mediated categories, and network flags and rules | 1:1 | the supervisor |
| `grants` | thread → its one-shot grant ("once" answers for the syscall it is paused in) | 1:1, per thread | the supervisor, before continuing the syscall; deleted by the BPF program when the syscall returns |
| `protected` | process → protected from signals | 1:1 | the supervisor (itself) |
| `events` | ring buffer of decisions | | the BPF programs; read by the supervisor |

The root loader creates the maps empty: it writes none of them.

## Root loader and privilege separation

Only loading the BPF programs needs root. On a workstation, hallpass starts a short-lived copy of itself as root, which loads and attaches the programs, hands the file descriptors of their maps and links back to the unprivileged supervisor, and exits. Updating the maps afterwards only needs those file descriptors.

- The root copy is started with an escalation tool (`--escalate`): `sudo`, `pkexec`, `run0` or `doas` (`auto` picks pkexec in a graphical session, else the first of sudo, run0 and doas found), `su`, or `manual`, which prints the command for you to run as root.
- It gets the supervisor's pid and the number of one end of a socketpair, and copies that end with `pidfd_getfd`, so it works whatever file descriptors the tool closes. It checks that the process runs the same hallpass binary and, when the tool says who invoked it (`SUDO_UID`, `PKEXEC_UID`, `DOAS_USER`...), that it belongs to that user.
- The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it (`task_kill`, and `file_send_sigiotask` for `SIGIO`).

In Kubernetes, `hallpass-node` already runs privileged: it loads the programs itself, and `hallpass-fd-store` keeps copies of their file descriptors across agent restarts.

## Overlayfs

Overlayfs is the exception: it writes to its lower and upper layers with the kernel's internal calls (copy-up, create, unlink, rename), which skip the path hooks. An overlay mounted by a sandboxed process with a protected directory as its upper layer would write there unchecked, so the LSM denies sandboxed processes mounting overlayfs (`sb_kern_mount`); fuse-overlayfs, which goes through the normal hooks, still works. Overlays set up outside the sandbox, such as a container's root, are used normally: the files opened through the overlay are checked, and the layer accesses behind them are not checked a second time.

## io_uring

`io_uring`, which performs I/O without the syscalls seccomp sees, is refused in both modes: the seccomp filter fails `io_uring_setup` with `EPERM`.

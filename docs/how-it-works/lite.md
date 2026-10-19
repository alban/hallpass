# Lite mode: seccomp user notification

Lite mode is unprivileged. A seccomp filter pauses the mediated syscalls and hands them to the hallpass supervisor through a notification file descriptor. The supervisor reads the syscall's arguments from the process's memory, resolves the path, applies the policy and, if needed, asks you. Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`; denied ones fail with `EACCES`.

This is what lets hallpass *ask* instead of just failing the call. It is best effort: because the allowed syscall is re-executed by the kernel, a malicious multi-threaded process can change the path between the check and the kernel acting on it (a TOCTOU race). [Strict mode](strict.md) closes that.

In practice lite mode is still useful, because that gap only matters against a process *deliberately* racing the check. Most escapes are accidents — a wrong path, an overeager script, a command run in the wrong directory — not adversarial races, and lite mode catches those reliably. Strict mode closes the TOCTOU race so filesystem enforcement also holds against a deliberate racer.

Neither mode contains a hostile agent today: programs are matched by path only, and `connect` is not mediated by default, so a sandboxed process can still ask a service outside the sandbox (`systemd-run --user`, a container daemon, the systemd or D-Bus socket) to write for it. See [Limitations](limitations.md).

## The filter

The seccomp filter only decides which syscalls reach the supervisor; the policy is in the supervisor. It sees the syscall number and its integer arguments, not the memory they point to:

- Syscalls are paused unconditionally (`unlinkat`, `execve`, `connect`...), or when an argument says so: `openat` with a write flag (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`), `sendto` with an address.
- Syscalls that hide their flags or address in a struct (`openat2`, `sendmsg`, `sendmmsg`) are always paused, and the supervisor continues those that need no check.
- Some are refused without asking: `io_uring_setup` (`EPERM`), which would perform I/O without the syscalls the filter sees, and new user and mount namespaces (`unshare`, `clone`, `setns`; `clone3` fails with `ENOSYS`, so libc falls back to `clone`), because inside a private mount namespace a process could bind-mount a protected directory at a harmless-looking path. On a workstation, `--allow-userns` lets namespaces through; strict mode always does.
- Only the categories selected with `--mediate` (or a policy's `mediate`) are installed. `execve` is paused in every case.

The syscalls of each category are listed in [Files](files.md), [Network](network.md) and [Programs](exec.md).

For each paused syscall, the supervisor reads the strings and structs it needs from `/proc/<pid>/mem`, resolves relative paths from `/proc/<pid>/cwd` or `/proc/<pid>/fd/<n>`, follows symlinks one component at a time, and checks with `SECCOMP_IOCTL_NOTIF_ID_VALID` that the syscall is still waiting before using what it read. While a prompt is pending, the thread only reacts to fatal signals (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, Linux 5.19 and later).

## On a workstation

`hallpass` re-executes itself as a small child, which sets `no_new_privs`, installs the filter, sends the notification file descriptor back to the supervisor over a socketpair, waits for the supervisor to be ready, and runs the command. Everything the command starts inherits the filter.

The supervisor is the subreaper of the processes the command leaves behind. If it exits while they run, their mediated syscalls fail (fail closed). See [Background processes](../workstation/usage.md#background-processes).

## In Kubernetes

`hallpass-node`, a DaemonSet, plays the supervisor for the containers of a node, with the OCI seccomp agent protocol:

1. Its [NRI](https://github.com/containerd/nri) plugin, on `CreateContainer` of an opted-in pod, adds a seccomp profile generated from the same rule table as the CLI's, merged into the container's own profile (`RuntimeDefault`, `Localhost` or `Unconfined`). The profile's `listenerPath` is the agent's unix socket, and its listener metadata names the pod, container and policy.
2. runc installs the filter when it starts the container, connects to `listenerPath`, and sends the notification file descriptor and the container's state (pid, annotations) with `SCM_RIGHTS`.
3. The agent mediates each container as a session. It runs in the host pid namespace and resolves paths through `/proc/<pid>/root`, so rules and prompts use the container's paths (`/workspace/x`).

Copies of the notification file descriptors are kept by `hallpass-fd-store`, so the sessions survive an agent restart. When every copy is closed, the mediated syscalls fail with `ENOSYS`. See [Restarts and upgrades](../kubernetes/install.md#restarts-and-upgrades) and [Fail open](../kubernetes/install.md#fail-open).

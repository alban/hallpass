# Limitations

hallpass is a proof of concept. It mediates filesystem writes and the programs run (by path only), and mediates `connect` only when network mediation is enabled. By default, a sandboxed process can therefore reach a service that acts on its behalf *outside* the sandbox, and so write anywhere that service can, without a prompt. For example `systemd-run --user`, or `docker`/`podman run` talking to a daemon, or a process connecting directly to the systemd or D-Bus session socket. Running those clients is asked about, but an allowed interpreter can connect to the socket itself. Network mediation asks about those connections, but an `always` on such a socket allows the escape again; treat the current build as "ask me about honest mistakes", not "contain a hostile agent".

## What is mediated

- Only writes (write-intent `open`, create, delete, rename, link, `truncate`, `mknod`), program executions and, with network mediation, connections and sends are mediated: reading files, secrets included, is not restricted.
- `chmod`, `chown`, extended attributes and timestamps are not mediated yet.

## Files

- Lite mode: allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so a malicious multi-threaded process can change the path between the check and the kernel acting on it (TOCTOU). Strict mode (BPF-LSM) closes this.
- Lite mode: `openat2` passes its flags in memory (`struct open_how`), which the seccomp filter cannot read: every `openat2` reaches hallpass, which reads the flags and lets the read-only ones through. A malicious process can change the flags after the check, as it can change the path. Strict mode closes this too.
- Lite mode: pre-existing hard links to protected files are not detected.
- Strict mode: sandboxed processes cannot mount overlayfs (for example rootless podman or buildah with the native overlay driver): overlayfs writes to its layers without going through the hooks hallpass checks. fuse-overlayfs works.

## Programs

- An allowed interpreter (`python3`, `node`, a shell) runs any code it is given, and the dynamic loader (`ld.so /path/to/program`) runs a program without executing it.
- A program copied or downloaded to a path an allow covers runs. The project directory is writable, not executable by default.
- When several commands are one binary (busybox, uutils coreutils), installed as symlinks, allowing one allows all: rules match the resolved path, and telling the commands apart needs `argv[0]`. Hard links and copies have paths of their own.
- A program run from a file descriptor (`execveat` with `AT_EMPTY_PATH`, for example a `memfd`) gives lite mode no path to read: it asks about it as an unknown path ("once" only). Strict mode matches the rules on the file the descriptor is open on, without asking, and always denies a file with no path at all (a `memfd`).
- `binfmt_misc` handlers (qemu, Wine) are not seen by lite mode, which only reads `#!` lines: they run. Strict mode checks them in the kernel like `#!` interpreters, but never asks about them at seccomp time: they need an allow rule.
- Lite mode: the path is read from memory after the check (TOCTOU), as for writes.
- In Kubernetes, the container's command (its `args[0]`) is allowed for good, with any arguments and any number of times.

## Network

- Sockets inherited from outside the sandbox, or received with `SCM_RIGHTS`, are already connected: their traffic is not asked about.
- Only IPv4, IPv6 and unix sockets are mediated; other families (netlink, packet, vsock...) are not.
- A UDP socket bound inside the sandbox is not a listener: sending to it is asked.
- Answers cover one destination; there are no answers for a subnet or a folder of sockets yet (use `--allow-net`).
- Lite mode: the destination address is read from memory after the check (TOCTOU), and a listener inherited from outside the sandbox counts as started inside it.
- Strict mode: listeners created before the BPF programs were loaded are not known as started inside the sandbox, and their connections are asked about. A one-shot grant holds a few destinations per thread.

## Strict mode

- The supervisor holds writable fds of the BPF maps, so the user running hallpass can put any process, including other users', under the policy or under signal protection. Choosing an escalation tool is the administrator's consent to that.
- If the supervisor dies, the programs are detached. Seccomp then fails the sandbox's mediated syscalls closed, but nothing else is enforced on processes left behind.
- When the helper runs without a recognised escalation tool in its environment (`--escalate=manual`, or `su`, which clears `SUDO_UID`/`PKEXEC_UID`/`DOAS_USER`), it cannot tell which user invoked it and only checks that the target runs the same hallpass binary.
- `kernel.yama.ptrace_scope=3` prevents the helper from fetching the socket (`pidfd_getfd`); run hallpass as root instead.

## Kubernetes

See [Kubernetes limitations](../kubernetes/index.md#limitations).

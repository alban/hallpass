# How it works

hallpass wraps a command and puts it, and everything it starts, under a sandbox. Writes inside the project directory go through without asking; writes anywhere else are mediated. It combines two kernel mechanisms, one per mode.

## Why from the kernel

Agent CLIs have their own permission prompts and sandboxes, but those are enforced by the agent process itself and configured by files the agent can often write. hallpass is enforced by the kernel, from outside the agent, so it does not depend on the agent being well-behaved. It complements the agent's own controls rather than replacing them.

## Lite mode: seccomp user notification

Lite mode is unprivileged. A seccomp filter pauses the syscalls that modify the filesystem — write-intent `open`, create, delete, rename, link, `truncate`, `mknod` — and hands them to the hallpass supervisor through a notification file descriptor. The supervisor resolves the path, applies the policy and, if needed, asks you. Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

This is what lets hallpass *ask* instead of just failing the call. It is best effort: because the allowed syscall is re-executed by the kernel, a malicious multi-threaded process can change the path between the check and the kernel acting on it (a TOCTOU race). Strict mode closes that.

## Strict mode: BPF-LSM

Strict mode adds an eBPF program on the kernel's LSM hooks. It enforces the same policy on the real file (inode), so it cannot be bypassed by symlink races, bind mounts, other mount namespaces or `io_uring`. Your answers to the prompts are pushed to the kernel before the paused syscall continues, so the enforcement and the question stay in sync.

Only loading the BPF programs needs root. hallpass starts a short-lived copy of itself as root, which loads and attaches the programs, hands their file descriptors back to the unprivileged supervisor and exits. The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it. See [Strict mode](usage.md#strict-mode) for how the root step is run.

## Prompts that don't flood you

Prompts are designed not to overwhelm you:

- one notification per session, updated in place;
- identical pending requests (for example from `make -j`) are coalesced;
- an "allow for 5 minutes" or "always" answer settles every pending request under that folder.

The prompt shows the target path and, as a `by:` line, the command that tried the write and its parent chain (for example `cp hello ~/.local/bin/hello ← make ← copilot`), so you can see who is really behind the access. Press Ctrl-] inside a session to see its current rules, including the answers given so far.

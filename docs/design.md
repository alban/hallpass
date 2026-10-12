# How it works

hallpass wraps a command and puts it, and everything it starts, under a sandbox. Writes inside the project directory go through without asking; writes anywhere else are mediated. It combines two kernel mechanisms, one per mode.

## Why from the kernel

Agent CLIs have their own permission prompts and sandboxes, but those are enforced by the agent process itself and configured by files the agent can often write. hallpass is enforced by the kernel, from outside the agent, so it does not depend on the agent being well-behaved. It complements the agent's own controls rather than replacing them.

## Lite mode: seccomp user notification

Lite mode is unprivileged. A seccomp filter pauses the syscalls that modify the filesystem — write-intent `open`, create, delete, rename, link, `truncate`, `mknod` — and hands them to the hallpass supervisor through a notification file descriptor. The supervisor resolves the path, applies the policy and, if needed, asks you. Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

This is what lets hallpass *ask* instead of just failing the call. It is best effort: because the allowed syscall is re-executed by the kernel, a malicious multi-threaded process can change the path between the check and the kernel acting on it (a TOCTOU race). Strict mode closes that.

In practice lite mode is still useful, because that gap only matters against a process *deliberately* racing the check. Most agent escapes are accidents — a wrong path, an overeager script, a command run in the wrong directory — not adversarial races, and lite mode catches those reliably. Strict mode is for when you also need to hold against a malicious or compromised agent.

## Strict mode: BPF-LSM

Strict mode exists to close the TOCTOU race that lite mode is inherently exposed to. With seccomp user notification the kernel re-executes the *allowed* syscall after the supervisor's check, resolving the path a second time. A malicious multi-threaded process can swap what the path points at in that window, so the file the supervisor approved is not the file the kernel acts on. No seccomp-based tool can fully close this; the check and the action are two separate steps.

Strict mode adds an eBPF program on the kernel's LSM hooks, which run at the moment of the action, on the real file (inode) the kernel is about to modify — after any symlink, bind mount, mount-namespace or rename trick has already been resolved. There is no second resolution to race, so the same bypasses that defeat lite mode (symlink races, bind mounts, other mount namespaces, `io_uring`) do not apply. Your answers to the prompts are pushed to the kernel before the paused syscall continues, so the enforcement and the question stay in sync.

Only loading the BPF programs needs root. hallpass starts a short-lived copy of itself as root, which loads and attaches the programs, hands their file descriptors back to the unprivileged supervisor and exits. The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it. See [Strict mode](usage.md#strict-mode) for how the root step is run.

## Prompts that don't flood you

Prompts are designed not to overwhelm you:

- one notification per session, updated in place;
- identical pending requests (for example from `make -j`) are coalesced;
- an "allow for 5 minutes" or "always" answer settles every pending request under that folder.

The prompt shows the target path and, as a `by:` line, the command that tried the write and its parent chain (for example `cp hello ~/.local/bin/hello ← make ← copilot`), so you can see who is really behind the access. Press Ctrl-] inside a session to see its current rules, including the answers given so far.

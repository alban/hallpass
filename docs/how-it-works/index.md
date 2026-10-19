# How it works

hallpass wraps a command and puts it, and everything it starts, under a sandbox. Writes inside the project directory go through without asking; writes anywhere else are mediated. It uses two kernel mechanisms: seccomp user notification in both modes, and BPF-LSM on top of it in strict mode.

## Why from the kernel

Any program you run can write wherever your user can. Some have their own permission prompts and sandboxes, such as AI agent CLIs, but those are enforced by the program itself and configured by files it can often write. hallpass is enforced by the kernel, from outside the program, so it does not depend on the program being well-behaved. It complements the program's own controls rather than replacing them.

## Security model

hallpass is a proof of concept. It is meant to catch **honest mistakes**: a wrong path, an overeager install script, a command run in the wrong directory, by the program or anything it starts, even when the program skips its own prompts.

What it protects:

- Writes outside the project, in both modes: paused and asked, or denied by your rules. The sandbox cannot change hallpass itself (its binary and config are denied), nor answer its own prompts: it cannot see the terminal prompt, and the session socket refuses sandboxed clients.
- In strict mode, also against a process that deliberately races the check (TOCTOU), or hides the target behind symlinks, bind mounts or other mount namespaces: the kernel checks the real file.

What it does not protect:

- Reads: a program can read your secrets, and send them away (the network is not mediated by default).
- Writes done for the sandbox by a service outside it (`systemd-run --user`, a container daemon, D-Bus): `connect` is only mediated with the experimental `--mediate=...,network`. Running a client of such a service (`systemd-run`, `docker`) is asked about, but programs are matched by path only (see [Programs](exec.md)), and a process can talk to the service without its client. This is why hallpass does not contain a hostile program today.
- Permissions, owners, extended attributes and timestamps.
- In lite mode, a deliberate TOCTOU race.
- Your answers: an `always` on a broad folder allows everything under it. The `by:` line of a prompt is set by the process and proves nothing.

The details are in [Limitations](limitations.md).

## Lite and strict mode

| | Lite mode | Strict mode |
|---|---|---|
| Privileges | None: hallpass runs as your user. | Root only to load the BPF programs: a short-lived root copy of hallpass loads them and exits; the supervisor runs as your user. |
| Enforced by | Seccomp user notification: the kernel pauses the syscall, the supervisor checks its arguments and lets it continue or fails it. | The same, plus BPF-LSM programs that check the object the kernel is about to act on. |
| TOCTOU | Exposed: a process can change the path or address it passed after the check. | Closed: the LSM hooks run after the kernel resolved the path or copied the address. |
| What is mediated | Files (writes), exec (programs), network (experimental, opt-in). New user and mount namespaces are refused (on a workstation, unless `--allow-userns`). | The same categories. On a workstation, new namespaces are allowed: the kernel checks the real files. |
| Workstation | The default. | `--mode=strict`, with BPF-LSM active. See [Strict mode](../workstation/strict.md). |
| Kubernetes | Nodes without BPF-LSM, or `hallpass-node --mode=lite`. | Nodes with BPF-LSM (`--mode=auto`, the default, or `--mode=strict`). See [Strict mode](../kubernetes/install.md#strict-mode). |

The pages below give the details:

- [Lite mode](lite.md): seccomp user notification, on a workstation and in Kubernetes.
- [Strict mode](strict.md): BPF-LSM, the root loader, and why.
- [Files](files.md), [Network](network.md) and [Programs](exec.md): for each category, what each mode pauses, reads and checks.
- [Limitations](limitations.md): what hallpass does not cover yet.

## Prompts

Prompts are designed not to overwhelm you: one question at a time, concurrent requests of a process for the same path coalesced, and pending requests settled by a new rule. See [Answers and rules](../answers/index.md#prompts-that-dont-flood-you).

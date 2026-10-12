# Usage

```
hallpass [flags] [--] [command [args...]]     # default command: $SHELL

  -C, --workdir DIR        project dir, writable without asking (default: cwd)
      --allow PATH         also writable without asking (repeatable)
      --deny PATH          always denied (repeatable, wins over --allow)
      --ask MODE           auto | term | desktop | answer | deny   (default: auto = term if on a terminal, else desktop, else answer)
      --timeout DUR        unanswered prompt is denied after DUR (default 30s; 0 = wait forever)
      --allow-userns       let the sandbox create user/mount namespaces (weakens lite mode; always on in strict mode)
      --log FILE           append one JSON line per mediated syscall to FILE
      --mode MODE          lite (default, no root) | strict (BPF-LSM enforcement)
      --escalate TOOL      strict mode as a regular user: how to run the loader as root:
                           auto | ask | pkexec | sudo | run0 | doas | su | manual | none
                           (default: saved choice, else ask on a terminal, else auto)

hallpass policy [flags]                       # print the rules these flags give, then exit
hallpass answer [PID]                         # answer another session's prompts from this terminal
```

## Default policy

By default, only `~/.config/hallpass` is denied (the sandbox must not change what hallpass runs next time); the project, a private `$TMPDIR` for the session (removed at exit if empty) and the usual `/dev` nodes are writable; anything else is asked, including the shared `/tmp`, `/var/tmp` and `/dev/shm` (answer "always" to allow them). Writes to known secret stores (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gh`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`) are asked too, with a red warning label like "SSH keys — secret store".

Press Ctrl-] inside a session to see its current rules, including answers given so far; any key closes the overlay.

## Strict mode

Strict mode builds on lite mode: it still pauses writes and asks you interactively, exactly as lite mode does, and the workload waits for your answer. The BPF-LSM program is an added layer, not a replacement: it enforces each answer in the kernel on the real file. It is not a silent, pre-configured policy.

Strict mode enforces your answers in the kernel with a BPF-LSM program, on the real file the kernel is about to modify. This closes the TOCTOU race that lite mode cannot: with seccomp, the kernel re-resolves the path after the check, so a malicious multi-threaded process can swap it in between (via a symlink, bind mount or rename). The LSM hook runs after that resolution, so there is no window to race.

Run hallpass as your user; only loading the BPF programs needs root:

```console
hallpass --mode=strict -- copilot
```

hallpass starts a short-lived copy of itself as root (`--escalate`: `auto` picks pkexec in a graphical session, else sudo, run0 or doas; `manual` prints the command for you to run as root and waits for Enter). Without `--escalate`, hallpass uses the choice saved in `~/.config/hallpass/config` (`escalate = sudo`), or else asks on the terminal which tool to use and whether to remember it; `--escalate=ask` asks again. The config directory is `$XDG_CONFIG_HOME/hallpass` when that variable is set to an absolute path, otherwise `~/.config/hallpass`. The sandbox can never write it. The helper checks it was started for a hallpass of the invoking user, loads and attaches the programs, hands their file descriptors back to the supervisor and exits. The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it.

## Using hallpass with agent CLIs

Wrap the top-level command; there is nothing to configure in the agent:

```console
hallpass -- copilot
hallpass -- claude
hallpass -C ~/src/app -- codex
```

Agents keep their own state (sessions, logs, caches) outside the project. For copilot that is `~/.copilot` and `~/.cache/copilot`:

```console
hallpass -allow ~/.copilot -allow ~/.cache/copilot -- copilot
```

The `-allow` flags are optional: without them, hallpass asks you when copilot writes there, which is a good way to see what an agent touches. Allowing all of `~/.copilot` does let the agent change its own config or hooks, which would apply to later runs without hallpass.

Things to know:

- **Full-screen TUIs**: hallpass draws its question over the agent's screen and repaints it afterwards; the agent's terminal is never resized. This also works over ssh.
- **Agents' own sandboxes**: some agents run commands inside their own bubblewrap sandbox (for example Codex), which creates user and mount namespaces. hallpass lite mode blocks new namespaces by default, because inside a private mount namespace a process could bind-mount a protected directory somewhere that looks harmless. The agent's own sandbox will then fail to start or fall back; disable it in the agent, pass `--allow-userns` and accept the weaker lite-mode guarantees, or use strict mode, which allows namespaces because it checks real inodes.
- **Agents that use seccomp user notification themselves** cannot install their own listener under hallpass: the kernel allows only one listener per filter chain and returns `EBUSY`. This fails closed.
- **sudo** does not work inside the sandbox (`no_new_privs`), in either mode, by design.

## Over ssh

hallpass draws its prompt over the terminal, so it works over ssh like any other full-screen program. Without a terminal (for example a non-interactive session, or when the agent fully owns the screen), use a desktop prompt (`--ask=desktop`) or answer from another terminal:

```console
hallpass --ask=answer -- copilot     # in one terminal
hallpass answer                      # in another, to see prompts and reply
```

`hallpass answer` connects to the running session's socket, shows each pending request (path, the `by:` command line and its parents) and lets you allow once, allow temporarily, allow always, deny or refuse forever.

`hallpass answer` is mainly a testing and debugging aid, and a fallback for the headless case above; the terminal overlay is the normal way to answer. The socket only accepts a client of the same user that is not itself sandboxed (it rejects any peer running under a seccomp filter), so the sandbox cannot answer its own prompts through it.

## Requirements

- Linux with seccomp user notification (5.0+; `SECCOMP_USER_NOTIF_FLAG_CONTINUE` needs 5.5+). Check `/proc/sys/kernel/seccomp/actions_avail` contains `user_notif`.
- arm64 or amd64.
- Strict mode: BPF-LSM active, i.e. `bpf` listed in `/sys/kernel/security/lsm`. Fedora enables it by default; Ubuntu builds it but does not activate it (add `bpf` to the `lsm=` kernel parameter). The programs also need the `bpf_path_d_path` kfunc (upstream 6.12; they also use `bpf_preempt_disable` from 6.10); the verifier rejects them otherwise. Tested on 7.2.
- Desktop prompts: a session D-Bus with an `org.freedesktop.Notifications` service supporting actions (GNOME, KDE, most notification daemons).

## Building

```console
go build ./cmd/hallpass
```

## Limitations

hallpass is a proof of concept. It mediates filesystem writes; it does not yet mediate
`execve` or `connect`, in either mode. A sandboxed process can therefore reach
a service that acts on its behalf *outside* the sandbox, and so write anywhere
that service can, without a prompt. For example `systemd-run --user`, or
`docker`/`podman run` talking to a daemon, or a process connecting directly to
the systemd or D-Bus session socket. These are trivial, known escapes until
`connect`/`execve` policy exists; treat the current build as "ask me about
honest mistakes", not "contain a hostile agent".

Lite mode is best effort:

- Only writes are mediated (write-intent `open`, create, delete, rename, link, `truncate`, `mknod`). Reading secrets is not blocked in lite mode.
- Allowed syscalls continue with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so a malicious multi-threaded process can change the path between the check and the kernel acting on it (TOCTOU). Strict mode (BPF-LSM) closes this.
- Pre-existing hard links to protected files are not detected.
- `chmod`, `chown`, extended attributes and timestamps are not mediated yet.
- Network and `execve` policy are not implemented yet (see above).

Strict mode:

- The supervisor holds writable fds of the BPF maps, so the user running hallpass can put any process, including other users', under the policy or under signal protection. Choosing an escalation tool is the administrator's consent to that.
- If the supervisor dies, the programs are detached. Seccomp then fails the sandbox's mediated syscalls closed, but nothing else is enforced on processes left behind.
- When the helper runs without a recognised escalation tool in its environment (`--escalate=manual`, or `su`, which clears `SUDO_UID`/`PKEXEC_UID`/`DOAS_USER`), it cannot tell which user invoked it and only checks that the target runs the same hallpass binary.
- `kernel.yama.ptrace_scope=3` prevents the helper from fetching the socket (`pidfd_getfd`); run hallpass as root instead.

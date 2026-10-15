# Web UI

Status: design, not implemented.

`hallpass web` serves a browser UI to watch and answer the requests of
every running hallpass session of the user, and to explore them: the
process chain, the facts, the rules that decided an access.

## Processes

```
browser ──HTTP (127.0.0.1)──> hallpass web ──gRPC (unix socket)──> hallpass session (monitor)
                                           ──gRPC (unix socket)──> hallpass session (monitor)
```

- The **session** (`hallpass -- cmd`) runs the monitor and serves its API
  over gRPC on its per-session socket, `$XDG_RUNTIME_DIR/hallpass/<pid>.sock`
  (today's answer socket). It holds no web code: it is the trusted part,
  and stays small.
- **`hallpass web`** is a client like the terminal overlay. It finds the
  sessions in the socket directory, subscribes to each, and serves the
  browser. It can be stopped and restarted without touching the sessions.
- Same binary (`hallpass web` subcommand): one artefact to install.

Several clients answer at once (terminal overlay, `hallpass answer`,
browser): the first verdict wins, the others see `Closed` and drop the
prompt (see [monitor.md](monitor.md#behaviour)).

## Session API (gRPC)

The monitor API one-to-one, plus what a client needs to list sessions:

```proto
service Session {
  rpc Info(InfoRequest) returns (SessionInfo);        // pid, command, cwd, mode, start time
  rpc Snapshot(SnapshotRequest) returns (SnapshotReply); // pending, rules, generation
  rpc Events(EventsRequest) returns (stream EventBatch); // EventOptions.Decided
  rpc Apply(Decision) returns (ApplyReply);            // generation, or ErrStale/ErrClosed/ErrUnsupported as status codes
}
```

Messages mirror `monitor.Request`, `Decided`, `Reason`, `rules.Rule`,
`Subject` and `Fact`. The socket keeps today's peer check: same uid, and
no seccomp filter (no sandboxed process can call it).

`hallpass answer` becomes a gRPC client too, and the line protocol of
`internal/ui/socket.go` goes away.

## Browser API

Shaped for the UI, not for the monitor, and free to change with it:

- `GET /` and static assets: one page, embedded (`go:embed`), no build step.
- `GET /api/sessions`: the sessions and their `Info`.
- `GET /api/sessions/{pid}/events`: server-sent events; first the
  snapshot, then the events (Opened, Closed, Rules, Decided).
- `POST /api/sessions/{pid}/answer`: `{request, answer}` with the same
  answers as the terminal (once, temp, always, never, deny).
- `POST /api/sessions/{pid}/rules`: remove a rule, or a set.

The answer-to-`Decision` mapping (once, temp and always grants, "never"
as an exact deny, a grant never shrinks) moves from `cmd/hallpass/prompt.go`
to a shared package, so the terminal and the browser offer the same
choices with the same effect.

## Views

- **Pending**: the queue across sessions, oldest first: op, objects, the
  subject chain (exe, cmdline, parents), the facts with their trust, the
  secret-store warning; answer buttons.
- **Activity**: the `Decided` stream since `hallpass web` connected,
  filterable by session, path, process, verdict, reason; each line links
  to the rule that decided it (strace-like, see
  [monitor.md](monitor.md#tracing)).
- **Rules**: per session, by set (implicit, session answers), with
  expiry; remove a rule.

## Security

`hallpass web` can approve any request, so it must not be reachable by:

1. **the sandbox**, which runs as the same user, can connect to
   127.0.0.1, and can read the user's files (lite and strict mode only
   mediate writes today);
2. **web pages in the browser** (cross-site requests, DNS rebinding);
3. **other local users**, who can connect to 127.0.0.1 too.

Measures:

- **Listen on 127.0.0.1 only** (random port by default, `--listen` to
  fix it).
- **Host and Origin checks**: requests must carry `Host: 127.0.0.1:<port>`
  or `localhost:<port>`, and state-changing requests and the event
  stream a matching `Origin`. Stops DNS rebinding and cross-site requests.
- **One-time pairing token**: `hallpass web` prints
  `http://127.0.0.1:<port>/pair?token=<random>` on its own terminal. The
  first request exchanges it for a session cookie (`HttpOnly`,
  `SameSite=Strict`, no expiry, random per `hallpass web` process) and
  burns it; Enter prints a new one. Not passed on a command line by
  default (`/proc/<pid>/cmdline` is readable by the same user); `--open`
  runs `xdg-open` anyway, for convenience. Stops other users and web
  pages.
- **Blocked at the source, later**: with `connect` mediation (network
  plan), the sandbox cannot connect to the web port at all. Strict mode
  first: an LSM `socket_connect` deny for members, cheap and sound. Lite
  mode needs a seccomp notification on `connect`, whose address the
  sandbox can change after the check (TOCTOU), so it waits for the
  TOCTOU work.

**Known hole in the first version**: the token and the cookie do not
stop the sandbox. It cannot read the token (printed on the web process's
terminal), but it can read the cookie from the browser profile (plaintext
in Firefox's `cookies.sqlite`; Chrome encrypts it with the keyring), then
connect to 127.0.0.1 and approve its own requests. This is weaker than
the terminal answer socket, which rejects peers with a seccomp filter.
It takes a deliberately malicious agent, not an accident, so `hallpass
web` ships as experimental and says so in `--help` and its banner until
the `connect` block lands.

A per-connection peer check (find the client socket with
`NETLINK_SOCK_DIAG`, scan `/proc/*/fd` for its inode, reject if a holder
descends from a session supervisor, a subreaper, or is a BPF member) was
considered and dropped: it is complex and still leaky (non-dumpable
processes hide their fds, pid reuse), and the `connect` block makes it
unnecessary.

Not covered, as today: the sandbox asking a service outside it
(`systemd-run --user`, D-Bus, a tmux server) to connect for it. See
[Limitations](../usage.md#limitations).

## Work items

1. gRPC session service on the socket; `hallpass answer` ported; the
   socket line protocol removed.
2. The terminal prompt is cancelled when another client answers
   (`ui.Asker.Ask` blocks today); the answer mapping moved to a shared
   package.
3. `hallpass web`: sessions, pending, answers, rules, activity; pairing,
   Host/Origin checks; marked experimental.
4. Facts filled by the monitor (secret store, listener in sandbox, ...).
5. Later: a backlog of `Decided` events in the monitor, replayed after
   `Snapshot`, so the activity view starts with the session; remote
   access (phone) with real authentication.
6. Later: deny `connect` from members to the web port (strict mode
   first, lite mode after the TOCTOU work); drop "experimental".

## Open questions

- Can the sandbox put a fake session socket in the socket directory
  (`$XDG_RUNTIME_DIR/hallpass/`), for `hallpass web` to list? It is not
  in the allow list, so file writes there are asked. But `bind()` on a
  unix socket path creates the inode without a syscall the seccomp
  filter sees, so lite mode does not catch it (strict mode would, if
  the LSM's mknod hook covers sockets: to check). `hallpass web` should
  check that the socket's owner (`SO_PEERCRED`) is the session's
  supervisor pid, as reported by `Info`.

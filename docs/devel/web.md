# Web UI

Status: work items 1–3 implemented; `hallpass web` is experimental.

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
  (today's answer socket). It also embeds the web server, restricted to
  itself, started only when the user opens its web UI (see
  [One server, two scopes](#one-server-two-scopes)).
- **`hallpass web`** is a client like the terminal overlay. It finds the
  sessions in the socket directory, subscribes to each, and serves the
  browser. It can be stopped and restarted without touching the sessions.
- Same binary (`hallpass web` subcommand): one artefact to install.
- **`--node ADDR`**: the sessions come from a Kubernetes node agent
  (`sessionapi.Node`, usually through `kubectl port-forward`) instead of
  the socket directory: one gRPC connection, `List` for the sessions,
  and the `hallpass-session` metadata to select one. The page names
  sessions by `SessionInfo.id` instead of pid, in the same URLs
  (`/api/sessions/{key}/...`).

Several clients answer at once (terminal overlay, `hallpass answer`,
browser): the first verdict wins, the others see `Closed` and drop the
prompt (see [monitor.md](monitor.md#behaviour)).

### One server, two scopes

A session opens its own web UI from the Ctrl-] menu ("[w] open the web
UI"), with `[w]` in a request's terminal prompt (desktop sessions only:
`DISPLAY` or `WAYLAND_DISPLAY` set), or with the "Open web UI" button of
a request's desktop
notification. It embeds the same `internal/web` server as `hallpass web`
(`web.NewSession(pid)`), started on the first "open" on a random
loopback port, and opens the page with `xdg-open` (in a new session, so
that the browser neither gets the program's terminal nor its hangup).
The page holds no secret, so the browser's command line holds none
either. The server is restricted to the session:

- `GET /api/sessions` lists it only; other sessions are refused (404).
  The page then shows no session list, but links to `hallpass web` for
  all sessions.
- Pairing is accepted only after an "open", once, within 60 seconds: the
  sandbox cannot start pairings out of the blue. A request racing the
  user's browser still cancels both and warns (the contention check
  comes first).
- The pairing code is confirmed in the terminal's overlay, or in a second
  desktop notification with [Pair] [Cancel]. Notification services show
  one critical notification at a time (GNOME queues the others), so the
  request's notification is hidden while the confirmation shows. In the
  terminal, the confirmation takes the place of the request's prompt
  (`ui.Terminal.Preempt`), which comes back afterwards: the request keeps
  `promptMu` until answered.
- Nothing is printed in the terminal, where a line would stay after the
  pairing; only an `xdg-open` failure prints the URL.
- Once paired, the page closes the pairing window
  (`POST /api/pair/close`): the sandbox cannot use the rest of it.
- Another "Open web UI" opens a new tab, which takes the credential of a
  paired tab of the same server instead of pairing again (see
  [Security](#security)).

The titles say which server a page belongs to: "hallpass: session PID"
for a session, "hallpass web: all sessions" (or "node sessions" in
`hallpass-node`) for `hallpass web`.

The server dials the session's own socket, like any client; the peer
check passes since the session is not under a seccomp filter. Pairing,
the credential, the event stream and the rule editing so stay in one
place. Its port is protected like `hallpass web`'s (see
[Protected denials](#protected-denials)).

The "Open web UI" button must not dismiss the request: the request's
notification gets the `resident` hint, and hallpass closes it itself once
answered. Services that close it on click anyway get it shown again
(closed within 2 seconds of the click). GNOME has room for three buttons,
so with this one the notification offers Allow once and Deny only; the
page has all answers. A click on the notification's text does nothing.
The click's activation
token (the service's `ActivationToken` signal) goes to `xdg-open` as
`XDG_ACTIVATION_TOKEN` and `DESKTOP_STARTUP_ID`, so that the browser's
window comes to the front. Signals are taken only from the owner of
`org.freedesktop.Notifications`: on GNOME it is a proxy, and gnome-shell
broadcasts the same signals behind it.

While a paired page has the user's attention, the session's requests get
no desktop notification: one place to answer, not two. Each page names
itself with a random tab id on its event streams (`?tab=…&visible=1`) and
reports its `visibilitychange`, `focus` and `blur` events
(`POST /api/visibility`); the server tells the session (`Server.Watching`,
then `Desktop.SetQuiet`) whether some page has a stream open, is visible
and has the focus. Visibility alone is not enough: a window merely covered
by others still counts as visible. So the notification shows while the
user types in the terminal, and goes away while the page has the focus.
`hallpass web` serves all sessions and does not quiet their notifications.

## Session API (gRPC)

The monitor API one-to-one, plus what a client needs to list sessions:

```proto
service Session {
  rpc Info(InfoRequest) returns (SessionInfo);        // pid, command, cwd, mode, start time
  rpc Snapshot(SnapshotRequest) returns (SnapshotReply); // pending, rules, generation
  rpc Events(EventsRequest) returns (stream EventBatch); // EventOptions.Decided, optional snapshot first
  rpc Apply(Decision) returns (ApplyReply);            // generation, or ErrStale/ErrClosed/ErrUnsupported as status codes
  rpc Answer(AnswerRequest) returns (AnswerReply);     // a terminal answer (once, temp, always, never, deny)
  rpc List(ListRequest) returns (ListReply);           // the sessions served (one on a session's socket)
}
```

A session's socket serves one session. The Kubernetes node agent serves
all the sessions of its node on one TCP listener (`sessionapi.Node`): `List`
gives their ids, and the other calls select one with the
`hallpass-session` gRPC metadata.

Messages mirror `monitor.Request`, `Decided`, `Reason`, `rules.Rule`,
`Subject` and `Fact`. Each pending request also carries its `Prompt`: the
text and the choices the terminal would show.

`EventsRequest.snapshot` makes the server subscribe first and then send
the snapshot in the first batch, so a client misses no event between the
two. `Decided` events are batched (500 ms quiet, 2 s at most); `Opened`
and `Closed` go out at once.

Both ends check each other with `SO_PEERCRED`:

- the server keeps today's peer check: same uid, and no seccomp filter
  (no sandboxed process can call it);
- the client (`sessionapi.Dial`) checks the server: same uid, no seccomp
  filter, and its pid is the one in the socket name. A sandboxed process
  that binds a fake `<pid>.sock` in the socket directory fails all of
  them.

`hallpass answer` becomes a gRPC client too, and the line protocol of
`internal/ui/socket.go` goes away.

## Browser API

Shaped for the UI, not for the monitor, and free to change with it:

- `POST /api/pair`: starts pairing this browser; returns `{id, code}`.
  `hallpass web` asks the user to confirm the code (see
  [Security](#security)).
- `POST /api/pair/wait`: `{id}`; waits for the user's answer, and returns
  `{credential}` if they confirmed. The page sends it as `Authorization:
  Bearer <credential>` on the requests below.
- `POST /api/pair/close` (authenticated): ends the session server's
  pairing window early, once the page is paired.
- `GET /api/scope`: which server this is, for the page's title, before
  pairing: `{"session": pid}`, `{"node": true}` or `{}` (all sessions).
- `GET /` and static assets: one page, embedded (`go:embed`), no build
  step. They hold no secret, and are served before pairing, to pair.
- `GET /favicon.svg`: the logo.
- `GET /api/sessions`: the sessions and their `Info`.
- `GET /api/sessions/{pid}/snapshot`: pending requests and rules.
- `GET /api/sessions/{pid}/events`: server-sent events; first the
  snapshot, then the events (Opened, Closed, Rules, Decided). The page
  reads them with `fetch`, not `EventSource`, which cannot send the
  `Authorization` header. `?tab=…&visible=0|1` names the page and says
  whether it is visible and has the focus (see [One server, two scopes](#one-server-two-scopes)).
- `POST /api/sessions/{pid}/answer`: `{request, answer}` with the same
  answers as the terminal (once, temp, always, never, deny).
- `POST /api/sessions/{pid}/rules`: remove a rule, or a set.
- `POST /api/visibility`: `{tab, visible, seq}`, on the page's
  `visibilitychange`, `focus` and `blur` events. `seq` numbers the page's
  reports, which may arrive out of order: the server keeps the latest.

Request ids are JSON strings (protojson writes 64-bit integers as
strings).

The answer-to-`Decision` mapping (once, temp and always grants, "never"
as an exact deny, a grant never shrinks) stays in the session, behind the
`Answer` RPC: the folder scope of a grant depends on the session's
policy, which clients do not have. The terminal, `hallpass answer` and
the browser so offer the same choices with the same effect.

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
- **Host and Origin checks**: requests must carry a loopback `Host`
  (`127.0.0.1`, `localhost` or `[::1]`, any port, so an SSH port forward
  works). POSTs need a matching `Origin`; GETs are checked when the
  browser sends one. Stops DNS rebinding and cross-site requests.
- **Headers**: `Content-Security-Policy: default-src 'self';
  frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Cache-Control:
  no-store`. The page renders all session data as text, never as HTML.
- **Pairing code**: the page shows a short code ("Pairing code: 482 913"),
  and `hallpass web` asks on its own terminal "Pair the browser showing
  482 913? [y/n]". Once confirmed, the page gets a credential (random per
  `hallpass web` process) that it keeps in a JavaScript variable only and
  sends as an `Authorization` header: no cookie, no storage, nothing the
  browser writes to its profile. A new tab asks the paired tabs of the
  same origin for it (`BroadcastChannel`, which never leaves the browser
  nor crosses origins; each server has its own port, so its own origin),
  and checks it with `GET /api/sessions` before using it. With no paired
  tab open, or after a reload of the last one, the page pairs again. The
  URL holds no secret, so `--open` can pass it to
  `xdg-open`. The code only needs to be authentic, not secret: the sandbox
  can neither read nor answer `hallpass web`'s terminal. The risk is a
  sandboxed process starting its own pairing just before the browser, and
  the user confirming without comparing codes, so:
  - at most one pairing is pending: another request cancels both and
    warns that something else tried to pair. The user's browser always
    asks too, so a sandbox racing it shows up as that warning, never as a
    second code to tell apart;
  - a pairing expires after 60 seconds, or when its page goes away.

  Stops other users and web pages.
- **Blocked at the source, with network mediation**: a session that
  mediates the network (`--mediate=files,exec,network`) denies its
  sandbox every connection to the web UI's ports and to the session
  sockets, whatever the rules say (below). Without network mediation,
  `connect` is not looked at (notifying every `connect` in lite mode was
  rejected for its cost), so the hole below stays open.

### Protected denials

A few denials are in the `protected` rule set, which the monitor refuses
to remove or to extend with anything but denials without expiry
(`monitor.ErrProtected`, `PermissionDenied` on the session API). A deny
wins over any allow, `--allow-net=all` and the listener-inside rule
included, in the rule engine and in the BPF walk, so these denials hold
even after "allow all networking":

- with files mediated: writes under the socket directory
  (`$XDG_RUNTIME_DIR/hallpass`, or `/tmp/hallpass-UID`): no fake or
  removed session socket, no forged port file;
- with the network mediated: `connect`/`sendto` to the unix sockets under
  that directory (the sessions' answer sockets, which already reject
  sandboxed peers, now unreachable), and to the TCP/UDP ports registered
  by `hallpass web` and by the sessions' own web UIs, at any address.

They are shown with their label (`hallpass sessions`, `hallpass web UI`)
in the Ctrl-] menu and `hallpass policy`.

**How a session learns the ports.** `hallpass web` runs apart from the
sessions, and sessions start before or after it. It registers its ports
in the socket directory, in `web-<pid>.port` (one port per line: its
listening port, and with `--node` the loopback port-forward to the node
agent, whose session API needs no pairing), written as a temporary file
and renamed, and removes it when it exits (SIGINT/SIGTERM/SIGHUP
included; a file whose process is gone is ignored and removed by the
next registration). Each session that mediates the network:

1. creates its socket (and with it the directory);
2. watches the directory with inotify (`IN_MOVED_TO`, `IN_CLOSE_WRITE`);
3. reads the files already there, and fails to start if it cannot deny
   their ports;
4. then starts the sandbox.

`hallpass web` registers before it prints its URL, so a web UI
started first is denied before the sandbox runs, and one started later is
denied a few milliseconds after it registers, before anyone can pair a
browser with it. Each session only adds denials; it keeps them until it
exits. A file is trusted only if it is a regular file of this user (read
with `O_NOFOLLOW`) and its pid is alive; the directory is 0700, and the
sandbox cannot write to it.

A session's own web UI registers its port the same way, under the
session's pid, when it starts, and removes it when the session exits. A
session that mediates the network also denies the port to its own
sandbox right away, before the page opens, rather than when its watch
sees the file; if it cannot, the web UI does not start.
A push over the session API (web calling each session) was considered:
it needs the file anyway for sessions started later, and `hallpass web`
only discovers sessions when the page asks.

Limits: in lite mode the address is read from the sandbox's memory, which
it can change after the check (the TOCTOU gap of lite mode, see
[Network](../how-it-works/network.md)); strict mode checks the kernel's copy. A BPF prefix
holds 8 entries: many web UIs at once can exceed it; a session then
fails to start, or prints a warning for a later registration. In
Kubernetes, the node agent's session API listens on its own pod's
loopback, which no workload reaches, so no denial is needed there; a
local `hallpass web --node` through a port-forward registers the
forwarded port.

**Known hole without network mediation**: the sandbox can still connect
to 127.0.0.1. It cannot get the credential from the browser profile (it
is never written there) nor answer the pairing (asked on `hallpass web`'s
terminal), but it can start its own pairing and hope the user confirms
its code instead of the browser's; the rules above make that a visible
warning rather than a silent race. Where Yama's `ptrace_scope` is 0, the
sandbox (same user) could also read the credential from the browser's
memory. This is weaker than the terminal answer socket, which rejects
peers with a seccomp filter. It takes a deliberately malicious agent, not
an accident, so `hallpass web` ships as experimental and says so in
`--help` and its banner: the connection is only blocked when the network
is mediated, which is not the default.

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

1. Done: gRPC session service on the socket; `hallpass answer` ported;
   the socket line protocol removed.
2. Done: the terminal prompt is cancelled when another client answers;
   the answer mapping served by the `Answer` RPC.
3. Done: `hallpass web`: sessions, pending, answers, rules, activity;
   pairing, Host/Origin checks; marked experimental.
4. Facts filled by the monitor (secret store, listener in sandbox, ...).
5. Later: a backlog of `Decided` events in the monitor, replayed after
   `Snapshot`, so the activity view starts with the session; remote
   access (phone) with real authentication.
6. Done with network mediation: protected deny of `connect` to the web
   UI's ports and the session sockets, lite and strict
   ([Protected denials](#protected-denials)). Later: without network
   mediation; drop "experimental".

## Resolved questions

- A fake session socket in `$XDG_RUNTIME_DIR/hallpass/`: lite mode may
  not see the `bind()` that creates it, but `sessionapi.Dial` rejects a
  server that has a seccomp filter or whose pid is not the one in the
  socket name (see [Session API](#session-api-grpc)).

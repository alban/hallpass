# Web UI

!!! warning
    Experimental.

```console
hallpass web
```

`hallpass web` serves a page on 127.0.0.1 that shows every session of the user: the pending requests with the same answers as the terminal, the activity (every decided access, filterable) and the rules, which can be [edited](#editing-rules). Open the address it prints: the page shows a pairing code, and `hallpass web` asks in its terminal "Pair the browser showing 482 913? [y/n]". Answer `y` only if the page shows the same code. `--open` opens the page with `xdg-open`, `--listen` picks the address (loopback only).

<video src="../../assets/demos/web.mp4" poster="../../assets/demos/web.png" controls muted playsinline aria-label="a shell under hallpass on the left and hallpass web on the right: a write to ~/.bashrc denied from the browser, then ~/.local/bin allowed always"></video>

*The same request shows in the terminal and in the browser; answering in the browser takes the terminal prompt down.*

`--node ADDR` follows the sessions of a Kubernetes node agent instead of this user's (see [Kubernetes: answer requests](../kubernetes/answer.md)).

## Editing rules

The Rules tab of a session lists its rules. **Edit** turns a rule into a text field in the [rule syntax](index.md#editing-rules), for example to narrow `allow write ~/.cache/**` to `~/.cache/pip/**`; Enter saves, Esc cancels. **Delete** removes the rule, and **Add rule** adds one. An allow rule gives at most what answering "always" would; the page shows why a change is refused. Changes apply to this session only.

<video src="../../assets/demos/rule-edit.mp4" poster="../../assets/demos/rule-edit.png" controls muted playsinline aria-label="a shell under hallpass on the left and hallpass web on the right: ~/.local allowed always, its rule narrowed to ~/.local/bin in the Rules tab, a deny rule added, an allow of / refused, and the edited rule deleted"></video>

*Narrowing an "always" answer, adding a deny rule, and the limit: an allow rule cannot give more than "always" could.*

## From a session

A session can open a web UI for itself only: press Ctrl-] then `w` in its terminal, `w` in a terminal prompt, or click "Open web UI" on its desktop notification. hallpass opens the page with `xdg-open` and asks you to confirm its pairing code in the terminal's overlay, or in a second notification with [Pair] and [Cancel]. Each "open" lets one browser pair, within a minute. While the page has the focus, the session's requests get no desktop notification. The page links to `hallpass web` for all sessions.

## Security
The page keeps its credential in memory only, never in a cookie. A new tab of the same web UI takes it from an already paired tab, without a code; with no paired tab left, the page pairs again. The title says which web UI it is: "hallpass: session PID" or "hallpass web: all sessions". A sandboxed agent can still connect to the port and start its own pairing, hoping you confirm its code: compare the codes, and if `hallpass web` warns that something else tried to pair, find out what. Sessions that mediate the network (`--mediate=write,exec,connect`) deny their sandbox every connection to the web UI's port, and to the session sockets, even with `--allow-net=all`: no answer or rule lifts that. Without network mediation, the port is reachable. See [docs/devel/web.md](https://github.com/alban/hallpass/blob/main/docs/devel/web.md#security) and [protected denials](https://github.com/alban/hallpass/blob/main/docs/devel/web.md#protected-denials).

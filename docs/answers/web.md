# Web UI

!!! warning
    Experimental.

```console
hallpass web
```

`hallpass web` serves a page on 127.0.0.1 that shows every session of the user: the pending requests with the same answers as the terminal, the activity (every decided access, filterable) and the rules, which can be removed. Open the address it prints: the page shows a pairing code, and `hallpass web` asks in its terminal "Pair the browser showing 482 913? [y/n]". Answer `y` only if the page shows the same code. `--open` opens the page with `xdg-open`, `--listen` picks the address (loopback only).

<video src="../../assets/demos/web.mp4" poster="../../assets/demos/web.png" controls muted playsinline aria-label="a shell under hallpass on the left and hallpass web on the right: a write to ~/.bashrc denied from the browser, then ~/.local/bin allowed always"></video>

*The same request shows in the terminal and in the browser; answering in the browser takes the terminal prompt down.*

`--node ADDR` follows the sessions of a Kubernetes node agent instead of this user's (see [Kubernetes: answer requests](../kubernetes/answer.md)).

The page keeps its credential in memory only, never in a cookie: reloading it or opening a new tab means pairing again. A sandboxed agent can still connect to the port and start its own pairing, hoping you confirm its code: compare the codes, and if `hallpass web` warns that something else tried to pair, find out what. Sessions that mediate the network (`--mediate=files,exec,network`) deny their sandbox every connection to the web UI's port, and to the session sockets, even with `--allow-net=all`: no answer or rule lifts that. Without network mediation, the port is reachable. See [docs/devel/web.md](https://github.com/alban/hallpass/blob/main/docs/devel/web.md#security) and [protected denials](https://github.com/alban/hallpass/blob/main/docs/devel/web.md#protected-denials).

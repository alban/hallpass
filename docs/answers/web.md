# Web UI

!!! warning
    Experimental.

```console
hallpass web
```

`hallpass web` serves a page on 127.0.0.1 that shows every session of the user: the pending requests with the same answers as the terminal, the activity (every decided access, filterable) and the rules, which can be removed. It prints a pairing link that works once; press Enter in its terminal for a new one. `--open` opens it with `xdg-open`, `--listen` picks the address (loopback only).

<video src="../../assets/demos/web.mp4" poster="../../assets/demos/web.png" controls muted playsinline aria-label="a shell under hallpass on the left and hallpass web on the right: a write to ~/.bashrc denied from the browser, then ~/.local/bin allowed always"></video>

*The same request shows in the terminal and in the browser; answering in the browser takes the terminal prompt down.*

`--node ADDR` follows the sessions of a Kubernetes node agent instead of this user's (see [Kubernetes: answer requests](../kubernetes/answer.md)).

The browser keeps a cookie that a sandboxed agent could read from the profile, then use to answer its own requests. See [docs/devel/web.md](https://github.com/alban/hallpass/blob/main/docs/devel/web.md#security).

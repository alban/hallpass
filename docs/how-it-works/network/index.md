# Network (experimental)

With `--mediate=write,exec,connect` (or `mediate` in a [HallpassPolicy](../../kubernetes/policies.md)), connections and sends to an address are mediated like writes. Destinations are IPv4/IPv6 addresses and ports (TCP, UDP), unix socket files and abstract unix names; IPv4-mapped IPv6 addresses are shown and matched as IPv4. Rules match addresses; prompts also show [names](dns.md). See [Network](../../workstation/usage.md#network-experimental) for the rules and answers.

The only destination allowed without asking is a loopback or unix listener started inside the sandbox, such as a test server.

Neither are the resolvers' [address sorting probes](dns.md#address-sorting-probes).

## Lite mode

Syscalls paused: `connect`, `sendto` with an address, `sendmsg` and `sendmmsg` (their address is in a struct the filter cannot read); for [names](dns.md), `recvfrom` with an address and `recvmsg`, continued at once but on a socket redirected to the DNS forwarder.

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

The kernel has no rules for IP addresses and abstract unix names: every connection or send to one that the supervisor lets through, by a rule or an answer, gets a one-shot grant of that exact destination for the thread, and the hooks deny any other. A unix socket file is matched by the peer's inode, whatever path reached it, with the same walk as for [files](../files.md#strict-mode); a "once" answer for it becomes a grant too.

Maps:

| Map | Key → value | Relation | Written by |
|---|---|---|---|
| `rules` | as for files, with allow, ask and deny for the unix sockets bound at that path | one entry per path component | the supervisor |
| `sessions` | session → whether its own listeners are allowed, and the rules for every unix socket | 1:1 | the supervisor |
| `socks` | unix socket → the session that created it, a random id, and the last peer it was allowed to reach | 1:1, socket storage | the BPF programs |
| `grants` | thread → the destinations the supervisor let through: up to 4 addresses (`sendmmsg`), an abstract name, or a socket file's node | 1:1, per thread | the supervisor, before continuing; deleted when the syscall returns |

A unix connection or datagram to a socket file is allowed when the peer socket was created by the session. A unix socket remembers the last peer it was allowed to reach, so the datagrams of a connected socket, checked at each send, go through without a new grant.

TOCTOU: closed for the destination: the hooks see the address the kernel copied, and the peer socket.

See [Limitations](../limitations.md#network).


See also [Names (DNS)](dns.md) and the [HTTPS proxy](https.md).

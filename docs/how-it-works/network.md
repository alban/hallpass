# Network (experimental)

With `--mediate=write,exec,connect` (or `mediate` in a [HallpassPolicy](../kubernetes/policies.md)), connections and sends to an address are mediated like writes. Destinations are IPv4/IPv6 addresses and ports (TCP, UDP), unix socket files and abstract unix names; IPv4-mapped IPv6 addresses are shown and matched as IPv4. Rules match addresses; prompts also show [names](#names). See [Network](../workstation/usage.md#network-experimental) for the rules and answers.

The only destination allowed without asking is a loopback or unix listener started inside the sandbox, such as a test server.

## Lite mode

Syscalls paused: `connect`, `sendto` with an address, `sendmsg` and `sendmmsg` (their address is in a struct the filter cannot read); for [names](#names), `recvfrom` with an address and `recvmsg`, continued at once but on a socket redirected to the DNS forwarder.

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

The kernel has no rules for IP addresses and abstract unix names: every connection or send to one that the supervisor lets through, by a rule or an answer, gets a one-shot grant of that exact destination for the thread, and the hooks deny any other. A unix socket file is matched by the peer's inode, whatever path reached it, with the same walk as for [files](files.md#strict-mode); a "once" answer for it becomes a grant too.

Maps:

| Map | Key → value | Relation | Written by |
|---|---|---|---|
| `rules` | as for files, with allow, ask and deny for the unix sockets bound at that path | one entry per path component | the supervisor |
| `sessions` | session → whether its own listeners are allowed, and the rules for every unix socket | 1:1 | the supervisor |
| `socks` | unix socket → the session that created it, a random id, and the last peer it was allowed to reach | 1:1, socket storage | the BPF programs |
| `grants` | thread → the destinations the supervisor let through: up to 4 addresses (`sendmmsg`), an abstract name, or a socket file's node | 1:1, per thread | the supervisor, before continuing; deleted when the syscall returns |

A unix connection or datagram to a socket file is allowed when the peer socket was created by the session. A unix socket remembers the last peer it was allowed to reach, so the datagrams of a connected socket, checked at each send, go through without a new grant.

TOCTOU: closed for the destination: the hooks see the address the kernel copied, and the peer socket.

See [Limitations](limitations.md#network).

## Names

Connect prompts name the address: `github.com (140.82.112.3:443)`. On a workstation, with `--dns=observe` (the default of `hallpass`), the sandbox's DNS queries go through a forwarder of hallpass's, which reads the answers; on Kubernetes, hallpass-node relays them (see [below](#names-on-kubernetes)).

- Before the sandbox starts, hallpass starts a forwarder for each name server of the host's `/etc/resolv.conf` (read when the session starts), listening on a port the kernel picks on `127.0.0.1` (or `[::1]`). An allowed `connect`, or UDP `sendto` with an address, to port 53 of one of those servers is done by the supervisor on a copy of the sandbox's socket (`pidfd_getfd`: the same socket, whichever descriptor of it the sandbox uses next), to the forwarder instead. On such a socket, a receive that asks for the source (`recvfrom` with an address, `recvmsg`) is done by the supervisor too, with the forwarder's address replaced by the server's: resolvers check it (glibc, musl). Go's resolver reads with `read`, which needs nothing. UDP and TCP, connected or not.
- The rules see the real name server: a sandbox denied DNS gets no forwarding. The forwarder's ports are denied to the sandbox (protected rules): it reaches them only through the redirect.
- Not redirected: `sendmsg` and `sendmmsg` with the server's address (no resolver sends so), and TCP fast open. Such queries go to the server, and their answers name nothing.
- The forwarder's own sockets are made in the sandbox's network namespace: queries leave as the sandbox's would. Replies are passed on byte for byte. It records only replies that answer a query it sent (same ID and question).
- Costs: every `recvmsg` of the sandbox, and every `recvfrom` with an address, is paused, to tell whether it is on a redirected socket (see [Limitations](limitations.md#network)). A blocking receive on a redirected socket waits in the supervisor: a signal the sandbox catches does not interrupt it (its `SO_RCVTIMEO` is kept). `getpeername` on a redirected socket gives the forwarder. hallpass remembers the last 4096 redirected sockets: DNS fails on an older one still in use.
- Needs Linux 5.14 (`SO_NETNS_COOKIE`: only the sockets of the sandbox's network namespace are redirected); without it, no names.
- Names come only from answers the sandbox got through hallpass: an address is named only with a name whose answer had it. A sandbox asking about `github.com` and connecting elsewhere gets no name. hallpass sends no query of its own for a name.
- A name stays on its addresses for 5 minutes, at least: programs keep answers past their TTL.
- systemd-resolved's varlink socket (`/run/systemd/resolve/io.systemd.Resolve`), which glibc programs use instead of port 53 on Fedora and Arch (`resolve` in `nsswitch.conf`): when the sandbox's `connect` to it is allowed, hallpass connects to resolved itself and puts one end of a socket pair in place of the sandbox's socket, then passes the messages both ways. The names come from resolved's own answers, so they are the addresses the program gets; resolved sees hallpass's user, the same as the program's. Only this socket is relayed. Socket options set before the `connect` are lost, which resolved's clients do not use.
- An address with no name from the above is shown with the names of its reverse DNS (PTR), marked unverified: `140.82.112.3:443 (reverse DNS, unverified: lb-140-82-112-3-iad.github.com)`. Whoever controls the address chooses them. hallpass makes that lookup only once the sandbox got an answer through hallpass (the forwarder or the varlink socket), through the host's name servers, so a sandbox denied DNS cannot use it to send data out.
- Host rules (`allow connect github.com:443`) match these names, in lite and strict mode: the relayed answers, never the reverse DNS names.

### HTTPS requests

For the hosts with `http` rules, see [HTTPS requests](../workstation/usage.md#https-requests-experimental). The swap happens at the `connect`, in lite and strict mode alike (no kernel `connect` happens for a swapped socket); `http` rules are the proxy's alone, never in the kernel. Costs of the swap: socket options set before the `connect` are lost, a non-blocking `connect` succeeds at once instead of `EINPROGRESS`, and one more loopback connection per connection.

### Names on Kubernetes

A container that mediates `connect` has its DNS queries redirected to a forwarder of hallpass-node's, as on a workstation (see [above](#names)), which reads the answers:

- Before the container's program starts, hallpass-node starts a forwarder for each name server of the container's `/etc/resolv.conf`, listening on a port the kernel picks on `127.0.0.1` (or `[::1]`) of the pod's network namespace. The container's monitor redirects its queries to port 53 of those servers there.
- The forwarder's own sockets are made in the pod's network namespace: queries leave from the pod's address, and NetworkPolicy still applies.
- The name servers are those of `/etc/resolv.conf` when the container starts: one the container writes later is not used.
- The container is denied its forwarder's ports, and so are the other mediated containers of the same pod (or of the node, with `hostNetwork: true`): they share its loopback.
- A container restored from the fd-store after hallpass-node restarted has no names.
- A container with `CAP_NET_RAW` (containerd's default) can sniff the forwarder's query and forge its reply: its names are shown in prompts but never matched by host rules (the started Event says so). Drop `NET_RAW` from the container's capabilities for host rules.
- The name servers are the container's own, which the pod's author chooses (`dnsConfig`): a host rule trusts them. Where pod authors are not trusted, prefer address rules, or the HTTPS proxy, which checks the servers' certificates.

# Names (DNS)

Connect prompts name the address: `github.com (140.82.112.3:443)`. With `--dns=observe` (the default of `hallpass`), the sandbox's DNS queries go through a forwarder of hallpass's, which reads the answers. On Kubernetes, hallpass-node does the same (see [below](#kubernetes)).

Before the sandbox starts, hallpass starts a forwarder for each name server of `/etc/resolv.conf`, on a port the kernel picks on `127.0.0.1` (or `[::1]`). An allowed `connect`, or UDP `sendto` with an address, to port 53 of one of those servers is done by the supervisor to the forwarder instead, on a copy of the sandbox's socket (`pidfd_getfd`: the same socket, whichever descriptor of it the sandbox uses next). On such a socket, a receive that asks for the source (`recvfrom` with an address, `recvmsg`) is done by the supervisor too, with the forwarder's address replaced by the server's: resolvers check it. UDP and TCP, connected or not. How each resolver goes through it:

## Workstation

=== "Go"

    Go's resolver connects a UDP socket per query type, then uses `write` and `read`, which are not trapped.

    ![DNS with Go's resolver on a workstation: the program's UDP connect to the name server is trapped and done to hallpass's DNS forwarder instead; the forwarder relays the query and records the answer; the program's later connect to the answer's address is trapped, matched against the rules of the name, and continued.](../../assets/diagrams/dns-go-workstation.svg#only-light)
    ![DNS with Go's resolver on a workstation: the program's UDP connect to the name server is trapped and done to hallpass's DNS forwarder instead; the forwarder relays the query and records the answer; the program's later connect to the answer's address is trapped, matched against the rules of the name, and continued.](../../assets/diagrams/dns-go-workstation-dark.svg#only-dark)

=== "glibc"

    glibc connects, sends both queries with one `sendmmsg` (no address: it continues), and checks the source of each answer with `recvfrom`. With `resolve` in `nsswitch.conf` (Fedora, Arch), glibc asks systemd-resolved's varlink socket instead: see the Go/cgo tab.

    ![DNS with glibc on a workstation: the UDP connect to systemd-resolved is trapped and done to hallpass's DNS forwarder instead; sendmmsg has no address and continues; the forwarder relays the queries and records the answers; recvfrom is done by the supervisor, which gives the name server as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-glibc-workstation.svg#only-light)
    ![DNS with glibc on a workstation: the UDP connect to systemd-resolved is trapped and done to hallpass's DNS forwarder instead; sendmmsg has no address and continues; the forwarder relays the queries and records the answers; recvfrom is done by the supervisor, which gives the name server as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-glibc-workstation-dark.svg#only-dark)

=== "musl"

    musl does not connect: it sends each query with `sendto` to the server's address, and reads the answers with `recvmsg`.

    ![DNS with musl on a workstation: each sendto to systemd-resolved is trapped and sent to hallpass's DNS forwarder instead; the forwarder relays the queries and records the answers; recvmsg is done by the supervisor, which gives the name server as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-musl-workstation.svg#only-light)
    ![DNS with musl on a workstation: each sendto to systemd-resolved is trapped and sent to hallpass's DNS forwarder instead; the forwarder relays the queries and records the answers; recvmsg is done by the supervisor, which gives the name server as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-musl-workstation-dark.svg#only-dark)

=== "Go/cgo"

    Go with cgo resolves through glibc: on Ubuntu, as in the glibc tab. With `resolve` in `nsswitch.conf` (Fedora, Arch), glibc asks systemd-resolved's varlink socket (`/run/systemd/resolve/io.systemd.Resolve`) instead of port 53. hallpass relays it:

    ![DNS through systemd-resolved's varlink socket on a workstation: the program's connect to the socket is trapped; hallpass connects to resolved itself and puts one end of a socket pair in place of the program's socket; it relays the messages and records the addresses of resolved's answers; the connect to an answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-cgo-workstation.svg#only-light)
    ![DNS through systemd-resolved's varlink socket on a workstation: the program's connect to the socket is trapped; hallpass connects to resolved itself and puts one end of a socket pair in place of the program's socket; it relays the messages and records the addresses of resolved's answers; the connect to an answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-cgo-workstation-dark.svg#only-dark)

    The names come from resolved's own answers, so they are the addresses the program gets. resolved sees hallpass's user, the same as the program's. Only this socket is relayed. Socket options set before the `connect` are lost, which resolved's clients do not use.

## What names match

- The rules see the real name server: a sandbox denied DNS gets no forwarding.
- Names come only from answers the sandbox got through hallpass: an address is named only with a name whose answer had it. A sandbox asking about `github.com` and connecting elsewhere gets no name. hallpass sends no query of its own for a name.
- The forwarder passes replies on byte for byte. It records only replies that answer a query it sent (same ID and question).
- A name stays on its addresses for 5 minutes, at least: programs keep answers past their TTL.
- An address with no name from the above is shown with the names of its reverse DNS (PTR), marked unverified: `140.82.112.3:443 (reverse DNS, unverified: lb-140-82-112-3-iad.github.com)`. Whoever controls the address chooses them. hallpass makes that lookup only once the sandbox got an answer through hallpass (the forwarder or the varlink socket), through the host's name servers, so a sandbox denied DNS cannot use it to send data out.
- Host rules (`allow connect github.com:443`) match these names, in lite and strict mode: the relayed answers, never the reverse DNS names.

## Limits

- The forwarder's sockets are made in the sandbox's network namespace: queries leave as the sandbox's would.
- The forwarder's ports are denied to the sandbox (protected rules): it reaches them only through the redirect. They are not denied to other programs of the host, other hallpass sessions included: their queries through it name addresses in this session too (see [Limitations](../limitations.md#network)).
- Not redirected: `sendmsg` and `sendmmsg` with the server's address (no resolver sends so), and TCP fast open. Such queries go to the server, and their answers name nothing.
- Costs: every `recvmsg` of the sandbox, and every `recvfrom` with an address, is paused, to tell whether it is on a redirected socket (see [Limitations](../limitations.md#network)). A blocking receive on a redirected socket waits in the supervisor: a signal the sandbox catches does not interrupt it (its `SO_RCVTIMEO` is kept). `getpeername` on a redirected socket gives the forwarder.
- hallpass remembers the last 4096 redirected sockets: DNS fails on an older one still in use.
- Needs Linux 5.14 (`SO_NETNS_COOKIE`: only the sockets of the sandbox's network namespace are redirected); without it, no names.

## Kubernetes

A container that mediates `connect` has its DNS queries redirected to a forwarder of hallpass-node's, as on a workstation. hallpass-node runs in the node's network namespace, but makes the forwarder's sockets in the pod's, with a thread that joined it: the forwarder listens on the pod's loopback, and queries leave from the pod's address, so NetworkPolicy still applies. There is no varlink relay: the name servers are those of the container's `/etc/resolv.conf`, usually kube-dns.

=== "Go"

    ![DNS with Go's resolver on Kubernetes: hallpass-node, in the node's network namespace, starts a forwarder in the pod's; the program's UDP connect to kube-dns is trapped and done to the forwarder instead; the forwarder queries kube-dns from the pod's address and records the answer; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-go-k8s.svg#only-light)
    ![DNS with Go's resolver on Kubernetes: hallpass-node, in the node's network namespace, starts a forwarder in the pod's; the program's UDP connect to kube-dns is trapped and done to the forwarder instead; the forwarder queries kube-dns from the pod's address and records the answer; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-go-k8s-dark.svg#only-dark)

=== "glibc"

    ![DNS with glibc on Kubernetes: hallpass-node starts a forwarder in the pod's network namespace; the UDP connect to kube-dns is trapped and done to the forwarder instead; sendmmsg continues; the forwarder queries kube-dns and records the answers; recvfrom is done by the supervisor, which gives kube-dns as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-glibc-k8s.svg#only-light)
    ![DNS with glibc on Kubernetes: hallpass-node starts a forwarder in the pod's network namespace; the UDP connect to kube-dns is trapped and done to the forwarder instead; sendmmsg continues; the forwarder queries kube-dns and records the answers; recvfrom is done by the supervisor, which gives kube-dns as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-glibc-k8s-dark.svg#only-dark)

=== "musl"

    ![DNS with musl on Kubernetes: hallpass-node starts a forwarder in the pod's network namespace; each sendto to kube-dns is trapped and sent to the forwarder instead; the forwarder queries kube-dns and records the answers; recvmsg is done by the supervisor, which gives kube-dns as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-musl-k8s.svg#only-light)
    ![DNS with musl on Kubernetes: hallpass-node starts a forwarder in the pod's network namespace; each sendto to kube-dns is trapped and sent to the forwarder instead; the forwarder queries kube-dns and records the answers; recvmsg is done by the supervisor, which gives kube-dns as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-musl-k8s-dark.svg#only-dark)

=== "Go/cgo"

    As glibc: there is no varlink relay on Kubernetes.

    ![DNS with glibc, or Go with cgo, on Kubernetes: hallpass-node starts a forwarder in the pod's network namespace; the UDP connect to kube-dns is trapped and done to the forwarder instead; sendmmsg continues; the forwarder queries kube-dns and records the answers; recvfrom is done by the supervisor, which gives kube-dns as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-glibc-k8s.svg#only-light)
    ![DNS with glibc, or Go with cgo, on Kubernetes: hallpass-node starts a forwarder in the pod's network namespace; the UDP connect to kube-dns is trapped and done to the forwarder instead; sendmmsg continues; the forwarder queries kube-dns and records the answers; recvfrom is done by the supervisor, which gives kube-dns as the source; the connect to the answer's address is matched against the rules of the name and continued.](../../assets/diagrams/dns-glibc-k8s-dark.svg#only-dark)

Differences from a workstation:

- The name servers are those of `/etc/resolv.conf` when the container starts: one the container writes later is not used.
- The container is denied its forwarder's ports, and so are the other mediated containers of the same pod (or of the node, with `hostNetwork: true`): they share its loopback.
- A container restored from the fd-store after hallpass-node restarted has no names.
- The name servers are the container's own, which the pod's author chooses (`dnsConfig`): a host rule trusts them. Where pod authors are not trusted, prefer address rules, or the HTTPS proxy, which checks the servers' certificates.

### CAP_NET_RAW

A container that may have `CAP_NET_RAW` can sniff the forwarder's query and forge its reply:

![A container with CAP_NET_RAW on Kubernetes: hallpass-node reads the container's config.json and makes its names display-only; the program sniffs the forwarder's query to kube-dns with a raw socket and sends a forged answer first, which the forwarder records; its connect to the forged address is shown with the name, but host rules ignore it, and port 443 is denied when the session has http rules or credentials.](../../assets/diagrams/dns-cap-net-raw.svg#only-light)
![A container with CAP_NET_RAW on Kubernetes: hallpass-node reads the container's config.json and makes its names display-only; the program sniffs the forwarder's query to kube-dns with a raw socket and sends a forged answer first, which the forwarder records; its connect to the forged address is shown with the name, but host rules ignore it, and port 443 is denied when the session has http rules or credentials.](../../assets/diagrams/dns-cap-net-raw-dark.svg#only-dark)

So its names are shown in prompts but never matched by host rules, and with `http` rules or credentials it is denied port 443 (the started Event says so). hallpass-node reads the capabilities in the container's OCI config (`config.json` of its bundle, under `--host-root`): `CAP_NET_RAW` in any set, containerd's default, or a config it cannot read or without capabilities, counts. Drop `NET_RAW` from the container's capabilities for host and `http` rules.

# HTTPS proxy

A connection to port 443 of a host with `http` rules, or of a credential's host, goes through hallpass's proxy, which decides each request. The host is known by the [names](dns.md) of the address. For the rules and the credentials, see [HTTPS requests](../../workstation/usage.md#https-requests-experimental) and [Credentials](../../workstation/usage.md#credentials-experimental).

## The swap

The monitor does not let the kernel connect: it puts one end of a loopback TCP connection in place of the program's socket (`SECCOMP_IOCTL_NOTIF_ADDFD`), and gives the other end to the proxy.

![HTTPS through hallpass's proxy on a workstation: curl's connect to api.github.com:443 is trapped; the name has http rules, so the monitor makes a loopback TCP pair and puts one end in place of curl's socket; curl's TLS reaches the proxy, which answers with a certificate of the session's CA, decides the request with the http rules, and sends it to api.github.com over TLS checked against the system's roots.](../../assets/diagrams/https-proxy-workstation.svg#only-light)
![HTTPS through hallpass's proxy on a workstation: curl's connect to api.github.com:443 is trapped; the name has http rules, so the monitor makes a loopback TCP pair and puts one end in place of curl's socket; curl's TLS reaches the proxy, which answers with a certificate of the session's CA, decides the request with the http rules, and sends it to api.github.com over TLS checked against the system's roots.](../../assets/diagrams/https-proxy-workstation-dark.svg#only-dark)

The swap happens at the `connect`, in lite and strict mode alike: no kernel `connect` happens for a swapped socket. `http` rules are the proxy's alone, never in the kernel.

Costs of the swap:

- socket options set before the `connect` are lost;
- a non-blocking `connect` succeeds at once instead of `EINPROGRESS`;
- one more loopback connection per connection.

## Kubernetes

hallpass-node runs in the node's network namespace, but makes the loopback pair, and its own connections to the servers, in the pod's: the servers see the pod's address, and NetworkPolicy applies as if the container connected.

![HTTPS through hallpass-node's proxy on Kubernetes: the monitor, in the node's network namespace, traps the container's connect to api.github.com:443; it makes a loopback TCP pair in the pod's network namespace and puts one end in place of the container's socket; the proxy answers with a certificate of the container's CA, trusted through /run/hallpass-trust/, and sends allowed requests to the server from the pod's address, checked against hallpass-node's roots.](../../assets/diagrams/https-proxy-k8s.svg#only-light)
![HTTPS through hallpass-node's proxy on Kubernetes: the monitor, in the node's network namespace, traps the container's connect to api.github.com:443; it makes a loopback TCP pair in the pod's network namespace and puts one end in place of the container's socket; the proxy answers with a certificate of the container's CA, trusted through /run/hallpass-trust/, and sends allowed requests to the server from the pod's address, checked against hallpass-node's roots.](../../assets/diagrams/https-proxy-k8s-dark.svg#only-dark)

The servers are checked with hallpass-node's roots, never the container's. A container that may have `CAP_NET_RAW` can forge its names: see [CAP_NET_RAW](dns.md#cap_net_raw).

## Credentials

The sandbox gets a placeholder; the proxy holds the token and puts it on the wire, only towards the credential's hosts.

![A credential put on the wire by the proxy: gh, in the sandbox, has a placeholder in GH_TOKEN; its connect to api.github.com:443 is swapped to the proxy; the proxy replaces the placeholder by the token in the Authorization header only, sends the request over TLS checked against the system's roots, and replaces the token by the placeholder in the answer's headers.](../../assets/diagrams/https-credentials.svg#only-light)
![A credential put on the wire by the proxy: gh, in the sandbox, has a placeholder in GH_TOKEN; its connect to api.github.com:443 is swapped to the proxy; the proxy replaces the placeholder by the token in the Authorization header only, sends the request over TLS checked against the system's roots, and replaces the token by the placeholder in the answer's headers.](../../assets/diagrams/https-credentials-dark.svg#only-dark)

## Without the proxy

A session with `http` rules or credentials but no proxy, or no names its rules can match (`--dns=off`, names for display only), is denied port 443, TCP and UDP (reason `no-proxy`), whatever its `connect` rules allow. Its `http` rules are not ignored, nor a placeholder sent. Other ports follow the rules.

![Port 443 without the proxy: with http rules or credentials but no proxy or no names, the monitor denies a connect or a UDP sendto to port 443 whatever the rules, while a connect to port 22 is decided by the rules and continued.](../../assets/diagrams/https-no-proxy.svg#only-light)
![Port 443 without the proxy: with http rules or credentials but no proxy or no names, the monitor denies a connect or a UDP sendto to port 443 whatever the rules, while a connect to port 22 is decided by the rules and continued.](../../assets/diagrams/https-no-proxy-dark.svg#only-dark)


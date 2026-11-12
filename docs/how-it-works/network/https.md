# HTTPS proxy

For the hosts with `http` rules, see [HTTPS requests](../../workstation/usage.md#https-requests-experimental). The swap happens at the `connect`, in lite and strict mode alike (no kernel `connect` happens for a swapped socket); `http` rules are the proxy's alone, never in the kernel. Costs of the swap: socket options set before the `connect` are lost, a non-blocking `connect` succeeds at once instead of `EINPROGRESS`, and one more loopback connection per connection.


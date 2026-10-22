// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright The hallpass Authors */

/*
 * DNS redirect (hallpass-node): cgroup sock_addr programs attached to one
 * mediated container's cgroup. A connect or a send to port 53 of one of
 * the container's name servers goes to that server's forwarder listener,
 * on the loopback of the container's network namespace; a datagram
 * received from a listener shows the name server as its source, so the
 * stub resolver accepts the reply. The forwarder relays the queries and
 * reads the answers: hallpass names the addresses the container connects
 * to with the answers it really got.
 *
 * Addresses are kept as IPv6, an IPv4 one mapped (::ffff:a.b.c.d), in
 * network byte order. One instance per container: its maps hold that
 * container's routes only, filled before attaching, read-only after.
 */

#include "vmlinux.h"
#include "bpf_helpers.h"

/* bpf2go builds for little-endian targets only (bpfel). */
#define bpf_htons(x) ((__u16)__builtin_bswap16(x))
#define bpf_htonl(x) ((__u32)__builtin_bswap32(x))
#define bpf_ntohl(x) bpf_htonl(x)

#define DNS_PORT 53
#define MAX_ROUTES 16

struct hp_addr6 {
	__u32 a[4];
};

struct hp_dns_listener {
	struct hp_addr6 addr; /* 127.0.0.1 (mapped) or ::1 */
	__u32 port;        /* network byte order, in the low 16 bits */
};

/* name server -> its listener */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ROUTES);
	__type(key, struct hp_addr6);
	__type(value, struct hp_dns_listener);
} routes SEC(".maps");

/* listener -> its name server */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ROUTES);
	__type(key, struct hp_dns_listener);
	__type(value, struct hp_addr6);
} back SEC(".maps");

static __always_inline void mapped(struct hp_addr6 *x, __u32 ip4)
{
	x->a[0] = 0;
	x->a[1] = 0;
	x->a[2] = bpf_htonl(0xffff);
	x->a[3] = ip4;
}

static __always_inline int is_mapped(const struct hp_addr6 *x)
{
	return x->a[0] == 0 && x->a[1] == 0 && x->a[2] == bpf_htonl(0xffff);
}

static __always_inline int loopback4(__u32 ip4)
{
	return (bpf_ntohl(ip4) >> 24) == 127;
}

/*
 * A socket bound to an address that is not a loopback one cannot reach
 * the listener: it is left alone (its query goes to the server, unnamed).
 */
static __always_inline int bound_elsewhere4(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	__u32 src;

	if (!sk)
		return 1;
	src = sk->src_ip4;
	return src != 0 && !loopback4(src);
}

static __always_inline int bound_elsewhere6(struct bpf_sock_addr *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	struct hp_addr6 src;

	if (!sk)
		return 1;
	src.a[0] = sk->src_ip6[0];
	src.a[1] = sk->src_ip6[1];
	src.a[2] = sk->src_ip6[2];
	src.a[3] = sk->src_ip6[3];
	if (!src.a[0] && !src.a[1] && !src.a[2] && !src.a[3])
		return 0;
	if (is_mapped(&src))
		return src.a[3] != 0 && !loopback4(src.a[3]);
	/* ::1 */
	return !(src.a[0] == 0 && src.a[1] == 0 && src.a[2] == 0 && src.a[3] == bpf_htonl(1));
}

static __always_inline int to_listener4(struct bpf_sock_addr *ctx)
{
	struct hp_addr6 ns;
	struct hp_dns_listener *l;

	if (ctx->user_port != bpf_htons(DNS_PORT))
		return 1;
	mapped(&ns, ctx->user_ip4);
	l = bpf_map_lookup_elem(&routes, &ns);
	if (!l || !is_mapped(&l->addr) || bound_elsewhere4(ctx))
		return 1;
	ctx->user_ip4 = l->addr.a[3];
	ctx->user_port = l->port;
	return 1;
}

static __always_inline int to_listener6(struct bpf_sock_addr *ctx)
{
	struct hp_addr6 ns;
	struct hp_dns_listener *l;

	if (ctx->user_port != bpf_htons(DNS_PORT))
		return 1;
	ns.a[0] = ctx->user_ip6[0];
	ns.a[1] = ctx->user_ip6[1];
	ns.a[2] = ctx->user_ip6[2];
	ns.a[3] = ctx->user_ip6[3];
	l = bpf_map_lookup_elem(&routes, &ns);
	/* An IPv4 server reached as mapped goes to the mapped IPv4 listener. */
	if (!l || is_mapped(&ns) != is_mapped(&l->addr) || bound_elsewhere6(ctx))
		return 1;
	ctx->user_ip6[0] = l->addr.a[0];
	ctx->user_ip6[1] = l->addr.a[1];
	ctx->user_ip6[2] = l->addr.a[2];
	ctx->user_ip6[3] = l->addr.a[3];
	ctx->user_port = l->port;
	return 1;
}

SEC("cgroup/connect4")
int hp_dns_connect4(struct bpf_sock_addr *ctx)
{
	return to_listener4(ctx);
}

SEC("cgroup/connect6")
int hp_dns_connect6(struct bpf_sock_addr *ctx)
{
	return to_listener6(ctx);
}

SEC("cgroup/sendmsg4")
int hp_dns_sendmsg4(struct bpf_sock_addr *ctx)
{
	return to_listener4(ctx);
}

SEC("cgroup/sendmsg6")
int hp_dns_sendmsg6(struct bpf_sock_addr *ctx)
{
	return to_listener6(ctx);
}

SEC("cgroup/recvmsg4")
int hp_dns_recvmsg4(struct bpf_sock_addr *ctx)
{
	struct hp_dns_listener l = {};
	struct hp_addr6 *ns;

	mapped(&l.addr, ctx->user_ip4);
	l.port = ctx->user_port;
	ns = bpf_map_lookup_elem(&back, &l);
	if (ns && is_mapped(ns)) {
		ctx->user_ip4 = ns->a[3];
		ctx->user_port = bpf_htons(DNS_PORT);
	}
	return 1;
}

SEC("cgroup/recvmsg6")
int hp_dns_recvmsg6(struct bpf_sock_addr *ctx)
{
	struct hp_dns_listener l = {};
	struct hp_addr6 *ns;

	l.addr.a[0] = ctx->user_ip6[0];
	l.addr.a[1] = ctx->user_ip6[1];
	l.addr.a[2] = ctx->user_ip6[2];
	l.addr.a[3] = ctx->user_ip6[3];
	l.port = ctx->user_port;
	ns = bpf_map_lookup_elem(&back, &l);
	if (ns) {
		ctx->user_ip6[0] = ns->a[0];
		ctx->user_ip6[1] = ns->a[1];
		ctx->user_ip6[2] = ns->a[2];
		ctx->user_ip6[3] = ns->a[3];
		ctx->user_port = bpf_htons(DNS_PORT);
	}
	return 1;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

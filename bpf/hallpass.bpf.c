// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright The hallpass Authors */

/*
 * Strict mode: BPF-LSM programs that enforce the session's policy on the
 * objects the kernel is about to modify, after any symlink, bind mount or
 * rename race has been resolved.
 *
 * Only tasks of a sandbox ("members") are checked, each against the rules of
 * its session: one instance of the programs serves every session of a node
 * (the containers of the node agent). A file is named by the
 * path inside its filesystem: the d_parent chain from the dentry up to the
 * filesystem root, without crossing mounts. The supervisor translates its
 * rules to these names with the session's mountinfo, so a rule
 * follows the files whichever bind mount or mount namespace they are reached
 * through.
 */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define EPERM 1
#define ENOMEM 12
#define EACCES 13
#define MAX_DEPTH 64
#define NAME_LEN 256
#define PATH_LEN 4096
#define PROC_NAME_LEN 32
#define COMM_LEN 16

#define FMODE_WRITE 0x2
/* Stable: ERR_PTR(-EINVAL), and the uapi MS_KERNMOUNT. */
#define MNT_NS_INTERNAL ((void *)-22L)
#define SB_KERNMOUNT (1UL << 22)
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define O_TRUNC 01000
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define SB_NOUSER (1UL << 31)
#define PROC_SUPER_MAGIC 0x9fa0
#define ROOT_COOKIE (1ULL << 63)
#define FOREVER (~0ULL)

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define MSG_FASTOPEN 0x20000000

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define hp_ntohs(x) __builtin_bswap16(x)
#else
#define hp_ntohs(x) (x)
#endif

/*
 * One rule node per path component: {parent cookie, name}. The root of a
 * filesystem is ROOT_COOKIE | s_dev; its own rules live under the empty name.
 * Expiries are bpf_ktime_get_ns() deadlines, FOREVER, or 0 (none).
 *
 * An ask rule is a cut-off: no allow inherited from above the node. The
 * access is then denied unless an allow below it, or the thread's grant
 * (the answer to the prompt), allows it. At one node, the ask wins over
 * the allow (the supervisor drops an ask shallower than the allow, which
 * only happens when rules reach the node through different mounts), and
 * the exact rules come after the tree ones.
 */
struct rule_key {
	__u64 parent;
	__u32 session;
	__u32 pad;
	char name[NAME_LEN];
};

struct rule_val {
	__u64 cookie;      /* parent cookie of this node's children */
	__u64 allow_tree;  /* allows this node and everything below */
	__u64 allow_exact; /* allows this node only */
	/* The same, for connections and sends to unix sockets bound there. */
	__u64 net_allow_tree;
	__u64 net_allow_exact;
	/* Ask rules: the expiry of the cut-off, as for allows. */
	__u64 ask_tree;
	__u64 ask_exact;
	__u64 net_ask_tree;
	__u64 net_ask_exact;
	__u8 deny_tree;
	__u8 deny_exact;
	__u8 net_deny_tree;
	__u8 net_deny_exact;
	__u8 pad[4];
};

/*
 * Writes to /proc/<pid>/<name> of a process outside the sandbox. A multiple
 * of 8 bytes: proc_granted compares it word by word.
 */
struct proc_key {
	char name[PROC_NAME_LEN];
	char comm[COMM_LEN];
	__u32 session;
	__u32 pad;
};

struct proc_val {
	__u64 allow; /* expiry, as in rule_val */
	__u64 ask;   /* an ask rule on the same key wins over the allow */
	__u8 deny;
	__u8 pad[7];
};

#define GRANT_NODES 2
#define GRANT_INET 4
#define UNIX_NAME_LEN 108

/* An inet destination: the address IPv4-mapped for IPv4. */
struct grant_inet {
	__u8 addr[16];
	__u16 port;
	__u16 proto;
	__u8 set;
	__u8 pad[3];
};

/*
 * "Allow once": what the user allowed for the syscall a member thread is
 * blocked in, waiting for the supervisor. Set by the supervisor before it
 * lets the syscall continue, and removed when the syscall returns
 * (hp_sys_exit), so that neither another thread nor a later syscall can use
 * it.
 */
struct hp_grant {
	__u64 seq;		   /* for the supervisor, to tell its grants apart */
	__u64 nodes[GRANT_NODES]; /* rule nodes allowed exactly: one per path of the syscall (rename, link: 2) */
	struct proc_key proc;	   /* proc.name[0] == 0: none */
	struct grant_inet inet[GRANT_INET]; /* sendmmsg: several */
	__u32 abstract_set;
	__u32 abstract_len;
	char abstract[UNIX_NAME_LEN]; /* abstract unix name, without the leading NUL */
};

enum hp_op {
	HP_OP_OPEN = 1,
	HP_OP_CREATE,
	HP_OP_MKDIR,
	HP_OP_RMDIR,
	HP_OP_UNLINK,
	HP_OP_SYMLINK,
	HP_OP_LINK,
	HP_OP_RENAME,
	HP_OP_TRUNCATE,
	HP_OP_CONNECT,
	HP_OP_SEND,
};

struct event {
	__u64 ts;
	__u32 pid; /* tgid, initial pid namespace */
	__u32 op;
	__s32 ret;
	__u32 session;
	char comm[COMM_LEN];
	char name[NAME_LEN]; /* last component, for operations on a directory entry */
	char path[PATH_LEN]; /* d_path of the file or of its directory */
	/*
	 * Network ops: family AF_INET6 (IPv4 mapped) with addr, port and
	 * proto; or AF_UNIX, with an abstract name of name_len bytes in path,
	 * or else the name of the socket file in name.
	 */
	__u16 family;
	__u16 port;
	__u16 proto;
	__u16 name_len;
	__u8 addr[16];
};

/* Keeps struct event in the BTF for bpf2go -type. */
const struct event *unused_event __attribute__((unused));

/*
 * Scratch space for check_dentry, too big for the stack. Per CPU, so it is
 * only used with preemption disabled: LSM programs only disable migration,
 * and another task on the same CPU would otherwise overwrite it mid-check.
 */
struct hp_scratch {
	__u32 depth;
	/* walk's WALK_* bits and leaf cookie: in memory, not tracked */
	__u32 bits;
	__u64 chain[MAX_DEPTH];
	struct rule_key key;
	__u64 leaf;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct hp_scratch);
} scratch SEC(".maps");

/* The session of each member; never 0. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u32);
} members SEC(".maps");

/*
 * Thread group leaders that members may not signal: the supervisor, which
 * runs as the same user as the sandbox. Not inherited.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u8);
} protected SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct hp_grant);
} grants SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 65536);
	__type(key, struct rule_key);
	__type(value, struct rule_val);
} rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct proc_key);
	__type(value, struct proc_val);
} proc SEC(".maps");

/*
 * Superblocks created by members (tmpfs, overlay, ... in their namespaces),
 * and their session.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} owned_sbs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

#define HP_MEDIATE_FILES 1
#define HP_MEDIATE_NET 4

#define HP_OWN_LISTENERS 1

/*
 * Per-session settings, set by the supervisor. A session without an entry
 * mediates files only, as before sessions had settings.
 */
struct session_cfg {
	__u32 mediate; /* HP_MEDIATE_* */
	__u32 flags;   /* HP_OWN_LISTENERS: allow connections to the session's listeners */
	__u64 any_unix_allow; /* expiry of an allow rule for every unix socket */
	__u8 any_unix_deny;
	__u8 pad[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct session_cfg);
} sessions SEC(".maps");

/*
 * Inet rules: a longest-prefix match on {session, address}, IPv4 as
 * IPv4-mapped IPv6. prefixlen 32 matches any address of the session. The
 * value of a prefix holds its own rules and those of every shorter prefix
 * containing it (the supervisor copies them), so one lookup sees all the
 * rules matching an address.
 */
#define NET_ENTRIES 8

struct inet_key {
	__u32 prefixlen;
	__u32 session;
	__u8 addr[16];
};

struct inet_entry {
	__u64 expiry; /* allow until then; 0: none */
	__u16 port_lo, port_hi; /* 0, 0: any port */
	__u16 proto;		/* 0: any */
	__u8 deny;
	__u8 pad;
};

struct inet_val {
	struct inet_entry e[NET_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 16384);
	__type(key, struct inet_key);
	__type(value, struct inet_val);
} inet_rules SEC(".maps");

/* Abstract unix names, the same way: prefixlen 32 + 8 * bytes of name. */
struct abstract_key {
	__u32 prefixlen;
	__u32 session;
	char name[UNIX_NAME_LEN];
};

struct abstract_entry {
	__u64 expiry;
	__u8 deny;
	__u8 exact; /* the name only, not longer ones */
	__u8 len;   /* of the rule's name */
	__u8 pad[5];
};

struct abstract_val {
	struct abstract_entry e[NET_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 16384);
	__type(key, struct abstract_key);
	__type(value, struct abstract_val);
} abstract_rules SEC(".maps");

/*
 * TCP listeners, of every task: the session that started them, for the
 * loopback connections to the session's own listeners. A listener of
 * another session or of a non-member on the same address makes it mixed
 * (never own). Deleted when the socket is freed.
 */
struct listen_key {
	__u32 netns;
	__u16 port;
	__u16 pad;
	__u8 addr[16]; /* IPv4 mapped */
};

struct listen_val {
	__u64 sk;
	__u32 session; /* 0: not a member */
	__u32 mixed;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct listen_key);
	__type(value, struct listen_val);
} listeners SEC(".maps");

/* The listeners key of each listening socket, to delete it when freed. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct listen_key);
} listen_sks SEC(".maps");

/*
 * Unix sockets: the session that created them, a random id, and for a
 * sender the id of the last peer it was allowed to reach (datagram sends
 * on a connected socket are checked at each send).
 */
struct hp_sock {
	__u64 id;
	__u64 allowed_peer;
	__u32 creator;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct hp_sock);
} socks SEC(".maps");

/* Set by the supervisor: also report allowed operations. */
const volatile bool log_allowed = false;

/* The session of task, 0 if it is not a member. */
static __always_inline __u32 session_of(struct task_struct *task)
{
	__u32 *s = bpf_task_storage_get(&members, task, 0, 0);

	return s ? *s : 0;
}

static __always_inline __u32 current_session(void)
{
	return session_of(bpf_get_current_task_btf());
}

static __always_inline __u32 mediated(__u32 session)
{
	struct session_cfg *c = bpf_map_lookup_elem(&sessions, &session);

	return c ? c->mediate : HP_MEDIATE_FILES;
}

/* The session of the current task if it mediates what, else 0. */
static __always_inline __u32 current_session_for(__u32 what)
{
	__u32 s = current_session();

	if (s && !(mediated(s) & what))
		return 0;
	return s;
}

static __always_inline bool live(__u64 expiry, __u64 now)
{
	return expiry > now;
}

static __always_inline struct hp_grant *current_grant(void)
{
	return bpf_task_storage_get(&grants, bpf_get_current_task_btf(), 0, 0);
}

static __always_inline bool granted(struct hp_grant *g, __u64 cookie)
{
	if (!g || !cookie)
		return false;
	for (int i = 0; i < GRANT_NODES; i++)
		if (g->nodes[i] == cookie)
			return true;
	return false;
}

#define WALK_ALLOW 1
#define WALK_DENY 2
/* An ask rule applies: allows from above it, or shallower, do not. */
#define WALK_ASK 4

/* An ask rule cuts off the allows found so far. */
static __always_inline __u32 walk_ask(__u32 b)
{
	return (b & ~WALK_ALLOW) | WALK_ASK;
}

/*
 * b updated with a node's rules, top-down; exact: the node is the target.
 * Tree rules before exact ones, and an ask after the allow of its level.
 */
static __always_inline __u32 node_bits(struct rule_val *v, bool exact, bool net, __u64 now,
				       __u32 b)
{
	__u64 allow_tree = v->allow_tree, allow_exact = v->allow_exact;
	__u64 ask_tree = v->ask_tree, ask_exact = v->ask_exact;
	bool deny = v->deny_tree || (exact && v->deny_exact);

	if (net) {
		allow_tree = v->net_allow_tree;
		allow_exact = v->net_allow_exact;
		ask_tree = v->net_ask_tree;
		ask_exact = v->net_ask_exact;
		deny = v->net_deny_tree || (exact && v->net_deny_exact);
	}
	if (deny)
		b |= WALK_DENY;
	if (live(allow_tree, now))
		b |= WALK_ALLOW;
	if (live(ask_tree, now))
		b = walk_ask(b);
	if (exact) {
		if (live(allow_exact, now))
			b |= WALK_ALLOW;
		if (live(ask_exact, now))
			b = walk_ask(b);
	}
	return b;
}

/*
 * The rules of target's path: WALK_* bits, or -EACCES when the path cannot
 * be named. It is allowed with WALK_ALLOW and without WALK_DENY. net: the
 * rules for connections and sends to a unix socket bound there.
 * Preemption must be disabled.
 */
static __always_inline int walk(struct hp_scratch *r, struct dentry *target,
				 struct hp_grant *g, __u32 session, bool net)
{
	struct super_block *sb = BPF_CORE_READ(target, d_sb);
	__u64 sbkey = (__u64)sb;
	__u64 cur = (__u64)target;
	__u64 now, cookie;
	struct rule_val *v;
	__u32 *owner;
	__u32 n;

	if (!net) {
		/* Pipes, sockets, memfds: not reachable by path. */
		if (BPF_CORE_READ(sb, s_flags) & SB_NOUSER)
			return WALK_ALLOW;
		owner = bpf_map_lookup_elem(&owned_sbs, &sbkey);
		if (owner && *owner == session)
			return WALK_ALLOW;
	}

	r->depth = MAX_DEPTH;
	for (int i = 0; i < MAX_DEPTH; i++) {
		__u64 parent = (__u64)BPF_CORE_READ((struct dentry *)cur, d_parent);

		if (parent == cur) {
			r->depth = i;
			break;
		}
		r->chain[i] = cur;
		cur = parent;
	}
	/* Too deep, or a disconnected dentry (open_by_handle_at). */
	if (r->depth >= MAX_DEPTH || cur != (__u64)BPF_CORE_READ(sb, s_root))
		return -EACCES;

	/* Read back from memory, so the verifier does not explore each depth. */
	n = r->depth;
	now = bpf_ktime_get_ns();
	cookie = ROOT_COOKIE | BPF_CORE_READ(sb, s_dev);

	r->key.parent = cookie;
	r->key.session = session;
	r->key.pad = 0;
	r->bits = 0;
	r->leaf = 0;
	__builtin_memset(r->key.name, 0, NAME_LEN);
	v = bpf_map_lookup_elem(&rules, &r->key);
	if (v)
		r->bits = node_bits(v, n == 0, net, now, r->bits);

	for (__u32 k = 0; k < MAX_DEPTH; k++) {
		const unsigned char *name;
		__u32 j;

		if (k >= n)
			break;
		j = (n - 1 - k) & (MAX_DEPTH - 1);
		/* Outside BPF_CORE_READ, which would relocate r->chain too. */
		struct dentry *d = (struct dentry *)r->chain[j];

		name = BPF_CORE_READ(d, d_name.name);
		r->key.parent = cookie;
		__builtin_memset(r->key.name, 0, NAME_LEN);
		if (bpf_probe_read_kernel_str(r->key.name, NAME_LEN, name) < 0)
			return -EACCES;
		v = bpf_map_lookup_elem(&rules, &r->key);
		if (!v)
			break;
		r->bits = node_bits(v, j == 0, net, now, r->bits);
		if (j == 0)
			r->leaf = v->cookie;
		cookie = v->cookie;
	}
	if (granted(g, r->leaf))
		r->bits |= WALK_ALLOW;

	return r->bits & (WALK_ALLOW | WALK_DENY | WALK_ASK);
}

/* Returns 0 to allow or -EACCES. */
static __always_inline int check_dentry(struct dentry *target, __u32 session)
{
	__u32 zero = 0;
	struct hp_scratch *r;
	struct hp_grant *g = current_grant();
	int ret = -EACCES;

	bpf_preempt_disable();
	r = bpf_map_lookup_elem(&scratch, &zero);
	if (r)
		ret = walk(r, target, g, session, false);
	bpf_preempt_enable();
	if (ret < 0 || (ret & (WALK_ALLOW | WALK_DENY)) != WALK_ALLOW)
		return -EACCES;
	return 0;
}

static __always_inline bool proc_granted(struct hp_grant *g, struct proc_key *k)
{
	__u64 *a, *b;

	if (!g || !g->proc.name[0])
		return false;
	a = (__u64 *)&g->proc;
	b = (__u64 *)k;
	for (int i = 0; i < sizeof(*k) / 8; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/*
 * Files under /proc/<pid>/: processes of the same sandbox may write each
 * other's files; for other processes, the proc map decides. Returns 1 when
 * inode is not such a file.
 */
static __always_inline int check_proc(struct dentry *dentry, struct inode *inode, __u32 session)
{
	struct proc_inode *pi;
	struct task_struct *task;
	struct proc_key key = {};
	struct proc_val *v;
	struct pid *pid;
	__u32 owner;

	if (BPF_CORE_READ(inode, i_sb, s_magic) != PROC_SUPER_MAGIC)
		return 1;
	pi = (void *)inode - bpf_core_field_offset(struct proc_inode, vfs_inode);
	pid = BPF_CORE_READ(pi, pid);
	if (!pid)
		return 1;

	task = bpf_task_from_pid(BPF_CORE_READ(pid, numbers[0].nr));
	if (!task)
		return -EACCES;
	if (task->thread_pid != pid) {
		bpf_task_release(task);
		return -EACCES;
	}
	owner = session_of(task);
	bpf_probe_read_kernel(key.comm, COMM_LEN, task->comm);
	bpf_task_release(task);
	if (owner == session)
		return 0;

	key.session = session;
	bpf_probe_read_kernel_str(key.name, PROC_NAME_LEN, BPF_CORE_READ(dentry, d_name.name));
	v = bpf_map_lookup_elem(&proc, &key);
	if (v && v->deny)
		return -EACCES;
	if (v && live(v->allow, bpf_ktime_get_ns()) && !live(v->ask, bpf_ktime_get_ns()))
		return 0;
	if (proc_granted(current_grant(), &key))
		return 0;
	return -EACCES;
}

/*
 * Reports the decision, if wanted, and returns it. When the ring buffer is
 * full the event is lost, not the decision.
 */
static __always_inline int finish(__u32 op, int ret, const struct path *path,
				  struct dentry *named, __u32 session)
{
	struct event *e;

	if (ret == 0 && !log_allowed)
		return ret;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return ret;
	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->op = op;
	e->ret = ret;
	e->session = session;
	bpf_get_current_comm(e->comm, COMM_LEN);
	e->path[0] = 0;
	if (path)
		bpf_path_d_path(path, e->path, PATH_LEN);
	e->name[0] = 0;
	if (named)
		bpf_probe_read_kernel_str(e->name, NAME_LEN, BPF_CORE_READ(named, d_name.name));
	e->family = 0;
	bpf_ringbuf_submit(e, 0);
	return ret;
}

/* One dentry; path is reported, and also the dentry name when named. */
static __always_inline int check_one(__u32 op, const struct path *path, struct dentry *dentry,
				     bool named)
{
	__u32 s = current_session_for(HP_MEDIATE_FILES);

	if (!s)
		return 0;
	return finish(op, check_dentry(dentry, s), path, named ? dentry : 0, s);
}

/* Two dentries (link, rename): both must be allowed. */
static __always_inline int check_two(__u32 op, const struct path *old_dir, struct dentry *old,
				     const struct path *new_dir, struct dentry *new)
{
	__u32 s = current_session_for(HP_MEDIATE_FILES);
	int ret;

	if (!s)
		return 0;
	ret = check_dentry(old, s);
	if (ret)
		return finish(op, ret, old_dir, old, s);
	return finish(op, check_dentry(new, s), new_dir, new, s);
}

/*
 * Network: connections and sends with a destination address, of sessions
 * that mediate the network. The supervisor asks at seccomp time and grants
 * the syscall once; here the kernel's own copy of the address is checked.
 */

struct inet_dest {
	__u8 addr[16]; /* IPv4 mapped */
	__u16 port;
	__u16 proto;
};

static __always_inline void map_v4(__u8 *a, __u32 v4)
{
	__builtin_memset(a, 0, 10);
	a[10] = 0xff;
	a[11] = 0xff;
	__builtin_memcpy(a + 12, &v4, 4);
}

static __always_inline bool eq16(const __u8 *a, const __u8 *b)
{
	for (int i = 0; i < 16; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

static __always_inline bool is_mapped(const __u8 *a)
{
	for (int i = 0; i < 10; i++)
		if (a[i])
			return false;
	return a[10] == 0xff && a[11] == 0xff;
}

static __always_inline bool is_loopback(const __u8 *a)
{
	if (is_mapped(a))
		return a[12] == 127;
	for (int i = 0; i < 15; i++)
		if (a[i])
			return false;
	return a[15] == 1;
}

/*
 * Reads an inet destination. unspec_v4: the socket treats AF_UNSPEC as
 * AF_INET (IPv4 UDP and raw sends). False when the address names no inet
 * destination, or the kernel will refuse it.
 */
static __always_inline bool read_inet(void *sa, int len, bool unspec_v4, struct inet_dest *d)
{
	struct sockaddr_in6 s6;
	struct sockaddr_in s4;
	__u16 fam = 0;

	if (!sa || len < (int)sizeof(fam) || bpf_probe_read_kernel(&fam, sizeof(fam), sa))
		return false;
	if (fam == AF_INET || (fam == 0 && unspec_v4)) {
		if (len < (int)sizeof(s4) || bpf_probe_read_kernel(&s4, sizeof(s4), sa))
			return false;
		map_v4(d->addr, s4.sin_addr.s_addr);
		d->port = hp_ntohs(s4.sin_port);
		return true;
	}
	if (fam == AF_INET6) {
		/* SIN6_LEN_RFC2133: without sin6_scope_id */
		if (len < 24 || bpf_probe_read_kernel(&s6, 24, sa))
			return false;
		__builtin_memcpy(d->addr, &s6.sin6_addr, 16);
		d->port = hp_ntohs(s6.sin6_port);
		return true;
	}
	return false;
}

static __always_inline __u32 netns_of(struct sock *sk)
{
	return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

/* MPTCP falls back to TCP: the same rules and listeners. */
static __always_inline __u16 proto_of(struct sock *sk)
{
	__u16 p = sk->sk_protocol;

	return p == IPPROTO_MPTCP ? IPPROTO_TCP : p;
}

/*
 * Whether the listener on k belongs to session: 1 yes, 0 no listener known
 * there, -1 another one (or one that stopped listening).
 */
static __always_inline int listener_owned(struct listen_key *k, __u32 session)
{
	struct listen_val *v = bpf_map_lookup_elem(&listeners, k);
	struct sock *sk;

	if (!v)
		return 0;
	if (v->mixed || v->session != session)
		return -1;
	/* Outside BPF_CORE_READ: listen_val is not a kernel type. */
	sk = (struct sock *)v->sk;
	if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_LISTEN)
		return -1;
	return 1;
}

/*
 * A TCP connection to a loopback address whose listeners, those the kernel
 * may pick (bound to the address, else to a wildcard), all belong to session.
 */
static __always_inline bool own_tcp_listener(struct sock *sk, struct inet_dest *d, __u32 session)
{
	struct listen_key k = {};
	bool v4 = is_mapped(d->addr);
	int r, any = 0;

	k.netns = netns_of(sk);
	k.port = d->port;
	__builtin_memcpy(k.addr, d->addr, 16);
	r = listener_owned(&k, session);
	if (r)
		return r > 0;
	/* :: may accept IPv4 too (unless IPV6_V6ONLY) */
	__builtin_memset(k.addr, 0, 16);
	r = listener_owned(&k, session);
	if (r < 0)
		return false;
	any |= r;
	if (v4) {
		map_v4(k.addr, 0);
		r = listener_owned(&k, session);
		if (r < 0)
			return false;
		any |= r;
	}
	return any;
}

static __always_inline int inet_rules_of(struct inet_val *v, struct inet_dest *d, __u64 now)
{
	int ret = 0;

	if (!v)
		return 0;
	for (int i = 0; i < NET_ENTRIES; i++) {
		struct inet_entry *e = &v->e[i];

		if (!e->expiry && !e->deny)
			continue;
		if (e->proto && e->proto != d->proto)
			continue;
		if ((e->port_lo || e->port_hi) && (d->port < e->port_lo || d->port > e->port_hi))
			continue;
		if (e->deny)
			ret |= WALK_DENY;
		else if (live(e->expiry, now))
			ret |= WALK_ALLOW;
	}
	return ret;
}

static __always_inline bool inet_granted(struct hp_grant *g, struct inet_dest *d)
{
	if (!g)
		return false;
	for (int i = 0; i < GRANT_INET; i++) {
		struct grant_inet *gi = &g->inet[i];

		/* proto 0: any, as in rules (the socket's protocol was unknown). */
		if (gi->set && gi->port == d->port && (!gi->proto || gi->proto == d->proto) &&
		    eq16(gi->addr, d->addr))
			return true;
	}
	return false;
}

static __always_inline void net_event(struct event *e, __u32 op, int ret, __u32 session)
{
	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->op = op;
	e->ret = ret;
	e->session = session;
	bpf_get_current_comm(e->comm, COMM_LEN);
	e->name[0] = 0;
	e->path[0] = 0;
	e->port = 0;
	e->proto = 0;
	e->name_len = 0;
}

static __always_inline int check_inet(__u32 op, struct sock *sk, struct inet_dest *d, __u32 s)
{
	struct inet_key k = {};
	struct session_cfg *cfg = bpf_map_lookup_elem(&sessions, &s);
	struct event *e;
	int bits, ret = -EACCES;

	k.prefixlen = 32 + 128;
	k.session = s;
	__builtin_memcpy(k.addr, d->addr, 16);
	bits = inet_rules_of(bpf_map_lookup_elem(&inet_rules, &k), d, bpf_ktime_get_ns());
	if (inet_granted(current_grant(), d))
		bits |= WALK_ALLOW;
	if (bits & WALK_DENY)
		ret = -EACCES;
	else if (bits & WALK_ALLOW)
		ret = 0;
	else if (cfg && (cfg->flags & HP_OWN_LISTENERS) && op == HP_OP_CONNECT &&
		 d->proto == IPPROTO_TCP && is_loopback(d->addr) && own_tcp_listener(sk, d, s))
		ret = 0;

	if (ret == 0 && !log_allowed)
		return 0;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return ret;
	net_event(e, op, ret, s);
	e->family = AF_INET6;
	e->port = d->port;
	e->proto = d->proto;
	__builtin_memcpy(e->addr, d->addr, 16);
	bpf_ringbuf_submit(e, 0);
	return ret;
}

static __always_inline struct hp_sock *sock_info(struct sock *sk)
{
	struct hp_sock *h = bpf_sk_storage_get(&socks, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);

	if (h && !h->id)
		h->id = ((__u64)bpf_get_prandom_u32() << 32 | bpf_get_prandom_u32()) | 1;
	return h;
}

static __always_inline int abstract_rules_of(struct abstract_val *v, __u32 len, __u64 now)
{
	int ret = 0;

	if (!v)
		return 0;
	for (int i = 0; i < NET_ENTRIES; i++) {
		struct abstract_entry *e = &v->e[i];

		if (!e->expiry && !e->deny)
			continue;
		if (e->exact && e->len != len)
			continue;
		if (e->deny)
			ret |= WALK_DENY;
		else if (live(e->expiry, now))
			ret |= WALK_ALLOW;
	}
	return ret;
}

static __always_inline bool abstract_granted(struct hp_grant *g, struct abstract_key *k, __u32 len)
{
	__u32 *a, *b;

	if (!g || !g->abstract_set || g->abstract_len != len)
		return false;
	a = (__u32 *)g->abstract;
	b = (__u32 *)k->name;
	for (int i = 0; i < UNIX_NAME_LEN / 4; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/*
 * A connection or a datagram from self to the unix socket peer. Unbound
 * peers (socketpair) have no address to check.
 */
static __always_inline int check_unix(__u32 op, struct sock *self, struct sock *peer, __u32 s)
{
	struct unix_sock *u = bpf_core_cast(peer, struct unix_sock);
	struct unix_address *addr = u->addr;
	struct dentry *dentry = u->path.dentry;
	struct session_cfg *cfg = bpf_map_lookup_elem(&sessions, &s);
	struct hp_grant *g = current_grant();
	struct hp_sock *me, *them;
	struct abstract_key k = {};
	struct event *e;
	__u32 zero = 0, len = 0;
	int bits = 0, ret = -EACCES;

	if (!addr)
		return 0;
	me = sock_info(self);
	them = sock_info(peer);
	if (dentry) {
		struct hp_scratch *r;

		bpf_preempt_disable();
		r = bpf_map_lookup_elem(&scratch, &zero);
		if (r)
			bits = walk(r, dentry, g, s, true);
		bpf_preempt_enable();
		if (bits < 0)
			bits = WALK_DENY;
	} else {
		int alen = BPF_CORE_READ(addr, len);

		/* sun_family, then the name after its leading NUL */
		len = alen - 3;
		if (alen < 3)
			len = 0;
		if (len > UNIX_NAME_LEN - 1)
			len = UNIX_NAME_LEN - 1;
		if (bpf_probe_read_kernel(k.name, len & 127, (void *)addr->name[0].sun_path + 1))
			return -EACCES;
		k.prefixlen = 32 + 8 * len;
		k.session = s;
		bits = abstract_rules_of(bpf_map_lookup_elem(&abstract_rules, &k), len,
					 bpf_ktime_get_ns());
		if (abstract_granted(g, &k, len))
			bits |= WALK_ALLOW;
	}
	if (cfg) {
		if (cfg->any_unix_deny)
			bits |= WALK_DENY;
		if (live(cfg->any_unix_allow, bpf_ktime_get_ns()))
			bits |= WALK_ALLOW;
	}
	if (me && them && me->allowed_peer == them->id)
		bits |= WALK_ALLOW;

	if (bits & WALK_DENY)
		ret = -EACCES;
	else if (bits & WALK_ALLOW)
		ret = 0;
	else if (cfg && (cfg->flags & HP_OWN_LISTENERS) && them && them->creator == s)
		ret = 0;
	if (ret == 0 && me && them)
		me->allowed_peer = them->id;

	if (ret == 0 && !log_allowed)
		return 0;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return ret;
	net_event(e, op, ret, s);
	e->family = AF_UNIX;
	if (dentry) {
		bpf_probe_read_kernel_str(e->name, NAME_LEN, BPF_CORE_READ(dentry, d_name.name));
	} else {
		e->name_len = len;
		bpf_probe_read_kernel(e->path, len & 127, k.name);
	}
	bpf_ringbuf_submit(e, 0);
	return ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(hp_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	struct inet_dest d = {};
	struct sock *sk;
	__u16 fam;
	__u32 s;

	if (ret)
		return ret;
	s = current_session_for(HP_MEDIATE_NET);
	if (!s)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	fam = sk->__sk_common.skc_family;
	/* Unix sockets: unix_stream_connect, unix_may_send. */
	if (fam != AF_INET && fam != AF_INET6)
		return 0;
	if (!read_inet(address, addrlen, false, &d))
		return 0;
	d.proto = proto_of(sk);
	return check_inet(HP_OP_CONNECT, sk, &d, s);
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(hp_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
	struct inet_dest d = {};
	__u32 op = HP_OP_SEND;
	struct sock *sk;
	__u16 fam;
	__u32 s;

	if (ret)
		return ret;
	if (!msg->msg_name)
		return 0;
	s = current_session_for(HP_MEDIATE_NET);
	if (!s)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	fam = sk->__sk_common.skc_family;
	if (fam != AF_INET && fam != AF_INET6)
		return 0;
	d.proto = proto_of(sk);
	if (sock->type == SOCK_STREAM && d.proto == IPPROTO_TCP) {
		/* TCP ignores the address, but for a TCP Fast Open connect. */
		if (!(msg->msg_flags & MSG_FASTOPEN))
			return 0;
		op = HP_OP_CONNECT;
	}
	if (!read_inet(msg->msg_name, msg->msg_namelen, fam == AF_INET, &d))
		return 0;
	return check_inet(op, sk, &d, s);
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(hp_unix_stream_connect, struct sock *sock, struct sock *other, struct sock *newsk,
	     int ret)
{
	__u32 s;

	if (ret)
		return ret;
	s = current_session_for(HP_MEDIATE_NET);
	if (!s)
		return 0;
	return check_unix(HP_OP_CONNECT, sock, other, s);
}

/* Datagrams: at connect, and at each send, connected or not. */
SEC("lsm/unix_may_send")
int BPF_PROG(hp_unix_may_send, struct socket *sock, struct socket *other, int ret)
{
	struct sock *sk, *osk;
	__u32 s;

	if (ret)
		return ret;
	s = current_session_for(HP_MEDIATE_NET);
	if (!s)
		return 0;
	sk = sock->sk;
	osk = other->sk;
	if (!sk || !osk)
		return 0;
	return check_unix(HP_OP_SEND, sk, osk, s);
}

/* Unix sockets: which session created them, for its own listeners. */
SEC("lsm/socket_post_create")
int BPF_PROG(hp_socket_post_create, struct socket *sock, int family, int type, int protocol,
	     int kern, int ret)
{
	struct hp_sock *h;
	struct sock *sk;
	__u32 s;

	if (ret || kern || family != AF_UNIX)
		return ret;
	s = current_session();
	if (!s)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;
	h = sock_info(sk);
	if (!h)
		return -ENOMEM;
	h->creator = s;
	return 0;
}

/*
 * Whether hp_listen is attached to __inet_listen_sk(struct sock *), which
 * MPTCP subflows go through too (Go listens with MPTCP by default), rather
 * than inet_listen(struct socket *) on older kernels.
 */
const volatile bool listen_sk = false;

/* TCP listeners, after listen() succeeded and bound the port. */
SEC("fexit/inet_listen")
int hp_listen(__u64 *ctx)
{
	struct listen_key k = {};
	struct listen_val v = {}, *old;
	struct sock *sk;
	__u64 skp;
	__u16 fam;

	if ((int)ctx[2])
		return 0;
	if (listen_sk)
		sk = (struct sock *)ctx[0];
	else
		sk = BPF_CORE_READ((struct socket *)ctx[0], sk);
	if (!sk)
		return 0;
	skp = (__u64)sk;
	fam = BPF_CORE_READ(sk, __sk_common.skc_family);
	k.netns = netns_of(sk);
	k.port = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (fam == AF_INET)
		map_v4(k.addr, BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
	else if (fam == AF_INET6)
		BPF_CORE_READ_INTO(&k.addr, sk, __sk_common.skc_v6_rcv_saddr);
	else
		return 0;
	old = bpf_map_lookup_elem(&listeners, &k);
	if (old) {
		/* SO_REUSEPORT: several listeners */
		if (old->sk != skp && old->session != current_session())
			old->mixed = 1;
		return 0;
	}
	v.sk = skp;
	v.session = current_session();
	if (bpf_map_update_elem(&listeners, &k, &v, BPF_NOEXIST))
		return 0;
	bpf_map_update_elem(&listen_sks, &skp, &k, BPF_ANY);
	return 0;
}

SEC("lsm/sk_free_security")
int BPF_PROG(hp_sk_free, struct sock *sk)
{
	__u64 skp = (__u64)sk;
	struct listen_key *k = bpf_map_lookup_elem(&listen_sks, &skp);
	struct listen_val *v;

	if (!k)
		return 0;
	v = bpf_map_lookup_elem(&listeners, k);
	if (v && v->sk == skp)
		bpf_map_delete_elem(&listeners, k);
	bpf_map_delete_elem(&listen_sks, &skp);
	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(hp_task_alloc, struct task_struct *task, __u64 clone_flags, int ret)
{
	__u32 s, *child;

	if (ret)
		return ret;
	s = current_session();
	if (!s)
		return 0;
	child = bpf_task_storage_get(&members, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!child)
		return -EACCES; /* never let a member spawn an unmarked task */
	*child = s;
	return 0;
}

/*
 * The end of every syscall, of every task: the grant of the syscall, if any,
 * is used up. A restarted syscall goes through seccomp again, and gets a new
 * one from the supervisor.
 */
SEC("tp_btf/sys_exit")
int BPF_PROG(hp_sys_exit, struct pt_regs *regs, long ret)
{
	bpf_task_storage_delete(&grants, bpf_get_current_task_btf());
	return 0;
}

static __always_inline bool is_protected(struct task_struct *p)
{
	return bpf_task_storage_get(&protected, p->group_leader, 0, 0) != 0;
}

/* kill, tgkill, pidfd_send_signal, also to process groups. */
SEC("lsm/task_kill")
int BPF_PROG(hp_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig,
	     const struct cred *cred, int ret)
{
	if (ret)
		return ret;
	if (sig && current_session() && is_protected(p))
		return -EPERM;
	return 0;
}

/*
 * SIGIO (any signal, with F_SETSIG) of a file whose owner was set to a
 * protected process. Called in whatever task triggers the I/O, so it cannot
 * tell who set the owner; the supervisor never asks for SIGIO itself.
 */
SEC("lsm/file_send_sigiotask")
int BPF_PROG(hp_file_send_sigiotask, struct task_struct *tsk, struct fown_struct *fown, int sig,
	     int ret)
{
	if (ret)
		return ret;
	if (is_protected(tsk))
		return -EPERM;
	return 0;
}

SEC("lsm/sb_alloc_security")
int BPF_PROG(hp_sb_alloc, struct super_block *sb, int ret)
{
	__u64 key = (__u64)sb;
	__u32 s;

	if (ret)
		return ret;
	s = current_session();
	if (s && bpf_map_update_elem(&owned_sbs, &key, &s, BPF_ANY))
		return -EACCES;
	return 0;
}

SEC("lsm/sb_free_security")
int BPF_PROG(hp_sb_free, struct super_block *sb)
{
	__u64 key = (__u64)sb;

	bpf_map_delete_elem(&owned_sbs, &key);
	return 0;
}

/*
 * Overlayfs writes to its layers with the kernel's own vfs_* calls (copy-up,
 * create, unlink, rename...), which bypass the path hooks, so an overlay a
 * member mounted with a protected upperdir would write there unchecked.
 * Members may not mount overlayfs; fuse-overlayfs still works.
 */
SEC("lsm/sb_kern_mount")
int BPF_PROG(hp_sb_kern_mount, struct super_block *sb, int ret)
{
	if (ret)
		return ret;
	if (current_session() && sb->s_magic == OVERLAYFS_SUPER_MAGIC)
		return -EPERM;
	return 0;
}

/*
 * Overlayfs opens the files of its layers itself: as backing files of the
 * overlay files the user opened, which were checked already, and for copy-up.
 * Its layers are private mounts, in no namespace, so not reachable by path.
 * clone_private_mount() is only used by overlayfs; kern_mount() also makes
 * internal mounts (shmem...), but of SB_KERNMOUNT superblocks. No member can
 * mount an overlay (hp_sb_kern_mount), so these are overlays set up outside
 * the sandbox, e.g. a container's root.
 */
static __always_inline bool on_overlay_layer(struct file *file)
{
	struct vfsmount *vfs = file->f_path.mnt;
	struct mount *mnt = (void *)vfs - bpf_core_field_offset(struct mount, mnt);

	return BPF_CORE_READ(mnt, mnt_ns) == MNT_NS_INTERNAL &&
	       !(BPF_CORE_READ(vfs, mnt_sb, s_flags) & SB_KERNMOUNT);
}

SEC("lsm/file_open")
int BPF_PROG(hp_file_open, struct file *file, int ret)
{
	__u32 s;

	if (ret)
		return ret;
	if (!(file->f_mode & FMODE_WRITE) && !(file->f_flags & O_TRUNC))
		return 0;
	if (on_overlay_layer(file))
		return 0;
	s = current_session_for(HP_MEDIATE_FILES);
	if (!s)
		return 0;
	ret = check_proc(file->f_path.dentry, file->f_inode, s);
	if (ret == 1)
		ret = check_dentry(file->f_path.dentry, s);
	return finish(HP_OP_OPEN, ret, &file->f_path, 0, s);
}

SEC("lsm/path_mknod")
int BPF_PROG(hp_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode,
	     unsigned int dev, int ret)
{
	if (ret)
		return ret;
	/* bind() of a unix socket: not a file write */
	if ((mode & S_IFMT) == S_IFSOCK)
		return 0;
	/*
	 * open(O_CREAT) of an existing but uncached file also gets here; procfs
	 * creates nothing, and file_open decides on its files.
	 */
	if (BPF_CORE_READ(dentry, d_sb, s_magic) == PROC_SUPER_MAGIC)
		return 0;
	return check_one(HP_OP_CREATE, dir, dentry, true);
}

SEC("lsm/path_mkdir")
int BPF_PROG(hp_path_mkdir, const struct path *dir, struct dentry *dentry, umode_t mode, int ret)
{
	if (ret)
		return ret;
	return check_one(HP_OP_MKDIR, dir, dentry, true);
}

SEC("lsm/path_rmdir")
int BPF_PROG(hp_path_rmdir, const struct path *dir, struct dentry *dentry, int ret)
{
	if (ret)
		return ret;
	return check_one(HP_OP_RMDIR, dir, dentry, true);
}

SEC("lsm/path_unlink")
int BPF_PROG(hp_path_unlink, const struct path *dir, struct dentry *dentry, int ret)
{
	if (ret)
		return ret;
	return check_one(HP_OP_UNLINK, dir, dentry, true);
}

SEC("lsm/path_symlink")
int BPF_PROG(hp_path_symlink, const struct path *dir, struct dentry *dentry,
	     const char *old_name, int ret)
{
	if (ret)
		return ret;
	return check_one(HP_OP_SYMLINK, dir, dentry, true);
}

/* The source too: a new link to a protected file would be a way in. */
SEC("lsm/path_link")
int BPF_PROG(hp_path_link, struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, int ret)
{
	if (ret)
		return ret;
	return check_two(HP_OP_LINK, 0, old_dentry, new_dir, new_dentry);
}

SEC("lsm/path_rename")
int BPF_PROG(hp_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags, int ret)
{
	if (ret)
		return ret;
	return check_two(HP_OP_RENAME, old_dir, old_dentry, new_dir, new_dentry);
}

SEC("lsm/path_truncate")
int BPF_PROG(hp_path_truncate, const struct path *path, int ret)
{
	if (ret)
		return ret;
	return check_one(HP_OP_TRUNCATE, path, path->dentry, false);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

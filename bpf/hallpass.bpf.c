// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright The hallpass Authors */

/*
 * Strict mode: BPF-LSM programs that enforce the session's policy on the
 * objects the kernel is about to modify, after any symlink, bind mount or
 * rename race has been resolved.
 *
 * Only tasks of the sandbox ("members") are checked. A file is named by the
 * path inside its filesystem: the d_parent chain from the dentry up to the
 * filesystem root, without crossing mounts. The supervisor translates its
 * rules (host paths) to these names with /proc/self/mountinfo, so a rule
 * follows the files whichever bind mount or mount namespace they are reached
 * through.
 */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

#define EACCES 13
#define MAX_DEPTH 64
#define NAME_LEN 256
#define PATH_LEN 4096
#define PROC_NAME_LEN 32
#define COMM_LEN 16

#define FMODE_WRITE 0x2
#define O_TRUNC 01000
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define SB_NOUSER (1UL << 31)
#define PROC_SUPER_MAGIC 0x9fa0
#define ROOT_COOKIE (1ULL << 63)
#define FOREVER (~0ULL)

/*
 * One rule node per path component: {parent cookie, name}. The root of a
 * filesystem is ROOT_COOKIE | s_dev; its own rules live under the empty name.
 * Expiries are bpf_ktime_get_ns() deadlines, FOREVER, or 0 (none).
 */
struct rule_key {
	__u64 parent;
	char name[NAME_LEN];
};

struct rule_val {
	__u64 cookie;      /* parent cookie of this node's children */
	__u64 allow_tree;  /* allows this node and everything below */
	__u64 allow_exact; /* allows this node only */
	__u8 deny_tree;
	__u8 deny_exact;
	__u8 pad[6];
};

/* Writes to /proc/<pid>/<name> of a process outside the sandbox. */
struct proc_key {
	char name[PROC_NAME_LEN];
	char comm[COMM_LEN];
};

struct proc_val {
	__u64 allow; /* expiry, as in rule_val */
	__u8 deny;
	__u8 pad[7];
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
};

struct event {
	__u64 ts;
	__u32 pid; /* tgid, initial pid namespace */
	__u32 op;
	__s32 ret;
	__u32 pad;
	char comm[COMM_LEN];
	char name[NAME_LEN]; /* last component, for operations on a directory entry */
	char path[PATH_LEN]; /* d_path of the file or of its directory */
};

/* Keeps struct event in the BTF for bpf2go -type. */
const struct event *unused_event __attribute__((unused));

/*
 * A ring buffer record doubles as scratch space: it is private to this
 * invocation even if the task is preempted, unlike a per-CPU array.
 */
struct record {
	struct event ev;
	__u32 depth;
	__u32 pad;
	__u64 chain[MAX_DEPTH];
	struct rule_key key;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u8);
} members SEC(".maps");

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

/* Superblocks created by members (tmpfs, overlay, ... in their namespaces). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u8);
} owned_sbs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Set by the supervisor: also report allowed operations. */
const volatile bool log_allowed = false;

static __always_inline bool is_member(void)
{
	return bpf_task_storage_get(&members, bpf_get_current_task_btf(), 0, 0) != 0;
}

static __always_inline bool live(__u64 expiry, __u64 now)
{
	return expiry > now;
}

/* Returns 0 to allow or -EACCES. */
static __always_inline int check_dentry(struct record *r, struct dentry *target)
{
	struct super_block *sb = BPF_CORE_READ(target, d_sb);
	__u64 sbkey = (__u64)sb;
	__u64 cur = (__u64)target;
	__u64 now, cookie;
	struct rule_val *v;
	bool allow = false, deny = false;
	__u32 n;

	/* Pipes, sockets, memfds: not reachable by path. */
	if (BPF_CORE_READ(sb, s_flags) & SB_NOUSER)
		return 0;
	if (bpf_map_lookup_elem(&owned_sbs, &sbkey))
		return 0;

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
	__builtin_memset(r->key.name, 0, NAME_LEN);
	v = bpf_map_lookup_elem(&rules, &r->key);
	if (v) {
		deny |= v->deny_tree || (n == 0 && v->deny_exact);
		allow |= live(v->allow_tree, now) || (n == 0 && live(v->allow_exact, now));
	}

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
		deny |= v->deny_tree || (j == 0 && v->deny_exact);
		allow |= live(v->allow_tree, now) || (j == 0 && live(v->allow_exact, now));
		cookie = v->cookie;
	}

	if (deny || !allow)
		return -EACCES;
	return 0;
}

/*
 * Files under /proc/<pid>/: processes of the sandbox may write each other's
 * files; for other processes, the proc map decides. Returns 1 when inode is
 * not such a file.
 */
static __always_inline int check_proc(struct dentry *dentry, struct inode *inode)
{
	struct proc_inode *pi;
	struct task_struct *task;
	struct proc_key key = {};
	struct proc_val *v;
	struct pid *pid;
	bool member;

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
	member = bpf_task_storage_get(&members, task, 0, 0) != 0;
	bpf_probe_read_kernel(key.comm, COMM_LEN, task->comm);
	bpf_task_release(task);
	if (member)
		return 0;

	bpf_probe_read_kernel_str(key.name, PROC_NAME_LEN, BPF_CORE_READ(dentry, d_name.name));
	v = bpf_map_lookup_elem(&proc, &key);
	if (!v || v->deny || !live(v->allow, bpf_ktime_get_ns()))
		return -EACCES;
	return 0;
}

static __always_inline struct record *reserve(void)
{
	return bpf_ringbuf_reserve(&events, sizeof(struct record), 0);
}

/* Reports the decision, if wanted, and releases the record. */
static __always_inline int finish(struct record *r, __u32 op, int ret,
				  const struct path *path, struct dentry *named)
{
	if (ret == 0 && !log_allowed) {
		bpf_ringbuf_discard(r, 0);
		return ret;
	}
	r->ev.ts = bpf_ktime_get_ns();
	r->ev.pid = bpf_get_current_pid_tgid() >> 32;
	r->ev.op = op;
	r->ev.ret = ret;
	bpf_get_current_comm(r->ev.comm, COMM_LEN);
	r->ev.path[0] = 0;
	if (path)
		bpf_path_d_path(path, r->ev.path, PATH_LEN);
	r->ev.name[0] = 0;
	if (named)
		bpf_probe_read_kernel_str(r->ev.name, NAME_LEN, BPF_CORE_READ(named, d_name.name));
	bpf_ringbuf_submit(r, 0);
	return ret;
}

/* One dentry; path is reported, and also the dentry name when named. */
static __always_inline int check_one(__u32 op, const struct path *path, struct dentry *dentry,
				     bool named)
{
	struct record *r;

	if (!is_member())
		return 0;
	r = reserve();
	if (!r)
		return -EACCES;
	return finish(r, op, check_dentry(r, dentry), path, named ? dentry : 0);
}

/* Two dentries (link, rename): both must be allowed. */
static __always_inline int check_two(__u32 op, const struct path *old_dir, struct dentry *old,
				     const struct path *new_dir, struct dentry *new)
{
	struct record *r;
	int ret;

	if (!is_member())
		return 0;
	r = reserve();
	if (!r)
		return -EACCES;
	ret = check_dentry(r, old);
	if (ret)
		return finish(r, op, ret, old_dir, old);
	return finish(r, op, check_dentry(r, new), new_dir, new);
}

SEC("lsm/task_alloc")
int BPF_PROG(hp_task_alloc, struct task_struct *task, __u64 clone_flags, int ret)
{
	if (ret)
		return ret;
	if (is_member() &&
	    !bpf_task_storage_get(&members, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE))
		return -EACCES; /* never let a member spawn an unmarked task */
	return 0;
}

SEC("lsm/sb_alloc_security")
int BPF_PROG(hp_sb_alloc, struct super_block *sb, int ret)
{
	__u64 key = (__u64)sb;
	__u8 one = 1;

	if (ret)
		return ret;
	if (is_member() && bpf_map_update_elem(&owned_sbs, &key, &one, BPF_ANY))
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

SEC("lsm/file_open")
int BPF_PROG(hp_file_open, struct file *file, int ret)
{
	struct record *r;

	if (ret)
		return ret;
	if (!(file->f_mode & FMODE_WRITE) && !(file->f_flags & O_TRUNC))
		return 0;
	if (!is_member())
		return 0;
	r = reserve();
	if (!r)
		return -EACCES;
	ret = check_proc(file->f_path.dentry, file->f_inode);
	if (ret == 1)
		ret = check_dentry(r, file->f_path.dentry);
	return finish(r, HP_OP_OPEN, ret, &file->f_path, 0);
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

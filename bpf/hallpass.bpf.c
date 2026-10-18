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

/*
 * One rule node per path component: {parent cookie, name}. The root of a
 * filesystem is ROOT_COOKIE | s_dev; its own rules live under the empty name.
 * Expiries are bpf_ktime_get_ns() deadlines, FOREVER, or 0 (none).
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
	__u8 deny_tree;
	__u8 deny_exact;
	__u8 pad[6];
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
	__u8 deny;
	__u8 pad[7];
};

#define GRANT_NODES 2

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
	__u32 session;
	char comm[COMM_LEN];
	char name[NAME_LEN]; /* last component, for operations on a directory entry */
	char path[PATH_LEN]; /* d_path of the file or of its directory */
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
	__u32 pad;
	__u64 chain[MAX_DEPTH];
	struct rule_key key;
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

/*
 * Per-session settings, set by the supervisor. A session without an entry
 * mediates files only, as before sessions had settings.
 */
struct session_cfg {
	__u32 mediate; /* HP_MEDIATE_* */
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, struct session_cfg);
} sessions SEC(".maps");

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

/* Returns 0 to allow or -EACCES. Preemption must be disabled. */
static __always_inline int walk(struct hp_scratch *r, struct dentry *target,
				 struct hp_grant *g, __u32 session)
{
	struct super_block *sb = BPF_CORE_READ(target, d_sb);
	__u64 sbkey = (__u64)sb;
	__u64 cur = (__u64)target;
	__u64 now, cookie, leaf = 0;
	struct rule_val *v;
	__u32 *owner;
	bool allow = false, deny = false;
	__u32 n;

	/* Pipes, sockets, memfds: not reachable by path. */
	if (BPF_CORE_READ(sb, s_flags) & SB_NOUSER)
		return 0;
	owner = bpf_map_lookup_elem(&owned_sbs, &sbkey);
	if (owner && *owner == session)
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
	r->key.session = session;
	r->key.pad = 0;
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
		if (j == 0)
			leaf = v->cookie;
		cookie = v->cookie;
	}
	allow |= granted(g, leaf);

	if (deny || !allow)
		return -EACCES;
	return 0;
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
		ret = walk(r, target, g, session);
	bpf_preempt_enable();
	return ret;
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
	if (v && live(v->allow, bpf_ktime_get_ns()))
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

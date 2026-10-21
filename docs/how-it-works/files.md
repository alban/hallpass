# Files

With `write` in `--mediate` (the default), writes outside what your rules allow are paused and asked about. What counts as a write: opening a file for writing or truncating it, creating, deleting, renaming or linking a file, a directory or a symlink, `truncate` and `mknod`. Reads, permissions, owners, extended attributes and timestamps are not mediated.

## Lite mode

Syscalls paused:

- `openat` with a write flag (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`), and `openat2` always: its flags are in a struct the filter cannot read.
- `unlinkat`, `mkdirat`, `mknodat`, `symlinkat`, `linkat`, `renameat`, `renameat2`, `truncate`.
- On x86-64, also the legacy `open` (with a write flag), `creat`, `unlink`, `rmdir`, `mkdir`, `mknod`, `symlink`, `link`, `rename`.

`linkat` and the renames are checked on both paths: linking a protected file elsewhere would allow writing it.

What the supervisor reads:

- The path strings, from `/proc/<pid>/mem`, and for `openat2` its `struct open_how`: an `openat2` without a write flag continues at once.
- The directory the path is relative to: `/proc/<pid>/cwd`, or `/proc/<pid>/fd/<n>` for a directory file descriptor. In Kubernetes, the path is resolved in `/proc/<pid>/root`.
- Each symlink of the path, one component at a time, with `/proc/self` taken as the calling process's. The last component is followed when the kernel would follow it (not with `O_NOFOLLOW`, nor `O_CREAT|O_EXCL`).

A path through `/proc/<pid>/fd/<n>` to a pipe or socket is not a file write and continues. A write to `/proc/<pid>/...` of another process of the sandbox continues; for a process outside it, the prompt names the file and the process. A path that cannot be read is asked about as an unknown path, "once" only (see [Unreadable paths](../workstation/usage.md#unreadable-paths)).

TOCTOU: exposed. The kernel resolves the path again when the syscall continues, and another thread can change the path string, the `openat2` flags or the files on the way (a symlink, a rename) after the check.

## Strict mode

The same syscalls are paused and asked about. Then the LSM hooks check the file the kernel is about to modify:

| Hook | Checks |
|---|---|
| `file_open` | a file opened for writing or with `O_TRUNC` |
| `path_mknod` | a file created (not a unix socket bound with `bind`, which is not a file write) |
| `path_mkdir`, `path_rmdir`, `path_unlink`, `path_symlink`, `path_truncate` | the file or directory |
| `path_link`, `path_rename` | both the source and the destination |
| `sb_alloc_security`, `sb_free_security` | record the filesystems a member mounts (a `tmpfs` in its namespace...): its session may write them |
| `sb_kern_mount` | denies members mounting overlayfs (see [Overlayfs](strict.md#overlayfs)) |

A file is checked by walking from it up to its filesystem's root, and looking up each component in the session's rules. Pipes, sockets and memfds have no path and are not checked. A file whose path cannot be walked (more than 64 components deep, or a disconnected dentry from `open_by_handle_at`) is denied. A write to `/proc/<pid>/...` is allowed for a process of the same session, and otherwise looked up by file name and process name.

When the supervisor cannot read the path, or the process is in another mount namespace or chroot than the session's, it lets the syscall continue without asking, and the kernel's rules decide.

Maps:

| Map | Key → value | Relation | Written by |
|---|---|---|---|
| `rules` | session, parent node, name → the node: an id for its children, and the allow, ask (expiries) and deny for the node and for everything below it | one entry per path component of each rule's path, shared by the rules below the same directory; a filesystem's root is a node too | the supervisor, translating each rule's path with the session's mounts |
| `proc` | session, `/proc/<pid>/` file name, process name → allow, ask (expiries) and deny | 1:1 with the rules on `/proc` files of processes outside the sandbox | the supervisor |
| `owned_sbs` | filesystem (superblock) → the session whose member mounted it | 1:1 | the BPF programs, at mount and unmount |
| `grants` | thread → the nodes of the paths of a "once" answer (up to 8: rename and link have two), or a `/proc` file | 1:1, per thread | the supervisor, before continuing; deleted when the syscall returns |

An ask rule cuts off the allows above it: the file is denied unless a deeper allow, or the thread's grant, allows it. A deny wins over both.

TOCTOU: closed. The hooks run on the dentry the kernel resolved, with the flags it uses.

See [Limitations](limitations.md#files).

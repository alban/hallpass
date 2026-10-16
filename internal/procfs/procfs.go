// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package procfs resolves a target process's syscall arguments (dirfd + path
// string) into an absolute, symlink-free path, by reading
// /proc/<pid>/{cwd,fd,mem}: a host path, or a path below a root directory
// such as /proc/<pid>/root for a process in a container.
//
// Symlinks are resolved component by component from the supervisor, with
// /proc/self and /proc/thread-self rewritten to the target, so that magic links
// such as /dev/stdout -> /proc/self/fd/1 are interpreted as the target sees
// them. The result is only valid at the time of the check: callers must
// re-check the notification with NOTIF_ID_VALID, and a concurrent process can
// still change the filesystem afterwards (TOCTOU). Strict mode (BPF-LSM) is the
// real enforcement.
package procfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	atFDCWD  = -100
	pathMax  = 4096
	maxLinks = 40
)

// Target is the outcome of resolving a path argument.
type Target struct {
	// Path is the absolute, symlink-resolved path (lexical beyond the first
	// component that does not exist yet).
	Path string
	// Special is set when the path designates an object that is not in the
	// filesystem, such as "pipe:[1234]" or "socket:[42]" reached through
	// /proc/<pid>/fd/<n>. Such accesses are not filesystem writes.
	Special string
}

// ReadCString reads a NUL-terminated string from the target's memory at addr.
func ReadCString(pid uint32, addr uint64) (string, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, pathMax)
	n, err := f.ReadAt(buf, int64(addr))
	if n == 0 && err != nil {
		return "", err
	}
	if i := strings.IndexByte(string(buf[:n]), 0); i >= 0 {
		return string(buf[:i]), nil
	}
	return "", fmt.Errorf("path not NUL-terminated within %d bytes", pathMax)
}

// DirFDArg extracts a signed dirfd from a raw syscall argument register. A
// negative DirFD index in the rule means "relative to cwd".
func DirFDArg(v uint64) int64 { return int64(int32(v)) }

// AtFDCWD is the dirfd value meaning "relative to the current directory".
const AtFDCWD = atFDCWD

// ProcRoot returns the root directory of thread tid, /proc/<tid>/root, for
// Resolve.
func ProcRoot(tid uint32) string {
	return fmt.Sprintf("/proc/%d/root", tid)
}

// Resolve turns a (dirfd, raw path) pair from the target's syscall into an
// absolute path. followLast says whether a symlink in the last component
// is followed (as open(2) without O_NOFOLLOW does) or acted on itself (as
// unlink(2) and rename(2) do).
//
// root is the directory the target sees as "/": "/" when it shares this
// process's view (the CLI), ProcRoot(pid) otherwise (the node agent, outside
// the container's mount namespace). The path is walked below root, absolute
// symlinks and ".." at the top are clamped to it, and the result is relative
// to it: a container path such as /workspace/x.
func Resolve(pid uint32, root string, dirfd int64, raw string, followLast bool) (Target, error) {
	r, err := newRootView(pid, root)
	if err != nil {
		return Target{}, err
	}
	var start string
	switch {
	case filepath.IsAbs(raw):
		start = raw
	default:
		var base string
		if dirfd == atFDCWD {
			base = fmt.Sprintf("/proc/%d/cwd", pid)
		} else {
			base = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
		}
		dir, err := os.Readlink(base)
		if err != nil {
			return Target{}, fmt.Errorf("readlink %s: %w", base, err)
		}
		if !filepath.IsAbs(dir) {
			return Target{}, fmt.Errorf("dirfd %d is not a directory (%s)", dirfd, dir)
		}
		if dir, err = r.inside(dir); err != nil {
			return Target{}, fmt.Errorf("dirfd %d: %w", dirfd, err)
		}
		start = dir + "/" + raw
	}
	return r.walk(start, followLast)
}

// rootView is how the target sees the filesystem: below root, with its own
// pids in the procfs mounted at root/proc.
type rootView struct {
	pid uint32
	// root is the directory the walk is done in, "/" for this process's
	// own view.
	root string
	// link is root as the kernel names it in the magic links of /proc
	// (cwd, fd/<n>): d_path from this process's root, or from the root of
	// the target's mount namespace when it is not reachable from here.
	link string
	// self and thread are the targets of /proc/self and /proc/thread-self
	// in the target's procfs.
	self, thread string
}

func newRootView(pid uint32, root string) (*rootView, error) {
	r := &rootView{pid: pid, root: filepath.Clean(root), link: "/"}
	tgid, tid := strconv.FormatUint(uint64(pid), 10), strconv.FormatUint(uint64(pid), 10)
	if r.root != "/" {
		l, err := os.Readlink(r.root)
		switch {
		case err == nil && filepath.IsAbs(l):
			r.link = filepath.Clean(l)
		case err == nil:
			return nil, fmt.Errorf("root %s: not a directory (%s)", root, l)
		default:
			// A plain directory (tests): the kernel names it by its path.
			if r.link, err = filepath.EvalSymlinks(r.root); err != nil {
				return nil, err
			}
		}
		// The target's procfs counts in its own pid namespace.
		if ns, ok := nsIDs(pid); ok {
			tgid, tid = strconv.Itoa(ns[0]), strconv.Itoa(ns[1])
		}
	}
	r.self = "/proc/" + tgid
	r.thread = "/proc/" + tgid + "/task/" + tid
	return r, nil
}

// inside turns p, a path as the kernel names it in a magic link, into a path
// below r.root. It fails if p is outside: the target's cwd or fd escaped its
// root.
func (r *rootView) inside(p string) (string, error) {
	if r.link == "/" {
		return p, nil
	}
	rel, ok := strings.CutPrefix(p, r.link)
	switch {
	case !ok, rel != "" && rel[0] != '/':
		return "", fmt.Errorf("%s is outside the root %s", p, r.link)
	case rel == "":
		return "/", nil
	}
	return rel, nil
}

// host returns the path to access p, a path below r.root, from this process.
func (r *rootView) host(p string) string {
	if r.root == "/" {
		return p
	}
	return r.root + p
}

// nsIDs returns the thread group id and thread id of tid in its innermost
// pid namespace (NStgid and NSpid in /proc/<tid>/status).
func nsIDs(tid uint32) ([2]int, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", tid))
	if err != nil {
		return [2]int{}, false
	}
	var out [2]int
	found := 0
	for _, line := range strings.Split(string(b), "\n") {
		for i, name := range []string{"NStgid:", "NSpid:"} {
			v, ok := strings.CutPrefix(line, name)
			if !ok {
				continue
			}
			f := strings.Fields(v)
			if len(f) == 0 {
				return [2]int{}, false
			}
			n, err := strconv.Atoi(f[len(f)-1])
			if err != nil {
				return [2]int{}, false
			}
			out[i] = n
			found++
		}
	}
	return out, found == 2
}

// split splits p into components without cleaning it: ".." must be applied
// after resolving the symlinks before it, as the kernel does, not lexically.
func split(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// rewriteSelf maps /proc/self and /proc/thread-self to the target. The
// notification carries the thread id; /proc/<tid> is valid for any thread.
func (r *rootView) rewriteSelf(p string) string {
	switch p {
	case "/proc/self":
		return r.self
	case "/proc/thread-self":
		return r.thread
	}
	return p
}

// walk resolves start, a path below r.root, one component at a time.
// Absolute symlinks restart from r.root, and ".." stops at it, as for the
// target.
func (r *rootView) walk(start string, followLast bool) (Target, error) {
	comps := split(start)
	cur := "/"
	links := 0
	for i := 0; i < len(comps); i++ {
		last := i == len(comps)-1
		if comps[i] == ".." {
			// cur is fully resolved, so its lexical parent is the real one.
			cur = filepath.Dir(cur)
			continue
		}
		next := r.rewriteSelf(filepath.Join(cur, comps[i]))
		if last && !followLast {
			return Target{Path: next}, nil
		}

		fi, err := os.Lstat(r.host(next))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// The rest does not exist yet (e.g. O_CREAT): lexical.
				// A ".." in the rest would make the kernel fail with
				// ENOENT anyway.
				rest := append([]string{next}, comps[i+1:]...)
				return Target{Path: filepath.Join(rest...)}, nil
			}
			return Target{}, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}

		links++
		if links > maxLinks {
			return Target{}, unix.ELOOP
		}
		dest, err := os.Readlink(r.host(next))
		if err != nil {
			return Target{}, err
		}
		switch {
		case !filepath.IsAbs(dest):
			if strings.HasPrefix(next, "/proc/") && strings.Contains(dest, ":") {
				// Magic link to a pipe, socket or anon inode.
				return Target{Special: dest}, nil
			}
			dest = cur + "/" + dest
		case strings.HasPrefix(next, "/proc/"):
			// A magic link (cwd, fd/<n>) is named from our root.
			if dest, err = r.inside(dest); err != nil {
				return Target{}, err
			}
		}
		comps = append(split(dest), comps[i+1:]...)
		cur = "/"
		i = -1
	}
	return Target{Path: cur}, nil
}

// Exe returns the target's executable path, for display in prompts.
func Exe(pid uint32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "?"
	}
	return p
}

// SeccompMode returns the "Seccomp:" field of /proc/<pid>/status (0 = none,
// 2 = filter), or -1 if it cannot be read.
func SeccompMode(pid int) int {
	return statusField(pid, "Seccomp:")
}

// statusField returns a numeric field of /proc/<pid>/status, or -1.
func statusField(pid int, name string) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, name); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return -1
			}
			return n
		}
	}
	return -1
}

// SameView reports whether thread tid sees the filesystem as process ref
// does (0: this process): same mount namespace and same root directory.
// Resolve's paths, from ref's root, are only meaningful then.
func SameView(tid uint32, ref int) (bool, error) {
	self := "/proc/self/"
	if ref != 0 {
		self = fmt.Sprintf("/proc/%d/", ref)
	}
	for _, f := range []string{"ns/mnt", "root"} {
		var a, b unix.Stat_t
		if err := unix.Stat(self+f, &a); err != nil {
			return false, err
		}
		if err := unix.Stat(fmt.Sprintf("/proc/%d/%s", tid, f), &b); err != nil {
			return false, err
		}
		if a.Dev != b.Dev || a.Ino != b.Ino {
			return false, nil
		}
	}
	return true, nil
}

// HostTID returns the id, in this process's pid namespace, of the thread
// that thread ref names nstid in its innermost pid namespace (as in a path
// that Resolve returned from ProcRoot(ref)). ok is false if there is none.
func HostTID(ref uint32, nstid int) (tid int, ok bool) {
	var refNS, selfNS unix.Stat_t
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/pid", ref), &refNS); err != nil {
		return 0, false
	}
	if err := unix.Stat("/proc/self/ns/pid", &selfNS); err != nil {
		return 0, false
	}
	if refNS.Ino == selfNS.Ino && refNS.Dev == selfNS.Dev {
		return nstid, true
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		var ns unix.Stat_t
		if unix.Stat("/proc/"+p.Name()+"/ns/pid", &ns) != nil || ns.Ino != refNS.Ino || ns.Dev != refNS.Dev {
			continue
		}
		tasks, _ := os.ReadDir("/proc/" + p.Name() + "/task")
		for _, t := range tasks {
			id, err := strconv.Atoi(t.Name())
			if err != nil {
				continue
			}
			if ids, ok := nsIDs(uint32(id)); ok && ids[1] == nstid {
				return id, true
			}
		}
	}
	return 0, false
}

// PidFile splits a resolved path of the form /proc/<pid>/<file> or
// /proc/<pid>/task/<tid>/<file> into the target thread id and the file name.
// Magic links below /proc/<pid> (cwd, root, fd/<n>, exe) are already resolved
// by Resolve, so what is left is a procfs file about that process.
func PidFile(path string) (tid int, name string, ok bool) {
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return 0, "", false
	}
	c := strings.Split(rest, "/")
	tid, err := strconv.Atoi(c[0])
	if err != nil || tid <= 0 || len(c) < 2 {
		return 0, "", false
	}
	if c[1] == "task" && len(c) >= 4 {
		if t, err := strconv.Atoi(c[2]); err == nil && t > 0 {
			tid = t
		}
	}
	return tid, c[len(c)-1], c[len(c)-1] != ""
}

// Comm returns the command name of thread tid, or "?".
func Comm(tid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", tid))
	if err != nil {
		return "?"
	}
	return strings.TrimSuffix(string(b), "\n")
}

// Cmdline returns the arguments of thread tid's process, or nil. The
// process controls them: show them, do not trust them.
func Cmdline(tid int) []string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", tid))
	if err != nil || len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
}

// Ancestors returns the command names of the processes above thread tid,
// nearest first, up to and including root (or init if tid does not descend
// from root), at most max of them. Racy like Descends: for display only.
func Ancestors(tid, root, max int) []string {
	var out []string
	pid := statusField(tid, "Tgid:")
	for len(out) < max && pid > 1 && pid != root {
		pid = statusField(pid, "PPid:")
		if pid <= 0 {
			break
		}
		out = append(out, Comm(pid))
	}
	return out
}

// Tgid returns the process id of thread tid, or -1.
func Tgid(tid int) int { return statusField(tid, "Tgid:") }

// Parent returns the parent process id of pid, or -1.
func Parent(pid int) int { return statusField(pid, "PPid:") }

// Descends reports whether thread tid belongs to root or one of its
// descendants, following the parent chain. This is racy (a process can exit
// and its pid be reused) and processes reparented to a subreaper or init no
// longer count: good enough for prompts, not for enforcement.
func Descends(tid, root int) bool {
	pid := statusField(tid, "Tgid:")
	for i := 0; i < 4096 && pid > 1; i++ {
		if pid == root {
			return true
		}
		pid = statusField(pid, "PPid:")
	}
	return false
}

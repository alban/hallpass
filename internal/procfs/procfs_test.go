// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestResolve(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	proj := filepath.Join(root, "proj")
	for _, d := range []string{filepath.Join(secret, "sub"), filepath.Join(proj, "dir")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"proj/abs":      secret,
		"proj/rel":      "../secret",
		"proj/subl":     secret + "/sub",
		"proj/relsub":   "dir/../../secret/sub", // dir is real: lexical == real here
		"proj/viasubl":  "subl/..",              // must resolve to secret, not proj
		"proj/dangling": secret + "/new",
		"proj/loop":     "loop",
	}
	for l, dst := range links {
		if err := os.Symlink(dst, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	pid := uint32(os.Getpid())

	for _, tc := range []struct {
		raw    string
		follow bool
		want   string
	}{
		{proj + "/dir/f", true, proj + "/dir/f"},
		{proj + "/abs/f", true, secret + "/f"},
		{proj + "/rel/f", true, secret + "/f"},
		{proj + "/subl/../f", true, secret + "/f"}, // ".." after a symlink
		{proj + "/viasubl/f", true, secret + "/f"},
		{proj + "/relsub/f", true, secret + "/sub/f"},
		{proj + "/dangling", true, secret + "/new"},
		{proj + "/dangling", false, proj + "/dangling"},
		{proj + "/abs", false, proj + "/abs"},
		{proj + "/./dir/../dir/f", true, proj + "/dir/f"},
		{proj + "/missing/../f", true, proj + "/f"},
	} {
		got, err := Resolve(pid, "/", AtFDCWD, tc.raw, tc.follow)
		if err != nil {
			t.Errorf("Resolve(%s): %v", tc.raw, err)
			continue
		}
		if got.Path != tc.want {
			t.Errorf("Resolve(%s, follow=%v) = %s, want %s", tc.raw, tc.follow, got.Path, tc.want)
		}
	}

	if _, err := Resolve(pid, "/", AtFDCWD, proj+"/loop/f", true); err == nil {
		t.Error("symlink loop: want error")
	}
}

func TestResolveRelative(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	got, err := Resolve(uint32(os.Getpid()), "/", AtFDCWD, "a/../b", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != dir+"/b" {
		t.Errorf("got %s, want %s", got.Path, dir+"/b")
	}

	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err = Resolve(uint32(os.Getpid()), "/", int64(f.Fd()), "c", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != dir+"/c" {
		t.Errorf("dirfd: got %s, want %s", got.Path, dir+"/c")
	}
}

func TestResolveDetached(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: fsopen")
	}
	pid := uint32(os.Getpid())
	mount := func(fstype string) int {
		fs, err := unix.Fsopen(fstype, unix.FSOPEN_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fs)
		if err := unix.FsconfigCreate(fs); err != nil {
			t.Fatal(err)
		}
		m, err := unix.Fsmount(fs, unix.FSMOUNT_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(m) })
		return m
	}

	// A detached tmpfs names its files "/x": not a path of our root.
	tmp := mount("tmpfs")
	if got, err := Resolve(pid, "/", int64(tmp), "x", true); err == nil {
		t.Errorf("detached tmpfs: got %+v, want an error", got)
	}

	// runc reopens its exec FIFO through a detached procfs.
	proc := mount("proc")
	fds, err := unix.Openat(proc, "self/fd", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds)
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	ff, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ff.Close()
	reg, err := os.Create(filepath.Join(dir, "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	n := strconv.Itoa(int(ff.Fd()))
	if got, err := Resolve(pid, "/", int64(fds), n, true); err != nil || got.Special != "fifo:"+n {
		t.Errorf("FIFO: got %+v, %v", got, err)
	}
	if got, err := Resolve(pid, "/", int64(fds), strconv.Itoa(int(reg.Fd())), true); err == nil {
		t.Errorf("regular file: got %+v, want an error", got)
	}
	if got, err := Resolve(pid, "/", int64(fds), "../fd/"+n, true); err == nil {
		t.Errorf("FIFO through ..: got %+v, want an error", got)
	}
}

func TestResolveProcSelf(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	got, err := Resolve(uint32(os.Getpid()), "/", AtFDCWD, "/proc/self/fd/"+strconv.Itoa(int(w.Fd())), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Special == "" {
		t.Errorf("pipe via /proc/self/fd: got %+v, want Special", got)
	}
}

// TestResolveRoot resolves paths below a fake root, as the node agent does
// below /proc/<pid>/root: absolute symlinks and ".." stay inside it, and
// the results are relative to it.
func TestResolveRoot(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(outside, "root")
	for _, d := range []string{"root/workspace/dir", "root/etc", "workspace", "etc"} {
		if err := os.MkdirAll(filepath.Join(outside, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"workspace/abs":     "/etc",               // the root's /etc, not the host's
		"workspace/rel":     "../etc",             // inside the root
		"workspace/escape":  "../../../../../etc", // ".." stops at the root
		"workspace/viaabs":  "/workspace/dir/..",  // ".." after an absolute link
		"workspace/new":     "/newdir/f",          // dangling, absolute
		"workspace/dotdots": "/../../workspace/dir",
	}
	for l, dst := range links {
		if err := os.Symlink(dst, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	pid := uint32(os.Getpid())
	for _, tc := range []struct {
		raw    string
		follow bool
		want   string
	}{
		{"/workspace/dir/f", true, "/workspace/dir/f"},
		{"/workspace/abs/f", true, "/etc/f"},
		{"/workspace/rel/f", true, "/etc/f"},
		{"/workspace/escape/f", true, "/etc/f"},
		{"/../../../workspace/f", true, "/workspace/f"},
		{"/workspace/viaabs/f", true, "/workspace/f"},
		{"/workspace/new", true, "/newdir/f"},
		{"/workspace/new", false, "/workspace/new"},
		{"/workspace/dotdots/f", true, "/workspace/dir/f"},
		{"/workspace/abs", false, "/workspace/abs"},
	} {
		got, err := Resolve(pid, root, AtFDCWD, tc.raw, tc.follow)
		if err != nil {
			t.Errorf("Resolve(%s): %v", tc.raw, err)
			continue
		}
		if got.Path != tc.want {
			t.Errorf("Resolve(%s, follow=%v) = %s, want %s", tc.raw, tc.follow, got.Path, tc.want)
		}
	}

	// Relative paths start from a directory fd below the root, named by the
	// kernel from our root.
	f, err := os.Open(filepath.Join(root, "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := Resolve(pid, root, int64(f.Fd()), "abs/../x", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/x" {
		t.Errorf("dirfd below the root: got %s, want /x", got.Path)
	}
	// A dirfd outside the root cannot be named in it.
	g, err := os.Open(filepath.Join(outside, "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if got, err := Resolve(pid, root, int64(g.Fd()), "x", true); err == nil {
		t.Errorf("dirfd outside the root: got %+v, want an error", got)
	}
	// So does a magic link to a file outside it.
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "etc"), filepath.Join(root, "proc", "magic")); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve(pid, root, AtFDCWD, "/proc/magic/f", true); err == nil {
		t.Errorf("magic link outside the root: got %+v, want an error", got)
	}
	if err := os.Symlink(filepath.Join(root, "etc"), filepath.Join(root, "proc", "inside")); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve(pid, root, AtFDCWD, "/proc/inside/f", true); err != nil || got.Path != "/etc/f" {
		t.Errorf("magic link inside the root: got %+v, %v, want /etc/f", got, err)
	}
}

// TestResolveInRoot checks ResolveInRoot against the kernel's own
// openat2(RESOLVE_IN_ROOT), from "/" and from a root directory: the kernel
// uses only the dirfd as the root, so the inode must be the same.
// TestResolveDirFD checks paths relative to a dirfd against the kernel's
// openat, the dirfd being opened through a symlink: ".." and relative
// symlinks climb from the directory's real parent.
func TestResolveDirFD(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"real/sub", "secret"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"f", "real/f", "secret/f"} {
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"link":         "real",
		"real/sub/rel": "../../secret",
		"real/sub/abs": root + "/secret",
		"real/sub/up":  "../../link",
	}
	for l, dst := range links {
		if err := os.Symlink(dst, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.Open(filepath.Join(root, "link/sub"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	dirfd := int(dir.Fd())
	pid := uint32(os.Getpid())
	for _, tc := range []struct {
		raw    string
		follow bool
		want   string // below root
	}{
		{".", true, "/real/sub"},
		{"..", true, "/real"},
		{"../f", true, "/real/f"},
		{"../../secret/f", true, "/secret/f"},
		{"rel/f", true, "/secret/f"},
		{"rel", false, "/real/sub/rel"},
		{"abs/f", true, "/secret/f"},
		{"rel/../f", true, "/f"},
		{"up/f", true, "/real/f"},
	} {
		want := root + tc.want
		got, err := Resolve(pid, "/", int64(dirfd), tc.raw, tc.follow)
		if err != nil {
			t.Errorf("Resolve(%s): %v", tc.raw, err)
		} else if got.Path != want {
			t.Errorf("Resolve(%s, follow=%v) = %s, want %s", tc.raw, tc.follow, got.Path, want)
		}
		flags := unix.O_PATH
		if !tc.follow {
			flags |= unix.O_NOFOLLOW
		}
		fd, err := unix.Openat(dirfd, tc.raw, flags, 0)
		if err != nil {
			t.Errorf("kernel: openat(%s): %v", tc.raw, err)
			continue
		}
		var ks, ws unix.Stat_t
		if err := unix.Fstat(fd, &ks); err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
		if err := unix.Lstat(want, &ws); err != nil || ks.Ino != ws.Ino || ks.Dev != ws.Dev {
			t.Errorf("kernel: openat(%s) is not %s", tc.raw, want)
		}
	}
}

func TestResolveInRoot(t *testing.T) {
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(outside, "root")
	for _, d := range []string{"root/workspace/a", "root/workspace/etc", "root/etc", "root/a"} {
		if err := os.MkdirAll(filepath.Join(outside, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"workspace/abs":    "/etc",        // the dirfd's etc
		"workspace/escape": "../../../..", // ".." stops at the dirfd
		"workspace/up":     "a/..",
		"workspace/a/rel":  "../etc",
		"workspace/dang":   "/new/f",
	}
	for l, dst := range links {
		if err := os.Symlink(dst, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.Open(filepath.Join(root, "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	dirfd := int(dir.Fd())
	pid := uint32(os.Getpid())
	for _, tc := range []struct {
		raw    string
		follow bool
		want   string // below root
	}{
		{"/etc", true, "/workspace/etc"},
		{"abs", true, "/workspace/etc"},
		{"abs", false, "/workspace/abs"},
		{"/abs/../a", true, "/workspace/a"},
		{"escape/etc", true, "/workspace/etc"},
		{"../../../a", true, "/workspace/a"},
		{"up/etc", true, "/workspace/etc"},
		{"a/rel", true, "/workspace/etc"},
		{"dang", true, "/workspace/new/f"},
		{"/x", true, "/workspace/x"},
	} {
		for _, r := range []string{"/", root} {
			got, err := ResolveInRoot(pid, r, int64(dirfd), tc.raw, tc.follow)
			if err != nil {
				t.Errorf("ResolveInRoot(%s, %s): %v", r, tc.raw, err)
				continue
			}
			want := tc.want
			if r == "/" {
				want = root + tc.want
			}
			if got.Path != want {
				t.Errorf("ResolveInRoot(%s, %s, follow=%v) = %s, want %s", r, tc.raw, tc.follow, got.Path, want)
			}
		}
		var flags uint64 = unix.O_PATH
		if !tc.follow {
			flags |= unix.O_NOFOLLOW
		}
		fd, err := unix.Openat2(dirfd, tc.raw, &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_IN_ROOT})
		if err != nil {
			if _, serr := os.Lstat(root + tc.want); serr == nil {
				t.Errorf("kernel: openat2(%s): %v, but %s exists", tc.raw, err, tc.want)
			}
			continue
		}
		var ks, ws unix.Stat_t
		if err := unix.Fstat(fd, &ks); err != nil {
			t.Fatal(err)
		}
		unix.Close(fd)
		if err := unix.Lstat(root+tc.want, &ws); err != nil || ks.Ino != ws.Ino || ks.Dev != ws.Dev {
			t.Errorf("kernel: openat2(%s) is not %s", tc.raw, tc.want)
		}
	}

	// The kernel does not follow magic links under RESOLVE_IN_ROOT.
	slash, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer slash.Close()
	for _, raw := range []string{"proc/self/fd/0", "proc/self/cwd/x"} {
		if got, err := ResolveInRoot(pid, "/", int64(slash.Fd()), raw, true); err == nil {
			t.Errorf("ResolveInRoot(%s) = %+v, want ELOOP", raw, got)
		}
		if fd, err := unix.Openat2(int(slash.Fd()), raw, &unix.OpenHow{Flags: unix.O_PATH, Resolve: unix.RESOLVE_IN_ROOT}); err == nil {
			unix.Close(fd)
			t.Errorf("kernel: openat2(%s) followed a magic link", raw)
		}
	}
}

func TestReadOpenHow(t *testing.T) {
	how := unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT, Mode: 0o644, Resolve: unix.RESOLVE_BENEATH}
	addr := uint64(uintptr(unsafe.Pointer(&how)))
	got, err := ReadOpenHow(uint32(os.Getpid()), addr, uint64(unsafe.Sizeof(how)))
	if err != nil || got != how {
		t.Errorf("ReadOpenHow = %+v, %v, want %+v", got, err, how)
	}
	if _, err := ReadOpenHow(uint32(os.Getpid()), addr, 16); err != unix.EINVAL {
		t.Errorf("size 16: %v, want EINVAL", err)
	}
	if _, err := ReadOpenHow(uint32(os.Getpid()), 8, 24); err != unix.EFAULT {
		t.Errorf("address 8: %v, want EFAULT", err)
	}
	runtime.KeepAlive(&how)
}

// TestResolveProcRoot resolves through /proc/self/root, the agent's case
// for a process sharing its view: the same as from "/".
func TestResolveProcRoot(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/proc/self", filepath.Join(dir, "self")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	pid := uint32(os.Getpid())
	for _, raw := range []string{"a", dir + "/b", "self/cwd/c"} {
		want, err := Resolve(pid, "/", AtFDCWD, raw, true)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Resolve(pid, ProcRoot(pid), AtFDCWD, raw, true)
		if err != nil || got != want {
			t.Errorf("Resolve(%s) from %s = %+v, %v; want %+v", raw, ProcRoot(pid), got, err, want)
		}
	}
}

func TestHostTID(t *testing.T) {
	pid := os.Getpid()
	if got, ok := HostTID(uint32(pid), pid); !ok || got != pid {
		t.Errorf("HostTID(self) = %d, %v; want %d", got, ok, pid)
	}
	if ok, err := SameView(uint32(pid), pid); err != nil || !ok {
		t.Errorf("SameView(self, self) = %v, %v", ok, err)
	}
}

func TestPidFile(t *testing.T) {
	for _, tc := range []struct {
		path string
		tid  int
		name string
		ok   bool
	}{
		{"/proc/12/oom_score_adj", 12, "oom_score_adj", true},
		{"/proc/12/task/13/comm", 13, "comm", true},
		{"/proc/12/attr/current", 12, "current", true},
		{"/proc/12", 0, "", false},
		{"/proc/sys/vm/swappiness", 0, "", false},
		{"/proc/0/x", 0, "", false},
		{"/home/u/proc/12/x", 0, "", false},
	} {
		tid, name, ok := PidFile(tc.path)
		if tid != tc.tid || name != tc.name || ok != tc.ok {
			t.Errorf("PidFile(%q) = %d, %q, %v; want %d, %q, %v", tc.path, tid, name, ok, tc.tid, tc.name, tc.ok)
		}
	}
}

func TestDescends(t *testing.T) {
	if !Descends(os.Getpid(), os.Getpid()) {
		t.Error("a process descends from itself")
	}
	// Spawn the child rather than using our own parent: Descends stops at
	// init, which is our parent in a vimto VM.
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		child.Process.Kill()
		child.Wait()
	}()
	if !Descends(child.Process.Pid, os.Getpid()) {
		t.Error("a process descends from its parent")
	}
	if Descends(os.Getpid(), child.Process.Pid) {
		t.Error("the parent descends from its child")
	}
}

func TestCmdlineAncestors(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	pid := child.Process.Pid

	// Until the exec completes, the child's cmdline is the test binary's,
	// then briefly empty.
	got := Cmdline(pid)
	for i := 0; i < 100 && !slices.Equal(got, []string{"sleep", "60"}); i++ {
		time.Sleep(10 * time.Millisecond)
		got = Cmdline(pid)
	}
	if !slices.Equal(got, []string{"sleep", "60"}) {
		t.Errorf("Cmdline = %q", got)
	}
	if got, want := Ancestors(pid, os.Getpid(), 4), []string{Comm(os.Getpid())}; !slices.Equal(got, want) {
		t.Errorf("Ancestors(child, self) = %q, want %q", got, want)
	}
	if got := Ancestors(os.Getpid(), os.Getpid(), 4); got != nil {
		t.Errorf("Ancestors(self, self) = %q, want none", got)
	}
	if got := Ancestors(pid, os.Getpid(), 0); got != nil {
		t.Errorf("Ancestors with max 0 = %q", got)
	}
}

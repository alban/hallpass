// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// mount is one line of /proc/<pid>/mountinfo.
type mount struct {
	id    uint64
	dev   uint32 // kernel encoding of the superblock's s_dev: major<<20 | minor
	root  string // directory of the filesystem mounted here
	point string // mount point
}

// loc names a file the way the BPF programs do: a filesystem and the path from
// its root, regardless of where it is mounted.
type loc struct {
	dev  uint32
	path string // "/" for the root of the filesystem
}

func readMounts(file string) ([]mount, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseMounts(f)
}

func parseMounts(r io.Reader) ([]mount, error) {
	var out []mount
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 {
			return nil, fmt.Errorf("mountinfo: short line %q", sc.Text())
		}
		maj, min, ok := strings.Cut(f[2], ":")
		if !ok {
			return nil, fmt.Errorf("mountinfo: bad device %q", f[2])
		}
		ma, err1 := strconv.ParseUint(maj, 10, 32)
		mi, err2 := strconv.ParseUint(min, 10, 32)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("mountinfo: bad device %q", f[2])
		}
		id, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("mountinfo: bad mount id %q", f[0])
		}
		out = append(out, mount{
			id:    id,
			dev:   uint32(ma<<20 | mi),
			root:  unescape(f[3]),
			point: unescape(f[4]),
		})
	}
	return out, sc.Err()
}

// unescape decodes the octal escapes (\040 for a space...) of mountinfo.
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountID returns the id of the mount the path p resolves to, or of its
// closest existing ancestor; 0 if unknown.
func mountID(p string) uint64 {
	for {
		var st unix.Statx_t
		err := unix.Statx(unix.AT_FDCWD, p, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st)
		if err == nil && st.Mask&unix.STATX_MNT_ID != 0 {
			return st.Mnt_id
		}
		if err == nil || p == "/" {
			return 0
		}
		p = path.Dir(p)
	}
}

// mountIDIn is mountID for path p in root directory root (/proc/<pid>/root):
// symlinks are resolved inside it, as the process sees them.
func mountIDIn(root, p string) uint64 {
	rfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0
	}
	defer unix.Close(rfd)
	for {
		fd, err := unix.Openat2(rfd, p, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err == nil {
			var st unix.Statx_t
			err = unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &st)
			unix.Close(fd)
			if err == nil && st.Mask&unix.STATX_MNT_ID != 0 {
				return st.Mnt_id
			}
			return 0
		}
		if p == "/" {
			return 0
		}
		p = path.Dir(p)
	}
}

// locate translates the absolute, cleaned host path p, on the mount with the
// given id. The first result is the filesystem p is on. For a tree rule, it is
// followed by the roots of the filesystems mounted below p, which the rule
// covers too.
//
// The mount id comes from the kernel's own path lookup: matching mount points
// alone picks the wrong one when a mount is stacked over the root after a
// chroot or pivot_root (vimto mounts 9p over its overlay root). Without it,
// the longest mount point wins.
func locate(mounts []mount, p string, tree bool, id uint64) []loc {
	best := -1
	for i, m := range mounts {
		if id != 0 && m.id == id && under(p, m.point) {
			best = i
			break
		}
	}
	for i, m := range mounts {
		if best >= 0 && mounts[best].id == id {
			break
		}
		if under(p, m.point) && (best < 0 || len(m.point) >= len(mounts[best].point)) {
			best = i // the last of equal mount points is on top
		}
	}
	if best < 0 {
		return nil
	}
	b := mounts[best]
	out := []loc{{b.dev, path.Join(b.root, strings.TrimPrefix(p, b.point))}}
	if tree {
		for i, m := range mounts {
			if i != best && m.point != p && under(m.point, p) {
				out = append(out, loc{m.dev, m.root})
			}
		}
	}
	return out
}

// under reports whether p is dir or lies beneath it.
func under(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}

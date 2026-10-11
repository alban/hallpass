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
)

// mount is one line of /proc/<pid>/mountinfo.
type mount struct {
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
		out = append(out, mount{
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

// locate translates the absolute, cleaned host path p. The first result is
// the filesystem p is on. For a tree rule, it is followed by the roots of the
// filesystems mounted below p, which the rule covers too.
func locate(mounts []mount, p string, tree bool) []loc {
	best := -1
	for i, m := range mounts {
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

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"reflect"
	"strings"
	"testing"
)

const testMountinfo = `22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
23 22 0:21 / /proc rw shared:2 - proc proc rw
24 22 0:30 / /tmp rw shared:3 - tmpfs tmpfs rw
25 22 0:31 /home /home rw shared:4 - btrfs /dev/sda2 rw,subvol=/home
26 25 0:31 /home/u/proj/sub /home/u/sub rw shared:4 - btrfs /dev/sda2 rw,subvol=/home
27 25 0:40 / /home/u/mnt\040usb rw shared:5 - vfat /dev/sdb1 rw
28 24 0:41 / /tmp rw shared:6 - tmpfs tmpfs rw
`

func TestLocate(t *testing.T) {
	m, err := parseMounts(strings.NewReader(testMountinfo))
	if err != nil {
		t.Fatal(err)
	}
	if m[0].dev != 8<<20|1 || m[5].point != "/home/u/mnt usb" {
		t.Fatalf("parse: %+v", m)
	}
	btrfs := uint32(31)
	for _, c := range []struct {
		path string
		tree bool
		want []loc
	}{
		{"/etc/passwd", false, []loc{{8<<20 | 1, "/etc/passwd"}}},
		// Subvolume: the path inside the filesystem includes it.
		{"/home/u/.ssh", true, []loc{{btrfs, "/home/u/.ssh"}}},
		// Bind mount of a subfolder: rules follow the files.
		{"/home/u/sub/x", false, []loc{{btrfs, "/home/u/proj/sub/x"}}},
		// A tree rule covers the filesystems mounted below.
		{"/home/u", true, []loc{
			{btrfs, "/home/u"},
			{btrfs, "/home/u/proj/sub"},
			{40, "/"},
		}},
		{"/home/u", false, []loc{{btrfs, "/home/u"}}},
		// Stacked mounts: the last one is visible, the one below is not.
		{"/tmp", true, []loc{{41, "/"}}},
		{"/tmp/f", false, []loc{{41, "/f"}}},
		{"/", false, []loc{{8<<20 | 1, "/"}}},
	} {
		if got := locate(m, c.path, c.tree, 0); !reflect.DeepEqual(got, c.want) {
			t.Errorf("locate(%q, %v) = %v, want %v", c.path, c.tree, got, c.want)
		}
	}
}

func TestLocateStackedRoot(t *testing.T) {
	// vimto: 9p mounted over / after the switch to the overlay root, which
	// path lookups still use.
	m, err := parseMounts(strings.NewReader(`32 27 0:27 / / rw - overlay overlay rw
34 32 0:32 / /proc rw - proc proc rw
41 32 0:35 / / rw - 9p sd-9p-0 rw
`))
	if err != nil {
		t.Fatal(err)
	}
	want := []loc{{27, "/tmp/x"}}
	if got := locate(m, "/tmp/x", true, 32); !reflect.DeepEqual(got, want) {
		t.Errorf("with mount id: %v, want %v", got, want)
	}
	if got := locate(m, "/tmp/x", false, 0); got[0].dev != 35 {
		t.Errorf("without mount id: %v", got)
	}
}

func TestMountID(t *testing.T) {
	m, err := readMounts("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/proc/self", "/proc/does/not/exist", t.TempDir()} {
		id := mountID(p)
		found := false
		for _, mt := range m {
			found = found || mt.id == id
		}
		if !found {
			t.Errorf("mountID(%q) = %d, not in mountinfo", p, id)
		}
	}
}

func TestNodes(t *testing.T) {
	l := &LSM{cookies: map[nodeKey]uint64{}, next: 1}
	nodes := map[nodeKey]hallpassRuleVal{}
	k1, _ := l.node(nodes, loc{7, "/a/b"})
	k2, _ := l.node(nodes, loc{7, "/a/c"})
	root, _ := l.node(nodes, loc{7, "/"})
	a := nodeKey{rootCookie | 7, "a"}
	if nodes[a].Cookie == 0 || k1 != (nodeKey{nodes[a].Cookie, "b"}) || k2.parent != k1.parent {
		t.Fatalf("nodes: %v %v %v", nodes, k1, k2)
	}
	if root != (nodeKey{rootCookie | 7, ""}) {
		t.Fatalf("root: %v", root)
	}
	if _, ok := l.node(nodes, loc{7, "/" + strings.Repeat("x", 256)}); ok {
		t.Fatal("over-long name accepted")
	}
}

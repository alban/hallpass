// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ociseccomp

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/seccomp"
)

var update = flag.Bool("update", false, "update the golden files")

var opts = Options{ListenerPath: "/run/hallpass/agent.sock", ListenerMetadata: `{"pod":"p"}`}

func loadBase(t *testing.T) *specs.LinuxSeccomp {
	t.Helper()
	// containerd's RuntimeDefault profile (contrib/seccomp.DefaultProfile)
	// on arm64 with the default capabilities. Syscall names are mostly
	// arch-independent, so it serves as a realistic base on every arch.
	b, err := os.ReadFile("testdata/runtime-default-arm64.json")
	if err != nil {
		t.Fatal(err)
	}
	var p specs.LinuxSeccomp
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// verdict is what a syscall gets from a profile.
type verdict struct {
	action specs.LinuxSeccompAction
	errno  uint
}

func (v verdict) String() string {
	if v.action == specs.ActErrno {
		return fmt.Sprintf("%s(%d)", v.action, v.errno)
	}
	return string(v.action)
}

func (v verdict) allows() bool { return allows(v.action) }

func errnoOf(p *uint, def uint) uint {
	if p != nil {
		return *p
	}
	return def
}

func matches(a specs.LinuxSeccompArg, args [6]uint64) bool {
	v := args[a.Index]
	switch a.Op {
	case specs.OpMaskedEqual:
		return v&a.Value == a.ValueTwo
	case specs.OpEqualTo:
		return v == a.Value
	case specs.OpNotEqual:
		return v != a.Value
	case specs.OpGreaterEqual:
		return v >= a.Value
	case specs.OpGreaterThan:
		return v > a.Value
	case specs.OpLessEqual:
		return v <= a.Value
	case specs.OpLessThan:
		return v < a.Value
	}
	panic(a.Op)
}

// evaluate models how runc and libseccomp compile p for one syscall: rules
// with the default action are skipped (runc), several conditions on one
// argument are ORed (runc), an unconditional rule wins over the conditional
// ones (libseccomp). Conditional rules with different actions matching the
// same arguments are reported as an error: libseccomp's choice is not
// specified.
func evaluate(p *specs.LinuxSeccomp, name string, args [6]uint64) (verdict, error) {
	def := verdict{p.DefaultAction, errnoOf(p.DefaultErrnoRet, uint(unix.EPERM))}
	var uncond *verdict
	var cond []verdict
	for _, s := range p.Syscalls {
		found := false
		for _, n := range s.Names {
			found = found || n == name
		}
		if !found {
			continue
		}
		v := verdict{s.Action, errnoOf(s.ErrnoRet, uint(unix.EPERM))}
		if v == def {
			continue
		}
		if len(s.Args) == 0 {
			if uncond == nil {
				uncond = &v
			}
			continue
		}
		count := map[uint]int{}
		for _, a := range s.Args {
			count[a.Index]++
		}
		multi := false
		for _, c := range count {
			multi = multi || c > 1
		}
		match := !multi
		for _, a := range s.Args {
			if multi && matches(a, args) {
				match = true
			}
			if !multi && !matches(a, args) {
				match = false
			}
		}
		if match {
			cond = append(cond, v)
		}
	}
	if uncond != nil {
		return *uncond, nil
	}
	if len(cond) == 0 {
		return def, nil
	}
	for _, v := range cond[1:] {
		if v != cond[0] {
			return verdict{}, fmt.Errorf("ambiguous: %v", cond)
		}
	}
	return cond[0], nil
}

// flagValues are FlagsArg values covering each bit of the masks, none, and
// harmless bits.
var flagValues = []uint64{
	0,
	unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY,
	unix.O_WRONLY,
	unix.O_RDWR | unix.O_CLOEXEC,
	unix.O_CREAT,
	unix.O_TRUNC,
	unix.O_WRONLY | unix.O_CREAT | unix.O_TRUNC,
	unix.CLONE_NEWUSER,
	unix.CLONE_NEWNS,
	unix.CLONE_NEWNET,
	unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD,
	unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID,
	1 << 40,
	0x7fff_0000_0000, // a pointer above 4 GiB
}

// want is what the CLI filter does with the syscall, applied on top of what
// the base does: a syscall the base denies stays denied.
func want(r seccomp.Rule, base verdict, flags uint64) verdict {
	if !base.allows() {
		return base
	}
	switch r.Kind {
	case seccomp.Notify:
		return verdict{action: specs.ActNotify, errno: uint(unix.EPERM)}
	case seccomp.Errno:
		return verdict{specs.ActErrno, uint(r.Errno)}
	case seccomp.NotifyIfWrite:
		if uint32(flags)&r.Mask() != 0 {
			return verdict{action: specs.ActNotify, errno: uint(unix.EPERM)}
		}
	case seccomp.ErrnoIfNamespace:
		if uint32(flags)&r.Mask() != 0 {
			return verdict{specs.ActErrno, uint(r.Errno)}
		}
	case seccomp.NotifyIfSet:
		if flags != 0 {
			return verdict{action: specs.ActNotify, errno: uint(unix.EPERM)}
		}
	}
	return base
}

func checkSemantics(t *testing.T, base *specs.LinuxSeccomp, rules []seccomp.Rule) {
	t.Helper()
	got, err := Profile(base, rules, opts)
	if err != nil {
		t.Fatal(err)
	}
	baseProfile := base
	if baseProfile == nil {
		baseProfile = &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
	}
	for _, r := range rules {
		for _, flags := range flagValues {
			var args [6]uint64
			args[r.FlagsArg] = flags
			b, err := evaluate(baseProfile, r.Name, args)
			if err != nil {
				t.Fatalf("base %s(%#x): %v", r.Name, flags, err)
			}
			v, err := evaluate(got, r.Name, args)
			if err != nil {
				t.Fatalf("%s(%#x): %v", r.Name, flags, err)
			}
			if w := want(r, b, flags); v != w {
				t.Errorf("%s(%#x): got %v, want %v (base %v)", r.Name, flags, v, w, b)
			}
		}
	}
	// The other syscalls are left to the base.
	for _, name := range []string{"read", "write", "socket", "mount", "chroot", "ptrace"} {
		var args [6]uint64
		b, _ := evaluate(baseProfile, name, args)
		v, err := evaluate(got, name, args)
		if err != nil || v != b {
			t.Errorf("%s: got %v (%v), want %v", name, v, err, b)
		}
	}
	if got.ListenerPath != opts.ListenerPath || got.ListenerMetadata != opts.ListenerMetadata {
		t.Errorf("listener: got %q %q", got.ListenerPath, got.ListenerMetadata)
	}
	if len(got.Architectures) != 1 || got.Architectures[0] != NativeArch {
		t.Errorf("architectures: got %v, want [%s]", got.Architectures, NativeArch)
	}
}

func TestUnconfined(t *testing.T) {
	for _, userns := range []bool{false, true} {
		checkSemantics(t, nil, seccomp.Rules(userns))
	}
}

func TestRuntimeDefault(t *testing.T) {
	base := loadBase(t)
	for _, userns := range []bool{false, true} {
		checkSemantics(t, base, seccomp.Rules(userns))
	}
}

// TestCapSysAdmin uses the shape of the RuntimeDefault profile with
// CAP_SYS_ADMIN, which allows clone, unshare and setns unconditionally.
func TestCapSysAdmin(t *testing.T) {
	base := loadBase(t)
	base.Syscalls = append(base.Syscalls, specs.LinuxSyscall{
		Names:  []string{"clone", "unshare", "setns", "mount"},
		Action: specs.ActAllow,
	})
	// Drop the conditional clone rule, as containerd does with
	// CAP_SYS_ADMIN.
	for i, s := range base.Syscalls {
		if len(s.Names) == 1 && s.Names[0] == "clone" && len(s.Args) > 0 {
			base.Syscalls = append(base.Syscalls[:i], base.Syscalls[i+1:]...)
			break
		}
	}
	checkSemantics(t, base, seccomp.Rules(false))
}

func TestDefaultLog(t *testing.T) {
	base := &specs.LinuxSeccomp{
		DefaultAction: specs.ActLog,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{"unlinkat", "read"}, Action: specs.ActAllow},
			{Names: []string{"mkdirat"}, Action: specs.ActKillProcess},
			{Names: []string{"openat"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 3, Value: 0, Op: specs.OpEqualTo}}},
		},
	}
	checkSemantics(t, base, seccomp.Rules(false))
}

func TestFlags(t *testing.T) {
	base := &specs.LinuxSeccomp{DefaultAction: specs.ActAllow, Flags: []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_LOG", FlagWaitKillableRecv}}
	o := opts
	got, err := Profile(base, seccomp.Rules(false), o)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.Flags) != "[SECCOMP_FILTER_FLAG_LOG]" {
		t.Errorf("flags: got %v", got.Flags)
	}
	o.WaitKillableRecv = true
	got, err = Profile(base, seccomp.Rules(false), o)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.Flags) != "[SECCOMP_FILTER_FLAG_LOG SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV]" {
		t.Errorf("flags: got %v", got.Flags)
	}
	if len(base.Flags) != 2 {
		t.Errorf("base modified: %v", base.Flags)
	}
}

func TestRefused(t *testing.T) {
	for name, base := range map[string]*specs.LinuxSeccomp{
		"listener":       {DefaultAction: specs.ActAllow, ListenerPath: "/other.sock"},
		"notify default": {DefaultAction: specs.ActNotify},
		"notify rule": {DefaultAction: specs.ActAllow, Syscalls: []specs.LinuxSyscall{
			{Names: []string{"read"}, Action: specs.ActNotify},
		}},
		"condition on flags": {DefaultAction: specs.ActErrno, Syscalls: []specs.LinuxSyscall{
			{Names: []string{"openat"}, Action: specs.ActAllow, Args: []specs.LinuxSeccompArg{{Index: 2, Value: 0, Op: specs.OpNotEqual}}},
		}},
		"conditional denial": {DefaultAction: specs.ActAllow, Syscalls: []specs.LinuxSyscall{
			{Names: []string{"unlinkat"}, Action: specs.ActErrno, Args: []specs.LinuxSeccompArg{{Index: 0, Value: 3, Op: specs.OpEqualTo}}},
		}},
	} {
		if _, err := Profile(base, seccomp.Rules(false), opts); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := Profile(nil, seccomp.Rules(false), Options{}); err == nil {
		t.Errorf("no listener path: no error")
	}
}

// TestGolden pins the generated profiles. Run with -update on each
// architecture to regenerate testdata/<GOARCH>/.
func TestGolden(t *testing.T) {
	for name, base := range map[string]*specs.LinuxSeccomp{
		"unconfined":      nil,
		"runtime-default": loadBase(t),
	} {
		got, err := Profile(base, seccomp.Rules(false), opts)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.MarshalIndent(got, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		path := filepath.Join("testdata", runtime.GOARCH, name+".json")
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		w, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			t.Skipf("no golden file for %s: run go test -update", runtime.GOARCH)
		}
		if err != nil {
			t.Fatal(err)
		}
		if string(w) != string(b) {
			t.Errorf("%s differs from the golden file %s:\n%s", name, path, strings.TrimSpace(string(b)))
		}
	}
}

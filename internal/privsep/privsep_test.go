// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package privsep

import (
	"bytes"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCommand(t *testing.T) {
	args := []string{"/opt/my hall'pass", HelperArg, "42", "7"}
	for tool, want := range map[string][]string{
		"sudo":   {"sudo", "--", "/opt/my hall'pass", HelperArg, "42", "7"},
		"pkexec": {"pkexec", "/opt/my hall'pass", HelperArg, "42", "7"},
		"su":     {"su", "-c", `'/opt/my hall'\''pass' '--internal-load' '42' '7'`, "root"},
	} {
		got, err := command(tool, args)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q, %v; want %q", tool, got, err, want)
		}
	}
	if _, err := command("bogus", args); err == nil {
		t.Error("bogus tool accepted")
	}
}

func TestShellQuote(t *testing.T) {
	args := []string{"a b", "it's", "$HOME", ""}
	out, err := exec.Command("sh", "-c", `printf '%s\n' `+shellQuote(args)).Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n"); !reflect.DeepEqual(got, args) {
		t.Errorf("got %q, want %q", got, args)
	}
}

func pair(t *testing.T) [2]int {
	t.Helper()
	p, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(p[0]); unix.Close(p[1]) })
	return p
}

// enterAfter is stdin pressing Enter twice; the helper's message arrives
// after the first press.
type enterAfter struct {
	presses int
	send    func()
}

func (e *enterAfter) Read(p []byte) (int, error) {
	if e.presses == 2 {
		return 0, io.EOF
	}
	e.presses++
	if e.presses == 2 {
		e.send()
	}
	p[0] = '\n'
	return 1, nil
}

func TestManual(t *testing.T) {
	p := pair(t)
	var out bytes.Buffer
	in := &enterAfter{send: func() {
		if err := unix.Sendmsg(p[1], []byte("ok"), unix.UnixRights(0, 1), nil, 0); err != nil {
			t.Error(err)
		}
	}}
	fds, err := manual([]string{"/bin/hallpass", HelperArg, "1", "2"}, p[0], in, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		unix.Close(fd)
	}
	if len(fds) != 2 {
		t.Errorf("got %d fds, want 2", len(fds))
	}
	if !strings.Contains(out.String(), `'/bin/hallpass' '--internal-load' '1' '2'`) || !strings.Contains(out.String(), "nothing received yet") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
}

func TestManualEOF(t *testing.T) {
	p := pair(t)
	if _, err := manual([]string{"x"}, p[0], strings.NewReader(""), io.Discard); err == nil {
		t.Error("no error on EOF")
	}
}

func TestReceiveBadMessage(t *testing.T) {
	p := pair(t)
	if err := unix.Sendmsg(p[1], []byte("no"), unix.UnixRights(0), nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := receive(p[0]); err == nil || !strings.Contains(err.Error(), "bad message") {
		t.Errorf("got %v", err)
	}
}

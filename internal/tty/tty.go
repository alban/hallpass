// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package tty runs the sandboxed program on a pseudo-terminal that hallpass
// relays to the user's terminal, like script(1) or tmux, so hallpass can ask
// questions in an overlay without the program seeing or answering them.
//
// Output normally passes through untouched and is mirrored into a terminal
// emulator. While a prompt is shown, the program's output is held back and
// its input diverted to hallpass; when the prompt closes, the rows under it
// are repainted from the emulator, the cursor is restored, and the held output
// is flushed. The program's terminal is never resized.
package tty

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Available reports whether stdin and stdout are terminals.
func Available() bool { return term.IsTerminal(0) && term.IsTerminal(1) }

// Term is the pseudo-terminal relay.
type Term struct {
	in, out *os.File
	master  *os.File
	slave   *os.File
	saved   *term.State

	mu         sync.Mutex
	emu        *vt.Emulator
	esc        escTracker
	rows, cols int
	ov         []string // overlay lines; nil when no prompt is shown
	held       []byte   // program output held while the overlay is shown

	keys    chan []byte
	outDone chan struct{}
	winch   chan os.Signal
}

// Open creates the pseudo-terminal, copying the settings and size of the
// user's terminal (stdin/stdout).
func Open() (*Term, error) {
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		unix.Close(mfd)
		return nil, fmt.Errorf("unlockpt: %w", err)
	}
	sfd, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(mfd), unix.TIOCGPTPEER,
		uintptr(unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC))
	if errno != 0 {
		unix.Close(mfd)
		return nil, fmt.Errorf("TIOCGPTPEER: %w", errno)
	}
	if tio, err := unix.IoctlGetTermios(0, unix.TCGETS); err == nil {
		_ = unix.IoctlSetTermios(int(sfd), unix.TCSETS, tio)
	}
	ws, err := unix.IoctlGetWinsize(1, unix.TIOCGWINSZ)
	if err != nil || ws.Row == 0 || ws.Col == 0 {
		ws = &unix.Winsize{Row: 24, Col: 80}
	}
	_ = unix.IoctlSetWinsize(mfd, unix.TIOCSWINSZ, ws)

	t := &Term{
		in:      os.Stdin,
		out:     os.Stdout,
		master:  os.NewFile(uintptr(mfd), "ptmx"),
		slave:   os.NewFile(sfd, "pts"),
		emu:     vt.NewEmulator(int(ws.Col), int(ws.Row)),
		rows:    int(ws.Row),
		cols:    int(ws.Col),
		keys:    make(chan []byte, 16),
		outDone: make(chan struct{}),
	}
	// The emulator answers terminal queries through a pipe that blocks
	// until read. The real terminal answers them, so drop these.
	go func() { _, _ = io.Copy(io.Discard, t.emu) }()
	return t, nil
}

// Slave is the program's side; use it as its stdin, stdout, stderr and
// controlling terminal.
func (t *Term) Slave() *os.File { return t.slave }

// Start puts the user's terminal in raw mode and starts relaying. Call it
// before starting the program, then CloseSlave once the program started.
func (t *Term) Start() error {
	st, err := term.MakeRaw(int(t.in.Fd()))
	if err != nil {
		return err
	}
	t.saved = st
	t.winch = make(chan os.Signal, 1)
	signal.Notify(t.winch, syscall.SIGWINCH)
	go t.resizeLoop()
	go t.inputLoop()
	go t.outputLoop()
	return nil
}

// CloseSlave closes hallpass's copy of the program's side.
func (t *Term) CloseSlave() { _ = t.slave.Close() }

// Close drains the remaining output and restores the user's terminal.
func (t *Term) Close() error {
	select {
	case <-t.outDone:
	case <-time.After(200 * time.Millisecond):
	}
	if t.winch != nil {
		signal.Stop(t.winch)
	}
	if t.saved != nil {
		_ = term.Restore(int(t.in.Fd()), t.saved)
	}
	return nil
}

func (t *Term) inputLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := t.in.Read(buf)
		if err != nil {
			return
		}
		t.mu.Lock()
		prompting := t.ov != nil
		t.mu.Unlock()
		if prompting {
			select {
			case t.keys <- append([]byte(nil), buf[:n]...):
			default:
			}
			continue
		}
		if _, err := t.master.Write(buf[:n]); err != nil {
			return
		}
	}
}

func (t *Term) outputLoop() {
	defer close(t.outDone)
	buf := make([]byte, 32*1024)
	for {
		n, err := t.master.Read(buf)
		if n > 0 {
			t.mu.Lock()
			if t.ov != nil {
				t.held = append(t.held, buf[:n]...)
			} else {
				t.emit(buf[:n])
			}
			t.mu.Unlock()
		}
		if err != nil {
			// EIO once every copy of the slave is closed.
			return
		}
	}
}

// emit passes program output to the user's terminal and the emulator.
func (t *Term) emit(p []byte) {
	_, _ = t.out.Write(p)
	_, _ = t.emu.Write(p)
	t.esc.feed(p)
}

func (t *Term) resizeLoop() {
	for range t.winch {
		ws, err := unix.IoctlGetWinsize(int(t.out.Fd()), unix.TIOCGWINSZ)
		if err != nil || ws.Row == 0 || ws.Col == 0 {
			continue
		}
		t.mu.Lock()
		t.rows, t.cols = int(ws.Row), int(ws.Col)
		t.emu.Resize(t.cols, t.rows)
		_ = unix.IoctlSetWinsize(int(t.master.Fd()), unix.TIOCSWINSZ, ws)
		if t.ov != nil {
			t.drawOverlay()
		}
		t.mu.Unlock()
	}
}

// Prompt shows lines at the bottom of the screen and waits for one of the
// accept keys. Keys pressed within guard of the prompt appearing are ignored,
// so typing meant for the program does not answer it; so is any input that
// is not a single key press (pastes, escape sequences other than a lone Esc).
// It returns 0 after timeout (0: no timeout) or when the program's
// terminal goes away.
func (t *Term) Prompt(lines []string, accept string, guard, timeout time.Duration) byte {
	t.mu.Lock()
	// Do not cut an escape sequence or a UTF-8 character in two.
	for wait := time.Now().Add(300 * time.Millisecond); !t.esc.ground() && time.Now().Before(wait); {
		t.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		t.mu.Lock()
	}
	for len(t.keys) > 0 {
		<-t.keys
	}
	t.ov = lines
	_, _ = t.out.WriteString("\x1b7") // DECSC: cursor, attributes, charset
	t.drawOverlay()
	t.mu.Unlock()

	shown := time.Now()
	var expired <-chan time.Time
	if timeout > 0 {
		tm := time.NewTimer(timeout)
		defer tm.Stop()
		expired = tm.C
	}
	var key byte
wait:
	for {
		select {
		case k := <-t.keys:
			if len(k) != 1 || time.Since(shown) < guard {
				continue
			}
			if strings.IndexByte(accept, k[0]) >= 0 {
				key = k[0]
				break wait
			}
		case <-expired:
			break wait
		case <-t.outDone:
			break wait
		}
	}

	t.mu.Lock()
	t.closeOverlay()
	t.mu.Unlock()
	return key
}

func (t *Term) overlayTop() int { return max(0, t.rows-len(t.ov)) }

func (t *Term) drawOverlay() {
	var b strings.Builder
	top := t.overlayTop()
	for i, l := range t.ov {
		if top+i >= t.rows {
			break
		}
		// Bold white on blue, erased to the end of line in that colour.
		fmt.Fprintf(&b, "\x1b[%d;1H\x1b[0;1;37;44m\x1b[2K%s", top+i+1, ansi.Truncate(l, t.cols-1, "…"))
	}
	b.WriteString("\x1b[0m")
	_, _ = t.out.WriteString(b.String())
}

// closeOverlay repaints the rows under the overlay from the emulator (which
// reflects the screen when the overlay opened), restores the cursor, and
// flushes the output held meanwhile.
func (t *Term) closeOverlay() {
	var b strings.Builder
	top := t.overlayTop()
	for y := top; y < top+len(t.ov) && y < t.rows; y++ {
		line := make(uv.Line, t.cols)
		for x := range line {
			if c := t.emu.CellAt(x, y); c != nil {
				line[x] = *c
			}
		}
		fmt.Fprintf(&b, "\x1b[%d;1H\x1b[0m\x1b[2K%s\x1b[0m", y+1, line.Render())
	}
	b.WriteString("\x1b8") // DECRC
	_, _ = t.out.WriteString(b.String())
	t.ov = nil
	held := t.held
	t.held = nil
	if len(held) > 0 {
		t.emit(held)
	}
}

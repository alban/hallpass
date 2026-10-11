// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package tty runs the sandboxed program on a pseudo-terminal that hallpass
// relays to the user's terminal, like script(1) or tmux, so hallpass can ask
// questions in an overlay without the program seeing or answering them.
//
// Output normally passes through untouched and is mirrored into a terminal
// emulator. While a prompt is shown, the program's input is diverted to
// hallpass and its output goes to the emulator only; the rows above the
// prompt are repainted from the emulator as output arrives, scrolled so the
// cursor line stays visible. The output is also kept, and when the prompt
// closes the screen as it was when the prompt opened is repainted, the cursor
// restored, and the kept output replayed, so the user's terminal ends in
// exactly the state the program put it in (modes, colours, scrollback). The
// program's terminal is never resized.
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
	esc        escTracker // parser state of the user's terminal
	rows, cols int

	// While a prompt is shown:
	ov      []string      // overlay lines; nil when no prompt is shown
	barX    int           // cursor column after drawing the overlay
	held    []byte        // program output, replayed when the overlay closes
	snap    []string      // rendered rows when the overlay opened
	painted []string      // rendered rows currently above the overlay
	exact   bool          // false after a resize: snap is stale, cannot replay
	resume  chan struct{} // closed when the overlay closes

	wmu   sync.Mutex    // orders writes to the user's terminal
	dirty chan struct{} // the emulator changed while the overlay is shown

	keys    chan []byte
	outDone chan struct{}
	winch   chan os.Signal
}

// maxHeld bounds the output kept while a prompt is shown; beyond it the
// program blocks on write until the prompt closes.
const maxHeld = 16 << 20

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
		dirty:   make(chan struct{}, 1),
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
	go t.paintLoop()
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
			if t.ov == nil {
				t.emit(buf[:n])
				t.mu.Unlock()
			} else {
				t.held = append(t.held, buf[:n]...)
				_, _ = t.emu.Write(buf[:n])
				select {
				case t.dirty <- struct{}{}:
				default:
				}
				full, resume := len(t.held) > maxHeld, t.resume
				t.mu.Unlock()
				if full {
					<-resume
				}
			}
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
			// The user's terminal reflowed the screen we saved: repaint
			// everything from the emulator now and when closing.
			t.exact = false
			t.painted = make([]string, t.overlayTop())
			t.write(t.drawOverlay() + t.paint())
		}
		t.mu.Unlock()
	}
}

// write sends s to the user's terminal. Call with mu held.
func (t *Term) write(s string) {
	t.wmu.Lock()
	_, _ = t.out.WriteString(s)
	t.wmu.Unlock()
}

// paintLoop repaints the rows above the overlay when the emulator changed.
// Output arriving while a repaint is written is coalesced into the next one,
// so a slow terminal gets fewer, larger updates.
func (t *Term) paintLoop() {
	for {
		select {
		case <-t.dirty:
		case <-t.outDone:
			return
		}
		t.mu.Lock()
		if t.ov == nil {
			t.mu.Unlock()
			continue
		}
		s := t.paint()
		// Take wmu before releasing mu so that closeOverlay, which needs
		// both, writes after this repaint.
		t.wmu.Lock()
		t.mu.Unlock()
		_, _ = t.out.WriteString(s)
		t.wmu.Unlock()
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
	t.exact = true
	t.resume = make(chan struct{})
	t.snap = make([]string, t.rows)
	for y := range t.snap {
		t.snap[y] = t.renderRow(y)
	}
	t.painted = append([]string(nil), t.snap[:t.overlayTop()]...)
	// DECSC saves cursor, attributes and charset for closeOverlay.
	t.write("\x1b7" + t.drawOverlay() + t.paint())
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

// drawOverlay returns the sequence drawing the overlay. Call with mu held.
func (t *Term) drawOverlay() string {
	var b strings.Builder
	top := t.overlayTop()
	t.barX = 1
	for i, l := range t.ov {
		if top+i >= t.rows {
			break
		}
		l = ansi.Truncate(l, t.cols-1, "…")
		// Bold white on blue, erased to the end of line in that colour.
		fmt.Fprintf(&b, "\x1b[%d;1H\x1b[0;1;37;44m\x1b[2K%s", top+i+1, l)
		t.barX = ansi.StringWidth(l) + 1
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

// renderRow returns row y of the emulator's screen as styled text.
func (t *Term) renderRow(y int) string {
	line := make(uv.Line, t.cols)
	for x := range line {
		if c := t.emu.CellAt(x, y); c != nil {
			line[x] = *c
		}
	}
	return line.Render()
}

func paintRow(b *strings.Builder, y int, line string) {
	fmt.Fprintf(b, "\x1b[%d;1H\x1b[0m\x1b[2K%s\x1b[0m", y+1, line)
}

// paint returns the sequence updating the rows above the overlay from the
// emulator, scrolled so that the program's cursor line stays visible. Only
// rows that changed are rewritten. Call with mu held.
func (t *Term) paint() string {
	top := t.overlayTop()
	off := max(0, t.emu.CursorPosition().Y-top+1)
	var b strings.Builder
	for y := 0; y < top && y < len(t.painted); y++ {
		line := t.renderRow(y + off)
		if line != t.painted[y] {
			paintRow(&b, y, line)
			t.painted[y] = line
		}
	}
	if b.Len() == 0 {
		return ""
	}
	// Park the cursor where the overlay left it.
	fmt.Fprintf(&b, "\x1b[%d;%dH", t.rows, min(t.barX, t.cols))
	return b.String()
}

// closeOverlay removes the overlay and brings the user's terminal to the
// state the program put it in. Call with mu held.
func (t *Term) closeOverlay() {
	var b strings.Builder
	if t.exact {
		// Restore the screen as it was when the overlay opened, then replay
		// the program's output: the user's terminal applies it as if it had
		// never been interrupted, modes and scrollback included.
		top := t.overlayTop()
		for y, line := range t.snap {
			if y >= top || t.painted[y] != line {
				paintRow(&b, y, line)
			}
		}
		b.WriteString("\x1b8") // DECRC
		b.Write(t.held)
		t.esc.feed(t.held)
	} else {
		// The size changed: show the emulator's screen. Modes the program
		// changed meanwhile are lost; full-screen programs redraw on resize.
		for y := range t.rows {
			paintRow(&b, y, t.renderRow(y))
		}
		p := t.emu.CursorPosition()
		fmt.Fprintf(&b, "\x1b8\x1b[%d;%dH", p.Y+1, p.X+1)
	}
	t.write(b.String())
	t.ov, t.held, t.snap, t.painted = nil, nil, nil, nil
	close(t.resume)
}

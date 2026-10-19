// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alban/hallpass/internal/answer"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/ui"
)

// client is hallpass's name in monitor.Reason.Client.
const client = "hallpass"

// maxParents bounds the parent chain shown in prompts.
const maxParents = 4

// prompts follows the monitor's events until the workload is gone, then
// closes gone. Requests are asked about in another goroutine, so a prompt
// left open does not delay gone.
func (s *session) prompts(evs <-chan []monitor.Event, gone chan<- struct{}) {
	defer close(gone)
	kick := make(chan struct{}, 1)
	go s.askLoop(kick)
	defer close(kick)
	for batch := range evs {
		changed := false
		for _, ev := range batch {
			switch {
			case ev.Opened != nil:
				changed = true
				select {
				case kick <- struct{}{}:
				default:
				}
			case ev.Closed != nil:
				changed = true
				s.cancelPrompt(ev.Closed.ID)
			case ev.Warning != "":
				s.notice("hallpass: " + ev.Warning)
			}
		}
		if changed {
			s.recount()
		}
	}
}

// recount sends the prompt shown, if any, the number of requests waiting
// behind it: the later ones, since askLoop asks the oldest first.
func (s *session) recount() {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	if s.curMore == nil {
		return
	}
	pending, _, _ := s.m.Snapshot()
	n := 0
	for _, r := range pending {
		if r.ID > s.curID {
			n++
		}
	}
	// Only the latest count matters: replace one not read yet.
	select {
	case <-s.curMore:
	default:
	}
	s.curMore <- n
}

// cancelPrompt takes down the prompt about request id, if shown: another
// client answered it, a rule settled it, or its task died.
func (s *session) cancelPrompt(id uint64) {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	if s.curID == id && s.curCancel != nil {
		s.curCancel()
	}
}

// askLoop asks about the pending requests, one at a time, oldest first,
// each time kick fires. A request closed meanwhile, e.g. by a folder the
// user just allowed, is not asked about.
func (s *session) askLoop(kick <-chan struct{}) {
	asked := map[uint64]bool{}
	for range kick {
		for {
			pending, rs, _ := s.m.Snapshot()
			var next *monitor.Request
			seen := map[uint64]bool{}
			for _, r := range pending {
				if asked[r.ID] {
					seen[r.ID] = true
				} else if next == nil {
					next = r
				}
			}
			asked = seen
			if next == nil {
				break
			}
			asked[next.ID] = true
			s.ask(next, len(pending)-len(seen)-1, rs)
		}
	}
}

// ask asks the user about req and applies the answer, unless another
// client answers first.
func (s *session) ask(req *monitor.Request, waiting int, rs []rules.Rule) {
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	more := make(chan int, 1)
	s.curMu.Lock()
	s.curID, s.curCancel, s.curMore = req.ID, cancel, more
	s.curMu.Unlock()
	defer func() {
		s.curMu.Lock()
		s.curID, s.curCancel, s.curMore = 0, nil, nil
		s.curMu.Unlock()
	}()
	// Closed before curID was set: cancelPrompt missed it.
	if !s.pending(req.ID) {
		return
	}
	ur := s.uiRequest(req, waiting)
	ur.More = more
	// Requests opened since askLoop counted were not sent.
	s.recount()
	a := s.cfg.Asker.Ask(ctx, ur)
	if ctx.Err() != nil {
		return
	}
	if err := s.answer(req, a, rs, client); err != nil && !errors.Is(err, monitor.ErrClosed) {
		s.warnLocked(fmt.Sprintf("hallpass: %v", err))
	}
}

// pending reports whether request id is still pending.
func (s *session) pending(id uint64) bool {
	pending, _, _ := s.m.Snapshot()
	for _, r := range pending {
		if r.ID == id {
			return true
		}
	}
	return false
}

// answer applies a, the answer of client who to req, with the session's
// policy (see answer.Apply).
func (s *session) answer(req *monitor.Request, a ui.Answer, rs []rules.Rule, who string) error {
	return answer.Apply(s.m, s.cfg.Defaults, req, a, rs, who)
}

// uiRequest describes req for the asker.
func (s *session) uiRequest(req *monitor.Request, waiting int) ui.Request {
	return answer.Request(s.cfg.Defaults, req, waiting)
}

// warnLocked prints a line for the user; promptMu must be held.
func (s *session) warnLocked(msg string) {
	if s.cfg.TTY != nil {
		fmt.Fprint(os.Stderr, "\r\n"+msg+"\r\n")
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

// menu shows the session's rules over the program's screen (Ctrl-]), until
// a key is pressed. Prompts wait meanwhile.
func (s *session) menu() {
	if !s.menuOpen.CompareAndSwap(false, true) {
		return
	}
	defer s.menuOpen.Store(false)
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	mode := "lite"
	if s.cfg.LSM != nil {
		mode = "strict"
	}
	_, rs, _ := s.m.Snapshot()
	deny, allow := s.cfg.Defaults.Summary(rs)
	w := s.cfg.TTY.Width() - 1
	lines := []string{fmt.Sprintf(" hallpass, %s mode: the rules of this session", mode)}
	lines = append(lines, wrapList(" Denied:   ", deny, w)...)
	lines = append(lines, wrapList(" Writable: ", allow, w)...)
	if s.wait.active.Load() {
		lines = append(lines, " The command exited; its background processes are still supervised.   [s] stop waiting")
	}
	lines = append(lines, " Anything else is asked. A folder covers everything below it.")
	lines = append(lines, " [w] open the web UI   [any key] close")
	keys := make([]byte, 0, 255)
	for k := 1; k < 256; k++ {
		keys = append(keys, byte(k))
	}
	switch s.cfg.TTY.Prompt(lines, string(keys), 0, 0, nil, nil) {
	case 's':
		if s.wait.active.Load() {
			s.wait.Stop()
		}
	case 'w':
		// Once the menu is closed: pairing asks in this overlay too.
		go s.openWeb()
	}
}

// wrapList lays out items after prefix, comma-separated, in lines of at
// most width columns, continuation lines indented like the first item.
func wrapList(prefix string, items []string, width int) []string {
	indent := strings.Repeat(" ", len(prefix))
	var lines []string
	line := prefix
	for i, it := range items {
		if i < len(items)-1 {
			it += ","
		}
		if line != prefix && line != indent && len(line)+1+len(it) > width {
			lines = append(lines, line)
			line = indent
		}
		if line != prefix && line != indent {
			line += " "
		}
		line += it
	}
	return append(lines, line)
}

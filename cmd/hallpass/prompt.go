// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

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

// answer applies a, the answer of client to req, with the session's
// policy: the folder of a grant, "never" as an exact deny. rs are the
// current rules. It fails with monitor.ErrClosed if req is no longer
// pending; the rules of a are applied anyway.
func (s *session) answer(req *monitor.Request, a ui.Answer, rs []rules.Rule, who string) error {
	if !s.uiRequest(req, 0).Valid(a) {
		a = ui.AnswerAllowOnce
	}
	d := monitor.Decision{Client: who}
	allow := false
	obj := req.Objects[0]
	switch a {
	case ui.AnswerAllowOnce:
		allow = true
	case ui.AnswerAllowTemp:
		allow = true
		s.grant(&d, rs, obj, time.Now().Add(ui.TempGrant))
	case ui.AnswerAllowAlways:
		allow = true
		s.grant(&d, rs, obj, time.Time{})
	case ui.AnswerNever:
		d.AddRules = append(d.AddRules, rules.Rule{Ops: rules.OpAll, Verdict: rules.Deny, Object: exact(obj)})
	}
	d.Verdicts = []monitor.Verdict{{Request: req.ID, Allow: allow}}
	_, err := s.m.Apply(d)
	if errors.Is(err, monitor.ErrClosed) {
		// Its task died, another client answered, or the monitor
		// closed: keep the rules.
		d.Verdicts = nil
		if len(d.AddRules)+len(d.RemoveRules) > 0 {
			_, _ = s.m.Apply(d)
		}
		return err
	}
	if err != nil {
		// The rules failed (strict mode): give the verdict alone.
		if _, err2 := s.m.Apply(monitor.Decision{Verdicts: d.Verdicts, Client: who}); err2 != nil {
			return errors.Join(err, err2)
		}
	}
	return err
}

// grant adds to d the rule an "allow temp/always" answer gives obj: its
// folder, or its kind of /proc file. A grant never shrinks: an existing
// grant on the same scope lasting longer is kept.
func (s *session) grant(d *monitor.Decision, rs []rules.Rule, obj rules.Object, expires time.Time) {
	var m rules.ObjectMatch
	switch {
	case obj.Path != nil:
		folder := s.cfg.Defaults.FolderFor(obj.Path.Path)
		if folder == "" {
			return
		}
		m.Path = &rules.PathMatch{Path: folder, Tree: true}
	case obj.Proc != nil:
		m.Proc = &rules.ProcMatch{Name: obj.Proc.Name, Comm: comm(obj.Proc)}
	default:
		return
	}
	for _, r := range rs {
		if r.Set != "" || r.Verdict != rules.Allow || !sameMatch(r.Object, m) {
			continue
		}
		if r.Expires.IsZero() || (!expires.IsZero() && !expires.After(r.Expires)) {
			return
		}
		d.RemoveRules = append(d.RemoveRules, r.ID)
	}
	d.AddRules = append(d.AddRules, rules.Rule{Ops: rules.OpAll, Verdict: rules.Allow, Object: m, Expires: expires})
}

// exact matches obj alone, for "never".
func exact(obj rules.Object) rules.ObjectMatch {
	switch {
	case obj.Path != nil:
		return rules.ObjectMatch{Path: &rules.PathMatch{Path: obj.Path.Path}}
	case obj.Proc != nil:
		return rules.ObjectMatch{Proc: &rules.ProcMatch{Name: obj.Proc.Name, Comm: comm(obj.Proc)}}
	}
	return rules.ObjectMatch{Unknown: true}
}

func sameMatch(a, b rules.ObjectMatch) bool {
	switch {
	case a.Path != nil && b.Path != nil:
		return *a.Path == *b.Path
	case a.Proc != nil && b.Proc != nil:
		return *a.Proc == *b.Proc
	}
	return a.Unknown && b.Unknown
}

func comm(p *rules.ProcObject) string {
	if len(p.Target.Chain) == 0 {
		return ""
	}
	return p.Target.Chain[0].Comm
}

// uiRequest describes req for the asker.
func (s *session) uiRequest(req *monitor.Request, waiting int) ui.Request {
	r := ui.Request{Op: req.Op.String(), Waiting: max(0, waiting)}
	if ch := req.Subject.Chain; len(ch) > 0 {
		r.Exe, r.PID, r.Cmdline = ch[0].Exe, uint32(ch[0].TID), ch[0].Cmdline
		for _, p := range ch[1:min(len(ch), maxParents+1)] {
			r.Parents = append(r.Parents, p.Comm)
		}
	}
	switch obj := req.Objects[0]; {
	case obj.Path != nil:
		r.Path = obj.Path.Path
		r.Scope = s.cfg.Defaults.FolderFor(r.Path)
		r.Never = "this path"
		if w := s.cfg.Defaults.Warn(r.Path); w != "" {
			r.Warn = w + " — secret store"
		}
	case obj.Proc != nil:
		r.Path = procPath(obj.Proc)
		what := fmt.Sprintf("%s of %q processes outside the sandbox", obj.Proc.Name, comm(obj.Proc))
		r.Scope, r.Never = what, what
	default:
		// Allowing it skips every rule, including the denies, and a
		// process can make its path unreadable on purpose: so only "once"
		// is offered, never a lasting grant.
		r.Path = "(unknown path)"
		r.Never = "all unknown paths"
		r.Warn = "Unknown path — hallpass could not read it (" + obj.Unknown.Error() + ")"
	}
	return r
}

func procPath(p *rules.ProcObject) string {
	tid := 0
	if len(p.Target.Chain) > 0 {
		tid = p.Target.Chain[0].TID
	}
	return fmt.Sprintf("/proc/%d/%s", tid, p.Name)
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
	lines = append(lines, " Anything else is asked. A folder covers everything below it.   [any key] close")
	keys := make([]byte, 0, 255)
	for k := 1; k < 256; k++ {
		keys = append(keys, byte(k))
	}
	if s.cfg.TTY.Prompt(lines, string(keys), 0, 0, nil, nil) == 's' && s.wait.active.Load() {
		s.wait.Stop()
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

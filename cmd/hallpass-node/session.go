// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/answer"
	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/ui"
)

const (
	// client is the agent's name in monitor.Reason.Client.
	client = "hallpass-node"
	// remoteClient names answers from the session API that name no client.
	remoteClient = "remote"
)

// session mediates one container.
type session struct {
	id     string
	pid    int
	md     metadata
	policy *Policy
	d      *defaults.Defaults
	m      *monitor.Monitor
	// ks is the session in the kernel, strict mode only. Closed after m.
	ks     *lsm.Session
	evs    <-chan []monitor.Event
	start  time.Time
	log    *slog.Logger
	rec    recorder
	denied *denials

	mu     sync.Mutex
	timers map[uint64]*time.Timer

	// listeners are the attached listeners, guarded by agent.mu.
	listeners []*attached
	// onRules is called when the rules change.
	onRules func()
}

// attached is a listener the session's monitor uses.
type attached struct {
	pid int
	fd  int
	j   *seccomp.Journal
}

// newSession creates the monitor of container id with policy p and rules
// rs, or the policy's if nil, enforced by kernel session ks too if not nil
// (strict). The caller attaches the listeners. On an error, ks is closed.
func newSession(id string, pid int, md metadata, p *Policy, rs []rules.Rule, ks *lsm.Session, log *slog.Logger, rec recorder) (*session, error) {
	cats, err := md.categories()
	if err != nil {
		if ks != nil {
			ks.Close()
		}
		return nil, fmt.Errorf("listener metadata: %w", err)
	}
	cfg := monitor.Config{ProcRoot: true}
	if ks != nil {
		cfg.Kernel = ks
	}
	m, err := monitor.New(cfg)
	if err != nil {
		if ks != nil {
			ks.Close()
		}
		return nil, err
	}
	d := defaultsFor(p, md.Home, cats)
	if rs == nil {
		rs = d.Rules()
	}
	if _, err := m.Apply(monitor.Decision{AddRules: rs, Client: client}); err != nil {
		m.Close()
		if ks != nil {
			ks.Close()
		}
		return nil, err
	}
	s := &session{
		id: id, pid: pid, md: md, policy: p, d: d, m: m, ks: ks,
		// Subscribed before the first Attach: no request is missed.
		// Decided: to report the automatic denials.
		evs:    m.Events(monitor.EventOptions{Decided: true}),
		start:  time.Now(),
		log:    log.With("namespace", md.Namespace, "pod", md.Pod, "container", md.Container),
		rec:    rec,
		timers: map[uint64]*time.Timer{},
	}
	s.denied = &denials{report: func(msg string) { s.event(true, reasonPolicyDenied, msg) }}
	return s, nil
}

// event emits an Event on the container's pod.
func (s *session) event(warning bool, reason, msg string) {
	s.rec.event(s.md, warning, reason, "container "+s.md.Container+": "+msg)
}

// close stops mediating, then deletes the kernel's rules (strict).
func (s *session) close() {
	s.m.Close()
	if s.ks != nil {
		s.ks.Close()
	}
}

// run handles the requests until the container is gone: without ask, they
// are denied at once; with it, after the policy's askTimeout.
func (s *session) run() {
	for batch := range s.evs {
		for _, ev := range batch {
			switch {
			case ev.Opened != nil:
				s.opened(ev.Opened)
			case ev.Closed != nil:
				s.closed(ev.Closed)
			case ev.Decided != nil:
				s.decided(ev.Decided)
			case ev.Rules != 0:
				if s.onRules != nil {
					s.onRules()
				}
			case ev.Dropped != 0:
				s.log.Debug("decided accesses not counted", "dropped", ev.Dropped)
			case ev.Warning != "":
				s.log.Warn(ev.Warning)
			}
		}
	}
	s.denied.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.timers {
		t.Stop()
		delete(s.timers, id)
	}
}

// decided counts the automatic denials.
func (s *session) decided(d *monitor.Decided) {
	if d.Allowed {
		return
	}
	for i, why := range d.Why {
		if why == (monitor.Reason{}) {
			continue
		}
		if automatic(why, s.policy.Ask) && i < len(d.Objects) {
			s.denied.add(d.Op.String() + " " + objectName(d.Objects[i]))
		}
		return
	}
}

// objectName names o in an Event.
func objectName(o rules.Object) string {
	switch {
	case o.Path != nil:
		return clean(o.Path.Path)
	case o.Inet != nil:
		return clean(o.Inet.String())
	case o.Unix != nil:
		return clean(o.Unix.String())
	case o.Unknown != nil:
		return "(unknown path)"
	}
	return "(not a file)"
}

func (s *session) opened(req *monitor.Request) {
	r := answer.Request(s.d, req, 0)
	s.log.Info("request", "id", req.ID, "op", r.Op, "path", r.Path, "exe", r.Exe, "pid", r.PID)
	if !s.policy.Ask {
		s.dismiss(req.ID)
		return
	}
	if s.policy.AskTimeout == 0 {
		// Waits for an answer, however long.
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timers[req.ID] = time.AfterFunc(s.policy.AskTimeout, func() { s.dismiss(req.ID) })
}

func (s *session) closed(c *monitor.Closed) {
	s.mu.Lock()
	if t := s.timers[c.ID]; t != nil {
		t.Stop()
		delete(s.timers, c.ID)
	}
	s.mu.Unlock()
	why := c.Why.Client
	switch {
	case c.Why.Rule != 0:
		why = "rule " + strconv.FormatUint(c.Why.Rule, 10)
	case c.Why.Died:
		why = "died"
	}
	s.log.Info("request closed", "id", c.ID, "by", why)
}

// dismiss denies request id, if still pending, without remembering it.
func (s *session) dismiss(id uint64) {
	req, rs, err := answer.Find(s.m, id)
	if err != nil {
		return
	}
	if err := answer.Apply(s.m, s.d, req, ui.AnswerDismissed, rs, client); err != nil {
		if !errors.Is(err, monitor.ErrClosed) {
			s.log.Error("deny", "id", id, "err", err)
		}
		return
	}
	if s.policy.Ask {
		s.event(true, reasonNotAnswered, fmt.Sprintf("%s: not answered within %v, denied", describe(answer.Request(s.d, req, 0)), s.policy.AskTimeout))
	}
}

// describe names a request in an Event: "write /etc/profile by /bin/sh".
func describe(r ui.Request) string {
	return r.Op + " " + clean(r.Path) + " by " + clean(r.Exe)
}

// Info implements sessionapi.Session.
func (s *session) Info() *pb.SessionInfo {
	var timeout time.Duration
	if s.policy.Ask {
		timeout = s.policy.AskTimeout
	}
	return &pb.SessionInfo{
		Pid:           int32(s.pid),
		Mode:          "lite",
		StartTime:     timestamppb.New(s.start),
		PromptTimeout: durationpb.New(timeout),
		Labels: map[string]string{
			"namespace":   s.md.Namespace,
			"pod":         s.md.Pod,
			"podUID":      s.md.PodUID,
			"container":   s.md.Container,
			"containerID": s.id,
			"policy":      s.policy.Name,
			"ask":         strconv.FormatBool(s.policy.Ask),
		},
	}
}

// Prompt implements sessionapi.Session.
func (s *session) Prompt(req *monitor.Request) *pb.Prompt {
	r := answer.Request(s.d, req, 0)
	return &pb.Prompt{
		Op: r.Op, Path: r.Path, Exe: r.Exe, Pid: r.PID,
		Cmdline: r.Cmdline, Parents: r.Parents,
		Scope: r.Scope, Never: r.Never, Warn: r.Warn, Note: r.Note, Detail: r.Detail,
	}
}

// Answer implements sessionapi.Session.
func (s *session) Answer(id uint64, a, who string) error {
	ans := ui.ParseAnswer(a)
	if ans == ui.AnswerDismissed && a != ui.AnswerDismissed.String() {
		return fmt.Errorf("%w %q", sessionapi.ErrBadAnswer, a)
	}
	if who == "" {
		who = remoteClient
	}
	req, rs, err := answer.Find(s.m, id)
	if err != nil {
		return err
	}
	s.log.Info("answer", "id", id, "answer", ans.String(), "client", who)
	if err := answer.Apply(s.m, s.d, req, ans, rs, who); err != nil {
		return err
	}
	deny := ans == ui.AnswerDenyOnce || ans == ui.AnswerNever || ans == ui.AnswerDismissed
	reason := reasonAllowed
	if deny {
		reason = reasonDenied
	}
	s.event(deny, reason, fmt.Sprintf("%s: answered %s from %s", describe(answer.Request(s.d, req, 0)), ans, clean(who)))
	return nil
}

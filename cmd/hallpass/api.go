// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/answer"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/ui"
)

// remoteClient is the Reason.Client of answers from the socket that name
// no client.
const remoteClient = "remote"

// Info implements sessionapi.Session.
func (s *session) Info() *pb.SessionInfo {
	mode := "lite"
	if s.cfg.LSM != nil {
		mode = "strict"
	}
	return &pb.SessionInfo{
		Pid:           int32(os.Getpid()),
		Command:       s.cfg.Args,
		Workdir:       s.cfg.Dir,
		Mode:          mode,
		StartTime:     timestamppb.New(s.start),
		PromptTimeout: durationpb.New(s.cfg.Timeout),
	}
}

// Prompt implements sessionapi.Session.
func (s *session) Prompt(req *monitor.Request) *pb.Prompt {
	return sessionapi.ToPBPrompt(s.uiRequest(req, 0))
}

// Answer implements sessionapi.Session.
func (s *session) Answer(id uint64, answer, who string) error {
	a := ui.ParseAnswer(answer)
	if a == ui.AnswerDismissed && answer != ui.AnswerDismissed.String() {
		return fmt.Errorf("%w %q", sessionapi.ErrBadAnswer, answer)
	}
	if who == "" {
		who = remoteClient
	}
	pending, rs, _ := s.m.Snapshot()
	for _, r := range pending {
		if r.ID == id {
			return s.answer(r, a, rs, who)
		}
	}
	return fmt.Errorf("request %d: %w", id, monitor.ErrClosed)
}

// CheckRules implements sessionapi.Session.
func (s *session) CheckRules(_ string, add, removed []rules.Rule) error {
	return answer.CheckRules(s.cfg.Defaults, add, removed)
}

// RulesChanged implements sessionapi.Session.
func (s *session) RulesChanged(string, []rules.Rule, []rules.Rule) {}

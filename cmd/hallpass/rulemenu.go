// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/ui"
)

// menuTerm is the part of tty.Term the rules menu uses.
type menuTerm interface {
	Height() int
	Prompt(lines []string, accept string, guard, timeout time.Duration, cancel <-chan struct{}, relabel <-chan []string) byte
	ReadLine(lines []string, text string) (string, bool)
}

// anyKey accepts every key in Prompt.
var anyKey = func() string {
	keys := make([]byte, 0, 255)
	for k := 1; k < 256; k++ {
		keys = append(keys, byte(k))
	}
	return string(keys)
}()

// ruleSyntax is the help shown while typing a rule.
var ruleSyntax = func() []string {
	var lines []string
	for _, l := range strings.Split(rules.SpecSyntax, "\n") {
		lines = append(lines, " "+l)
	}
	return append(lines, ` An allow rule gives at most what answering "always" would, or narrows the rule it replaces.`)
}()

// rulesMenu lists the session's rules over the program's screen, to add,
// edit or delete one, until another key is pressed. Changes apply to this
// session only, with the same checks as from the session API. Call with
// promptMu held.
func (s *session) rulesMenu(t menuTerm) {
	msg := ""
	page := 0
	for {
		_, rs, gen := s.m.Snapshot()
		per := max(1, t.Height()-4)
		pages := max(1, (len(rs)+per-1)/per)
		page = min(max(page, 0), pages-1)
		title := " hallpass: the rules of this session (changes apply to this session only)"
		keys := " [a] add   [e] edit   [d] delete   [any key] close"
		if pages > 1 {
			title = fmt.Sprintf(" hallpass: the rules of this session, page %d/%d (changes apply to this session only)", page+1, pages)
			keys = " [a] add   [e] edit   [d] delete   [n] next page   [p] previous page   [any key] close"
		}
		head := append([]string{title}, ruleLines(rs[page*per:min(len(rs), (page+1)*per)], time.Now())...)
		lines := head
		if msg != "" {
			lines = append(lines[:len(lines):len(lines)], " "+msg)
		}
		lines = append(lines[:len(lines):len(lines)], keys)
		var (
			d   monitor.Decision
			err error
		)
		switch t.Prompt(lines, anyKey, 0, 0, nil, nil) {
		case 'n':
			page, msg = page+1, ""
			continue
		case 'p':
			page, msg = page-1, ""
			continue
		case 'a':
			spec, ok := t.ReadLine(append(ruleSyntax[:len(ruleSyntax):len(ruleSyntax)], " Rule: "), "")
			if !ok {
				msg = ""
				continue
			}
			label, ok := t.ReadLine([]string{" Rule: " + spec, " Label (optional): "}, "")
			if !ok {
				msg = ""
				continue
			}
			d, err = addRuleDecision(spec, strings.TrimSpace(label), time.Now())
		case 'e':
			var old rules.Rule
			old, err = s.pickRule(t, head, rs, " Edit rule ID: ")
			if old.ID == 0 && err == nil {
				msg = ""
				continue
			}
			if err != nil {
				break
			}
			if err = checkEditable(old, time.Now()); err != nil {
				break
			}
			spec, ok := t.ReadLine(append(ruleSyntax[:len(ruleSyntax):len(ruleSyntax)], fmt.Sprintf(" Rule %d: ", old.ID)), old.EditSpec(time.Now()))
			if !ok {
				msg = ""
				continue
			}
			d, err = editRuleDecision(old, spec, gen, time.Now())
		case 'd':
			var old rules.Rule
			old, err = s.pickRule(t, head, rs, " Delete rule ID: ")
			if old.ID == 0 && err == nil {
				msg = ""
				continue
			}
			d.RemoveRules = []uint64{old.ID}
		default:
			return
		}
		if err == nil {
			d.Client = client
			_, err = sessionapi.ApplyRules(s.m, s, d)
		}
		if err != nil {
			msg = "Not changed: " + ruleError(err).Error()
		} else {
			msg = "Done."
			if len(d.AddRules) > 0 {
				// The monitor adds rules last: show them.
				page = len(rs) + 1
			}
		}
	}
}

// pickRule asks for the ID of one of rs, under head. It returns a zero rule
// and no error when cancelled.
func (s *session) pickRule(t menuTerm, head []string, rs []rules.Rule, prompt string) (rules.Rule, error) {
	id, ok := t.ReadLine(append(head[:len(head):len(head)], prompt), "")
	if !ok || strings.TrimSpace(id) == "" {
		return rules.Rule{}, nil
	}
	return ruleByID(rs, strings.TrimSpace(id))
}

// ruleLines shows rs, one per line.
func ruleLines(rs []rules.Rule, now time.Time) []string {
	if len(rs) == 0 {
		return []string{"   (none)"}
	}
	var lines []string
	for _, r := range rs {
		l := fmt.Sprintf(" %4d  %s", r.ID, ui.Sanitize(r.EditSpec(now)))
		if r.Label != "" {
			l += "  (" + ui.Sanitize(r.Label) + ")"
		}
		lines = append(lines, l)
	}
	return lines
}

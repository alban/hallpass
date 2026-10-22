// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rulepb"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/ui"
)

const ruleCmdUsage = `hallpass answer [PID] rules                  list the session's rules
hallpass answer [PID] add [--label TEXT] RULE  add a rule
hallpass answer [PID] edit ID RULE           replace rule ID
hallpass answer [PID] delete ID...           remove rules`

// isRuleCmd reports whether arg starts a rule command of hallpass answer.
func isRuleCmd(arg string) bool {
	switch arg {
	case "rules", "add", "edit", "delete":
		return true
	}
	return false
}

// runRuleCmd runs the rule command args on the session c, as answerClient.
func runRuleCmd(ctx context.Context, c pb.SessionClient, args []string, out io.Writer) error {
	snap, err := c.Snapshot(ctx, &pb.SnapshotRequest{})
	if err != nil {
		return errors.New(status.Convert(err).Message())
	}
	rs := make([]rules.Rule, 0, len(snap.Rules))
	for _, p := range snap.Rules {
		r, err := rulepb.From(p)
		if err != nil {
			// Shown as "?", and can still be deleted.
			r = rules.Rule{Label: p.Label}
		}
		r.ID = p.Id
		rs = append(rs, r)
	}
	now := time.Now()
	var d monitor.Decision
	switch args[0] {
	case "rules":
		if len(args) != 1 {
			return errors.New("usage: " + ruleCmdUsage)
		}
		listRules(out, rs, now)
		return nil
	case "add":
		label := ""
		args = args[1:]
		if len(args) > 1 && args[0] == "--label" {
			label, args = args[1], args[2:]
		}
		d, err = addRuleDecision(args, label, now)
	case "edit":
		if len(args) < 3 {
			return errors.New("usage: hallpass answer [PID] edit ID RULE")
		}
		old, err := ruleByID(rs, args[1])
		if err != nil {
			return err
		}
		d, err = editRuleDecision(old, args[2:], snap.Generation, now)
		if err != nil {
			return err
		}
	case "delete":
		if len(args) < 2 {
			return errors.New("usage: hallpass answer [PID] delete ID...")
		}
		for _, a := range args[1:] {
			r, err := ruleByID(rs, a)
			if err != nil {
				return err
			}
			d.RemoveRules = append(d.RemoveRules, r.ID)
		}
	}
	if err != nil {
		return err
	}
	pd := &pb.Decision{RemoveRules: d.RemoveRules, IfGeneration: d.IfGeneration, Client: answerClient}
	for _, r := range d.AddRules {
		pd.AddRules = append(pd.AddRules, rulepb.To(r))
	}
	if _, err := c.Apply(ctx, pd); err != nil {
		return ruleError(err)
	}
	return nil
}

// ruleError turns an error applying a rule change into one for the user.
func ruleError(err error) error {
	st := status.Convert(err)
	if st.Code() == codes.FailedPrecondition {
		return errors.New("the rules changed meanwhile: look at them again")
	}
	return errors.New(st.Message())
}

// listRules writes rs as a table: ID, rule, label.
func listRules(out io.Writer, rs []rules.Rule, now time.Time) {
	if len(rs) == 0 {
		fmt.Fprintln(out, "No rules.")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tRULE\tLABEL")
	for _, r := range rs {
		fmt.Fprintf(tw, "%d\t%s\t%s\n", r.ID, ui.Sanitize(r.EditSpec(now)), ui.Sanitize(r.Label))
	}
	tw.Flush()
}

// ruleByID returns the rule of rs whose ID is written id.
func ruleByID(rs []rules.Rule, id string) (rules.Rule, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(id, "#"), 10, 64)
	if err != nil {
		return rules.Rule{}, fmt.Errorf("bad rule ID %q", id)
	}
	for _, r := range rs {
		if r.ID == n {
			return r, nil
		}
	}
	return rules.Rule{}, fmt.Errorf("no rule %d", n)
}

// addRuleDecision adds the rule spec, labelled label.
func addRuleDecision(args []string, label string, now time.Time) (monitor.Decision, error) {
	r, err := rules.ParseSpecArgs(args, now)
	if err != nil {
		return monitor.Decision{}, err
	}
	r.Label = label
	return monitor.Decision{AddRules: []rules.Rule{r}}, nil
}

// editRuleDecision replaces old by the rule of args (rules.ParseSpecArgs),
// if the rules are still at generation gen.
func editRuleDecision(old rules.Rule, args []string, gen uint64, now time.Time) (monitor.Decision, error) {
	if err := checkEditable(old, now); err != nil {
		return monitor.Decision{}, err
	}
	r, err := rules.ParseSpecArgs(args, now)
	if err != nil {
		return monitor.Decision{}, err
	}
	r.Label = old.EditLabel()
	return monitor.Decision{AddRules: []rules.Rule{r}, RemoveRules: []uint64{old.ID}, IfGeneration: gen}, nil
}

// checkEditable fails for a rule the text syntax cannot write.
func checkEditable(r rules.Rule, now time.Time) error {
	if !r.Editable(now) {
		return fmt.Errorf("rule %d cannot be written as text: delete it and add another", r.ID)
	}
	return nil
}

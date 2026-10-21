// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/sessionapi"
	"github.com/alban/hallpass/internal/ui"
)

// answerClient is `hallpass answer`'s name in monitor.Reason.Client.
const answerClient = "hallpass answer"

func answerMain(argv []string) int {
	var path string
	pid := ""
	if len(argv) > 0 && !isRuleCmd(argv[0]) {
		pid, argv = argv[0], argv[1:]
	}
	if len(argv) > 0 && !isRuleCmd(argv[0]) {
		return fail(errors.New("usage: hallpass answer [PID]\n" + ruleCmdUsage))
	}
	if pid == "" {
		matches, _ := filepath.Glob(filepath.Join(sessionapi.SocketDir(), "*.sock"))
		switch len(matches) {
		case 0:
			return fail(errors.New("no hallpass session is waiting for answers"))
		case 1:
			path = matches[0]
		default:
			return fail(fmt.Errorf("several sessions; pick one: hallpass answer PID (%s)", strings.Join(matches, " ")))
		}
	} else {
		var n int
		if _, err := fmt.Sscanf(pid, "%d", &n); err != nil {
			return fail(fmt.Errorf("bad PID %q", pid))
		}
		path = sessionapi.SocketPath(n)
	}
	if len(argv) > 0 {
		if err := ruleCmd(path, argv, os.Stdout); err != nil {
			return fail(err)
		}
		return 0
	}
	if err := runAnswer(path, os.Stdin, os.Stdout); err != nil {
		return fail(err)
	}
	return 0
}

// ruleCmd runs the rule command args on the session on path.
func ruleCmd(path string, args []string, out io.Writer) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	conn, c, err := sessionapi.Dial(path)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return runRuleCmd(ctx, c, args, out)
}

// runAnswer follows the session on path and asks, one at a time, about its
// pending requests on in and out, until the session or in ends.
func runAnswer(path string, in io.Reader, out io.Writer) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	conn, c, err := sessionapi.Dial(path)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := c.Info(ctx, &pb.InfoRequest{}); err != nil {
		return errors.New(status.Convert(err).Message())
	}
	stream, err := c.Events(ctx, &pb.EventsRequest{Snapshot: true})
	if err != nil {
		return errors.New(status.Convert(err).Message())
	}
	fmt.Fprintf(out, "Connected to %s. Waiting for prompts...\n", path)

	batches := make(chan *pb.EventBatch)
	go func() {
		defer close(batches)
		for {
			b, err := stream.Recv()
			if err != nil {
				return
			}
			batches <- b
		}
	}()
	lines := make(chan string)
	go func() {
		defer close(lines)
		r := bufio.NewReader(in)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			select {
			case lines <- l:
			case <-ctx.Done():
				return
			}
		}
	}()

	var (
		queue []*pb.Request // pending, oldest first
		shown *pb.Request
		keys  map[string]ui.Answer
	)
	remove := func(id uint64) bool {
		for i, r := range queue {
			if r.Id == id {
				queue = append(queue[:i], queue[i+1:]...)
				return true
			}
		}
		return false
	}
	add := func(r *pb.Request) {
		for _, q := range queue {
			if q.Id == r.Id {
				return
			}
		}
		queue = append(queue, r)
	}
	for {
		if shown == nil && len(queue) > 0 {
			shown = queue[0]
			var text string
			text, keys = promptRequest(shown.Prompt, len(queue)-1).Text()
			fmt.Fprint(out, "\n"+text)
		}
		select {
		case b, ok := <-batches:
			if !ok {
				fmt.Fprintln(out, "Session ended.")
				return nil
			}
			if s := b.Snapshot; s != nil {
				for _, r := range s.Pending {
					add(r)
				}
			}
			for _, e := range b.Events {
				switch k := e.Kind.(type) {
				case *pb.Event_Opened:
					add(k.Opened)
				case *pb.Event_Closed:
					remove(k.Closed.Id)
					if shown != nil && shown.Id == k.Closed.Id {
						fmt.Fprintf(out, "\n  (%s)\n", closedBy(k.Closed.Why))
						shown = nil
					}
				}
			}
		case l, ok := <-lines:
			if !ok {
				return nil
			}
			if shown == nil {
				continue
			}
			a, ok := keys[strings.ToLower(strings.TrimSpace(l))]
			if !ok {
				a = ui.AnswerDismissed
			}
			id := shown.Id
			remove(id)
			shown = nil
			_, err := c.Answer(ctx, &pb.AnswerRequest{Request: id, Answer: a.String(), Client: answerClient})
			switch status.Code(err) {
			case codes.OK:
			case codes.NotFound:
				fmt.Fprintln(out, "  (already closed)")
			default:
				fmt.Fprintf(out, "  (error: %s)\n", status.Convert(err).Message())
			}
		}
	}
}

// promptRequest converts p for display. waiting is the number of other
// requests queued behind it.
func promptRequest(p *pb.Prompt, waiting int) ui.Request {
	if p == nil {
		return ui.Request{Op: "access", Path: "(unknown)", Waiting: waiting}
	}
	return ui.Request{
		Op: p.Op, Path: p.Path, Exe: p.Exe, PID: p.Pid,
		Cmdline: p.Cmdline, Parents: p.Parents,
		Scope: p.Scope, Never: p.Never, Warn: p.Warn, Note: p.Note, Detail: p.Detail, Group: p.Group,
		Advance: p.Advance, Reason: p.Reason, For: p.GrantFor.AsDuration(),
		Waiting: waiting,
	}
}

// closedBy says why a request closed before this client answered it.
func closedBy(why *pb.Reason) string {
	switch {
	case why == nil:
		return "closed"
	case why.Died:
		return "the process is gone"
	case why.Rule != 0:
		return fmt.Sprintf("settled by rule %d", why.Rule)
	case why.Builtin != "":
		return "settled by hallpass (" + why.Builtin + ")"
	case why.Client == client:
		return "answered in the session's terminal, or timed out"
	case why.Client != "":
		return "answered by " + why.Client
	}
	return "closed"
}

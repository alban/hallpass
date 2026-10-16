// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alban/hallpass/internal/sessionapi"
	pb "github.com/alban/hallpass/internal/sessionpb"
)

// clientFlags are the flags of the client commands.
func clientFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:7323", "the node agent's session API, e.g. through kubectl port-forward")
	return fs, addr
}

func dial(addr string) (pb.SessionClient, func(), error) {
	conn, c, err := sessionapi.DialHub(addr)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { conn.Close() }, nil
}

func cmdSessions(args []string) error {
	fs, addr := clientFlags("sessions")
	_ = fs.Parse(args)
	c, done, err := dial(*addr)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l, err := c.List(ctx, &pb.ListRequest{})
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SESSION\tNAMESPACE/POD/CONTAINER\tPOLICY\tPID\tSTARTED")
	for _, s := range l.Sessions {
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", s.Id, name(s), s.Labels["policy"], s.Pid, s.StartTime.AsTime().Format(time.RFC3339))
	}
	return w.Flush()
}

// name is a session's namespace/pod/container.
func name(s *pb.SessionInfo) string {
	return s.Labels["namespace"] + "/" + s.Labels["pod"] + "/" + s.Labels["container"]
}

// findSession resolves ref, a session id, a unique id prefix, or
// namespace/pod/container (the latest session of that container).
func findSession(ctx context.Context, c pb.SessionClient, ref string) (string, error) {
	l, err := c.List(ctx, &pb.ListRequest{})
	if err != nil {
		return "", err
	}
	var found *pb.SessionInfo
	n := 0
	for _, s := range l.Sessions {
		switch {
		case s.Id == ref:
			return s.Id, nil
		case strings.Count(ref, "/") == 2 && name(s) == ref:
			if found == nil || s.StartTime.AsTime().After(found.StartTime.AsTime()) {
				found = s
			}
			n = 1
		case strings.HasPrefix(s.Id, ref):
			found = s
			n++
		}
	}
	switch n {
	case 0:
		return "", fmt.Errorf("no session %q", ref)
	case 1:
		return found.Id, nil
	}
	return "", fmt.Errorf("session %q is ambiguous", ref)
}

func cmdPending(args []string) error {
	fs, addr := clientFlags("pending")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: hallpass-node pending [--addr host:port] <session|namespace/pod/container>")
	}
	c, done, err := dial(*addr)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := findSession(ctx, c, fs.Arg(0))
	if err != nil {
		return err
	}
	snap, err := c.Snapshot(sessionapi.WithSession(ctx, id), &pb.SnapshotRequest{})
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "REQUEST\tOP\tPATH\tEXE\tPID")
	for _, r := range snap.Pending {
		p := r.GetPrompt()
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\n", r.GetId(), p.GetOp(), p.GetPath(), p.GetExe(), p.GetPid())
	}
	return w.Flush()
}

func cmdAnswer(args []string) error {
	fs, addr := clientFlags("answer")
	_ = fs.Parse(args)
	if fs.NArg() != 3 {
		return fmt.Errorf("usage: hallpass-node answer [--addr host:port] <session|namespace/pod/container> <request> <once|temp|always|deny|never>")
	}
	req, err := strconv.ParseUint(fs.Arg(1), 10, 64)
	if err != nil {
		return fmt.Errorf("request %q: %w", fs.Arg(1), err)
	}
	c, done, err := dial(*addr)
	if err != nil {
		return err
	}
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := findSession(ctx, c, fs.Arg(0))
	if err != nil {
		return err
	}
	_, err = c.Answer(sessionapi.WithSession(ctx, id), &pb.AnswerRequest{Request: req, Answer: fs.Arg(2), Client: "hallpass-node answer"})
	return err
}

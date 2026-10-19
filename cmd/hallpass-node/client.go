// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/nodeclient"
	"github.com/alban/hallpass/internal/ui"
)

// clientFlags are the flags of the client commands.
func clientFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:7323", "the node agent's session API, e.g. through kubectl port-forward")
	return fs, addr
}

func dial(addr string) (pb.SessionClient, func(), error) {
	conn, c, err := nodeclient.Dial(addr)
	if err != nil {
		return nil, nil, err
	}
	return c, func() { conn.Close() }, nil
}

// cmdReady checks the agent's gRPC health service: the readiness probe.
func cmdReady(args []string) error {
	fs, addr := clientFlags("ready")
	_ = fs.Parse(args)
	conn, _, err := nodeclient.Dial(*addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		return err
	}
	if r.Status != healthpb.HealthCheckResponse_SERVING {
		return fmt.Errorf("not ready: %v (see the agent's logs)", r.Status)
	}
	return nil
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
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n", s.Id, nodeclient.Name(s), s.Labels["policy"], s.Pid, s.StartTime.AsTime().Format(time.RFC3339))
	}
	return w.Flush()
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
	id, err := nodeclient.Find(ctx, c, fs.Arg(0))
	if err != nil {
		return err
	}
	snap, err := c.Snapshot(nodeclient.WithSession(ctx, id), &pb.SnapshotRequest{})
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "REQUEST\tOP\tPATH\tEXE\tPID")
	for _, r := range snap.Pending {
		p := r.GetPrompt()
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\n", r.GetId(), p.GetOp(), p.GetPath(), p.GetExe(), p.GetPid())
		if s := advanceLine(p); s != "" {
			// No tab: a line's last cell does not size the columns.
			fmt.Fprintln(w, s)
		}
	}
	return w.Flush()
}

// advanceLine describes a request made in advance below its row, or ""
// for another request: "  asked in advance for 10m; reason given by the
// program (unverified): "...""
func advanceLine(p *pb.Prompt) string {
	if !p.GetAdvance() {
		return ""
	}
	r := ui.Request{For: p.GetGrantFor().AsDuration(), Reason: p.GetReason()}
	s := "  asked in advance " + r.AdvanceFor() + ", answer grant or deny"
	if reason := r.AdvanceReason(); reason != "" {
		s += "; " + ui.ReasonLabel + ": " + reason
	}
	return s
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
	id, err := nodeclient.Find(ctx, c, fs.Arg(0))
	if err != nil {
		return err
	}
	_, err = c.Answer(nodeclient.WithSession(ctx, id), &pb.AnswerRequest{Request: req, Answer: fs.Arg(2), Client: "hallpass-node answer"})
	return err
}

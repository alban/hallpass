// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rulepb"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/ui"
)

// ToPBPrompt converts what a prompt shows (see Session.Prompt).
func ToPBPrompt(r ui.Request) *pb.Prompt {
	p := &pb.Prompt{
		Op: r.Op, Path: r.Path, Exe: r.Exe, Pid: r.PID,
		Cmdline: r.Cmdline, Parents: r.Parents,
		Scope: r.Scope, Never: r.Never, Warn: r.Warn, Note: r.Note, Detail: r.Detail, Group: r.Group,
		Advance: r.Advance, Reason: r.Reason,
	}
	if r.For > 0 {
		p.GrantFor = durationpb.New(r.For)
	}
	return p
}

func toPBRequest(r *monitor.Request, p *pb.Prompt) *pb.Request {
	out := &pb.Request{
		Id:      r.ID,
		Syscall: r.Syscall,
		Op:      uint32(r.Op),
		Subject: toPBSubject(r.Subject),
		Prompt:  p,
	}
	for _, o := range r.Objects {
		out.Objects = append(out.Objects, toPBObject(o))
	}
	for _, f := range r.Facts {
		out.Facts = append(out.Facts, &pb.Fact{Kind: f.Kind, Value: f.Value, Trust: pb.Trust(f.Trust)})
	}
	if a := r.Advance; a != nil {
		out.Advance = &pb.Advance{Tree: a.Tree, Reason: a.Reason, Writable: a.Writable}
		if a.Net.IsNet() {
			out.Advance.Dest = a.Net.NetString()
		}
		if a.For > 0 {
			out.Advance.For = durationpb.New(a.For)
		}
	}
	return out
}

func toPBObject(o rules.Object) *pb.Object {
	switch {
	case o.Path != nil:
		return &pb.Object{Kind: &pb.Object_Path{Path: &pb.PathObject{Path: o.Path.Path, Dev: o.Path.Dev, Ino: o.Path.Ino}}}
	case o.Proc != nil:
		return &pb.Object{Kind: &pb.Object_Proc{Proc: &pb.ProcObject{Name: o.Proc.Name, Target: toPBSubject(o.Proc.Target)}}}
	case o.Unknown != nil:
		return &pb.Object{Kind: &pb.Object_Unknown{Unknown: o.Unknown.Error()}}
	case o.Inet != nil:
		return &pb.Object{Kind: &pb.Object_Inet{Inet: &pb.InetObject{
			Proto: uint32(o.Inet.Proto), Addr: o.Inet.Addr.Addr().String(), Port: uint32(o.Inet.Addr.Port()),
			OwnListener: o.Inet.OwnListener,
		}}}
	case o.Unix != nil:
		return &pb.Object{Kind: &pb.Object_Unix{Unix: &pb.UnixObject{
			Path: o.Unix.Path, Abstract: o.Unix.Abstract, Name: o.Unix.Name, Type: int32(o.Unix.Type),
			OwnListener: o.Unix.OwnListener,
		}}}
	}
	return &pb.Object{}
}

func toPBSubject(s rules.Subject) *pb.Subject {
	out := &pb.Subject{}
	for _, t := range s.Chain {
		out.Chain = append(out.Chain, &pb.Task{
			Pid: int32(t.PID), Tid: int32(t.TID), StartTime: t.StartTime,
			Comm: t.Comm, Exe: t.Exe, ExeDev: t.ExeDev, ExeIno: t.ExeIno,
			Cmdline: t.Cmdline, Cwd: t.Cwd,
		})
	}
	return out
}

func toPBReason(r monitor.Reason) *pb.Reason {
	return &pb.Reason{Client: r.Client, Rule: r.Rule, Builtin: r.Builtin, Died: r.Died}
}

func toPBDecided(d *monitor.Decided) *pb.Decided {
	out := &pb.Decided{
		Time:    timestamppb.New(d.Time),
		Syscall: d.Syscall,
		Op:      uint32(d.Op),
		Subject: toPBSubject(d.Subject),
		Allowed: d.Allowed,
		Source:  pb.Source(d.Source),
	}
	for _, o := range d.Objects {
		out.Objects = append(out.Objects, toPBObject(o))
	}
	for _, r := range d.Why {
		out.Why = append(out.Why, toPBReason(r))
	}
	return out
}

func fromPBDecision(d *pb.Decision) (monitor.Decision, error) {
	out := monitor.Decision{
		RemoveRules:  d.GetRemoveRules(),
		RemoveSets:   d.GetRemoveSets(),
		IfGeneration: d.GetIfGeneration(),
		Client:       d.GetClient(),
		TimedOut:     d.GetTimedOut(),
	}
	for _, v := range d.GetVerdicts() {
		out.Verdicts = append(out.Verdicts, monitor.Verdict{Request: v.GetRequest(), Allow: v.GetAllow()})
	}
	for _, r := range d.GetAddRules() {
		rr, err := rulepb.From(r)
		if err != nil {
			return out, err
		}
		out.AddRules = append(out.AddRules, rr)
	}
	return out, nil
}

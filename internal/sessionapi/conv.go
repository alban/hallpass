// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"errors"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
)

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

func toPBRule(r rules.Rule) *pb.Rule {
	out := &pb.Rule{
		Id:      r.ID,
		Ops:     uint32(r.Ops),
		Object:  &pb.ObjectMatch{},
		Verdict: pb.RuleVerdict(r.Verdict),
		Label:   r.Label,
		Set:     r.Set,
	}
	switch o := r.Object; {
	case o.Path != nil:
		out.Object.Kind = &pb.ObjectMatch_Path{Path: &pb.PathMatch{Path: o.Path.Path, Tree: o.Path.Tree}}
	case o.Proc != nil:
		out.Object.Kind = &pb.ObjectMatch_Proc{Proc: &pb.ProcMatch{Name: o.Proc.Name, Comm: o.Proc.Comm}}
	case o.Unknown:
		out.Object.Kind = &pb.ObjectMatch_Unknown{Unknown: true}
	}
	if !r.Expires.IsZero() {
		out.Expires = timestamppb.New(r.Expires)
	}
	return out
}

func fromPBRule(r *pb.Rule) (rules.Rule, error) {
	out := rules.Rule{
		Ops:     rules.Op(r.GetOps()),
		Verdict: rules.Verdict(r.GetVerdict()),
		Label:   r.GetLabel(),
		Set:     r.GetSet(),
	}
	if out.Verdict < rules.Allow || out.Verdict > rules.Ask {
		return out, errors.New("unknown rule verdict")
	}
	switch k := r.GetObject().GetKind().(type) {
	case *pb.ObjectMatch_Path:
		out.Object.Path = &rules.PathMatch{Path: k.Path.GetPath(), Tree: k.Path.GetTree()}
	case *pb.ObjectMatch_Proc:
		out.Object.Proc = &rules.ProcMatch{Name: k.Proc.GetName(), Comm: k.Proc.GetComm()}
	case *pb.ObjectMatch_Unknown:
		out.Object.Unknown = k.Unknown
	default:
		return out, errors.New("rule without an object")
	}
	if e := r.GetExpires(); e != nil {
		out.Expires = e.AsTime()
	}
	return out, nil
}

func fromPBDecision(d *pb.Decision) (monitor.Decision, error) {
	out := monitor.Decision{
		RemoveRules:  d.GetRemoveRules(),
		RemoveSets:   d.GetRemoveSets(),
		IfGeneration: d.GetIfGeneration(),
		Client:       d.GetClient(),
	}
	for _, v := range d.GetVerdicts() {
		out.Verdicts = append(out.Verdicts, monitor.Verdict{Request: v.GetRequest(), Allow: v.GetAllow()})
	}
	for _, r := range d.GetAddRules() {
		rr, err := fromPBRule(r)
		if err != nil {
			return out, err
		}
		out.AddRules = append(out.AddRules, rr)
	}
	return out, nil
}

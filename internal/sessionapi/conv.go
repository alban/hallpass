// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"errors"
	"fmt"
	"net/netip"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
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
	case o.Inet != nil:
		m := &pb.InetMatch{Proto: uint32(o.Inet.Proto), PortLo: uint32(o.Inet.PortLo), PortHi: uint32(o.Inet.PortHi)}
		if o.Inet.Prefix.IsValid() {
			m.Prefix = o.Inet.Prefix.String()
		}
		out.Object.Kind = &pb.ObjectMatch_Inet{Inet: m}
	case o.Unix != nil:
		out.Object.Kind = &pb.ObjectMatch_Unix{Unix: &pb.UnixMatch{
			Path: o.Unix.Path, Abstract: o.Unix.Abstract, Name: o.Unix.Name, Prefix: o.Unix.Prefix,
		}}
	case o.OwnListener:
		out.Object.Kind = &pb.ObjectMatch_OwnListener{OwnListener: true}
	case o.AnyNet:
		out.Object.Kind = &pb.ObjectMatch_AnyNet{AnyNet: true}
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
	case *pb.ObjectMatch_Inet:
		i := k.Inet
		if i.GetProto() > 0xffff || i.GetPortLo() > 0xffff || i.GetPortHi() > 0xffff {
			return out, errors.New("inet rule: protocol or port out of range")
		}
		m := &rules.InetMatch{Proto: uint16(i.GetProto()), PortLo: uint16(i.GetPortLo()), PortHi: uint16(i.GetPortHi())}
		if s := i.GetPrefix(); s != "" {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return out, fmt.Errorf("inet rule: %w", err)
			}
			m.Prefix = p
		}
		out.Object.Inet = m
	case *pb.ObjectMatch_Unix:
		u := k.Unix
		out.Object.Unix = &rules.UnixMatch{Path: u.GetPath(), Abstract: u.GetAbstract(), Name: u.GetName(), Prefix: u.GetPrefix()}
	case *pb.ObjectMatch_OwnListener:
		out.Object.OwnListener = k.OwnListener
	case *pb.ObjectMatch_AnyNet:
		out.Object.AnyNet = k.AnyNet
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
		TimedOut:     d.GetTimedOut(),
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

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package rulepb converts rules to and from the session API messages. It
// builds for js/wasm, for the Headlamp plugin.
package rulepb

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/rules"
)

// To converts a rule to its API message.
func To(r rules.Rule) *pb.Rule {
	out := &pb.Rule{
		Id:      r.ID,
		Ops:     uint32(r.Ops),
		Object:  &pb.ObjectMatch{},
		Verdict: pb.RuleVerdict(r.Verdict),
		Label:   r.Label,
		Set:     r.Set,
	}
	if r.Editable(time.Now()) {
		out.Spec = r.Spec()
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

// From converts an API message to a rule. The ID is not copied: the
// monitor gives the rules a client adds their IDs.
func From(r *pb.Rule) (rules.Rule, error) {
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

// Parse parses rules written in the rules.SpecSyntax, for a client to add.
func Parse(specs []string, label string, now time.Time) ([]*pb.Rule, error) {
	var out []*pb.Rule
	for _, s := range specs {
		r, err := rules.ParseSpec(s, now)
		if err != nil {
			return nil, err
		}
		if label != "" {
			r.Label = label
		}
		out = append(out, To(r))
	}
	return out, nil
}

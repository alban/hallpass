// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	pb "github.com/alban/hallpass/api/session/v1"
)

func TestAdvanceLine(t *testing.T) {
	for _, tc := range []struct {
		p    *pb.Prompt
		want string
	}{
		{&pb.Prompt{Op: "write", Path: "/etc/x"}, ""},
		{nil, ""},
		{
			&pb.Prompt{Advance: true, GrantFor: durationpb.New(10 * time.Minute), Reason: "build\x1b[2Jcache"},
			`  asked in advance for 10m, answer grant or deny; reason given by the program (unverified): "build?[2Jcache"`,
		},
		{&pb.Prompt{Advance: true}, "  asked in advance for the rest of the session, answer grant or deny"},
	} {
		if got := advanceLine(tc.p); got != tc.want {
			t.Errorf("advanceLine(%v) = %q, want %q", tc.p, got, tc.want)
		}
	}
}

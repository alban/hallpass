// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	"github.com/alban/hallpass/internal/monitor"
)

// The reasons of the Events on the pods of mediated containers.
const (
	// reasonAllowed and reasonDenied: a human answered a request.
	reasonAllowed = "HallpassAllowed"
	reasonDenied  = "HallpassDenied"
	// reasonNotAnswered: a request was denied after the policy's promptTimeout.
	reasonNotAnswered = "HallpassNotAnswered"
	// reasonPolicyDenied: accesses denied without asking (a deny rule, a
	// policy that does not ask), summarized at most once per
	// summaryPeriod per container.
	reasonPolicyDenied = "HallpassPolicyDenied"
	// reasonStarted: the container is sandboxed, and how to answer.
	reasonStarted = "HallpassStarted"
)

// startedMessage is the message of the reasonStarted Event.
func startedMessage(pol *Policy, strict bool) string {
	mode := "lite"
	if strict {
		mode = "strict"
	}
	s := fmt.Sprintf("sandboxed by hallpass (%s mode, policy %q); ", mode, pol.Name)
	if !pol.Prompt {
		return s + "requests are denied without asking"
	}
	return s + "answer its requests with Headlamp or `hallpass web --node`"
}

// summaryPeriod is how often automatic denials are reported, per container
// (a variable for the tests).
var summaryPeriod = time.Minute

// recorder emits Events on the pod of a mediated container.
type recorder interface {
	event(md metadata, warning bool, reason, msg string)
}

type noRecorder struct{}

func (noRecorder) event(metadata, bool, string, string) {}

// kubeRecorder emits Kubernetes Events. record.EventRecorder does not
// block: it drops events when the API server cannot keep up, and merges
// repeated ones.
type kubeRecorder struct{ r record.EventRecorder }

func (k kubeRecorder) event(md metadata, warning bool, reason, msg string) {
	typ := corev1.EventTypeNormal
	if warning {
		typ = corev1.EventTypeWarning
	}
	k.r.Event(&corev1.ObjectReference{
		APIVersion: "v1",
		Kind:       "Pod",
		Namespace:  md.Namespace,
		Name:       md.Pod,
		UID:        types.UID(md.PodUID),
		FieldPath:  fmt.Sprintf("spec.containers{%s}", md.Container),
	}, typ, reason, msg)
}

// clean makes workload-controlled text (paths, executables) safe for an
// Event: no control characters, at most maxLen bytes.
func clean(s string) string {
	const maxLen = 200
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) > maxLen {
		s = strings.ToValidUTF8(s[:maxLen], "") + "..."
	}
	return s
}

// denials summarizes a container's automatic denials: the first one is
// reported at once, the next ones at the end of each summaryPeriod with
// any.
type denials struct {
	report func(msg string)

	mu     sync.Mutex
	n      int
	byWhat map[string]int // "op path"
	timer  *time.Timer
	done   bool
}

func (d *denials) add(what string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return
	}
	if d.timer == nil {
		d.report("denied by the policy: " + what)
		d.timer = time.AfterFunc(summaryPeriod, d.flush)
		return
	}
	if d.byWhat == nil {
		d.byWhat = map[string]int{}
	}
	d.n++
	d.byWhat[what]++
}

// flush reports the denials since the last report, if any.
func (d *denials) flush() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.n == 0 || d.done {
		d.timer = nil
		return
	}
	d.report(d.summary())
	d.n, d.byWhat = 0, nil
	d.timer = time.AfterFunc(summaryPeriod, d.flush)
}

// stop reports what is left; add does nothing afterwards.
func (d *denials) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
	}
	if d.n > 0 && !d.done {
		d.report(d.summary())
	}
	d.done = true
}

func (d *denials) summary() string {
	const top = 3
	whats := slices.SortedFunc(maps.Keys(d.byWhat), func(a, b string) int {
		return cmp.Or(cmp.Compare(d.byWhat[b], d.byWhat[a]), cmp.Compare(a, b))
	})
	times := "times"
	if d.n == 1 {
		times = "time"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "denied by the policy %d %s in the last %v: ", d.n, times, summaryPeriod)
	for i, w := range whats[:min(top, len(whats))] {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%d)", w, d.byWhat[w])
	}
	if len(whats) > top {
		fmt.Fprintf(&b, " and %d more", len(whats)-top)
	}
	return b.String()
}

// automatic reports whether a denied access was decided without a human:
// by a rule, by the mechanism, or by the agent when the policy does not
// ask. The agent's denials of a policy that asks are timeouts, reported
// one by one; a human's answers are reported by session.Answer.
func automatic(why monitor.Reason, ask bool) bool {
	switch {
	case why.Died:
		return false
	case why.Rule != 0, why.Builtin != "":
		return true
	case why.Client == client:
		return !ask
	}
	return false
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"sync"
	"time"
)

// Batching of events: see Monitor.Events.
var (
	batchQuiet = 500 * time.Millisecond
	batchMax   = 2 * time.Second
)

// maxQueued bounds the Decided events queued for a slow client.
const maxQueued = 8192

type subscriber struct {
	decided bool
	ch      chan []Event
	wake    chan struct{}

	mu      sync.Mutex
	queue   []Event
	dropped uint64
	urgent  bool // the queue has an event other than Decided
	done    bool
}

func newSubscriber(decided bool) *subscriber {
	return &subscriber{decided: decided, ch: make(chan []Event), wake: make(chan struct{}, 1)}
}

// push queues ev. It never blocks: the monitor's lock may be held.
func (s *subscriber) push(ev Event) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	if ev.Decided != nil && len(s.queue) >= maxQueued {
		s.dropped++
	} else {
		s.queue = append(s.queue, ev)
	}
	s.urgent = s.urgent || ev.Decided == nil
	s.mu.Unlock()
	s.signal()
}

func (s *subscriber) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// finish makes run flush the queue and close the channel.
func (s *subscriber) finish() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
	s.signal()
}

// take returns the queued events, with the drop count, and whether the
// subscription is done.
func (s *subscriber) take() ([]Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	evs := s.queue
	s.queue = nil
	s.urgent = false
	if s.dropped > 0 {
		evs = append(evs, Event{Dropped: s.dropped})
		s.dropped = 0
	}
	return evs, s.done
}

// run delivers the batches.
func (s *subscriber) run() {
	defer close(s.ch)
	quietUntil := time.Time{} // batching until then
	for {
		<-s.wake
		if time.Now().After(quietUntil) {
			// First event after a quiet period: at once.
		} else {
			// Hold until quiet for batchQuiet, at most batchMax.
			deadline := time.Now().Add(batchMax)
		hold:
			for {
				if s.flushNow() {
					break
				}
				wait := min(batchQuiet, time.Until(deadline))
				if wait <= 0 {
					break
				}
				t := time.NewTimer(wait)
				select {
				case <-s.wake:
					t.Stop()
				case <-t.C:
					break hold
				}
			}
		}
		evs, done := s.take()
		if len(evs) > 0 {
			s.ch <- evs
		}
		if done {
			return
		}
		quietUntil = time.Now().Add(batchQuiet)
	}
}

// flushNow reports whether the queue is to be sent without waiting: it
// holds an event other than Decided, or the subscription is done.
func (s *subscriber) flushNow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.urgent || s.done
}

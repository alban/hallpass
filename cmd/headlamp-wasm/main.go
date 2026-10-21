// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// The Headlamp plugin's client of the node agents' session API, compiled
// to wasm. It speaks gRPC over a port-forward WebSocket that the plugin
// opens through Headlamp (see docs/devel/kubernetes.md).
//
// It defines globalThis.hallpassConnect(transport, callbacks), which
// follows the sessions of the agent at the other end of a port-forward
// WebSocket. The plugin owns the WebSocket (Headlamp's stream()):
//
//   - transport.send(Uint8Array) sends a WebSocket message;
//     transport.close() closes the WebSocket;
//   - callbacks.onState(json): the sessions, their pending requests and
//     rules (nodeclient.State), after each change;
//   - callbacks.onClose(error): the connection ended; error is a string,
//     empty after close().
//
// It returns {deliver, closed, answer, rules, close}:
//
//   - deliver(ArrayBuffer): a message received on the WebSocket;
//   - closed(reason): the WebSocket closed or failed;
//   - answer(session, request, answer): answers a pending request, as
//     `hallpass-node answer`; returns a Promise;
//   - rules(session, remove, add, label, generation): changes the
//     session's rules in one Apply: removes the rules with the ids in
//     remove, adds the rules written in the rules syntax in add (with
//     label), and fails if the rules' generation is not generation (unless
//     ""); returns a Promise;
//   - close(): ends the connection.
//
// These are bound functions (Function.prototype.bind) of js.Funcs made
// once, with the connection's id: JavaScript collects them like any
// object, while a js.Func per connection would stay in the Go runtime's
// table until released, and calling a released one panics. Calls for a
// connection that ended are ignored (answer and rules reject).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"syscall/js"
	"time"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/nodeclient"
	"github.com/alban/hallpass/internal/rulepb"
	"google.golang.org/grpc/status"
)

func main() {
	js.Global().Set("hallpassConnect", js.FuncOf(connect))
	select {}
}

// listInterval is how often the sessions are listed.
const listInterval = 2 * time.Second

// link is a connection to an agent.
type link struct {
	pc     *pfConn
	c      pb.SessionClient
	ctx    context.Context
	cancel context.CancelFunc
}

var (
	linksMu sync.Mutex
	links   = map[int]*link{}
	nextID  int
)

func lookup(args []js.Value) *link {
	linksMu.Lock()
	defer linksMu.Unlock()
	return links[args[0].Int()]
}

var errClosed = errors.New("connection closed")

// The methods of the object connect returns, as js.Funcs taking the
// connection's id first.
var (
	deliverFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		l := lookup(args)
		if l == nil {
			return nil
		}
		view := js.Global().Get("Uint8Array").New(args[1])
		b := make([]byte, view.Get("length").Int())
		js.CopyBytesToGo(b, view)
		l.pc.deliver(b)
		return nil
	})
	closedFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		l := lookup(args)
		if l == nil {
			return nil
		}
		reason := "port-forward closed"
		if len(args) > 1 && args[1].Type() == js.TypeString && args[1].String() != "" {
			reason = args[1].String()
		}
		l.pc.closeWithError(errors.New(reason))
		return nil
	})
	answerFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		l := lookup(args)
		session, request, answer := args[1].String(), args[2].String(), args[3].String()
		return promise(func() error {
			if l == nil {
				return errClosed
			}
			id, err := strconv.ParseUint(request, 10, 64)
			if err != nil {
				return err
			}
			actx, acancel := context.WithTimeout(nodeclient.WithSession(l.ctx, session), 10*time.Second)
			defer acancel()
			_, err = l.c.Answer(actx, &pb.AnswerRequest{Request: id, Answer: answer, Client: "headlamp"})
			return err
		})
	})
	closeFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		if l := lookup(args); l != nil {
			l.cancel()
		}
		return nil
	})
	rulesFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		l := lookup(args)
		session, remove, add := args[1].String(), jsStrings(args[2]), jsStrings(args[3])
		label, generation := args[4].String(), args[5].String()
		return promise(func() error {
			if l == nil {
				return errClosed
			}
			d := &pb.Decision{Client: "headlamp"}
			for _, s := range remove {
				id, err := strconv.ParseUint(s, 10, 64)
				if err != nil {
					return err
				}
				d.RemoveRules = append(d.RemoveRules, id)
			}
			if generation != "" {
				g, err := strconv.ParseUint(generation, 10, 64)
				if err != nil {
					return err
				}
				d.IfGeneration = g
			}
			var err error
			if d.AddRules, err = rulepb.Parse(add, label, time.Now()); err != nil {
				return err
			}
			actx, acancel := context.WithTimeout(nodeclient.WithSession(l.ctx, session), 10*time.Second)
			defer acancel()
			_, err = l.c.Apply(actx, d)
			return err
		})
	})
)

// jsStrings reads a JavaScript array of strings.
func jsStrings(v js.Value) []string {
	out := make([]string, v.Length())
	for i := range out {
		out[i] = v.Index(i).String()
	}
	return out
}

func connect(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		panic("hallpassConnect(transport, callbacks)")
	}
	transport, cb := args[0], args[1]
	uint8Array := js.Global().Get("Uint8Array")

	pc := newPFConn(func(b []byte) error {
		buf := uint8Array.New(len(b))
		js.CopyBytesToJS(buf, b)
		transport.Call("send", buf)
		return nil
	})
	pc.hangup = func() { transport.Call("close") }

	ctx, cancel := context.WithCancel(context.Background())
	conn, c, err := nodeclient.DialConn(pc)
	if err != nil {
		cancel()
		go cb.Call("onClose", err.Error())
		return nil
	}
	l := &link{pc: pc, c: c, ctx: ctx, cancel: cancel}
	linksMu.Lock()
	nextID++
	id := nextID
	links[id] = l
	linksMu.Unlock()

	go func() {
		err := nodeclient.Watch(ctx, c, listInterval, func(st nodeclient.State) {
			b, err := json.Marshal(st)
			if err != nil {
				return
			}
			cb.Call("onState", string(b))
		})
		linksMu.Lock()
		delete(links, id)
		linksMu.Unlock()
		cancel()
		conn.Close()
		msg := ""
		if err != nil && !errors.Is(err, context.Canceled) {
			msg = err.Error()
		}
		cb.Call("onClose", msg)
	}()

	bind := func(f js.Func) js.Value { return f.Call("bind", js.Null(), id) }
	res := js.Global().Get("Object").New()
	res.Set("deliver", bind(deliverFn))
	res.Set("closed", bind(closedFn))
	res.Set("answer", bind(answerFn))
	res.Set("close", bind(closeFn))
	res.Set("rules", bind(rulesFn))
	return res
}

// promise runs f in a goroutine and returns a Promise of its result.
func promise(f func() error) js.Value {
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			defer executor.Release()
			if err := f(); err != nil {
				// The server's message, without "rpc error: code = ...".
				reject.Invoke(js.Global().Get("Error").New(status.Convert(err).Message()))
				return
			}
			resolve.Invoke()
		}()
		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

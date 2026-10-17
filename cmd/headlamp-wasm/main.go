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
//     rules (hubclient.State), after each change;
//   - callbacks.onClose(error): the connection ended; error is a string,
//     empty after close().
//
// It returns {deliver, closed, answer, close}:
//
//   - deliver(ArrayBuffer): a message received on the WebSocket;
//   - closed(reason): the WebSocket closed or failed;
//   - answer(session, request, answer): answers a pending request, as
//     `hallpass-node answer`; returns a Promise;
//   - close(): ends the connection.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"syscall/js"
	"time"

	"github.com/alban/hallpass/internal/hubclient"
	pb "github.com/alban/hallpass/internal/sessionpb"
)

func main() {
	js.Global().Set("hallpassConnect", js.FuncOf(connect))
	select {}
}

// listInterval is how often the sessions are listed.
const listInterval = 2 * time.Second

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
	conn, c, err := hubclient.DialConn(pc)
	if err != nil {
		cancel()
		go cb.Call("onClose", err.Error())
		return nil
	}
	// The functions are not released: the plugin may still call them
	// after onClose.
	fn := func(f func(args []js.Value) any) js.Func {
		return js.FuncOf(func(_ js.Value, args []js.Value) any { return f(args) })
	}
	go func() {
		err := hubclient.Watch(ctx, c, listInterval, func(st hubclient.State) {
			b, err := json.Marshal(st)
			if err != nil {
				return
			}
			cb.Call("onState", string(b))
		})
		cancel()
		conn.Close()
		msg := ""
		if err != nil && !errors.Is(err, context.Canceled) {
			msg = err.Error()
		}
		cb.Call("onClose", msg)
	}()

	res := js.Global().Get("Object").New()
	res.Set("deliver", fn(func(args []js.Value) any {
		view := uint8Array.New(args[0])
		b := make([]byte, view.Get("length").Int())
		js.CopyBytesToGo(b, view)
		pc.deliver(b)
		return nil
	}))
	res.Set("closed", fn(func(args []js.Value) any {
		reason := "port-forward closed"
		if len(args) > 0 && args[0].Type() == js.TypeString && args[0].String() != "" {
			reason = args[0].String()
		}
		pc.closeWithError(errors.New(reason))
		return nil
	}))
	res.Set("answer", fn(func(args []js.Value) any {
		session, request, answer := args[0].String(), args[1].String(), args[2].String()
		return promise(func() error {
			id, err := strconv.ParseUint(request, 10, 64)
			if err != nil {
				return err
			}
			actx, acancel := context.WithTimeout(hubclient.WithSession(ctx, session), 10*time.Second)
			defer acancel()
			_, err = c.Answer(actx, &pb.AnswerRequest{Request: id, Answer: answer, Client: "headlamp"})
			return err
		})
	}))
	res.Set("close", fn(func([]js.Value) any {
		cancel()
		return nil
	}))
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
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke()
		}()
		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

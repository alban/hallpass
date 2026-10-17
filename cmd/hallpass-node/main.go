// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Command hallpass-node is the hallpass Kubernetes node agent (a
// DaemonSet): an NRI plugin that adds a seccomp profile to the containers
// of opted-in pods, the seccomp agent runc hands their listeners to, and
// one session API for all of them. It also has a small client for that
// API. See docs/kubernetes/.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/stub"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
)

const defaultFDStore = "/run/hallpass/fd-store.sock"

const usage = `usage: hallpass-node <command> [flags]

commands:
  run       run the node agent (in the DaemonSet)
  fd-store  keep the agent's listeners while it restarts (in its own DaemonSet)
  sessions  list the sessions of a node agent
  pending   list the pending requests of a session
  answer    answer a pending request: once, temp, always, deny or never
  ready     exit 0 if the node agent is ready (its readiness probe)

Run "hallpass-node <command> -h" for the flags of a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "run":
		err = runAgent(args)
	case "fd-store":
		err = runFDStore(args)
	case "sessions":
		err = cmdSessions(args)
	case "pending":
		err = cmdPending(args)
	case "answer":
		err = cmdAnswer(args)
	case "ready":
		err = cmdReady(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "hallpass-node: unknown command %q\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "hallpass-node: %v\n", err)
		os.Exit(1)
	}
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	nriSocket := fs.String("nri-socket", "/var/run/nri/nri.sock", "containerd's NRI socket")
	socket := fs.String("socket", "/run/hallpass/agent.sock", "the seccomp agent socket, the same path on the host (its directory is made root-only)")
	fdStore := fs.String("fd-store", defaultFDStore, `the fd-store socket, that keeps the listeners while the agent restarts ("": none)`)
	maxInflight := fs.Int("max-inflight", seccomp.DefaultSlots, "the most notifications in flight per listener, most of them waiting for an answer; more wait in the kernel")
	listenAddr := fs.String("listen", "127.0.0.1:7323", "the session API address (keep it on the pod's loopback: clients are not authenticated)")
	nsSelector := fs.String("namespace-selector", "hallpass.io/enabled=true", "label selector of the namespaces whose pods may opt in")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file (default: in-cluster)")
	wk := fs.String("wait-killable", "auto", "add SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: auto, true or false")
	hostRoot := fs.String("host-root", "/proc/1/root", "the host's root, to run runc features in")
	runc := fs.String("runc", "", "runc's path on the host (default: search the usual paths)")
	pluginIdx := fs.String("plugin-index", "50", "NRI plugin index")
	mode := fs.String("mode", "auto", "lite (seccomp only) | strict (the kernel also enforces the answers with BPF-LSM; fail without it) | auto (strict if the node has BPF-LSM)")
	verbose := fs.Bool("v", false, "debug logs")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("run: unexpected arguments %v", fs.Args())
	}
	if *maxInflight < 1 {
		return fmt.Errorf("--max-inflight: %d, want at least 1", *maxInflight)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	sel, err := labels.Parse(*nsSelector)
	if err != nil {
		return fmt.Errorf("--namespace-selector: %w", err)
	}
	waitKillableRecv, why, err := waitKillable(*wk, *hostRoot, *runc)
	if err != nil {
		return err
	}
	log.Info("SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV", "set", waitKillableRecv, "why", why)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	k, err := newKube(ctx, *kubeconfig, sel, log)
	if err != nil {
		return err
	}

	node := sessionapi.NewNode()
	tcp, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return err
	}
	go func() {
		if err := node.Serve(tcp); err != nil {
			log.Error("session API", "err", err)
			cancel()
		}
	}()
	defer node.Stop()

	ag := newAgent(k, node, log, k.recorder(ctx), *maxInflight)
	if *fdStore != "" {
		// Adopt the sessions of a previous agent before runc hands their
		// next listeners.
		if err := ag.connectStore(*fdStore); err != nil {
			log.Warn("no fd-store: the requests in flight are lost if the agent restarts", "err", err)
		}
		go ag.keepStore(ctx, *fdStore)
	}
	if err := ag.setupStrict(*mode, *hostRoot); err != nil {
		return err
	}
	ln, err := listen(*socket)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		if err := ag.serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("seccomp agent", "err", err)
			cancel()
		}
	}()

	p := &plugin{cluster: k, listenerPath: *socket, waitKillable: waitKillableRecv, log: log}
	st, err := stub.New(p,
		stub.WithPluginName("hallpass"),
		stub.WithPluginIdx(*pluginIdx),
		stub.WithSocketPath(*nriSocket))
	if err != nil {
		return err
	}
	log.Info("started", "session-api", *listenAddr, "socket", *socket, "namespace-selector", sel.String())
	// Ready (the readiness probe, hallpass-node ready) once registered with
	// NRI and with the caches synced: until then, opted-in containers are
	// refused, or start unmediated if the agent is not registered at all.
	go func() {
		was := false
		for {
			ready := p.registered.Load() && k.Synced()
			if ready != was {
				node.SetReady(ready)
				log.Info("readiness", "ready", ready, "nri", p.registered.Load(), "caches", k.Synced())
				was = ready
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()
	// The listeners of running containers live in this process: when the
	// runtime goes away (e.g. containerd restarts), register again rather
	// than exit.
	for {
		err := st.Run(ctx)
		p.registered.Store(false)
		if ctx.Err() != nil {
			return nil
		}
		log.Error("NRI connection lost, reconnecting", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
	}
}

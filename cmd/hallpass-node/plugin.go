// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"

	"github.com/containerd/nri/pkg/api"
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/alban/hallpass/internal/ociseccomp"
	"github.com/alban/hallpass/internal/seccomp"
)

// PolicyAnnotation opts a pod in, naming its HallpassPolicy.
const PolicyAnnotation = "hallpass.io/policy"

// metadata is the profile's listenerMetadata: what the agent needs to know
// about the container when runc hands it the listener.
type metadata struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	PodUID    string `json:"podUID"`
	Container string `json:"container"`
	Policy    string `json:"policy"`
	Home      string `json:"home,omitempty"`
	// Mediate is the categories the filter notifies (seccomp.Category
	// String); "": seccomp.DefaultCategories.
	Mediate string `json:"mediate,omitempty"`
}

// categories returns the categories md's filter notifies.
func (md metadata) categories() (seccomp.Category, error) {
	if md.Mediate == "" {
		return seccomp.DefaultCategories, nil
	}
	return seccomp.ParseCategories(md.Mediate)
}

// plugin is the NRI plugin: it adds the hallpass seccomp profile to the
// containers of opted-in pods.
type plugin struct {
	cluster      cluster
	listenerPath string
	waitKillable bool
	log          *slog.Logger
	// registered is set by Synchronize, the end of the registration, and
	// cleared when the NRI connection ends.
	registered atomic.Bool
}

// Synchronize implements stub.SynchronizeInterface. The runtime calls it
// once registered, before sending container events.
func (p *plugin) Synchronize(context.Context, []*api.PodSandbox, []*api.Container) ([]*api.ContainerUpdate, error) {
	p.registered.Store(true)
	return nil, nil
}

// CreateContainer implements stub.CreateContainerInterface.
func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	adj, err := p.adjust(pod, ctr)
	log := p.log.With("namespace", pod.GetNamespace(), "pod", pod.GetName(), "container", ctr.GetName())
	switch {
	case err != nil:
		// Fail closed: the container is not created.
		log.Error("refusing container", "err", err)
	case adj != nil:
		log.Info("mediating container", "policy", pod.GetAnnotations()[PolicyAnnotation])
	}
	return adj, nil, err
}

// adjust returns the adjustment for ctr, nil if it is not opted in.
func (p *plugin) adjust(pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, error) {
	name := pod.GetAnnotations()[PolicyAnnotation]
	if name == "" {
		return nil, nil
	}
	ok, err := p.cluster.Selected(pod.GetNamespace())
	if err != nil {
		return nil, fmt.Errorf("hallpass: namespace %s: %w", pod.GetNamespace(), err)
	}
	if !ok {
		p.log.Debug("namespace not selected, ignoring annotation", "namespace", pod.GetNamespace(), "pod", pod.GetName())
		return nil, nil
	}
	pol, err := p.cluster.Policy(name)
	if err != nil {
		return nil, fmt.Errorf("hallpass: %w", err)
	}
	cats := pol.Mediate
	if cats == 0 {
		cats = seccomp.DefaultCategories
	}
	md, err := json.Marshal(metadata{
		Namespace: pod.GetNamespace(),
		Pod:       pod.GetName(),
		PodUID:    pod.GetUid(),
		Container: ctr.GetName(),
		Policy:    name,
		Home:      envHome(ctr.GetEnv()),
		Mediate:   cats.String(),
	})
	if err != nil {
		return nil, err
	}
	prof, err := ociseccomp.Profile(toOCISeccomp(ctr.GetLinux().GetSeccompPolicy()), seccomp.Select(seccomp.Rules(false), cats), ociseccomp.Options{
		ListenerPath:     p.listenerPath,
		ListenerMetadata: string(md),
		WaitKillableRecv: p.waitKillable,
	})
	if err != nil {
		return nil, fmt.Errorf("hallpass: %w", err)
	}
	adj := &api.ContainerAdjustment{}
	adj.SetLinuxSeccompPolicy(api.FromOCILinuxSeccomp(prof))
	return adj, nil
}

// envHome returns $HOME from a container's environment.
func envHome(env []string) string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			return v
		}
	}
	return ""
}

// toOCISeccomp converts the container's current seccomp policy; nil when it
// has none (unconfined).
func toOCISeccomp(s *api.LinuxSeccomp) *specs.LinuxSeccomp {
	if s == nil {
		return nil
	}
	o := &specs.LinuxSeccomp{
		DefaultAction:    specs.LinuxSeccompAction(s.DefaultAction),
		ListenerPath:     s.ListenerPath,
		ListenerMetadata: s.ListenerMetadata,
		Syscalls:         api.ToOCILinuxSyscalls(s.Syscalls),
	}
	if s.DefaultErrno != nil {
		v := uint(s.DefaultErrno.Value)
		o.DefaultErrnoRet = &v
	}
	for _, a := range s.Architectures {
		o.Architectures = append(o.Architectures, specs.Arch(a))
	}
	for _, f := range s.Flags {
		o.Flags = append(o.Flags, specs.LinuxSeccompFlag(f))
	}
	return o
}

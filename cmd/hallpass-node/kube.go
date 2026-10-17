// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// policyGVR is the HallpassPolicy resource.
var policyGVR = schema.GroupVersionResource{Group: "hallpass.io", Version: "v1alpha1", Resource: "hallpasspolicies"}

// cluster is what the agent needs from the API server.
type cluster interface {
	// Selected reports whether namespace ns matches --namespace-selector.
	Selected(ns string) (bool, error)
	// Policy returns HallpassPolicy name.
	Policy(name string) (*Policy, error)
}

// errNotSynced fails the lookups until the caches have synced.
var errNotSynced = errors.New("namespace and HallpassPolicy caches not synced yet")

// kube reads namespaces and policies from informer caches.
type kube struct {
	selector   labels.Selector
	namespaces listersv1.NamespaceLister
	policies   cache.GenericLister
	synced     atomic.Bool
}

// newKube starts the informers and returns without waiting for their
// caches: until they sync, Synced is false and the lookups fail, so that
// the agent can register with NRI first and refuse the opted-in
// containers rather than let them start unmediated. kubeconfig "" means
// in-cluster.
func newKube(ctx context.Context, kubeconfig string, selector labels.Selector, log *slog.Logger) (*kube, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig == "" {
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	const resync = 10 * time.Minute
	nsf := informers.NewSharedInformerFactory(cs, resync)
	nsInf := nsf.Core().V1().Namespaces()
	k := &kube{selector: selector, namespaces: nsInf.Lister()}
	dynf := dynamicinformer.NewDynamicSharedInformerFactory(dyn, resync)
	polInf := dynf.ForResource(policyGVR)
	k.policies = polInf.Lister()
	nsf.Start(ctx.Done())
	dynf.Start(ctx.Done())
	go func() {
		start := time.Now()
		done := make(chan struct{})
		go func() {
			select {
			case <-done:
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
				log.Warn("namespace and HallpassPolicy caches not synced yet, refusing opted-in containers (API server reachable? CRD installed?)")
			}
		}()
		ok := cache.WaitForCacheSync(ctx.Done(), nsInf.Informer().HasSynced, polInf.Informer().HasSynced)
		close(done)
		if ok {
			k.synced.Store(true)
			log.Info("caches synced", "after", time.Since(start).Round(time.Millisecond))
		}
	}()
	return k, nil
}

// Synced reports whether the caches have synced.
func (k *kube) Synced() bool { return k.synced.Load() }

func (k *kube) Selected(ns string) (bool, error) {
	if !k.Synced() {
		return false, errNotSynced
	}
	n, err := k.namespaces.Get(ns)
	if err != nil {
		return false, err
	}
	return k.selector.Matches(labels.Set(n.Labels)), nil
}

func (k *kube) Policy(name string) (*Policy, error) {
	if !k.Synced() {
		return nil, errNotSynced
	}
	obj, err := k.policies.Get(name)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("no HallpassPolicy %q", name)
	}
	if err != nil {
		return nil, err
	}
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("HallpassPolicy %q: unexpected %T", name, obj)
	}
	var spec PolicySpec
	raw, _ := u.Object["spec"].(map[string]any)
	if raw == nil {
		raw = map[string]any{}
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &spec); err != nil {
		return nil, fmt.Errorf("HallpassPolicy %q: %w", name, err)
	}
	return parsePolicy(name, spec)
}

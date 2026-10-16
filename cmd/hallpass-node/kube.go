// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
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

// kube reads namespaces and policies from informer caches.
type kube struct {
	selector   labels.Selector
	namespaces listersv1.NamespaceLister
	policies   cache.GenericLister
}

// newKube starts the informers and waits for their caches. kubeconfig ""
// means in-cluster.
func newKube(ctx context.Context, kubeconfig string, selector labels.Selector) (*kube, error) {
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
	if !cache.WaitForCacheSync(ctx.Done(), nsInf.Informer().HasSynced, polInf.Informer().HasSynced) {
		return nil, fmt.Errorf("namespace and HallpassPolicy caches did not sync (is the CRD installed?)")
	}
	return k, nil
}

func (k *kube) Selected(ns string) (bool, error) {
	n, err := k.namespaces.Get(ns)
	if err != nil {
		return false, err
	}
	return k.selector.Matches(labels.Set(n.Labels)), nil
}

func (k *kube) Policy(name string) (*Policy, error) {
	obj, err := k.policies.Get(name)
	if errors.IsNotFound(err) {
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

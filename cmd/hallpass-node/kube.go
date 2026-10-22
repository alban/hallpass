// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alban/hallpass/internal/policy"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/record"
)

// policyGVR is the HallpassPolicy resource.
var policyGVR = schema.GroupVersionResource{Group: "hallpass.io", Version: "v1alpha1", Resource: "hallpasspolicies"}

// cluster is what the agent needs from the API server.
type cluster interface {
	// Selected reports whether namespace ns matches --namespace-selector.
	Selected(ns string) (bool, error)
	// Policy returns HallpassPolicy name.
	Policy(name string) (*Policy, error)
	// Secret returns the value of key of Secret name in namespace ns.
	Secret(ns, name, key string) (string, error)
}

// errNotSynced fails the lookups until the caches have synced.
var errNotSynced = errors.New("namespace and HallpassPolicy caches not synced yet")

// kube reads namespaces and policies from informer caches.
type kube struct {
	cs         kubernetes.Interface
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
	k := &kube{cs: cs, selector: selector, namespaces: nsInf.Lister()}
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

// recorder returns the recorder of the Events on the pods of mediated
// containers, until ctx is done. $NODE_NAME (from the downward API) names
// the node in their source.
func (k *kube) recorder(ctx context.Context) recorder {
	b := record.NewBroadcaster(record.WithContext(ctx))
	b.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: k.cs.CoreV1().Events("")})
	return kubeRecorder{b.NewRecorder(scheme.Scheme, corev1.EventSource{Component: client, Host: os.Getenv("NODE_NAME")})}
}

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
	var spec policy.Spec
	raw, _ := u.Object["spec"].(map[string]any)
	if raw == nil {
		raw = map[string]any{}
	}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &spec); err != nil {
		return nil, fmt.Errorf("HallpassPolicy %q: %w", name, err)
	}
	return parsePolicy(name, spec)
}

// Secret reads a key of a Secret, without caching it: hallpass-node may
// read only the Secrets a namespace's owner granted it, by name.
func (k *kube) Secret(ns, name, key string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := k.cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsForbidden(err) {
			return "", fmt.Errorf("secret %s/%s: hallpass-node may not read it: grant its service account get on it (see the docs, Credentials): %w", ns, name, err)
		}
		return "", fmt.Errorf("secret %s/%s: %w", ns, name, err)
	}
	v := strings.TrimSpace(string(s.Data[key]))
	if v == "" {
		return "", fmt.Errorf("secret %s/%s: no key %q, or an empty value", ns, name, key)
	}
	return v, nil
}

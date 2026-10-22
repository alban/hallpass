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

	"github.com/alban/hallpass/internal/egress/profiles"
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
	// Profile returns credential profile ref: built in ("gh"), or
	// "config:NAME" from the profiles ConfigMap (profilesConfigMap).
	Profile(ref string) (*profiles.Profile, error)
}

// profilesConfigMap is the ConfigMap of the credential profiles, in
// hallpass-node's namespace ($POD_NAMESPACE): one key NAME.toml per
// profile, as in ~/.config/hallpass/credentials.d, which a policy names
// config:NAME.
const profilesConfigMap = "hallpass-credential-profiles"

// errNotSynced fails the lookups until the caches have synced.
var errNotSynced = errors.New("namespace and HallpassPolicy caches not synced yet")

// kube reads namespaces and policies from informer caches.
type kube struct {
	cs         kubernetes.Interface
	selector   labels.Selector
	namespaces listersv1.NamespaceLister
	policies   cache.GenericLister
	synced     atomic.Bool
	// profiles reads profilesConfigMap; profilesSynced is set once its
	// cache synced (it may never: without the ConfigMap's namespace or
	// the RBAC to read it, the containers with config: credentials are
	// refused).
	profiles       listersv1.ConfigMapLister
	profilesNS     string
	profilesSynced atomic.Bool
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
	// The profiles ConfigMap alone: a field selector on its name, in
	// hallpass-node's namespace.
	k.profilesNS = os.Getenv("POD_NAMESPACE")
	if k.profilesNS == "" {
		k.profilesNS = "hallpass-system"
	}
	cmf := informers.NewSharedInformerFactoryWithOptions(cs, resync, informers.WithNamespace(k.profilesNS),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.FieldSelector = "metadata.name=" + profilesConfigMap }))
	cmInf := cmf.Core().V1().ConfigMaps()
	k.profiles = cmInf.Lister()
	nsf.Start(ctx.Done())
	dynf.Start(ctx.Done())
	cmf.Start(ctx.Done())
	go func() {
		if cache.WaitForCacheSync(ctx.Done(), cmInf.Informer().HasSynced) {
			k.profilesSynced.Store(true)
		}
	}()
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

// Profile returns credential profile ref: built in ("gh"), or
// "config:NAME", the key NAME.toml of the profiles ConfigMap. Until the
// ConfigMap's cache synced, a config:NAME one fails: the container is
// refused rather than created without its credential.
func (k *kube) Profile(ref string) (*profiles.Profile, error) {
	return profiles.Find(ref, func(name string) ([]byte, string, error) {
		if !k.profilesSynced.Load() {
			return nil, "", fmt.Errorf("credential %s: ConfigMap %s/%s not read yet (hallpass-node may not read it?)", ref, k.profilesNS, profilesConfigMap)
		}
		return configMapProfile(k.profiles, k.profilesNS, name)
	})
}

// configMapProfile returns the key name.toml of the profiles ConfigMap in
// namespace ns, from lister l.
func configMapProfile(l listersv1.ConfigMapLister, ns, name string) ([]byte, string, error) {
	where := "ConfigMap " + ns + "/" + profilesConfigMap + " key " + name + ".toml"
	cm, err := l.ConfigMaps(ns).Get(profilesConfigMap)
	if apierrors.IsNotFound(err) {
		return nil, where, os.ErrNotExist
	}
	if err != nil {
		return nil, where, err
	}
	v, ok := cm.Data[name+".toml"]
	if !ok {
		return nil, where, os.ErrNotExist
	}
	return []byte(v), where, nil
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// "Sandbox with hallpass": the workload that owns a pod, and the patch that
// sets the hallpass.io/policy annotation on its pod template. The agent
// only mediates containers created with the annotation, so the change
// takes effect when the workload recreates its pods.

export const policyAnnotation = 'hallpass.io/policy';
export const policiesPath = '/apis/hallpass.io/v1alpha1/hallpasspolicies';

interface OwnerRef {
  apiVersion: string;
  kind: string;
  name: string;
  controller?: boolean;
}

interface Obj {
  apiVersion?: string;
  kind?: string;
  metadata: {
    name: string;
    namespace?: string;
    ownerReferences?: OwnerRef[];
    annotations?: Record<string, string>;
  };
  spec?: any;
}

// A workload whose pod template can carry the annotation.
export interface Owner {
  kind: string;
  name: string;
  namespace: string;
  // The API path of the object.
  path: string;
  // The current annotation on its pod template.
  policy: string;
  // What a change does to the pods that exist.
  effect: string;
  // Whether the workload replaces its pods by itself after a change.
  replaces: boolean;
  // Why it cannot be patched, if it cannot.
  unsupported?: string;
}

type Get = (path: string) => Promise<Obj>;

const resources: Record<string, string> = {
  'apps/v1/Deployment': 'deployments',
  'apps/v1/ReplicaSet': 'replicasets',
  'apps/v1/StatefulSet': 'statefulsets',
  'apps/v1/DaemonSet': 'daemonsets',
  'batch/v1/Job': 'jobs',
  'batch/v1/CronJob': 'cronjobs',
};

function apiPath(ref: { apiVersion: string; kind: string; name: string }, ns: string) {
  const res = resources[`${ref.apiVersion}/${ref.kind}`];
  if (!res) {
    return null;
  }
  return `/apis/${ref.apiVersion}/namespaces/${ns}/${res}/${ref.name}`;
}

function controller(o: Obj): OwnerRef | undefined {
  return o.metadata.ownerReferences?.find(r => r.controller);
}

function template(kind: string, o: Obj): any {
  return kind === 'CronJob' ? o.spec?.jobTemplate?.spec?.template : o.spec?.template;
}

// rollout says what a change of the pod template does to the pods that
// exist: the agent only mediates containers created with the annotation.
export function rollout(kind: string, o: Obj): { effect: string; replaces: boolean } {
  const manual = 'Its pods keep running as they are: delete them to recreate them with the change.';
  switch (kind) {
    case 'Deployment':
      return { effect: 'Its pods are replaced with the change.', replaces: true };
    case 'StatefulSet':
    case 'DaemonSet': {
      const strategy = o.spec?.updateStrategy;
      if (strategy?.type === 'OnDelete') {
        return { effect: `Its update strategy is OnDelete. ${manual}`, replaces: false };
      }
      const partition = strategy?.rollingUpdate?.partition;
      if (kind === 'StatefulSet' && partition > 0) {
        return {
          effect: `Only its pods with an ordinal of ${partition} or more are replaced (rollingUpdate.partition).`,
          replaces: false,
        };
      }
      return { effect: 'Its pods are replaced with the change.', replaces: true };
    }
    case 'ReplicaSet':
      return { effect: `A ReplicaSet does not roll out changes. ${manual}`, replaces: false };
    case 'CronJob':
      return {
        effect: 'Only the Jobs it starts from now on get the change; running Jobs keep going as they are.',
        replaces: false,
      };
  }
  return { effect: '', replaces: false };
}

// findOwner follows the pod's controllers up to the workload to patch: a
// Deployment rather than its ReplicaSet, a CronJob rather than its Job.
export async function findOwner(pod: Obj, get: Get): Promise<Owner> {
  const ns = pod.metadata.namespace || '';
  let ref = controller(pod);
  if (!ref) {
    return {
      kind: 'Pod',
      name: pod.metadata.name,
      namespace: ns,
      path: '',
      policy: pod.metadata.annotations?.[policyAnnotation] || '',
      effect: '',
      replaces: false,
      unsupported:
        'This pod has no controller. Add the annotation to its manifest and recreate it.',
    };
  }
  for (;;) {
    const path = apiPath(ref, ns);
    if (!path) {
      return {
        kind: ref.kind,
        name: ref.name,
        namespace: ns,
        path: '',
        policy: '',
        effect: '',
        replaces: false,
        unsupported: `hallpass cannot patch a ${ref.kind}: add the annotation to its pod template.`,
      };
    }
    const o = await get(path);
    const up = controller(o);
    if (up && ((ref.kind === 'ReplicaSet' && up.kind === 'Deployment') ||
      (ref.kind === 'Job' && up.kind === 'CronJob'))) {
      ref = up;
      continue;
    }
    const owner: Owner = {
      kind: ref.kind,
      name: ref.name,
      namespace: ns,
      path,
      policy: template(ref.kind, o)?.metadata?.annotations?.[policyAnnotation] || '',
      ...rollout(ref.kind, o),
    };
    if (ref.kind === 'Job') {
      owner.unsupported = 'The pod template of a Job cannot change: recreate the Job with the annotation.';
    }
    return owner;
  }
}

// templatePatch is the merge patch that sets the policy on the owner's pod
// template, or removes it if policy is empty.
export function templatePatch(kind: string, policy: string): object {
  const tmpl = { metadata: { annotations: { [policyAnnotation]: policy || null } } };
  if (kind === 'CronJob') {
    return { spec: { jobTemplate: { spec: { template: tmpl } } } };
  }
  return { spec: { template: tmpl } };
}

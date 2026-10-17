// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { findOwner, templatePatch } from './sandbox';

const ref = (apiVersion: string, kind: string, name: string) => [
  { apiVersion, kind, name, controller: true },
];

const objects: Record<string, any> = {
  '/apis/apps/v1/namespaces/ns/replicasets/web-123': {
    metadata: { name: 'web-123', ownerReferences: ref('apps/v1', 'Deployment', 'web') },
  },
  '/apis/apps/v1/namespaces/ns/deployments/web': {
    metadata: { name: 'web' },
    spec: { template: { metadata: { annotations: { 'hallpass.io/policy': 'p1' } } } },
  },
  '/apis/apps/v1/namespaces/ns/replicasets/bare': { metadata: { name: 'bare' }, spec: {} },
  '/apis/batch/v1/namespaces/ns/jobs/nightly-1': {
    metadata: { name: 'nightly-1', ownerReferences: ref('batch/v1', 'CronJob', 'nightly') },
  },
  '/apis/batch/v1/namespaces/ns/cronjobs/nightly': {
    metadata: { name: 'nightly' },
    spec: {
      jobTemplate: {
        spec: { template: { metadata: { annotations: { 'hallpass.io/policy': 'p2' } } } },
      },
    },
  },
  '/apis/batch/v1/namespaces/ns/jobs/once': { metadata: { name: 'once' } },
};

const get = async (path: string) => {
  if (!objects[path]) {
    throw new Error(`not found: ${path}`);
  }
  return objects[path];
};

const pod = (owners?: any[]) => ({
  metadata: { name: 'p', namespace: 'ns', ownerReferences: owners },
});

describe('findOwner', () => {
  it('finds the Deployment of a ReplicaSet', async () => {
    const o = await findOwner(pod(ref('apps/v1', 'ReplicaSet', 'web-123')), get);
    expect(o).toEqual({
      kind: 'Deployment',
      name: 'web',
      namespace: 'ns',
      path: '/apis/apps/v1/namespaces/ns/deployments/web',
      policy: 'p1',
    });
  });

  it('stops at a ReplicaSet without a Deployment', async () => {
    const o = await findOwner(pod(ref('apps/v1', 'ReplicaSet', 'bare')), get);
    expect(o).toMatchObject({ kind: 'ReplicaSet', policy: '' });
    expect(o.unsupported).toBeUndefined();
  });

  it('finds the CronJob of a Job', async () => {
    const o = await findOwner(pod(ref('batch/v1', 'Job', 'nightly-1')), get);
    expect(o).toMatchObject({ kind: 'CronJob', name: 'nightly', policy: 'p2' });
    expect(o.unsupported).toBeUndefined();
  });

  it('cannot patch a Job, a bare pod or an unknown owner', async () => {
    expect((await findOwner(pod(ref('batch/v1', 'Job', 'once')), get)).unsupported).toMatch(
      /Job/
    );
    expect((await findOwner(pod(), get)).unsupported).toMatch(/no controller/);
    expect(
      (await findOwner(pod(ref('example.com/v1', 'Thing', 't')), get)).unsupported
    ).toMatch(/Thing/);
  });
});

describe('templatePatch', () => {
  it('sets and removes the annotation', () => {
    expect(templatePatch('Deployment', 'p')).toEqual({
      spec: { template: { metadata: { annotations: { 'hallpass.io/policy': 'p' } } } },
    });
    expect(templatePatch('CronJob', '')).toEqual({
      spec: {
        jobTemplate: {
          spec: { template: { metadata: { annotations: { 'hallpass.io/policy': null } } } },
        },
      },
    });
  });
});

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

import { K8s } from '@kinvolk/headlamp-plugin/lib';
import { getCluster } from '@kinvolk/headlamp-plugin/lib/Utils';
import { useEffect, useSyncExternalStore } from 'react';
import { agentNamespace, agentSelector, realDeps } from './client';
import { ClusterStore, RulesChange } from './store';
import { Agent, AgentState, Answer } from './types';

const stores = new Map<string, ClusterStore>();

export function getStore(cluster: string): ClusterStore {
  let s = stores.get(cluster);
  if (!s) {
    s = new ClusterStore(cluster, realDeps);
    stores.set(cluster, s);
  }
  return s;
}

export interface Hallpass {
  cluster: string;
  agents: AgentState[];
  listed: boolean;
  listError?: string;
  answer(pod: string, session: string, request: string, answer: Answer): Promise<void>;
  rules(pod: string, session: string, change: RulesChange): Promise<void>;
}

// useHallpass lists the hallpass-node pods of the current cluster, keeps a
// connection to each, and returns their state.
export function useHallpass(): Hallpass {
  const cluster = getCluster() || '';
  const store = getStore(cluster);
  const [pods, error] = K8s.ResourceClasses.Pod.useList({
    cluster,
    namespace: agentNamespace,
    labelSelector: agentSelector,
  });
  const listError = error ? String(error.message || error) : undefined;
  // A stable key: the list is a new array on every render.
  const key = JSON.stringify(
    (pods || [])
      .filter(p => p.status?.phase === 'Running')
      .map((p): Agent => ({ pod: p.metadata.name, node: p.spec?.nodeName || '' }))
  );
  useEffect(() => {
    if (pods === null && !error) {
      return;
    }
    store.setAgents(JSON.parse(key), listError);
  }, [store, key, listError, pods === null]);
  const agents = useSyncExternalStore(store.subscribe, store.getSnapshot);
  return {
    cluster,
    agents,
    listed: store.listed,
    listError: store.listError,
    answer: (pod, session, request, answer) => store.answer(pod, session, request, answer),
    rules: (pod, session, change) => store.rules(pod, session, change),
  };
}

// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Connections to the hallpass-node agents of a cluster, one per agent pod,
// and their merged state. This module has no React or Headlamp
// dependency: the WebSocket and the wasm client are injected, so that
// tests can replace them.

import { Agent, AgentState, Answer, NodeState } from './types';

// A port-forward WebSocket to an agent pod.
export interface Socket {
  send(b: Uint8Array): void;
  close(): void;
}

// Opens a port-forward to an agent pod; onMessage receives the WebSocket
// messages, onFail is called if the WebSocket fails or closes
// unexpectedly.
export type OpenFn = (
  cluster: string,
  pod: string,
  onMessage: (data: ArrayBuffer) => void,
  onFail: () => void
) => Socket;

// The wasm client's handle on a connection (cmd/headlamp-wasm).
export interface Link {
  deliver(data: ArrayBuffer): void;
  closed(reason?: string): void;
  answer(session: string, request: string, answer: string): Promise<void>;
  rules(
    session: string,
    remove: string[],
    add: string[],
    label: string,
    generation: string
  ): Promise<void>;
  close(): void;
}

// globalThis.hallpassConnect, as defined by the wasm client.
export type ConnectFn = (
  transport: { send(b: Uint8Array): void; close(): void },
  callbacks: { onState(json: string): void; onClose(error: string): void }
) => Link | null;

export interface Deps {
  load(): Promise<ConnectFn>;
  open: OpenFn;
  setTimeout(f: () => void, ms: number): unknown;
  clearTimeout(t: unknown): void;
}

export const maxBackoff = 30_000;

// A change of a session's rules, applied at once: the ids of the rules to
// remove, the rules to add in the rules syntax (rules.SpecSyntax) with
// their label, and the rules' generation the change was made from, if it
// must fail when they changed meanwhile.
export interface RulesChange {
  remove?: string[];
  add?: string[];
  label?: string;
  generation?: string;
}

class AgentConn {
  state: AgentState;
  private link: Link | null = null;
  private socket: Socket | null = null;
  private stopped = false;
  private failures = 0;
  private timer: unknown = null;

  constructor(private store: ClusterStore, agent: Agent) {
    this.state = { ...agent, connected: false, sessions: [] };
  }

  async open() {
    this.timer = null;
    let connect: ConnectFn;
    try {
      connect = await this.store.deps.load();
    } catch (e) {
      this.fail(`loading the hallpass client: ${e}`);
      return;
    }
    if (this.stopped) {
      return;
    }
    // The wasm client calls these from Go: an exception would crash it.
    let link: Link | null = null;
    let done = false;
    const socket = this.store.deps.open(
      this.store.cluster,
      this.state.pod,
      data => link?.deliver(data),
      () => link?.closed('port-forward closed')
    );
    const end = (error: string) => {
      if (done) {
        return;
      }
      done = true;
      socket.close();
      if (this.link === link) {
        this.link = null;
        this.socket = null;
      }
      if (!this.stopped) {
        this.fail(error || 'connection closed');
      }
    };
    link = connect(
      {
        send: b => {
          try {
            socket.send(b);
          } catch (e) {
            link?.closed(`port-forward: ${e}`);
          }
        },
        close: () => socket.close(),
      },
      {
        onState: json => {
          try {
            this.onState(JSON.parse(json));
          } catch (e) {
            console.error('hallpass: bad state', e);
          }
        },
        onClose: error => {
          try {
            end(error);
          } catch (e) {
            console.error('hallpass:', e);
          }
        },
      }
    );
    if (!link) {
      // connect reports the error through onClose.
      return;
    }
    if (done) {
      return;
    }
    this.link = link;
    this.socket = socket;
  }

  private onState(st: NodeState) {
    if (this.stopped) {
      return;
    }
    this.failures = 0;
    this.update({ connected: true, error: undefined, sessions: st.sessions || [] });
  }

  private fail(error: string) {
    this.update({ connected: false, error, sessions: [] });
    const delay = Math.min(maxBackoff, 1000 * 2 ** this.failures);
    this.failures++;
    this.timer = this.store.deps.setTimeout(() => this.open(), delay);
  }

  private update(s: Partial<AgentState>) {
    this.state = { ...this.state, ...s };
    this.store.changed();
  }

  setNode(node: string) {
    if (node !== this.state.node) {
      this.update({ node });
    }
  }

  answer(session: string, request: string, answer: Answer): Promise<void> {
    if (!this.link) {
      return Promise.reject(new Error(`not connected to ${this.state.pod}`));
    }
    return this.link.answer(session, request, answer);
  }

  rules(session: string, change: RulesChange): Promise<void> {
    if (!this.link) {
      return Promise.reject(new Error(`not connected to ${this.state.pod}`));
    }
    return this.link.rules(
      session,
      change.remove || [],
      change.add || [],
      change.label || '',
      change.generation || ''
    );
  }

  stop() {
    this.stopped = true;
    if (this.timer !== null) {
      this.store.deps.clearTimeout(this.timer);
      this.timer = null;
    }
    this.link?.close();
    this.socket?.close();
    this.link = null;
    this.socket = null;
  }
}

// ClusterStore follows the agents of one cluster.
export class ClusterStore {
  private conns = new Map<string, AgentConn>();
  private listeners = new Set<() => void>();
  private snapshot: AgentState[] = [];
  // Whether the agent pods were listed at least once.
  listed = false;
  // The error listing the agent pods, e.g. forbidden.
  listError: string | undefined;

  constructor(public cluster: string, public deps: Deps) {}

  // setAgents sets the agent pods to connect to.
  setAgents(agents: Agent[], listError?: string) {
    const changed = !this.listed || listError !== this.listError;
    this.listed = true;
    this.listError = listError;
    const want = new Map(agents.map(a => [a.pod, a]));
    for (const [pod, c] of this.conns) {
      if (!want.has(pod)) {
        c.stop();
        this.conns.delete(pod);
      }
    }
    let added = false;
    for (const a of agents) {
      const c = this.conns.get(a.pod);
      if (c) {
        c.setNode(a.node);
        continue;
      }
      const nc = new AgentConn(this, a);
      this.conns.set(a.pod, nc);
      added = true;
      nc.open();
    }
    if (changed || added || want.size !== this.snapshot.length) {
      this.changed();
    }
  }

  answer(pod: string, session: string, request: string, answer: Answer): Promise<void> {
    const c = this.conns.get(pod);
    if (!c) {
      return Promise.reject(new Error(`no agent ${pod}`));
    }
    return c.answer(session, request, answer);
  }

  // rules changes a session's rules in one decision.
  rules(pod: string, session: string, change: RulesChange): Promise<void> {
    const c = this.conns.get(pod);
    if (!c) {
      return Promise.reject(new Error(`no agent ${pod}`));
    }
    return c.rules(session, change);
  }

  changed() {
    this.snapshot = [...this.conns.values()]
      .map(c => c.state)
      .sort((a, b) => a.node.localeCompare(b.node) || a.pod.localeCompare(b.pod));
    for (const l of this.listeners) {
      l();
    }
  }

  getSnapshot = (): AgentState[] => this.snapshot;

  subscribe = (l: () => void): (() => void) => {
    this.listeners.add(l);
    return () => this.listeners.delete(l);
  };

  stop() {
    for (const c of this.conns.values()) {
      c.stop();
    }
    this.conns.clear();
  }
}

// pendingCount counts the pending requests of the agents.
export function pendingCount(agents: AgentState[]): number {
  let n = 0;
  for (const a of agents) {
    for (const s of a.sessions) {
      n += s.pending?.length || 0;
    }
  }
  return n;
}

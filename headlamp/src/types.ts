// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// The state of a hallpass-node agent, as nodeclient.State.MarshalJSON
// writes it: protobuf messages in protojson (camelCase, unset fields
// omitted, 64-bit integers as strings).

export interface SessionInfo {
  id?: string;
  pid?: number;
  command?: string[];
  mode?: string;
  startTime?: string;
  promptTimeout?: string;
  labels?: Record<string, string>;
}

export interface Prompt {
  op?: string;
  path?: string;
  exe?: string;
  pid?: number;
  cmdline?: string[];
  parents?: string[];
  scope?: string;
  never?: string;
  warn?: string;
}

export interface PendingRequest {
  id: string;
  syscall?: string;
  prompt?: Prompt;
}

export interface Rule {
  id?: string;
  ops?: number;
  object?: { path?: { path?: string; tree?: boolean }; proc?: { name?: string; comm?: string } };
  verdict?: 'ALLOW' | 'DENY' | 'ASK';
  label?: string;
  expires?: string;
  set?: string;
}

export interface Session {
  info: SessionInfo;
  pending?: PendingRequest[];
  rules?: Rule[];
}

export interface NodeState {
  sessions?: Session[];
}

// An agent pod, one per node.
export interface Agent {
  pod: string;
  node: string;
}

export interface AgentState extends Agent {
  connected: boolean;
  error?: string;
  sessions: Session[];
}

export type Answer = 'once' | 'temp' | 'always' | 'deny' | 'never';

export const answers: Answer[] = ['once', 'temp', 'always', 'deny', 'never'];

// Whether an answer applies to a prompt: temp and always cover the
// prompt's scope, and some requests have none.
export function answerAllowed(answer: Answer, prompt?: Prompt): boolean {
  return (answer !== 'temp' && answer !== 'always') || !!prompt?.scope;
}

export function sessionName(s: Session): string {
  const l = s.info.labels || {};
  if (l.namespace && l.pod) {
    return `${l.namespace}/${l.pod}/${l.container || ''}`;
  }
  return (s.info.command || []).join(' ') || s.info.id || '';
}

export function ruleObject(r: Rule): string {
  if (r.object?.path) {
    return r.object.path.path + (r.object.path.tree ? '/**' : '');
  }
  if (r.object?.proc) {
    return `proc ${r.object.proc.name || r.object.proc.comm || ''}`;
  }
  return '';
}

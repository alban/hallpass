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
  note?: string;
  detail?: string; // qualifies path, e.g. "udp"
  // A request made in advance: answered with grant or deny.
  advance?: boolean;
  reason?: string; // written by the workload: show it as its claim
  grantFor?: string; // protojson Duration, e.g. "600s"; unset: the session
  group?: string; // the program group "group" allows, e.g. "@git (git: 1 program)"
}

export interface PendingRequest {
  id: string;
  syscall?: string;
  prompt?: Prompt;
}

export interface Rule {
  id?: string;
  ops?: number;
  object?: {
    path?: { path?: string; tree?: boolean };
    proc?: { name?: string; comm?: string };
    inet?: { proto?: number; prefix?: string; portLo?: number; portHi?: number };
    unix?: { path?: string; abstract?: boolean; name?: string; prefix?: boolean };
    ownListener?: boolean;
    anyNet?: boolean;
    unknown?: boolean;
  };
  verdict?: 'ALLOW' | 'DENY' | 'ASK';
  label?: string;
  expires?: string;
  set?: string;
  // The rule in the syntax an edit takes, without its expiry
  // (rules.Rule.Spec, written by the server).
  spec?: string;
}

export interface Session {
  info: SessionInfo;
  pending?: PendingRequest[];
  rules?: Rule[];
  generation?: string; // of the rules, for an edit to check they did not change
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

export type Answer = 'once' | 'temp' | 'always' | 'group' | 'deny' | 'never' | 'grant';

export const answers: Answer[] = ['once', 'temp', 'always', 'group', 'deny', 'never'];

// The answers to a request made in advance.
export const advanceAnswers: Answer[] = ['grant', 'deny'];

// The answers shown for a prompt.
export function answersFor(prompt?: Prompt): Answer[] {
  return prompt?.advance ? advanceAnswers : answers;
}

// Whether an answer applies to a prompt: temp and always cover the
// prompt's scope, and some requests have none; group needs the program
// group of an exec; grant is for requests made in advance, which take only
// grant and deny.
export function answerAllowed(answer: Answer, prompt?: Prompt): boolean {
  if (prompt?.advance) {
    return advanceAnswers.includes(answer);
  }
  if (answer === 'grant') {
    return false;
  }
  if (answer === 'group') {
    return !!prompt?.group;
  }
  return (answer !== 'temp' && answer !== 'always') || !!prompt?.scope;
}

// grantForText formats Prompt.grantFor like the terminal: "for 10m", or
// "for the rest of the session".
export function grantForText(d?: string): string {
  const s = d ? Math.round(parseFloat(d)) : 0;
  if (!s) {
    return 'for the rest of the session';
  }
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return 'for ' + (h ? `${h}h` : '') + (m ? `${m}m` : '') + (sec ? `${sec}s` : '');
}

export function sessionName(s: Session): string {
  const l = s.info.labels || {};
  if (l.namespace && l.pod) {
    return `${l.namespace}/${l.pod}/${l.container || ''}`;
  }
  return (s.info.command || []).join(' ') || s.info.id || '';
}

// forSuffix is what is left of an expiry, rounded down, as a " for"
// suffix of a rule: an edit can keep an expiry, not extend it.
export function forSuffix(expires: string | undefined, now: number): string {
  if (!expires) {
    return '';
  }
  const secs = Math.floor((Date.parse(expires) - now) / 1000);
  if (!(secs > 0)) {
    return '';
  }
  return ' for ' + (secs >= 120 ? `${Math.floor(secs / 60)}m` : `${secs}s`);
}

// editLabel is the label an edit keeps: a program group's goes with the
// rules the group gave.
export function editLabel(r: Rule): string {
  return (r.label || '').startsWith('@') ? '' : r.label || '';
}

export const ruleSyntax = `VERDICT KIND VALUE [for DURATION]: allow path /data/**, deny exec /usr/bin/curl, ask net tcp:10.0.0.1:443 for 1h, allow proc environ bash. An allow rule gives at most what answering "always" would, or narrows the rule it replaces.`;

export function ruleObject(r: Rule): string {
  if (r.object?.path) {
    return r.object.path.path + (r.object.path.tree ? '/**' : '');
  }
  if (r.object?.proc) {
    return `proc ${r.object.proc.name || r.object.proc.comm || ''}`;
  }
  const net = netMatch(r.object);
  return net ? `network: ${net}` : '';
}

function protoName(p: number): string {
  return p === 6 ? 'tcp' : p === 17 ? 'udp' : `ip/${p}`;
}

// netMatch mirrors rules.ObjectMatch.NetString: '' if o is not a network
// match.
export function netMatch(o: Rule['object']): string {
  if (o?.anyNet) {
    return 'all';
  }
  if (o?.ownListener) {
    return 'listeners started inside the sandbox';
  }
  if (o?.unix) {
    const u = o.unix;
    if (u.abstract) {
      return `unix:@${u.name || ''}${u.prefix ? '*' : ''}`;
    }
    return `unix:${u.prefix ? (u.path || '').replace(/\/$/, '') + '/**' : u.path || ''}`;
  }
  if (o?.inet) {
    const i = o.inet;
    let s = i.proto ? `${protoName(i.proto)}:` : '';
    const [addr, bits] = (i.prefix || '').split('/');
    const v6 = (addr || '').includes(':');
    if (!addr) {
      s += '*';
    } else {
      s += (v6 ? `[${addr}]` : addr) + (bits && bits !== (v6 ? '128' : '32') ? `/${bits}` : '');
    }
    const lo = i.portLo || 0;
    const hi = i.portHi || 0;
    if (lo || hi) {
      s += `:${lo}${hi !== lo ? `-${hi}` : ''}`;
    }
    return s;
  }
  return '';
}

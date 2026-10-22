// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// The rule builder: an http rule made from a pending HTTPS request, its
// path cut at a segment or with segments made "*", as the web UI's
// "Make a rule" (internal/web/static/app.js) does.

import { Prompt } from './types';

export const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

export type Verdict = 'allow' | 'ask' | 'deny';

export interface Draft {
  verdict: Verdict;
  methods: string[]; // none or all: any method ("*")
  host: string;
  segs: string[]; // the request's path segments
  wild: number[]; // segments made "*"
  cut: number; // -1, or keep the segments before cut, then "/**"
}

// httpRequest returns the method, host and path of an HTTPS request's
// prompt (op is the method, path the URL), or null for another prompt.
export function httpRequest(p?: Prompt): { method: string; host: string; path: string } | null {
  const m = /^https:\/\/([^/]+)(\/[^?#]*)?$/.exec(p?.path || '');
  if (!m || !p?.op || !/^[A-Z]+$/.test(p.op)) {
    return null;
  }
  return { method: p.op, host: m[1], path: m[2] || '/' };
}

function segments(path: string): string[] {
  return path.split('/').filter(s => s);
}

// newDraft is the rule allowing exactly the request of p.
export function newDraft(p?: Prompt): Draft | null {
  const r = httpRequest(p);
  if (!r) {
    return null;
  }
  return {
    verdict: 'allow',
    methods: [r.method],
    host: r.host,
    segs: segments(r.path),
    wild: [],
    cut: -1,
  };
}

// draftPath is the rule's path glob.
export function draftPath(d: Draft): string {
  const segs = d.segs.map((s, i) => (d.wild.includes(i) ? '*' : s));
  if (d.cut >= 0) {
    const head = segs.slice(0, d.cut).join('/');
    return head ? `/${head}/**` : '/**';
  }
  return '/' + segs.join('/');
}

// draftText is the rule's text, as rules.ParseSpec takes it.
export function draftText(d: Draft): string {
  const ms =
    d.methods.length === 0 || d.methods.length === methods.length ? '*' : d.methods.join(' ');
  return `${d.verdict} http ${ms} https://${d.host}${draftPath(d)}`;
}

// globSeg mirrors rules.segMatch: "*" matches within one segment.
function globSeg(g: string, s: string): boolean {
  const re = new RegExp(
    '^' +
      g
        .split('*')
        .map(x => x.replace(/[.+?^${}()|[\]\\]/g, '\\$&'))
        .join('[^/]*') +
      '$'
  );
  return re.test(s);
}

// draftMatches reports whether the rule matches the request of prompt p.
export function draftMatches(d: Draft, p?: Prompt): boolean {
  const r = httpRequest(p);
  if (!r || r.host !== d.host) {
    return false;
  }
  if (d.methods.length && d.methods.length !== methods.length && !d.methods.includes(r.method)) {
    return false;
  }
  const want = d.segs.map((s, i) => (d.wild.includes(i) ? '*' : s));
  const g = d.cut >= 0 ? want.slice(0, d.cut) : want;
  const segs = segments(r.path);
  if (d.cut >= 0 ? segs.length < g.length : segs.length !== g.length) {
    return false;
  }
  return g.every((x, i) => globSeg(x, segs[i]));
}

// toggle adds x to l, or removes it.
export function toggle<T>(l: T[], x: T): T[] {
  return l.includes(x) ? l.filter(y => y !== x) : [...l, x];
}

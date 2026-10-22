// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { ClusterStore, ConnectFn, Deps, Link, maxBackoff, pendingCount } from './store';
import {
  answerAllowed,
  answersFor,
  editLabel,
  forSuffix,
  grantForText,
  ruleObject,
  sessionName,
} from './types';

// A fake wasm client and port-forward: each open() creates a connection
// the test drives.
class Fake {
  conns: {
    pod: string;
    sent: Uint8Array[];
    socketClosed: boolean;
    onMessage: (d: ArrayBuffer) => void;
    onFail: () => void;
    cb: { onState(json: string): void; onClose(error: string): void };
    delivered: ArrayBuffer[];
    closedReason?: string;
    linkClosed: boolean;
    answers: string[][];
  }[] = [];
  timers: { f: () => void; ms: number; cleared: boolean }[] = [];

  connect: ConnectFn = (transport, cb) => {
    const c = this.conns[this.conns.length - 1];
    c.cb = cb;
    transport.send(new Uint8Array([1]));
    const link: Link = {
      deliver: d => c.delivered.push(d),
      closed: r => {
        c.closedReason = r;
      },
      answer: async (s, r, a) => {
        c.answers.push([s, r, a]);
      },
      rules: async (s, remove, add, label, gen) => {
        c.answers.push([s, 'rules', remove.join(','), add.join(','), label, gen]);
      },
      close: () => {
        c.linkClosed = true;
        cb.onClose('');
      },
    };
    return link;
  };

  deps: Deps = {
    load: async () => this.connect,
    open: (_cluster, pod, onMessage, onFail) => {
      const c = {
        pod,
        sent: [] as Uint8Array[],
        socketClosed: false,
        onMessage,
        onFail,
        cb: undefined as any,
        delivered: [],
        linkClosed: false,
        answers: [],
      };
      this.conns.push(c);
      return {
        send: b => c.sent.push(b),
        close: () => {
          c.socketClosed = true;
        },
      };
    },
    setTimeout: (f, ms) => {
      const t = { f, ms, cleared: false };
      this.timers.push(t);
      return t;
    },
    clearTimeout: t => {
      (t as any).cleared = true;
    },
  };
}

const tick = () => new Promise(r => setTimeout(r, 0));

const state = JSON.stringify({
  sessions: [
    {
      info: { id: 's1', labels: { namespace: 'ns', pod: 'p', container: 'c', policy: 'pol' } },
      pending: [{ id: '7', prompt: { op: 'write', path: '/etc/x', scope: '/etc' } }],
    },
  ],
});

describe('ClusterStore', () => {
  it('connects to each agent and merges their state', async () => {
    const f = new Fake();
    const s = new ClusterStore('c', f.deps);
    let notified = 0;
    s.subscribe(() => notified++);
    s.setAgents([
      { pod: 'b', node: 'n2' },
      { pod: 'a', node: 'n1' },
    ]);
    await tick();
    expect(f.conns.map(c => c.pod)).toEqual(['b', 'a']);
    expect(f.conns[0].sent).toHaveLength(1);
    expect(s.getSnapshot().map(a => a.pod)).toEqual(['a', 'b']);
    expect(s.getSnapshot().every(a => !a.connected)).toBe(true);

    f.conns[1].cb.onState(state);
    const a = s.getSnapshot()[0];
    expect(a.connected).toBe(true);
    expect(a.sessions[0].info.id).toBe('s1');
    expect(pendingCount(s.getSnapshot())).toBe(1);
    expect(notified).toBeGreaterThan(1);

    const data = new ArrayBuffer(3);
    f.conns[1].onMessage(data);
    expect(f.conns[1].delivered).toEqual([data]);
    f.conns[1].onFail();
    expect(f.conns[1].closedReason).toBe('port-forward closed');

    await s.answer('a', 's1', '7', 'once');
    expect(f.conns[1].answers).toEqual([['s1', '7', 'once']]);
    await expect(s.answer('zz', 's1', '7', 'once')).rejects.toThrow();

    await s.rules('a', 's1', { remove: ['3'], add: ['deny write /x'], label: 'l', generation: '5' });
    await s.rules('a', 's1', { add: ['allow write /y'] });
    expect(f.conns[1].answers.slice(1)).toEqual([
      ['s1', 'rules', '3', 'deny write /x', 'l', '5'],
      ['s1', 'rules', '', 'allow write /y', '', ''],
    ]);
    await expect(s.rules('zz', 's1', { remove: ['3'] })).rejects.toThrow();
  });

  it('reconnects with a backoff', async () => {
    const f = new Fake();
    const s = new ClusterStore('c', f.deps);
    s.setAgents([{ pod: 'a', node: 'n1' }]);
    await tick();
    f.conns[0].cb.onClose('connection reset');
    expect(f.conns[0].socketClosed).toBe(true);
    expect(s.getSnapshot()[0]).toMatchObject({ connected: false, error: 'connection reset' });
    await expect(s.answer('a', 's1', '7', 'once')).rejects.toThrow(/not connected/);
    expect(f.timers.map(t => t.ms)).toEqual([1000]);

    f.timers[0].f();
    await tick();
    expect(f.conns).toHaveLength(2);
    f.conns[1].cb.onClose('again');
    expect(f.timers.map(t => t.ms)).toEqual([1000, 2000]);
    for (let i = 0; i < 10; i++) {
      f.timers[f.timers.length - 1].f();
      await tick();
      f.conns[f.conns.length - 1].cb.onClose('again');
    }
    expect(f.timers[f.timers.length - 1].ms).toBe(maxBackoff);

    // A state resets the backoff.
    f.timers[f.timers.length - 1].f();
    await tick();
    f.conns[f.conns.length - 1].cb.onState(state);
    f.conns[f.conns.length - 1].cb.onClose('again');
    expect(f.timers[f.timers.length - 1].ms).toBe(1000);
  });

  it('disconnects from removed agents', async () => {
    const f = new Fake();
    const s = new ClusterStore('c', f.deps);
    s.setAgents([{ pod: 'a', node: 'n1' }], undefined);
    await tick();
    s.setAgents([], 'forbidden');
    expect(f.conns[0].linkClosed).toBe(true);
    expect(f.conns[0].socketClosed).toBe(true);
    expect(f.timers).toHaveLength(0);
    expect(s.getSnapshot()).toEqual([]);
    expect(s.listError).toBe('forbidden');
  });
});

describe('types', () => {
  it('allows temp and always only with a scope', () => {
    expect(answerAllowed('once', {})).toBe(true);
    expect(answerAllowed('never', {})).toBe(true);
    expect(answerAllowed('temp', {})).toBe(false);
    expect(answerAllowed('always', { scope: '' })).toBe(false);
    expect(answerAllowed('always', { scope: '/etc' })).toBe(true);
    expect(answerAllowed('grant', { scope: '/etc' })).toBe(false);
    expect(answerAllowed('group', { scope: '/usr/bin/ls' })).toBe(false);
    expect(answerAllowed('group', { group: '@coreutils (ls: 1 program)' })).toBe(true);
    expect(answerAllowed('group', { advance: true, group: '@x (x: 1 program)' })).toBe(false);
  });

  it('answers requests made in advance with grant or deny', () => {
    const p = { advance: true, scope: '/etc', grantFor: '600s' };
    expect(answersFor(p)).toEqual(['grant', 'deny']);
    expect(answersFor({})).toContain('once');
    expect(answersFor({})).toContain('group');
    expect(answerAllowed('grant', p)).toBe(true);
    expect(answerAllowed('once', p)).toBe(false);
    expect(answerAllowed('always', p)).toBe(false);
    expect(grantForText(p.grantFor)).toBe('for 10m');
    expect(grantForText('5400s')).toBe('for 1h30m');
    expect(grantForText(undefined)).toBe('for the rest of the session');
  });

  it('names sessions', () => {
    expect(sessionName({ info: { labels: { namespace: 'n', pod: 'p', container: 'c' } } })).toBe(
      'n/p/c'
    );
    expect(sessionName({ info: { command: ['sh', '-c'] } })).toBe('sh -c');
  });

  it('names network rules', () => {
    expect(ruleObject({ object: { anyNet: true } })).toBe('network: all');
    expect(ruleObject({ object: { inet: { proto: 6, prefix: '10.0.0.0/8', portLo: 22, portHi: 22 } } })).toBe(
      'network: tcp:10.0.0.0/8:22'
    );
    expect(ruleObject({ object: { inet: { prefix: '::1/128', portLo: 80, portHi: 90 } } })).toBe(
      'network: [::1]:80-90'
    );
    expect(ruleObject({ object: { inet: {} } })).toBe('network: *');
    expect(ruleObject({ object: { unix: { abstract: true, name: 'x', prefix: true } } })).toBe(
      'network: unix:@x*'
    );
    expect(ruleObject({ object: { unix: { path: '/run/', prefix: true } } })).toBe('network: unix:/run/**');
  });

  it('keeps what is left of an expiry and the label in an edit', () => {
    const now = Date.parse('2026-10-20T10:00:00Z');
    expect(forSuffix('2026-10-20T11:00:30Z', now)).toBe(' for 60m');
    expect(forSuffix('2026-10-20T10:01:30Z', now)).toBe(' for 90s');
    expect(forSuffix('2026-10-20T09:00:00Z', now)).toBe(' for 1s');
    expect(forSuffix(undefined, now)).toBe('');
    expect(editLabel({ label: '@git' })).toBe('');
    expect(editLabel({ label: 'SSH keys' })).toBe('SSH keys');
  });
});

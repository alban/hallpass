// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { draftMatches, draftText, httpRequest, newDraft, toggle } from './builder';

const prompt = (op: string, path: string) => ({ op, path });

describe('rule builder', () => {
  it('reads HTTPS requests only', () => {
    expect(httpRequest(prompt('POST', 'https://api.github.com/repos/a/b/issues'))).toEqual({
      method: 'POST',
      host: 'api.github.com',
      path: '/repos/a/b/issues',
    });
    expect(httpRequest(prompt('write', '/data/x'))).toBeNull();
    expect(httpRequest(prompt('connect', 'tcp:1.2.3.4:443'))).toBeNull();
    expect(newDraft(prompt('write', '/data/x'))).toBeNull();
  });

  it('makes the rule text', () => {
    const d = newDraft(prompt('GET', 'https://api.github.com/repos/alban/hallpass/pulls/5'))!;
    expect(draftText(d)).toBe('allow http GET https://api.github.com/repos/alban/hallpass/pulls/5');
    d.wild = [3];
    expect(draftText(d)).toBe('allow http GET https://api.github.com/repos/alban/hallpass/*/5');
    d.cut = 2;
    d.wild = [];
    d.methods = toggle(d.methods, 'POST');
    d.verdict = 'ask';
    expect(draftText(d)).toBe('ask http GET POST https://api.github.com/repos/alban/**');
    d.methods = [];
    d.cut = 0;
    expect(draftText(d)).toBe('ask http * https://api.github.com/**');
  });

  it('matches like the rule', () => {
    const d = newDraft(prompt('GET', 'https://api.github.com/repos/alban/hallpass/pulls/5'))!;
    const get = (path: string) => prompt('GET', 'https://api.github.com' + path);
    expect(draftMatches(d, get('/repos/alban/hallpass/pulls/5'))).toBe(true);
    expect(draftMatches(d, get('/repos/alban/hallpass/pulls/6'))).toBe(false);
    expect(
      draftMatches(d, prompt('POST', 'https://api.github.com/repos/alban/hallpass/pulls/5'))
    ).toBe(false);
    d.wild = [4];
    expect(draftMatches(d, get('/repos/alban/hallpass/pulls/6'))).toBe(true);
    expect(draftMatches(d, get('/repos/alban/hallpass/pulls/6/files'))).toBe(false);
    d.cut = 2;
    expect(draftMatches(d, get('/repos/alban/other'))).toBe(true);
    expect(draftMatches(d, get('/repos/alice/other'))).toBe(false);
    expect(draftMatches(d, prompt('GET', 'https://github.com/repos/alban/x'))).toBe(false);
  });
});

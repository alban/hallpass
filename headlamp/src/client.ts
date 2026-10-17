// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// The real dependencies of the store: the wasm client, served next to the
// plugin's main.js, and port-forwards through Headlamp's WebSocket proxy
// to the API server.

import './wasm_exec.js';
import { stream } from '@kinvolk/headlamp-plugin/lib/ApiProxy';
import { ConnectFn, Deps, Socket } from './store';

export const agentNamespace = 'hallpass-system';
export const agentSelector = 'app.kubernetes.io/name=hallpass-node';
export const sessionPort = 7323;

const pluginName = 'hallpass';

// Headlamp serves plugins from different paths depending on how they were
// installed; the desktop app from its local server.
async function fetchWasm(): Promise<Response> {
  const desktop = typeof navigator === 'object' && navigator.userAgent.includes('Electron');
  const base = desktop ? 'http://localhost:4466' : '';
  const tried: string[] = [];
  for (const prefix of ['plugins', 'user-plugins', 'static-plugins']) {
    const url = `${base}/${prefix}/${pluginName}/main.wasm.gz`;
    tried.push(url);
    try {
      const resp = await fetch(url);
      if (resp.ok && resp.body) {
        return resp;
      }
    } catch {
      // try the next prefix
    }
  }
  throw new Error(`main.wasm.gz not found at ${tried.join(', ')}`);
}

async function load(): Promise<ConnectFn> {
  const resp = await fetchWasm();
  const bytes = await new Response(
    resp.body!.pipeThrough(new DecompressionStream('gzip'))
  ).arrayBuffer();
  const go = new (globalThis as any).Go();
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  // run returns when the program exits; main sets hallpassConnect first.
  go.run(instance).then(() => {
    console.error('hallpass: wasm client exited');
    loading = null;
  });
  const connect = (globalThis as any).hallpassConnect;
  if (typeof connect !== 'function') {
    throw new Error('hallpassConnect not defined by the wasm client');
  }
  return connect;
}

let loading: Promise<ConnectFn> | null = null;

export function loadClient(): Promise<ConnectFn> {
  if (!loading) {
    loading = load().catch(e => {
      loading = null;
      throw e;
    });
  }
  return loading;
}

// The WebSocket subprotocols of port-forward; the API server picks the
// first it supports.
const portForwardProtocols = [
  'v4.channel.k8s.io',
  'v3.channel.k8s.io',
  'v2.channel.k8s.io',
  'channel.k8s.io',
];

export function openPortForward(
  cluster: string,
  pod: string,
  onMessage: (data: ArrayBuffer) => void,
  onFail: () => void
): Socket {
  const url = `/api/v1/namespaces/${agentNamespace}/pods/${encodeURIComponent(
    pod
  )}/portforward?ports=${sessionPort}`;
  let closed = false;
  const s = stream<ArrayBuffer>(
    url,
    data => {
      if (closed) {
        // Closed before the WebSocket was created: stream() cannot cancel
        // it then.
        s.cancel();
        return;
      }
      onMessage(data);
    },
    {
      additionalProtocols: portForwardProtocols,
      failCb: () => closed || onFail(),
      reconnectOnFailure: false,
      cluster,
    }
  );
  return {
    send(b) {
      const ws = s.getSocket();
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        throw new Error('WebSocket not open');
      }
      ws.send(b);
    },
    close() {
      closed = true;
      s.cancel();
    },
  };
}

export const realDeps: Deps = {
  load: loadClient,
  open: openPortForward,
  setTimeout: (f, ms) => window.setTimeout(f, ms),
  clearTimeout: t => window.clearTimeout(t as number),
};

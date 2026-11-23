// TEST ONLY: `--import` preload for the V-7 offline gate.
// Replaces node:net, tls, dgram, dns, http, https, http2 and global fetch/WebSocket so any network attempt
// is recorded to CLI_OFFLINE_LOG and throws immediately. Inherited automatically by Worker threads.
import { appendFileSync } from 'node:fs';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import process from 'node:process';

const logPath = process.env.CLI_OFFLINE_LOG;

function block(api) {
  if (logPath) {
    try {
      appendFileSync(logPath, `${api}\n`, 'utf8');
    } catch {
      // Best-effort log; still throw below.
    }
  }
  const err = new Error(`OFFLINE_GATE_VIOLATION: blocked network call (${api})`);
  err.code = 'OFFLINE_GATE_VIOLATION';
  throw err;
}

function blocker(api) {
  return function blockedNetworkApi() {
    block(api);
  };
}

const require = createRequire(import.meta.url);

const moduleFns = {
  net: ['connect', 'createConnection', 'createServer', 'Socket', 'Server'],
  tls: ['connect', 'createServer', 'TLSSocket', 'Server'],
  dgram: ['createSocket', 'Socket'],
  dns: [
    'lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCaa',
    'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr', 'resolveSoa',
    'resolveSrv', 'resolveTxt', 'reverse', 'Resolver',
  ],
  http: ['request', 'get', 'createServer', 'Agent', 'ClientRequest', 'Server'],
  https: ['request', 'get', 'createServer', 'Agent', 'Server'],
  http2: ['connect', 'createServer', 'createSecureServer'],
};

for (const [modName, names] of Object.entries(moduleFns)) {
  const mod = require(`node:${modName}`);
  for (const fn of names) {
    if (fn in mod) {
      const api = `${modName}.${fn}`;
      try {
        Object.defineProperty(mod, fn, { value: blocker(api), writable: true, configurable: true });
      } catch {
        mod[fn] = blocker(api);
      }
    }
  }
  if (modName === 'dns' && mod.promises) {
    for (const fn of Object.keys(mod.promises)) {
      if (typeof mod.promises[fn] === 'function') {
        const api = `dns.promises.${fn}`;
        try {
          Object.defineProperty(mod.promises, fn, { value: blocker(api), writable: true, configurable: true });
        } catch {
          mod.promises[fn] = blocker(api);
        }
      }
    }
  }
}

syncBuiltinESMExports();

Object.defineProperty(globalThis, 'fetch', {
  value: blocker('globalThis.fetch'),
  writable: true,
  configurable: true,
});
if ('WebSocket' in globalThis) {
  Object.defineProperty(globalThis, 'WebSocket', {
    value: blocker('globalThis.WebSocket'),
    writable: true,
    configurable: true,
  });
}

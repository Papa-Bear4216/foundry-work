/**
 * V-6 spike: Linux `os-session` (kernel keyring via `keyctl`) evaluation.
 *
 * Designed to be run on a real Linux host or CI runner (`ubuntu-latest` / Fedora / Debian).
 * Not executed on the Windows development host (per V-6 rule: never start WSL, Docker, or any VM).
 *
 * Uses Node built-ins only and invokes `/usr/bin/keyctl` or `/bin/keyctl` with `shell: false`
 * and stdin-only payload transfer (`keyctl padd`, NEVER `keyctl add`).
 *
 * Synthetic TEST-ONLY secrets only. Revokes and unlinks every key created in `finally`.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { createFailToNoneCache, createNoneAdapter } from './key-cache-port.mjs';

const KEYCTL_CANDIDATES = ['/usr/bin/keyctl', '/bin/keyctl'];
const CHILD_TIMEOUT_MS = 5_000;

function resolveKeyctlBinary() {
  for (const candidate of KEYCTL_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

function runKeyctl(binary, args, input) {
  const t0 = performance.now();
  const res = spawnSync(binary, args, {
    shell: false,
    input,
    timeout: CHILD_TIMEOUT_MS,
    encoding: null,
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' },
  });
  const elapsedMs = performance.now() - t0;
  return { res, args, elapsedMs };
}

function keyDescription(desc) {
  assert.match(desc.vaultId, /^[0-9a-f]{32}$/u);
  assert.match(desc.kdfSaltHash, /^[0-9a-f]{64}$/u);
  // Short salt prefix binds cache key to current passphrase KDF salt.
  return `foundry:v1:${desc.vaultId}:${desc.kdfSaltHash.slice(0, 16)}`;
}

function stats(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  return {
    samplesMs: samples.map(v => Number(v.toFixed(2))),
    minMs: Number(sorted[0].toFixed(2)),
    medianMs: Number(median.toFixed(2)),
    maxMs: Number(sorted[sorted.length - 1].toFixed(2)),
  };
}

function createLinuxKeyctlSpikeAdapter(binary, ring = '@s') {
  const lookupId = (desc) => {
    const label = keyDescription(desc);
    const { res } = runKeyctl(binary, ['search', ring, 'user', label]);
    if (res.error) throw res.error;
    if (res.status !== 0) return null;
    const id = res.stdout.toString('utf8').trim();
    return /^\d+$/u.test(id) ? id : null;
  };

  return {
    name: /** @type {const} */ ('os-session'),
    probe() {
      if (process.platform !== 'linux') return { available: false, reason: 'not-linux' };
      if (!binary) return { available: false, reason: 'keyctl-missing' };
      const { res } = runKeyctl(binary, ['id', ring]);
      if (res.error || res.status !== 0) {
        return {
          available: false,
          reason: res.stderr?.toString('utf8').trim() || res.error?.message || 'keyring-unavailable',
        };
      }
      return { available: true };
    },
    set(desc, kek, ttlSeconds = 300) {
      const label = keyDescription(desc);
      // Use `padd` (stdin), NEVER `add` (argv leaks in /proc/<pid>/cmdline).
      const { res } = runKeyctl(binary, ['padd', 'user', label, ring], kek);
      if (res.error || res.status !== 0) {
        throw new Error(res.stderr?.toString('utf8').trim() || res.error?.message || `keyctl-padd-${res.status}`);
      }
      const keyId = res.stdout.toString('utf8').trim();
      if (!/^\d+$/u.test(keyId)) throw new Error('unexpected-key-id');
      const t = runKeyctl(binary, ['timeout', keyId, String(ttlSeconds)]);
      if (t.res.error || t.res.status !== 0) {
        // Fail closed: never leave a key without its kernel TTL.
        runKeyctl(binary, ['revoke', keyId]);
        runKeyctl(binary, ['unlink', keyId, ring]);
        throw new Error(t.res.stderr?.toString('utf8').trim() || 'keyctl-timeout-failed');
      }
      return true;
    },
    get(desc) {
      const keyId = lookupId(desc);
      if (!keyId) return null;
      const { res } = runKeyctl(binary, ['pipe', keyId]);
      if (res.error || res.status !== 0) return null;
      return Buffer.from(res.stdout);
    },
    clear(desc) {
      const keyId = lookupId(desc);
      if (!keyId) return;
      runKeyctl(binary, ['revoke', keyId]);
      runKeyctl(binary, ['unlink', keyId, ring]);
    },
  };
}

async function main() {
  const binary = resolveKeyctlBinary();
  const noneCache = createNoneAdapter();
  assert.equal(noneCache.probe().available, true);

  if (process.platform !== 'linux') {
    const adapter = createFailToNoneCache(createLinuxKeyctlSpikeAdapter(binary));
    console.log(JSON.stringify({
      platform: process.platform,
      status: 'untested-on-this-host',
      probe: adapter.probe(),
      note: 'Run on a real Linux host or CI runner (e.g. ubuntu-latest with keyutils installed).',
    }, null, 2));
    return;
  }

  if (!binary) {
    const adapter = createFailToNoneCache(createLinuxKeyctlSpikeAdapter(null));
    console.log(JSON.stringify({
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.versions.node,
      keyctlBinary: null,
      probe: adapter.probe(),
      fallbackToNone: true,
    }, null, 2));
    return;
  }

  const ringId = (spec) => {
    const { res } = runKeyctl(binary, ['id', spec]);
    return res.status === 0 ? res.stdout.toString('utf8').trim() : null;
  };
  const sessionId = ringId('@s');
  const userSessionId = ringId('@us');
  const userId = ringId('@u');

  const syntheticKey = randomBytes(32);
  const syntheticKeyHex = syntheticKey.toString('hex');
  const desc = {
    vaultId: randomBytes(16).toString('hex'),
    kdfSaltHash: createHash('sha256').update(randomBytes(32)).digest('hex'),
  };
  const fallbacks = [];
  const cache = createFailToNoneCache(createLinuxKeyctlSpikeAdapter(binary, '@s'), e => fallbacks.push(e));
  const tempBefore = new Set(readdirSync(tmpdir()));

  try {
    const probe = cache.probe();
    if (!probe.available) {
      console.log(JSON.stringify({
        platform: process.platform,
        keyctlBinary: binary,
        probe,
        keyringIds: { session: sessionId, userSession: userSessionId, user: userId },
        fallbackToNone: true,
      }, null, 2));
      return;
    }

    // 1. Round-trip latency (1 cold + 5 warm)
    const setTimes = [];
    const getTimes = [];
    for (let i = 0; i < 6; i++) {
      const t0 = performance.now();
      assert.equal(cache.set(desc, syntheticKey, 60), true);
      setTimes.push(performance.now() - t0);

      const t1 = performance.now();
      const got = cache.get(desc);
      getTimes.push(performance.now() - t1);
      assert.ok(got && Buffer.compare(got, syntheticKey) === 0);
      got.fill(0);
    }

    // Verify description never carries secret bytes
    const label = keyDescription(desc);
    const secretInLabel = label.includes(syntheticKeyHex);

    // 2. Kernel-enforced timeout expiry check (2 s TTL)
    cache.clear(desc);
    assert.equal(cache.set(desc, syntheticKey, 2), true);
    const beforeExpiry = cache.get(desc);
    const readableBeforeExpiry = Boolean(beforeExpiry && Buffer.compare(beforeExpiry, syntheticKey) === 0);
    if (beforeExpiry) beforeExpiry.fill(0);

    await delay(3_000);
    const afterExpiry = cache.get(desc);
    const expiredCleanly = afterExpiry === null;
    if (afterExpiry) afterExpiry.fill(0);

    // 3. Explicit revocation check
    assert.equal(cache.set(desc, syntheticKey, 60), true);
    cache.clear(desc);
    const afterClear = cache.get(desc);
    const clearedCleanly = afterClear === null;
    if (afterClear) afterClear.fill(0);

    const tempAfter = new Set(readdirSync(tmpdir()));
    const newTempEntries = [...tempAfter].filter(name => !tempBefore.has(name));

    console.log(JSON.stringify({
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.versions.node,
      keyctlBinary: binary,
      shellOption: false,
      keyringTopology: {
        sessionRingId: sessionId,
        userSessionRingId: userSessionId,
        userRingId: userId,
        distinctSessionKeyring: Boolean(sessionId && userSessionId && sessionId !== userSessionId),
      },
      timings: {
        coldSetMs: Number(setTimes[0].toFixed(2)),
        warmSet: stats(setTimes.slice(1)),
        coldGetMs: Number(getTimes[0].toFixed(2)),
        warmGet: stats(getTimes.slice(1)),
      },
      nodeParentMaxRssMiB: Number((process.resourceUsage().maxRSS / 1024).toFixed(2)),
      checks: {
        secretInLabel,
        readableBeforeExpiry,
        expiredCleanly,
        clearedCleanly,
        unexpectedTempEntriesCreated: newTempEntries,
        fallbackEventsRecorded: fallbacks.length,
      },
    }, null, 2));
  } finally {
    cache.clear(desc);
    syntheticKey.fill(0);
  }
}

await main();

import assert from 'node:assert/strict';
import { mkdtempDisposableSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeKeyring } from '../dist/index.js';
import { formatRecoveryKey } from '../dist/recovery.js';
import { cases, fixture, identity, keyId, keyringPath, writable } from './vault-fixture.mjs';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3');
const existingProbe = fileURLToPath(new URL('./vault-probe.mjs', import.meta.url));
const sessionProbe = fileURLToPath(new URL('./session-probe.mjs', import.meta.url));
const recoveryBytes = Buffer.from(cases.recovery_key, 'hex');
const recovery = formatRecoveryKey(recoveryBytes);

const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-session-budget-'));
try {
  const vector = fixture(temp.path);
  const entries = vector.keyring.keys.map(entry => entry.state === 'destroyed' ? entry : {
    ...entry, key: vector.keys.get(entry.key_id), label: vector.labels.get(entry.key_id),
  });
  // Rewrite keyring to version 1 so stage + retire have version headroom while using production scrypt defaults.
  const initialKeyring = encodeKeyring(
    { vaultId: identity.vaultId, version: 1, masterKey: vector.masterKey, entries },
    cases.passphrase,
    recoveryBytes,
  );
  writeFileSync(keyringPath(temp.path), initialKeyring);
  for (const step of ['append', 'close']) {
    const prep = measurePeakRss(existingProbe, step, temp.path, JSON.stringify({
      vaultId: identity.vaultId, recovery, keyId,
    }));
    assert.equal(prep.status, 0, prep.stderr);
  }

  for (const mode of ['session', 'credential']) {
    writeFileSync(keyringPath(temp.path), initialKeyring);
    const result = measurePeakRss(sessionProbe, mode, temp.path);
    assert.equal(result.status, 0, result.stderr);
    const { blobs, encodedBytes, kdfCalls, ms, peakRssKiB } = JSON.parse(result.stdout);
    assert.ok(Number.isFinite(peakRssKiB) && peakRssKiB > 0);
    console.log(
      `${mode}: ${kdfCalls} KDF(s), ${blobs} blobs, ${encodedBytes} encoded bytes, ` +
      `${ms} ms, internal ${peakRssKiB} KiB, external ${result.externalPeakKiB} KiB`,
    );
    if (mode === 'session') {
      assert.equal(kdfCalls, 1);
      assert.ok(Math.max(peakRssKiB, result.externalPeakKiB) <= 256 * 1024, 'Passphrase session exceeded 256 MiB peak RSS.');
    } else {
      assert.equal(kdfCalls, 4);
    }
  }
} finally {
  writable(temp.path);
  temp.remove();
}

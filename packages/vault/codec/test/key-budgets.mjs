import assert from 'node:assert/strict';
import { mkdtempDisposableSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatRecoveryKey } from '../dist/recovery.js';
import { measurePeakRss } from './peak-rss.mjs';

// TEST ONLY: use the frozen synthetic hierarchy and production KDF sizes.
const vector = name => readFileSync(new URL('./vectors/' + name, import.meta.url));
const cases = JSON.parse(vector('cases.json'));
const script = fileURLToPath(new URL('./key-probe.mjs', import.meta.url));
const vaultId = cases.metadata.vault_id;
const current = cases.passphrase;
const passphrase = 'TEST ONLY replacement for memory measurement';
const recoveryKey = formatRecoveryKey(Buffer.from(cases.recovery_key, 'hex'));
const currentCollectionIds = [cases.ids.collection];
const historicalCollectionIds = [];
const initial = vector('ring-p2.json');
const initialVersion = JSON.parse(initial).version;

assert.equal(process.versions.node, '24.22.3');
for (const [label, command, input] of [
  ['create (default p=1)', 'create', { passphrase }],
  ['create (p=2)', 'create', { passphrase, parallelism: 2 }],
  ['unlock by passphrase (p=2)', 'unlock-passphrase', { vaultId, passphrase: current }],
  ['unlock by recovery', 'unlock-recovery', { vaultId, recoveryKey }],
  ['passphrase change (p=2)', 'change', { vaultId, current, passphrase }],
  ['passphrase reset with the recovery key (p=2)', 'reset-passphrase', { vaultId, recoveryKey, passphrase }],
  ['rekey all (p=2)', 'rekey', { vaultId, current, passphrase, currentCollectionIds, historicalCollectionIds }],
]) {
  using directory = mkdtempDisposableSync(join(tmpdir(), 'vault-key-budget-'));
  const path = join(directory.path, 'KEYRING.json');
  if (command !== 'create') writeFileSync(path, initial);
  const result = measurePeakRss(script, command, directory.path, JSON.stringify(input));
  assert.equal(result.status, 0, result.stderr);
  const probe = JSON.parse(result.stdout);
  assert.equal(probe.command, command);
  const published = readFileSync(path);
  if (command === 'create') {
    assert.equal(JSON.parse(published).version, 1);
  } else if (command === 'change' || command === 'reset-passphrase' || command === 'rekey') {
    assert.equal(JSON.parse(published).version, initialVersion + 1);
  } else {
    assert.deepEqual(published, initial);
  }

  const { peakRssKiB } = probe;
  const { externalPeakKiB } = result;
  console.log(`${label}: internal ${peakRssKiB} KiB, external ${externalPeakKiB} KiB`);
  assert.ok(Number.isFinite(peakRssKiB) && peakRssKiB > 0);
  assert.ok(Math.max(peakRssKiB, externalPeakKiB) <= 256 * 1024, 'Key operation exceeded the 256 MiB peak RSS budget.');
}

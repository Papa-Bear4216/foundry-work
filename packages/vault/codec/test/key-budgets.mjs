import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempDisposableSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatRecoveryKey } from '../src/recovery.ts';

// TEST ONLY: use the frozen synthetic hierarchy and production KDF sizes.
const vector = name => readFileSync(new URL('./vectors/' + name, import.meta.url));
const cases = JSON.parse(vector('cases.json'));
const script = fileURLToPath(new URL('./key-probe.mjs', import.meta.url));
const vaultId = cases.metadata.vault_id;
const current = cases.passphrase;
const passphrase = 'TEST ONLY replacement for memory measurement';
const recoveryKey = formatRecoveryKey(Buffer.from(cases.recovery_key, 'hex'));
const currentCollectionIds = [cases.ids.collection];

assert.equal(process.versions.node, '24.22.3');
for (const [label, command, input] of [
  ['create (default p=1)', 'create', { passphrase }],
  ['create (p=2)', 'create', { passphrase, parallelism: 2 }],
  ['unlock by passphrase (p=2)', 'unlock-passphrase', { vaultId, passphrase: current }],
  ['unlock by recovery', 'unlock-recovery', { vaultId, recoveryKey }],
  ['passphrase change (p=2)', 'change', { vaultId, current, passphrase }],
  ['rekey all (p=2)', 'rekey', { vaultId, current, passphrase, currentCollectionIds }],
]) {
  using directory = mkdtempDisposableSync(join(tmpdir(), 'vault-key-budget-'));
  if (command !== 'create') writeFileSync(join(directory.path, 'KEYRING.json'), vector('ring-p2.json'));
  const result = spawnSync(process.execPath, [script, command], {
    cwd: directory.path, input: JSON.stringify(input), encoding: 'utf8', timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const { peakRssKiB } = JSON.parse(result.stdout);
  console.log(`${label}: ${peakRssKiB} KiB (${(peakRssKiB / 1024).toFixed(2)} MiB)`);
  assert.ok(peakRssKiB > 0 && peakRssKiB <= 256 * 1024, 'Key operation exceeded the 256 MiB peak RSS budget.');
}

import assert from 'node:assert/strict';
import { mkdirSync, mkdtempDisposableSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { encodeKeyring, retireIndexKey, stageIndexKey, unlockByPassphrase } from '../src/index.ts';
import { cases, fixture, identity, keyringPath, unlockFixture } from './vault-fixture.mjs';

function nonIndexBytes(bytes) {
  const { keys, master, kdf } = JSON.parse(bytes);
  // The stored document is canonical and its objects are already in canonical member order.
  return [kdf, master, ...keys.filter(entry => entry.kind !== 'index')].map(value => Buffer.from(JSON.stringify(value)));
}

test('durably stage, reopen, publish, and retry retirement without altering unrelated keyring bytes', () => {
  using temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-index-keys-'));
  const directory = join(temp.path, 'vault');
  mkdirSync(directory);
  const path = keyringPath(directory);
  const vector = fixture(directory);
  const vaultId = identity.vaultId;
  const credential = { recoveryKey: Buffer.from(cases.recovery_key, 'hex') };
  const entries = vector.keyring.keys.map(entry => entry.state === 'destroyed' ? entry : {
    ...entry, key: vector.keys.get(entry.key_id), label: vector.labels.get(entry.key_id),
  });
  // The fixed vectors exercise the version ceiling. This test needs room for two rewrites.
  const bytes = encodeKeyring({ vaultId, version: 1, masterKey: vector.masterKey, entries },
    cases.passphrase, credential.recoveryKey);
  writeFileSync(path, bytes);
  const before = unlockFixture(directory);
  const oldId = cases.ids.index;
  const newId = 'ab'.repeat(16);
  const stagedKey = stageIndexKey(path, vaultId, credential, newId);
  assert.equal(stagedKey.length, 32);
  assert.notDeepEqual(stagedKey, before.keys.get(oldId));
  const stagedBytes = readFileSync(path);
  assert.deepEqual(nonIndexBytes(stagedBytes), nonIndexBytes(bytes));

  // Simulate interruption after stage. The caller's generation record retains the new ID.
  const reopened = unlockFixture(directory);
  assert.deepEqual(reopened.masterKey, before.masterKey);
  assert.equal(reopened.keyring.version, before.keyring.version + 1);
  assert.deepEqual(reopened.keys.get(oldId), before.keys.get(oldId));
  assert.deepEqual(reopened.keys.get(newId), stagedKey);
  assert.deepEqual(stageIndexKey(path, vaultId, credential, newId), stagedKey);
  assert.deepEqual(readFileSync(path), stagedBytes);

  // Publish the caller's generation pointer before calling retirement.
  const pending = join(temp.path, 'generation.pending');
  const published = join(temp.path, 'generation');
  writeFileSync(pending, newId, { flush: true });
  renameSync(pending, published);
  assert.equal(readFileSync(published, 'utf8'), newId);
  retireIndexKey(path, vaultId, credential, oldId);
  const retiredBytes = readFileSync(path);
  assert.deepEqual(nonIndexBytes(retiredBytes), nonIndexBytes(bytes));
  const retired = unlockByPassphrase(path, vaultId, cases.passphrase);
  assert.equal(retired.keyring.version, before.keyring.version + 2);
  assert.equal(retired.keys.has(oldId), false);
  assert.equal(retired.keyring.keys.find(entry => entry.key_id === oldId).wrapped, null);
  assert.deepEqual(retired.keys.get(newId), stagedKey);
  assert.deepEqual(retired.masterKey, before.masterKey);
  retireIndexKey(path, vaultId, credential, oldId);
  assert.deepEqual(readFileSync(path), retiredBytes);
  assert.throws(() => stageIndexKey(path, vaultId, credential, oldId), { code: 'KEY' });
  assert.throws(() => stageIndexKey(path, vaultId, credential, cases.ids.collection), { code: 'KEY' });
  assert.throws(() => retireIndexKey(path, vaultId, credential, cases.ids.profile), { code: 'KEY' });
  assert.throws(() => retireIndexKey(path, vaultId, credential, '00'.repeat(16)), { code: 'KEY' });
  assert.throws(() => retireIndexKey(path, vaultId, { recoveryKey: Buffer.alloc(32) }, oldId), { code: 'AUTH' });
  assert.deepEqual(readFileSync(path), retiredBytes);
});

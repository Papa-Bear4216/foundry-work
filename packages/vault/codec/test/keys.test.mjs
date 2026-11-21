import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs, { mkdtempDisposableSync, readFileSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonical, derive } from '../src/bytes.ts';
import { publishKeyring } from '../src/keyring-file.ts';
import { formatRecoveryKey } from '../src/recovery.ts';
import {
  changePassphrase, create, decodeKeyring, decodeRecord, decodeRecoveryKey, rekeyAll,
  signingPublicKey, unlockByPassphrase, unlockByRecovery,
} from '../src/index.ts';

// TEST ONLY: these credentials and all generated keyrings are synthetic.
const first = 'TEST ONLY cafe\u0301 \u{1f512}\n';
const second = 'TEST ONLY replacement';
const third = 'TEST ONLY rekey';
const vector = name => readFileSync(new URL('./vectors/' + name, import.meta.url));
const cases = JSON.parse(vector('cases.json'));
const vectorId = cases.metadata.vault_id;
const vectorRecovery = Buffer.from(cases.recovery_key, 'hex');
const vectorText = formatRecoveryKey(vectorRecovery);

function testPath(t, initial) {
  const directory = mkdtempDisposableSync(join(tmpdir(), 'vault-keys-'));
  t.after(() => directory.remove());
  const path = join(directory.path, 'KEYRING.json');
  if (initial) writeFileSync(path, initial);
  return path;
}

function pythonUnlock(keyring, vaultId, passphrase, recoveryKey, collectionIds = []) {
  const script = fileURLToPath(new URL('../../reference/check_keyring.py', import.meta.url));
  const result = spawnSync(process.env.VAULT_TEST_PYTHON || 'python', ['-B', script], {
    input: JSON.stringify({
      keyring: keyring.toString('base64'), vaultId, passphrase,
      recovery: decodeRecoveryKey(recoveryKey).toString('hex'), collectionIds,
    }),
    encoding: 'utf8', timeout: 30_000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('create, unlock with either credential, and change the passphrase using frozen bytes', t => {
  const path = testPath(t);
  const { vaultId, recoveryKey, signingPublicKey: publicKey } = create(path, { passphrase: first });
  const created = readFileSync(path);
  const original = unlockByPassphrase(path, vaultId, first);
  assert.deepEqual(unlockByRecovery(path, vaultId, recoveryKey).masterKey, original.masterKey);
  assert.equal(original.keyring.version, 1);
  assert.deepEqual({ ...original.keyring.kdf, salt: undefined }, {
    name: 'scrypt', N: 131072, r: 8, p: 1, salt: undefined,
  });
  assert.equal(original.keyring.keys.length, 1);
  const signing = original.keyring.keys[0];
  assert.equal(signing.kind, 'signing');
  assert.deepEqual(signingPublicKey(original.keys.get(signing.key_id)), publicKey);
  assert.throws(() => unlockByPassphrase(path, vaultId, first.trimEnd()), { code: 'AUTH' });
  assert.deepEqual(pythonUnlock(created, vaultId, first, recoveryKey), []);
  assert.throws(() => create(path, { passphrase: second }), /already exists/u);
  assert.deepEqual(readFileSync(path), created);

  changePassphrase(path, vaultId, first, { passphrase: second, parallelism: 2 });
  const changed = readFileSync(path);
  const updated = unlockByPassphrase(path, vaultId, second);
  assert.equal(updated.keyring.version, 2);
  assert.equal(updated.keyring.kdf.p, 2);
  assert.notEqual(updated.keyring.kdf.salt, original.keyring.kdf.salt);
  assert.notEqual(updated.keyring.master.by_passphrase, original.keyring.master.by_passphrase);
  assert.equal(updated.keyring.master.by_recovery, original.keyring.master.by_recovery);
  assert.notEqual(updated.keyring.mac, original.keyring.mac);
  assert.deepEqual(updated.keyring.keys, original.keyring.keys);
  assert.deepEqual(updated.masterKey, original.masterKey);
  assert.deepEqual(unlockByRecovery(path, vaultId, recoveryKey).masterKey, original.masterKey);
  assert.throws(() => unlockByPassphrase(path, vaultId, first), { code: 'AUTH' });
  assert.deepEqual(pythonUnlock(changed, vaultId, second, recoveryKey), []);
});

test('rekey rotates future write keys, keeps history readable and preserves erasure and signing', t => {
  const path = testPath(t, vector(cases.keyring));
  const before = unlockByRecovery(path, vectorId, vectorText);
  // The frozen vector starts one below the version ceiling. Leave room for two rotations.
  const { mac: _vectorMac, ...body } = before.keyring;
  body.version = 1;
  const mac = crypto.createHmac('sha256', derive(before.masterKey, 'keyring-mac', Buffer.from(vectorId, 'hex')))
    .update(canonical(body)).digest('base64');
  const initial = Buffer.from(canonical({ ...body, mac }));
  writeFileSync(path, initial);
  const { collection, profile, index, signing, erased } = cases.ids;
  const options = { passphrase: third, currentCollectionIds: [collection] };
  assert.throws(() => rekeyAll(path, vectorId, { recoveryKey: vectorText }, {
    ...options, currentCollectionIds: [erased],
  }), { code: 'KEY' });
  assert.deepEqual(readFileSync(path), initial);

  const { recoveryKey, collectionIds } = rekeyAll(path, vectorId, { recoveryKey: vectorText }, options);
  const currentCollection = collectionIds.get(collection);
  assert.equal(collectionIds.size, 1);
  assert.notEqual(currentCollection, collection);
  assert.notEqual(recoveryKey, vectorText);
  const after = unlockByPassphrase(path, vectorId, third);
  assert.deepEqual(unlockByRecovery(path, vectorId, recoveryKey).masterKey, after.masterKey);
  assert.throws(() => unlockByRecovery(path, vectorId, vectorText), { code: 'AUTH' });
  assert.throws(() => unlockByPassphrase(path, vectorId, cases.passphrase), { code: 'AUTH' });
  assert.equal(after.keyring.version, body.version + 1);
  assert.notEqual(after.keyring.kdf.salt, before.keyring.kdf.salt);
  assert.notDeepEqual(after.masterKey, before.masterKey);
  for (const id of [profile, index]) assert.notDeepEqual(after.keys.get(id), before.keys.get(id));
  assert.deepEqual(after.labels, before.labels);
  assert.deepEqual(after.keys.get(signing), before.keys.get(signing));
  const entry = (ring, id) => ring.keyring.keys.find(key => key.key_id === id);
  assert.notEqual(entry(after, signing).wrapped, entry(before, signing).wrapped);
  assert.deepEqual(after.erased, before.erased);
  assert.deepEqual(entry(after, erased), entry(before, erased));
  assert.throws(() => after.collectionEncryptionKey(erased), { code: 'ERASED' });
  const oldKey = before.collectionEncryptionKey(collection);
  const newKey = after.collectionEncryptionKey(currentCollection);
  assert.deepEqual(after.collectionEncryptionKey(collection), oldKey);
  assert.notDeepEqual(newKey, oldKey);
  assert.equal(decodeRecord(vector('event.fvr'), vectorId, oldKey).type, 1);
  assert.throws(() => decodeRecord(vector('event.fvr'), vectorId, newKey), { code: 'AUTH' });
  assert.deepEqual(pythonUnlock(readFileSync(path), vectorId, third, recoveryKey, [collection, currentCollection]),
    [oldKey.toString('hex'), newKey.toString('hex')]);

  const again = rekeyAll(path, vectorId, { recoveryKey }, {
    passphrase: third, currentCollectionIds: [currentCollection],
  });
  const latest = unlockByRecovery(path, vectorId, again.recoveryKey);
  assert.equal(latest.keyring.keys.length, after.keyring.keys.length + 1);
  assert.deepEqual(latest.collectionEncryptionKey(collection), oldKey);
  assert.deepEqual(latest.collectionEncryptionKey(currentCollection), newKey);
});

test('out-of-bounds headers and upgrades fail before scrypt', t => {
  const path = testPath(t, vector(cases.keyring));
  const mockKdf = t.mock.method(crypto, 'scryptSync', () => assert.fail('scrypt must not run'));
  syncBuiltinESMExports();
  try {
    for (const [parameter, value] of [['name', 'other'], ['N', 65536], ['N', 262144], ['r', 1], ['p', 0], ['p', 3]]) {
      const invalid = JSON.parse(vector(cases.keyring));
      invalid.kdf[parameter] = value;
      writeFileSync(path, canonical(invalid));
      assert.throws(() => unlockByPassphrase(path, vectorId, first), { code: 'KDF' });
      assert.throws(() => unlockByRecovery(path, vectorId, vectorText), { code: 'KDF' });
      assert.throws(() => changePassphrase(path, vectorId, first, { passphrase: second }), { code: 'KDF' });
      assert.throws(() => rekeyAll(path, vectorId, { passphrase: first }, {
        passphrase: second, currentCollectionIds: [cases.ids.collection],
      }), { code: 'KDF' });
    }
    writeFileSync(path, vector('ring-p2.json'));
    for (const parallelism of [0, 1, 3]) {
      assert.throws(() => changePassphrase(path, vectorId, first, { passphrase: second, parallelism }), { code: 'KDF' });
      assert.throws(() => rekeyAll(path, vectorId, { passphrase: first }, {
        passphrase: second, parallelism, currentCollectionIds: [cases.ids.collection],
      }), { code: 'KDF' });
    }
    assert.throws(() => create(path, { passphrase: first, parallelism: 3 }), { code: 'KDF' });
    writeFileSync(path, vector(cases.changed_keyring));
    assert.throws(() => changePassphrase(path, vectorId, first, { passphrase: second }), { code: 'SCHEMA' });
    assert.throws(() => rekeyAll(path, vectorId, { passphrase: first }, {
      passphrase: second, currentCollectionIds: [cases.ids.collection],
    }), { code: 'SCHEMA' });
    assert.equal(mockKdf.mock.callCount(), 0);
  } finally {
    mockKdf.mock.restore();
    syncBuiltinESMExports();
  }
});

test('slot and vault transplantation fail authentication before the MAC check', () => {
  const original = JSON.parse(vector(cases.keyring));
  const swapped = structuredClone(original);
  [swapped.master.by_passphrase, swapped.master.by_recovery] =
    [swapped.master.by_recovery, swapped.master.by_passphrase];
  const moved = { ...original, vault_id: 'a1'.repeat(16) };
  for (const credential of [{ passphrase: cases.passphrase }, { recoveryKey: vectorRecovery }]) {
    assert.throws(() => decodeKeyring(Buffer.from(canonical(swapped)), credential, vectorId), { code: 'AUTH' });
    assert.throws(() => decodeKeyring(Buffer.from(canonical(moved)), credential, moved.vault_id), { code: 'AUTH' });
  }
  assert.throws(() => decodeKeyring(vector('entry-slot-swap.json'), { recoveryKey: vectorRecovery }, vectorId), { code: 'AUTH' });
});

test('printed recovery text rejects version, grouping, and checksum mistakes', () => {
  assert.deepEqual(decodeRecoveryKey(vectorText), vectorRecovery);
  assert.throws(() => decodeRecoveryKey('2' + vectorText.slice(1)), /format/u);
  assert.throws(() => decodeRecoveryKey(vectorText.replace('-', '')), /format/u);
  const wrong = vectorText.slice(0, -1) + (vectorText.endsWith('A') ? 'B' : 'A');
  assert.throws(() => decodeRecoveryKey(wrong), /checksum/u);
});

test('competing or stale writers preserve the last published keyring', t => {
  const initial = vector(cases.keyring);
  const next = vector(cases.changed_keyring);
  const path = testPath(t, initial);
  const pending = path + '.pending';
  writeFileSync(pending, next);
  assert.throws(() => publishKeyring(path, next, initial), /in progress or was interrupted/u);
  assert.deepEqual(readFileSync(path), initial);
  assert.deepEqual(readFileSync(pending), next);
  fs.unlinkSync(pending);
  assert.throws(() => publishKeyring(path, next, next), /changed during rewrite/u);
  assert.deepEqual(readFileSync(path), initial);
  assert.equal(fs.existsSync(pending), false);
  publishKeyring(path, next, initial);
  assert.deepEqual(readFileSync(path), next);
  assert.equal(fs.existsSync(pending), false);
});

test('Windows retries a transient sharing violation', { skip: process.platform !== 'win32' }, t => {
  const initial = vector(cases.keyring);
  const next = vector(cases.changed_keyring);
  const path = testPath(t, initial);
  const rename = fs.renameSync;
  let attempts = 0;
  const mockRename = t.mock.method(fs, 'renameSync', (from, to) => {
    if (++attempts === 1) throw Object.assign(new Error('TEST ONLY sharing violation'), { code: 'EPERM' });
    return rename(from, to);
  });
  syncBuiltinESMExports();
  try {
    publishKeyring(path, next, initial);
    assert.equal(attempts, 2);
    assert.deepEqual(readFileSync(path), next);
  } finally {
    mockRename.mock.restore();
    syncBuiltinESMExports();
  }
});

test('the descriptor adapter rejects argv and environment secrets before reading input', () => {
  const script = fileURLToPath(new URL('./key-probe.mjs', import.meta.url));
  for (const [args, env, error] of [
    [['--passphrase', first], {}, /Unexpected command-line arguments/u],
    [[first], {}, /Unexpected command-line arguments/u],
    [[], { FOUNDRY_VAULT_PASSPHRASE: first }, /Secret environment variables are refused/u],
    [[], { FOUNDRY_RECOVERY_KEY: vectorText }, /Secret environment variables are refused/u],
  ]) {
    const result = spawnSync(process.execPath, [script, 'create', ...args], {
      input: 'TEST ONLY invalid JSON', env: { ...process.env, ...env }, encoding: 'utf8', timeout: 10_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 1);
    assert.match(result.stderr, error);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes('TEST ONLY'));
  }
});

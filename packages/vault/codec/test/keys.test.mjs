import assert from 'node:assert/strict';
import { fork, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { once } from 'node:events';
import fs, { mkdtempDisposableSync, readFileSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { canonical, derive, seal } from '../src/bytes.ts';
import { publishKeyring } from '../src/keyring-file.ts';
import { formatRecoveryKey } from '../src/recovery.ts';
import {
  changePassphrase, create, decodeKeyring, decodeRecord, decodeRecoveryKey, rekeyAll,
  guardSecretInput, readSecretFromFd, signingPublicKey, unlockByPassphrase, unlockByRecovery,
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
  const options = { passphrase: third, currentCollectionIds: [collection], historicalCollectionIds: [] };
  assert.throws(() => rekeyAll(path, vectorId, { recoveryKey: vectorText }, {
    ...options, currentCollectionIds: [erased],
  }), { code: 'KEY' });
  assert.deepEqual(readFileSync(path), initial);

  let handoff;
  let newTombstoneKey;
  const { recoveryKey, collectionIds, indexKeyId } = rekeyAll(path, vectorId, { recoveryKey: vectorText }, {
    ...options,
    beforePublish(value) {
      handoff = value;
      assert.deepEqual(readFileSync(path), initial);
      assert.deepEqual(value.oldTombstoneKey, derive(before.masterKey, 'tombstone', Buffer.from(vectorId, 'hex')));
      newTombstoneKey = Buffer.from(value.newTombstoneKey);
    },
  });
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
  assert.notDeepEqual(after.keys.get(profile), before.keys.get(profile));
  assert.notEqual(indexKeyId, index);
  assert.notDeepEqual(after.keys.get(indexKeyId), before.keys.get(index));
  assert.equal(after.keys.has(index), false);
  assert.deepEqual(handoff.collectionIds, collectionIds);
  assert.equal(handoff.indexKeyId, indexKeyId);
  assert.deepEqual(newTombstoneKey, derive(after.masterKey, 'tombstone', Buffer.from(vectorId, 'hex')));
  assert.deepEqual(handoff.oldTombstoneKey, Buffer.alloc(32));
  assert.deepEqual(handoff.newTombstoneKey, Buffer.alloc(32));
  assert.deepEqual(after.labels, before.labels);
  assert.deepEqual(after.keys.get(signing), before.keys.get(signing));
  const entry = (ring, id) => ring.keyring.keys.find(key => key.key_id === id);
  assert.notEqual(entry(after, signing).wrapped, entry(before, signing).wrapped);
  assert.deepEqual(after.erased, new Map([...before.erased, [index, entry(after, index).destroyed_at]]));
  assert.deepEqual(entry(after, index), {
    key_id: index, kind: 'index', parent: 'master', state: 'destroyed', wrapped: null,
    destroyed_at: entry(after, indexKeyId).created_at,
  });
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
    passphrase: third, currentCollectionIds: [currentCollection], historicalCollectionIds: [collection],
  });
  const latest = unlockByRecovery(path, vectorId, again.recoveryKey);
  assert.equal(latest.keyring.keys.length, after.keyring.keys.length + 2);
  assert.deepEqual(entry(latest, index), entry(after, index));
  assert.equal(entry(latest, indexKeyId).state, 'destroyed');
  assert.notEqual(again.indexKeyId, indexKeyId);
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
        passphrase: second, currentCollectionIds: [cases.ids.collection], historicalCollectionIds: [],
      }), { code: 'KDF' });
    }
    writeFileSync(path, vector('ring-p2.json'));
    for (const parallelism of [0, 1, 3]) {
      assert.throws(() => changePassphrase(path, vectorId, first, { passphrase: second, parallelism }), { code: 'KDF' });
      assert.throws(() => rekeyAll(path, vectorId, { passphrase: first }, {
        passphrase: second, parallelism, currentCollectionIds: [cases.ids.collection], historicalCollectionIds: [],
      }), { code: 'KDF' });
    }
    assert.throws(() => create(path, { passphrase: first, parallelism: 3 }), { code: 'KDF' });
    writeFileSync(path, vector(cases.changed_keyring));
    assert.throws(() => changePassphrase(path, vectorId, first, { passphrase: second }), { code: 'SCHEMA' });
    assert.throws(() => rekeyAll(path, vectorId, { passphrase: first }, {
      passphrase: second, currentCollectionIds: [cases.ids.collection], historicalCollectionIds: [],
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

test('rekey requires a full, disjoint partition and exactly one credential before scrypt', t => {
  const ring = JSON.parse(vector(cases.keyring));
  const { collection } = cases.ids;
  const another = 'fe'.repeat(16);
  ring.keys.push({ ...ring.keys.find(key => key.key_id === collection), key_id: another });
  ring.keys.sort((a, b) => a.key_id.localeCompare(b.key_id));
  const initial = Buffer.from(canonical(ring));
  const path = testPath(t, initial);
  const mockKdf = t.mock.method(crypto, 'scryptSync', () => assert.fail('scrypt must not run'));
  syncBuiltinESMExports();
  try {
    const credential = { passphrase: first };
    for (const [currentCollectionIds, historicalCollectionIds] of [
      [[collection], []],
      [[collection], [collection]],
      [[collection], ['ff'.repeat(16)]],
      [[collection, another], undefined],
    ]) {
      assert.throws(() => rekeyAll(path, vectorId, credential, {
        passphrase: second, currentCollectionIds, historicalCollectionIds,
      }), { code: 'KEY' });
    }
    assert.throws(() => rekeyAll(path, vectorId, { ...credential, recoveryKey: vectorText }, {
      passphrase: second, currentCollectionIds: [collection], historicalCollectionIds: [another],
    }), { code: 'KEY' });
    assert.throws(() => decodeKeyring(initial, { ...credential, recoveryKey: vectorRecovery }, vectorId), { code: 'KEY' });
    assert.equal(mockKdf.mock.callCount(), 0);
    assert.deepEqual(readFileSync(path), initial);
  } finally {
    mockKdf.mock.restore();
    syncBuiltinESMExports();
  }
});

test('a throwing rekey handoff leaves the original bytes and clears borrowed keys', t => {
  const initial = vector(cases.keyring);
  const path = testPath(t, initial);
  const failure = new Error('TEST ONLY staging failure');
  let handoff;
  const mockKdf = t.mock.method(crypto, 'scryptSync');
  syncBuiltinESMExports();
  try {
    assert.throws(() => rekeyAll(path, vectorId, { passphrase: cases.passphrase }, {
      passphrase: second, currentCollectionIds: [cases.ids.collection], historicalCollectionIds: [],
      beforePublish(value) {
        handoff = value;
        throw failure;
      },
    }), error => error === failure);
    assert.equal(mockKdf.mock.callCount(), 2);
    assert.deepEqual(handoff.oldTombstoneKey, Buffer.alloc(32));
    assert.deepEqual(handoff.newTombstoneKey, Buffer.alloc(32));
    assert.deepEqual(readFileSync(path), initial);
    assert.deepEqual(pendingFiles(path), []);
  } finally {
    mockKdf.mock.restore();
    syncBuiltinESMExports();
  }
});

test('a decoded invalid profile label clears the master, unwrapped keys and temporary buffers', t => {
  const initial = vector(cases.keyring);
  const original = decodeKeyring(initial, { recoveryKey: vectorRecovery }, vectorId);
  const { mac: _mac, ...body } = original.keyring;
  const profile = body.keys.find(key => key.kind === 'profile');
  const salt = Buffer.from(vectorId, 'hex');
  const invalidText = Buffer.from([0xff]);
  const nonce = Buffer.alloc(12, 0xd1);
  profile.label_enc = Buffer.concat([nonce, seal(derive(original.masterKey, 'profile-label', salt), nonce,
    Buffer.from(canonical([body.format, vectorId, profile.key_id, 'profile-label', profile.parent, null])),
    invalidText)]).toString('base64');
  const mac = crypto.createHmac('sha256', derive(original.masterKey, 'keyring-mac', salt))
    .update(canonical(body)).digest('base64');
  const tampered = Buffer.from(canonical({ ...body, mac }));
  const decryptions = t.mock.method(Buffer, 'concat');
  const derivations = t.mock.method(crypto, 'hkdfSync');
  syncBuiltinESMExports();
  try {
    assert.throws(() => decodeKeyring(tampered, { recoveryKey: vectorRecovery }, vectorId), { code: 'SCHEMA' });
    const plaintext = decryptions.mock.calls.map(call => call.result);
    assert.ok(plaintext.filter(bytes => bytes.length === 32).length >= 2);
    assert.equal(plaintext.at(-1).length, invalidText.length);
    for (const bytes of plaintext) assert.deepEqual(bytes, Buffer.alloc(bytes.length));
    assert.deepEqual(derivations.mock.calls.map(call => call.arguments[3].toString()), [
      'foundry/recovery-wrap/v1', 'foundry/keyring-mac/v1', 'foundry/profile-label/v1',
    ]);
    for (const call of derivations.mock.calls) assert.deepEqual(Buffer.from(call.result), Buffer.alloc(32));
  } finally {
    decryptions.mock.restore();
    derivations.mock.restore();
    syncBuiltinESMExports();
  }
});

test('printed recovery text rejects version, grouping, and checksum mistakes', () => {
  assert.deepEqual(decodeRecoveryKey(vectorText), vectorRecovery);
  assert.throws(() => decodeRecoveryKey('2' + vectorText.slice(1)), /format/u);
  assert.throws(() => decodeRecoveryKey(vectorText.replace('-', '')), /format/u);
  const wrong = vectorText.slice(0, -1) + (vectorText.endsWith('A') ? 'B' : 'A');
  assert.throws(() => decodeRecoveryKey(wrong), /checksum/u);
  assert.throws(() => formatRecoveryKey(Buffer.alloc(31)), { code: 'KEY' });
  assert.throws(() => formatRecoveryKey(Buffer.alloc(33)), { code: 'KEY' });

  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const payload = vectorText.replaceAll('-', '').slice(1, 53);
  const withPadding = payload.slice(0, -1) + alphabet[alphabet.indexOf(payload.at(-1)) | 1];
  const hash = crypto.createHash('sha256').update('1' + withPadding).digest();
  const top20 = (hash[0] << 12) | (hash[1] << 4) | (hash[2] >> 4);
  const checksum = [15, 10, 5, 0].map(shift => alphabet[(top20 >> shift) & 31]).join('');
  const nonCanonical = '1-' + (withPadding + checksum).match(/.{4}/gu).join('-');
  assert.throws(() => decodeRecoveryKey(nonCanonical), /padding/u);
});

function pendingFiles(path) {
  return fs.readdirSync(dirname(path)).filter(name => name.startsWith(basename(path) + '.pending-'));
}

function startWriter(t, path, mode, ready) {
  const child = fork(fileURLToPath(new URL('./keyring-writer.mjs', import.meta.url)), [path, mode], {
    execArgv: [], windowsHide: true,
  });
  const messages = [];
  child.on('message', message => messages.push(message));
  const exited = once(child, 'exit');
  const waiting = new Promise((resolve, reject) => {
    function onMessage(message) {
      if (message === ready) {
        child.off('message', onMessage);
        resolve();
      }
    }
    child.on('message', onMessage);
    exited.then(([code, signal]) => reject(new Error('Writer exited before readiness (' + (signal ?? code) + ').')), reject);
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await exited;
  });
  return { child, messages, exited, waiting };
}

test('a killed lock holder leaves the old keyring readable and the next writer recovers', { timeout: 15_000 }, async t => {
  const initial = vector(cases.keyring);
  const next = vector(cases.changed_keyring);
  const path = testPath(t, initial);
  const writer = startWriter(t, path, 'hold', 'temp-synced');
  await writer.waiting;
  assert.equal(pendingFiles(path).length, 1);
  if (process.platform === 'win32') {
    const killed = spawnSync('taskkill.exe', ['/F', '/PID', String(writer.child.pid)], { windowsHide: true, timeout: 5000 });
    assert.ifError(killed.error);
    // Restricted runners may forbid taskkill from opening the PID. The parent already holds its process handle.
    if (killed.status !== 0) assert.ok(writer.child.kill('SIGKILL'), killed.stderr.toString());
  } else {
    assert.ok(writer.child.kill('SIGKILL'));
  }
  assert.notDeepEqual(await writer.exited, [0, null]);
  assert.equal(pendingFiles(path).length, 1);
  assert.deepEqual(readFileSync(path), initial);
  assert.equal(unlockByRecovery(path, vectorId, vectorText).keyring.version, JSON.parse(initial).version);
  const unrelated = join(dirname(path), 'different.json.pending-' + 'ab'.repeat(16));
  const similar = path + '.pending-keep';
  writeFileSync(unrelated, '');
  writeFileSync(similar, '');
  publishKeyring(path, next, initial);
  assert.deepEqual(readFileSync(path), next);
  assert.deepEqual(pendingFiles(path), [basename(similar)]);
  assert.ok(fs.existsSync(unrelated));
});

test('concurrent writers serialize and the loser rejects its stale input', { timeout: 15_000 }, async t => {
  const initial = vector(cases.keyring);
  const next = vector(cases.changed_keyring);
  const path = testPath(t, initial);
  const firstWriter = startWriter(t, path, 'hold', 'temp-synced');
  await firstWriter.waiting;
  const laterWriter = startWriter(t, path, 'compete', 'attempting');
  await laterWriter.waiting;
  writeFileSync(path + '.release', '');
  assert.deepEqual(await firstWriter.exited, [0, null]);
  assert.deepEqual(await laterWriter.exited, [0, null]);
  assert.deepEqual(firstWriter.messages, ['attempting', 'temp-synced', 'published']);
  assert.deepEqual(laterWriter.messages, ['attempting', 'stale']);
  assert.deepEqual(readFileSync(path), next);
  assert.deepEqual(pendingFiles(path), []);
});

test('POSIX syncs and closes the temp file, then renames and syncs its parent directory',
  { skip: process.platform === 'win32' }, t => {
    const initial = vector(cases.keyring);
    const path = testPath(t, initial);
    const event = [];
    const mocks = ['openSync', 'writeFileSync', 'fsyncSync', 'closeSync', 'renameSync'].map(name => {
      const real = fs[name];
      return t.mock.method(fs, name, (...args) => {
        const result = real(...args);
        event.push({ name, args, result });
        return result;
      });
    });
    syncBuiltinESMExports();
    try {
      publishKeyring(path, vector(cases.changed_keyring), initial);
    } finally {
      mocks.forEach(mock => mock.mock.restore());
      syncBuiltinESMExports();
    }
    const start = event.findIndex(call => call.name === 'openSync' && call.args[1] === 'wx');
    const calls = event.slice(start);
    assert.deepEqual(calls.map(call => call.name), [
      'openSync', 'writeFileSync', 'fsyncSync', 'closeSync', 'renameSync', 'openSync', 'fsyncSync', 'closeSync',
    ]);
    const temp = calls[0];
    const directory = calls[5];
    for (const call of calls.slice(1, 4)) assert.equal(call.args[0], temp.result);
    assert.deepEqual(calls[4].args, [temp.args[0], path]);
    assert.deepEqual(directory.args, [dirname(path), 'r']);
    for (const call of calls.slice(6)) assert.equal(call.args[0], directory.result);
  });

test('temp cleanup preserves the primary write error', t => {
  const initial = vector(cases.keyring);
  const path = testPath(t, initial);
  const failure = new Error('TEST ONLY write failure');
  const write = t.mock.method(fs, 'writeFileSync', () => { throw failure; });
  const closeSync = fs.closeSync;
  const close = t.mock.method(fs, 'closeSync', fd => {
    const isTemp = fs.fstatSync(fd).size === 0;
    closeSync(fd);
    if (isTemp) throw new Error('TEST ONLY close failure');
  });
  const unlink = t.mock.method(fs, 'unlinkSync', () => { throw new Error('TEST ONLY cleanup failure'); });
  syncBuiltinESMExports();
  try {
    assert.throws(() => publishKeyring(path, vector(cases.changed_keyring), initial), error => error === failure);
    assert.equal(unlink.mock.callCount(), 1);
    assert.deepEqual(readFileSync(path), initial);
  } finally {
    write.mock.restore();
    close.mock.restore();
    unlink.mock.restore();
    syncBuiltinESMExports();
  }
});

test('Windows retries a transient sharing violation', { skip: process.platform !== 'win32' }, t => {
  const initial = vector(cases.keyring);
  const next = vector(cases.changed_keyring);
  const path = testPath(t, initial);
  const rename = fs.renameSync;
  let attempts = 0;
  const wait = t.mock.method(Atomics, 'wait', () => 'timed-out');
  const mockRename = t.mock.method(fs, 'renameSync', (from, to) => {
    if (++attempts <= 9) throw Object.assign(new Error('TEST ONLY sharing violation'), { code: 'EPERM' });
    return rename(from, to);
  });
  syncBuiltinESMExports();
  try {
    publishKeyring(path, next, initial);
    assert.equal(attempts, 10);
    const delays = wait.mock.calls.map(call => call.arguments[3]);
    assert.ok(delays.slice(1).every((delay, index) => delay >= delays[index]));
    const retryBudget = delays.reduce((total, delay) => total + delay, 0);
    assert.ok(retryBudget >= 1750 && retryBudget <= 2250);
    assert.deepEqual(readFileSync(path), next);
  } finally {
    mockRename.mock.restore();
    syncBuiltinESMExports();
  }
});

test('the input guard inspects parsed options, declared positionals and scoped environment names', () => {
  const parsed = args => parseArgs({
    args, strict: false, tokens: true, options: { all: { type: 'boolean' }, vault: { type: 'string' } },
  });
  const cliError = /Unexpected command-line arguments/u;
  for (const name of ['passphrase', 'password', 'recovery-key', 'secret']) {
    for (const args of [['--' + name], ['--' + name, first], ['--' + name + '=' + first]]) {
      assert.throws(() => guardSecretInput(parsed(args), {}, 1), cliError);
    }
  }
  assert.throws(() => guardSecretInput(parsed([first]), {}), cliError);
  assert.throws(() => guardSecretInput(parsed(['target', '--', first]), {}, 1), cliError);
  assert.doesNotThrow(() => guardSecretInput(parsed(['--all', '--vault', 'target']), {}));
  assert.doesNotThrow(() => guardSecretInput(parsed(['--all', 'target']), {}, 1));

  for (const name of [
    'FOUNDRY_PASS', 'FOUNDRY_PASSWD', 'FOUNDRY_PASSWORD', 'FOUNDRY_VAULT_PASSPHRASE', 'FOUNDRY_VAULT_SECRET',
    'FOUNDRY_MASTER_KEY', 'FOUNDRY_RECOVERY_KEY', 'FOUNDRY_TOKEN', 'VAULT_PASSWORD',
  ]) {
    assert.throws(() => guardSecretInput(parsed([]), { [name]: '' }), /Secret environment variables are refused/u);
  }
  assert.doesNotThrow(() => guardSecretInput(parsed([]), {
    FOUNDRY_PASSPHRASE: undefined, RESTIC_PASSWORD: first, BUILD_PASS: first, RECOVERY_MODE: first,
  }));
});

test('descriptor reads preserve UTF-8 across chunks, enforce the byte cap and clear all read buffers', t => {
  const path = testPath(t);
  const read = t.mock.method(fs, 'readSync');
  syncBuiltinESMExports();
  const boundary = 'x'.repeat(4095) + '\u{1f512}' + '\n' + 'y'.repeat(65536 - 4100);
  assert.equal(Buffer.byteLength(boundary), 65536);
  for (const [input, expected] of [
    [boundary, undefined],
    [boundary + 'z', /exceeds 64 KiB/u],
    [Buffer.from([0xff]), /valid UTF-8/u],
  ]) {
    writeFileSync(path, input);
    const fd = fs.openSync(path, 'r');
    read.mock.resetCalls();
    try {
      if (expected) assert.throws(() => readSecretFromFd(fd), expected);
      else assert.equal(readSecretFromFd(fd), boundary);
      const buffers = read.mock.calls.filter(call => call.arguments[0] === fd)
        .map(call => call.arguments[1]);
      assert.ok(buffers.length > 0);
      for (const buffer of buffers) assert.deepEqual(buffer, Buffer.alloc(buffer.length));
    } finally {
      fs.closeSync(fd);
    }
  }
  read.mock.restore();
  syncBuiltinESMExports();
});

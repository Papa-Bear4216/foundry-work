// V-7a (A-41): collection keys on demand. ensureCollectionKeys and collectionKeyId.
// TEST ONLY: every credential, key, vault ID and collection name in this file is synthetic.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { mkdtempDisposableSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { getKdfCallCountForTest, resetKdfCallCountForTest } from '../src/keyring.ts';
import { formatRecoveryKey } from '../src/recovery.ts';
import {
  collectionKeyId, create, decodeKeyring, decodeRecord, decodeRecoveryKey, encodeKeyring, encodeRecord,
  ensureCollectionKeys, rekeyAll, unlockVault,
} from '../src/index.ts';

const PASSPHRASE = 'TEST ONLY collection keys passphrase';
const UNUSED_PASSPHRASE = 'TEST ONLY unused passphrase (scrypt is mocked)';
const MARKER = 'foundry:collection-key-id-rule/v1';
const CREATED = '2026-11-22T00:00:00Z';

function testPath(t, initial) {
  const directory = mkdtempDisposableSync(join(tmpdir(), 'vault-collection-keys-'));
  t.after(() => directory.remove());
  const path = join(directory.path, 'KEYRING.json');
  if (initial) writeFileSync(path, initial);
  return path;
}

/** Run `action` with scrypt replaced by a constant (TEST ONLY), so building fixtures runs no real KDF. */
function withFakeKdf(t, action) {
  const mock = t.mock.method(crypto, 'scryptSync', () => Buffer.alloc(32, 0x5a));
  syncBuiltinESMExports();
  try {
    return action();
  } finally {
    mock.mock.restore();
    syncBuiltinESMExports();
  }
}

const newId = () => crypto.randomBytes(16).toString('hex');
const signing = () => ({ key_id: newId(), kind: 'signing', parent: 'master', state: 'active' });
const profile = (key_id, label) => ({ key_id, kind: 'profile', parent: 'master', state: 'active', label });
const collection = (key_id, parent) => ({ key_id, kind: 'collection', parent, state: 'active' });
const destroyed = (key_id, kind, parent) => ({ key_id, kind, parent, state: 'destroyed', destroyed_at: CREATED });

/** A keyring built with encodeKeyring (scrypt mocked). Unlock it with the recovery key or a session. */
function buildRing(t, entries, keys = {}) {
  const vaultId = keys.vaultId ?? newId();
  const masterKey = keys.masterKey ?? crypto.randomBytes(32);
  const recovery = crypto.randomBytes(32);
  const input = entries.map(entry => entry.state === 'destroyed' ? entry
    : { created_at: CREATED, key: crypto.randomBytes(32), ...entry });
  const bytes = withFakeKdf(t, () => encodeKeyring({ vaultId, version: 1, masterKey, entries: input }, UNUSED_PASSPHRASE,
    recovery));
  return { path: testPath(t, bytes), vaultId, masterKey, recovery, credential: { recoveryKey: recovery } };
}

/** The pinned A-41 rule, written out independently of the code under test. */
function expectedId(masterKey, vaultId, profileKeyId, name) {
  const nk = Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.from(vaultId, 'hex'),
    Buffer.from('foundry/collection-key-id/v1', 'ascii'), 32));
  const message = Buffer.concat([Buffer.from(profileKeyId, 'ascii'), Buffer.from([0x0a]), Buffer.from(name, 'utf8')]);
  return crypto.createHmac('sha256', nk).update(message).digest().subarray(0, 16).toString('hex');
}

const unlock = ({ path, vaultId, recovery }) => decodeKeyring(readFileSync(path), { recoveryKey: recovery }, vaultId);
const parse = path => JSON.parse(readFileSync(path, 'utf8'));
const entryOf = (unlocked, id) => unlocked.keyring.keys.find(entry => entry.key_id === id);

/** The call fails with `code` and the keyring file stays byte-identical. */
function assertFailsUnchanged(path, action, code, message) {
  const before = readFileSync(path);
  assert.throws(action, { code }, message);
  assert.deepEqual(readFileSync(path), before, message);
}

/** Same helper as keys.test.mjs; returns undefined when no Python interpreter can be started. */
function pythonUnlock(keyring, vaultId, passphrase, recoveryKey, collectionIds) {
  const script = fileURLToPath(new URL('../../reference/check_keyring.py', import.meta.url));
  const result = spawnSync(process.env.VAULT_TEST_PYTHON || 'python', ['-B', script], {
    input: JSON.stringify({
      keyring: keyring.toString('base64'), vaultId, passphrase,
      recovery: decodeRecoveryKey(recoveryKey).toString('hex'), collectionIds,
    }),
    encoding: 'utf8', timeout: 30_000,
  });
  if (result.error?.code === 'ENOENT') return undefined;
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('on a keyring made by create(): one profile "me", the marker and three collection keys in one publish', t => {
  const path = testPath(t);
  const { vaultId, recoveryKey } = create(path, { passphrase: PASSPHRASE });
  const names = ['google-takeout/mail/2024', 'google-takeout/contacts/undated', 'café/2023'];

  resetKdfCallCountForTest();
  const result = ensureCollectionKeys(path, vaultId, { passphrase: PASSPHRASE }, 'me', names);
  assert.equal(getKdfCallCountForTest(), 1, 'a passphrase credential runs the KDF once');
  assert.equal(result.created, 3, 'created counts requested names only');
  assert.deepEqual([...result.keyIds.keys()], names);

  const recovery = decodeRecoveryKey(recoveryKey);
  const unlocked = decodeKeyring(readFileSync(path), { recoveryKey: recovery }, vaultId);
  const P = result.profileKeyId;
  assert.deepEqual([...unlocked.labels], [[P, 'me']]);
  assert.equal(unlocked.keyring.version, 2, 'one version step');
  assert.equal(unlocked.keyring.keys.length, 6, 'signing + profile + marker + 3 collections');
  const markerId = expectedId(unlocked.masterKey, vaultId, P, MARKER);
  assert.deepEqual({ ...entryOf(unlocked, markerId), created_at: undefined, wrapped: undefined },
    { key_id: markerId, kind: 'collection', parent: P, state: 'active', created_at: undefined, wrapped: undefined });
  for (const name of names) {
    const id = result.keyIds.get(name);
    assert.equal(id, expectedId(unlocked.masterKey, vaultId, P, name), name);
    assert.equal(entryOf(unlocked, id).parent, P);
    assert.equal(collectionKeyId(unlocked, 'me', name), id);
    const key = unlocked.collectionEncryptionKey(id);
    const plaintext = Buffer.from('TEST ONLY record for ' + name);
    const record = encodeRecord({ type: 2, keyId: id, context: 0n }, plaintext, vaultId, key);
    assert.deepEqual(decodeRecord(record, vaultId, key).plaintext, plaintext);
  }
  // No Unicode normalisation: the decomposed spelling is a different name with a different ID.
  assert.notEqual(expectedId(unlocked.masterKey, vaultId, P, 'café/2023'), result.keyIds.get('café/2023'));
  assert.equal(collectionKeyId(unlocked, 'me', 'café/2023'), undefined);

  const ids = names.map(name => result.keyIds.get(name));
  const python = pythonUnlock(readFileSync(path), vaultId, PASSPHRASE, recoveryKey, ids);
  if (python === undefined) {
    t.diagnostic('Python is not available; the reference-reader check was skipped.');
  } else {
    assert.deepEqual(python, ids.map(id => unlocked.collectionEncryptionKey(id).toString('hex')));
  }
});

test('marker rule: collections without the marker fail KEY; a profile without collections gets its marker', t => {
  const P = newId();
  const legacy = buildRing(t, [signing(), profile(P, 'me'), collection(newId(), P)]);
  assertFailsUnchanged(legacy.path, () => ensureCollectionKeys(legacy.path, legacy.vaultId, legacy.credential, 'me',
    ['google-takeout/mail/2024']), 'KEY');
  assert.throws(() => collectionKeyId(unlock(legacy), 'me', 'google-takeout/mail/2024'), { code: 'KEY' });

  const fresh = buildRing(t, [signing(), profile(P, 'me')]);
  const result = ensureCollectionKeys(fresh.path, fresh.vaultId, fresh.credential, 'me', ['google-takeout/mail/2024']);
  assert.equal(result.profileKeyId, P, 'the existing profile is used');
  assert.equal(result.created, 1);
  const unlocked = unlock(fresh);
  assert.equal(unlocked.keyring.keys.length, 4);
  assert.equal(entryOf(unlocked, expectedId(fresh.masterKey, fresh.vaultId, P, MARKER)).state, 'active');
});

test('marker rule after rekeyAll: both functions fail KEY and the failed call leaves the keyring unchanged', t => {
  const ring = buildRing(t, [signing()]);
  const first = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', ['google-takeout/mail/2024']);
  const active = unlock(ring).keyring.keys.filter(entry => entry.kind === 'collection' && entry.state === 'active')
    .map(entry => entry.key_id);
  assert.equal(active.length, 2, 'the collection key and the marker');
  const { recoveryKey } = withFakeKdf(t, () => rekeyAll(ring.path, ring.vaultId,
    { recoveryKey: formatRecoveryKey(ring.recovery) },
    { passphrase: UNUSED_PASSPHRASE, currentCollectionIds: active, historicalCollectionIds: [] }));
  const credential = { recoveryKey: decodeRecoveryKey(recoveryKey) };
  for (const names of [['google-takeout/mail/2024'], ['google-takeout/mail/2025']]) {
    assertFailsUnchanged(ring.path, () => ensureCollectionKeys(ring.path, ring.vaultId, credential, 'me', names), 'KEY');
  }
  const after = decodeKeyring(readFileSync(ring.path), credential, ring.vaultId);
  assert.equal(entryOf(after, first.profileKeyId).kind, 'profile', 'rekeyAll keeps the profile key ID');
  assert.throws(() => collectionKeyId(after, 'me', 'google-takeout/mail/2024'), { code: 'KEY' });
});

test('erased-profile rule: a destroyed profile and no active "me" fail ERASED; an active "me" beside it works', t => {
  const D = newId();
  const erased = buildRing(t, [signing(), destroyed(D, 'profile', 'master')]);
  assertFailsUnchanged(erased.path, () => ensureCollectionKeys(erased.path, erased.vaultId, erased.credential, 'me',
    ['google-takeout/mail/2024']), 'ERASED');
  assert.throws(() => collectionKeyId(unlock(erased), 'me', 'google-takeout/mail/2024'), { code: 'ERASED' });

  const P = newId();
  const mixed = buildRing(t, [signing(), destroyed(D, 'profile', 'master'), profile(P, 'me')]);
  const result = ensureCollectionKeys(mixed.path, mixed.vaultId, mixed.credential, 'me', ['google-takeout/mail/2024']);
  assert.equal(result.profileKeyId, P);
  assert.equal(collectionKeyId(unlock(mixed), 'me', 'google-takeout/mail/2024'), result.keyIds.get('google-takeout/mail/2024'));
});

test('names with the reserved foundry: prefix fail KEY in both functions', t => {
  const ring = buildRing(t, [signing()]);
  const unlocked = unlock(ring);
  for (const name of ['foundry:x', MARKER]) {
    assertFailsUnchanged(ring.path, () => ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', [name]), 'KEY');
    assert.throws(() => collectionKeyId(unlocked, 'me', name), { code: 'KEY' });
  }
});

test('a repeated call writes nothing; one new name adds exactly one entry; unrelated parts stay byte-identical', t => {
  const Q = newId();
  const ring = buildRing(t, [
    signing(), profile(Q, 'other'), collection(newId(), Q), destroyed(newId(), 'collection', Q),
    { key_id: newId(), kind: 'index', parent: 'master', state: 'active' },
  ]);
  const original = parse(ring.path);
  const first = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', ['a/2024', 'b/2024', 'a/2024']);
  assert.equal(first.created, 2, 'duplicates count once');
  assert.equal(first.keyIds.size, 2);
  const afterFirst = readFileSync(ring.path);

  const again = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', ['b/2024', 'a/2024']);
  assert.deepEqual(readFileSync(ring.path), afterFirst, 'nothing to change: no write');
  assert.equal(again.created, 0);
  assert.equal(again.profileKeyId, first.profileKeyId);
  assert.deepEqual(new Map([...again.keyIds].sort()), new Map([...first.keyIds].sort()));

  const third = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', ['a/2024', 'c/2024']);
  assert.equal(third.created, 1);
  assert.equal(third.keyIds.get('a/2024'), first.keyIds.get('a/2024'));
  const before = JSON.parse(afterFirst.toString());
  const after = parse(ring.path);
  assert.equal(after.version, before.version + 1);
  assert.equal(after.keys.length, before.keys.length + 1);
  for (const ring2 of [before, after]) {
    assert.deepEqual(ring2.kdf, original.kdf);
    assert.deepEqual(ring2.master, original.master);
    for (const entry of original.keys) {
      assert.equal(JSON.stringify(ring2.keys.find(key => key.key_id === entry.key_id)), JSON.stringify(entry));
    }
  }
  for (const entry of before.keys) {
    assert.equal(JSON.stringify(after.keys.find(key => key.key_id === entry.key_id)), JSON.stringify(entry));
  }
});

test('KDF count: a session credential runs 0, a recovery credential runs 0', t => {
  const ring = buildRing(t, [signing()]);
  resetKdfCallCountForTest();
  ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', ['a/2024']);
  assert.equal(getKdfCallCountForTest(), 0, 'recovery');
  const session = unlockVault(ring.path, ring.vaultId, { recoveryKey: ring.recovery });
  try {
    const result = ensureCollectionKeys(ring.path, ring.vaultId, { session }, 'me', ['a/2024', 'b/2024']);
    assert.equal(result.created, 1);
    assert.equal(getKdfCallCountForTest(), 0, 'session');
  } finally {
    session.dispose();
  }
});

test('failures leave the keyring byte-identical', t => {
  const vaultId = newId();
  const masterKey = crypto.randomBytes(32);
  const P = newId();
  const Q = newId();
  const derived = name => expectedId(masterKey, vaultId, P, name);
  const ring = buildRing(t, [
    signing(), profile(P, 'me'), profile(Q, 'other'), collection(derived(MARKER), P),
    destroyed(derived('erased/2020'), 'collection', P),
    { key_id: derived('index/2021'), kind: 'index', parent: 'master', state: 'active' },
    collection(derived('elsewhere/2022'), Q),
  ], { vaultId, masterKey });
  const ensure = (names, credential = ring.credential, id = vaultId, label = 'me') =>
    () => ensureCollectionKeys(ring.path, id, credential, label, names);

  assertFailsUnchanged(ring.path, ensure(['a/2024'], ring.credential, newId()), 'KEY', 'wrong vault ID');
  assertFailsUnchanged(ring.path, ensure(['erased/2020']), 'ERASED', 'destroyed entry under a derived ID');
  assertFailsUnchanged(ring.path, ensure(['a/2024', 'erased/2020']), 'ERASED', 'one bad name stops the whole call');
  assertFailsUnchanged(ring.path, ensure(['index/2021']), 'KEY', 'another kind under a derived ID');
  assertFailsUnchanged(ring.path, ensure(['elsewhere/2022']), 'KEY', 'another parent under a derived ID');
  assertFailsUnchanged(ring.path, ensure(['index/2021', 'erased/2020']), 'KEY', 'per name in the order given');

  const session = unlockVault(ring.path, vaultId, { recoveryKey: ring.recovery });
  session.dispose();
  assertFailsUnchanged(ring.path, ensure(['a/2024'], { session }), 'KEY', 'disposed session');

  const invalid = ['', 'x'.repeat(513), 'é'.repeat(256) + 'x', '\ud800', 42, null, undefined];
  for (const value of invalid) {
    assertFailsUnchanged(ring.path, ensure([value]), 'KEY', `name ${JSON.stringify(value)}`);
    assertFailsUnchanged(ring.path, () => ensureCollectionKeys(ring.path, vaultId, ring.credential, value, ['a/2024']),
      'KEY', `label ${JSON.stringify(value)}`);
  }
  assertFailsUnchanged(ring.path, ensure('a/2024'), 'KEY', 'names must be an array');
  assertFailsUnchanged(ring.path, ensure([]), 'KEY', 'empty names');
  const many = Array.from({ length: 4097 }, (_, index) => `many/${index}`);
  assertFailsUnchanged(ring.path, ensure(many), 'KEY', 'more than 4,096 distinct names');
  // Accepted at the limits: 512 bytes of name.
  const longest = 'é'.repeat(256);
  assert.equal(ensureCollectionKeys(ring.path, vaultId, ring.credential, 'me', [longest]).created, 1);

  // Validation runs before any file read.
  assert.throws(() => ensureCollectionKeys(join(ring.path, '..', 'missing.json'), vaultId, ring.credential, 'me', ['']),
    { code: 'KEY' });

  const tampered = parse(ring.path);
  tampered.mac = Buffer.alloc(32, 1).toString('base64');
  writeFileSync(ring.path, JSON.stringify(tampered));
  assertFailsUnchanged(ring.path, ensure(['a/2024']), 'MAC', 'tampered MAC');

  const P2 = newId();
  const twice = buildRing(t, [signing(), profile(P, 'me'), profile(P2, 'me')]);
  assertFailsUnchanged(twice.path, () => ensureCollectionKeys(twice.path, twice.vaultId, twice.credential, 'me', ['a/2024']),
    'KEY', 'two active profiles with the same label');
  assert.throws(() => collectionKeyId(unlock(twice), 'me', 'a/2024'), { code: 'KEY' });
});

test('4,096 distinct names plus duplicates are within the limit and go into one publish', t => {
  const ring = buildRing(t, [signing()]);
  const names = Array.from({ length: 4096 }, (_, index) => `limit/${index}`);
  const result = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', [...names, ...names.slice(0, 10)]);
  assert.equal(result.created, 4096);
  assert.equal(result.keyIds.size, 4096);
  const after = parse(ring.path);
  assert.equal(after.version, 2);
  assert.equal(after.keys.length, 1 + 1 + 1 + 4096);
});

test('collectionKeyId: known ID, undefined for unknown name or profile, ERASED for a destroyed entry, no file read', t => {
  const vaultId = newId();
  const masterKey = crypto.randomBytes(32);
  const P = newId();
  const derived = name => expectedId(masterKey, vaultId, P, name);
  const ring = buildRing(t, [
    signing(), profile(P, 'me'), collection(derived(MARKER), P), collection(derived('known/2024'), P),
    destroyed(derived('erased/2020'), 'collection', P),
  ], { vaultId, masterKey });
  const unlocked = unlock(ring);
  rmSync(ring.path);
  assert.equal(collectionKeyId(unlocked, 'me', 'known/2024'), derived('known/2024'));
  assert.equal(collectionKeyId(unlocked, 'me', 'unknown/2024'), undefined);
  assert.equal(collectionKeyId(unlocked, 'nobody', 'known/2024'), undefined);
  assert.throws(() => collectionKeyId(unlocked, 'me', 'erased/2020'), { code: 'ERASED' });
  for (const value of ['', 'x'.repeat(513), '\ud800', 7]) {
    assert.throws(() => collectionKeyId(unlocked, 'me', value), { code: 'KEY' });
    assert.throws(() => collectionKeyId(unlocked, value, 'known/2024'), { code: 'KEY' });
  }
  assert.ok(unlocked.masterKey.some(byte => byte !== 0), 'the caller keeps its master key');
});

test('the same name under two profiles gives two IDs, and two names give two IDs', t => {
  const ring = buildRing(t, [signing()]);
  const me = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'me', ['x/2024', 'y/2024']);
  const work = ensureCollectionKeys(ring.path, ring.vaultId, ring.credential, 'work', ['x/2024']);
  assert.notEqual(me.profileKeyId, work.profileKeyId);
  assert.notEqual(me.keyIds.get('x/2024'), work.keyIds.get('x/2024'));
  assert.notEqual(me.keyIds.get('x/2024'), me.keyIds.get('y/2024'));
  const unlocked = unlock(ring);
  assert.deepEqual([...unlocked.labels.values()].sort(), ['me', 'work']);
  assert.equal(collectionKeyId(unlocked, 'work', 'x/2024'), work.keyIds.get('x/2024'));
  assert.equal(collectionKeyId(unlocked, 'work', 'y/2024'), undefined);
});

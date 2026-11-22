import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdirSync, mkdtempDisposableSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { canonical, derive } from '../src/bytes.ts';
import {
  decodeKeyring, encodeKeyring, openVaultReplay, rekeyAll, retireIndexKey, stageIndexKey,
  UnlockSession, unlockVault, VaultFormatError, VaultWriter,
} from '../src/index.ts';
import {
  getKdfCallCountForTest, isSessionMasterKeyZeroedForTest, resetKdfCallCountForTest,
} from '../src/keyring.ts';
import { blob, cases, event, fixture, identity, keyId, keyringPath, writable } from './vault-fixture.mjs';

// TEST ONLY: all credentials, keys and content are synthetic.
const recoveryKey = () => Buffer.from(cases.recovery_key, 'hex');

function setupVault(t, dirName = 'vault') {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-session-'));
  const directory = join(temp.path, dirName);
  mkdirSync(directory);
  const vector = fixture(directory);
  const path = keyringPath(directory);
  const vaultId = identity.vaultId;
  // Rewrite keyring to version 1 so stage/retire/rekey have version headroom.
  const entries = vector.keyring.keys.map(entry => entry.state === 'destroyed' ? entry : {
    ...entry, key: vector.keys.get(entry.key_id), label: vector.labels.get(entry.key_id),
  });
  const initialKeyring = encodeKeyring(
    { vaultId, version: 1, masterKey: vector.masterKey, entries },
    cases.passphrase,
    recoveryKey(),
  );
  writeFileSync(path, initialKeyring);
  const unlocked = decodeKeyring(initialKeyring, { recoveryKey: recoveryKey() }, vaultId);
  const writer = VaultWriter.open(directory, unlocked);
  try {
    writer.appendBatch([
      event('TEST ONLY sealed event'),
      blob('TEST ONLY sealed blob'),
    ]);
    writer.closeSegment();
    writer.appendBatch([
      event('TEST ONLY open event'),
      blob('TEST ONLY open blob'),
    ]);
  } finally {
    writer.release();
    unlocked.masterKey.fill(0);
    for (const k of unlocked.keys.values()) k.fill(0);
  }
  t.after(() => {
    writable(directory);
    temp.remove();
  });
  return { directory, path, vaultId, initialKeyring };
}

function consumeReplay(source) {
  const withdrawals = [...source.replay({ withdrawalsOnly: true })];
  const items = [];
  let skipped;
  const iter = source.replay();
  for (let next = iter.next(); ; next = iter.next()) {
    if (next.done) {
      skipped = next.value.skipped;
      break;
    }
    items.push(next.value);
  }
  const blobs = items.filter(item => item.type === 'blob').map(item => ({
    blobId: item.blobId,
    bytes: Buffer.concat([...source.streamBlob(item.location)]),
  }));
  return { boundary: source.boundary, skipped, withdrawals, items, blobs };
}

function nonIndexBytes(bytes) {
  const { keys, master, kdf } = JSON.parse(bytes);
  return [kdf, master, ...keys.filter(entry => entry.kind !== 'index')].map(value => Buffer.from(JSON.stringify(value)));
}

test('passphrase session runs exactly one scrypt KDF across decode, replay, stage, and retire with identical results', t => {
  const vault = setupVault(t, 'vault-equiv');
  const oldIndexId = cases.ids.index;
  const newIndexId = 'cc'.repeat(16);

  // 1) Session path: exactly ONE scrypt call across unlockVault + 4 operations.
  resetKdfCallCountForTest();
  const session = unlockVault(vault.path, vault.vaultId, { passphrase: cases.passphrase });
  assert.equal(getKdfCallCountForTest(), 1);
  assert.equal(session.vaultId, vault.vaultId);
  assert.equal(session.disposed, false);
  assert.equal(isSessionMasterKeyZeroedForTest(session), false);
  // Session object must not expose master key material as enumerable properties.
  assert.deepEqual(Object.keys(session), ['vaultId']);

  let sessionDecoded;
  let sessionMasterCopy;
  let sessionReplayData;
  let sessionStagedKey;
  let sessionEncKey;
  let sessionAfterBytes;
  try {
    sessionDecoded = decodeKeyring(readFileSync(vault.path), { session }, vault.vaultId);
    sessionEncKey = sessionDecoded.collectionEncryptionKey(keyId);
    // Clearing caller-owned decoded masterKey must not wipe the session's owned copy.
    sessionMasterCopy = Buffer.from(sessionDecoded.masterKey);
    sessionDecoded.masterKey.fill(0);
    assert.equal(isSessionMasterKeyZeroedForTest(session), false);

    const replay = openVaultReplay(vault.directory, { session });
    try {
      sessionReplayData = consumeReplay(replay);
    } finally {
      replay.close();
    }
    // replay.close() clears replay-owned keys; session must still work for stage + retire.
    sessionStagedKey = stageIndexKey(vault.path, vault.vaultId, { session }, newIndexId);
    assert.equal(sessionStagedKey.length, 32);
    // Retrying stage returns the same key with zero KDF calls.
    assert.deepEqual(stageIndexKey(vault.path, vault.vaultId, { session }, newIndexId), sessionStagedKey);
    // Decoding after stage sees the new key without re-running KDF.
    const afterStage = decodeKeyring(readFileSync(vault.path), { session }, vault.vaultId);
    assert.deepEqual(afterStage.masterKey, sessionMasterCopy);
    assert.deepEqual(afterStage.keys.get(newIndexId), sessionStagedKey);
    afterStage.masterKey.fill(0);

    retireIndexKey(vault.path, vault.vaultId, { session }, oldIndexId);
    sessionAfterBytes = readFileSync(vault.path);
    // Decoding after retire sees old key destroyed and new key active.
    const afterRetire = decodeKeyring(sessionAfterBytes, { session }, vault.vaultId);
    assert.equal(afterRetire.keyring.version, 3);
    assert.equal(afterRetire.keys.has(oldIndexId), false);
    assert.deepEqual(afterRetire.keys.get(newIndexId), sessionStagedKey);
    afterRetire.masterKey.fill(0);

    assert.equal(getKdfCallCountForTest(), 1);
  } finally {
    session.dispose();
  }
  assert.equal(session.disposed, true);
  assert.equal(isSessionMasterKeyZeroedForTest(session), true);

  // Updated session-written keyring is still readable with passphrase credential.
  const cred = { passphrase: cases.passphrase };
  const verified = decodeKeyring(sessionAfterBytes, cred, vault.vaultId);
  assert.equal(verified.keyring.version, 3);
  assert.deepEqual(verified.keys.get(newIndexId), sessionStagedKey);
  assert.equal(verified.keys.has(oldIndexId), false);
  verified.masterKey.fill(0);

  // 2) Restore initial keyring and run the exact same 4 operations with passphrase credential.
  writeFileSync(vault.path, vault.initialKeyring);
  resetKdfCallCountForTest();
  const credDecoded = decodeKeyring(readFileSync(vault.path), cred, vault.vaultId);
  const credEncKey = credDecoded.collectionEncryptionKey(keyId);
  const credReplay = openVaultReplay(vault.directory, cred);
  let credReplayData;
  try {
    credReplayData = consumeReplay(credReplay);
  } finally {
    credReplay.close();
  }
  const credStagedKey = stageIndexKey(vault.path, vault.vaultId, cred, newIndexId);
  retireIndexKey(vault.path, vault.vaultId, cred, oldIndexId);
  const credAfterBytes = readFileSync(vault.path);
  assert.equal(getKdfCallCountForTest(), 4);

  // Results match between session and credential forms.
  assert.deepEqual(sessionDecoded.keyring, credDecoded.keyring);
  assert.deepEqual(sessionMasterCopy, credDecoded.masterKey);
  assert.deepEqual(sessionDecoded.keys, credDecoded.keys);
  assert.deepEqual(sessionDecoded.labels, credDecoded.labels);
  assert.deepEqual(sessionDecoded.erased, credDecoded.erased);
  assert.deepEqual(sessionEncKey, credEncKey);
  assert.deepEqual(sessionReplayData, credReplayData);
  assert.deepEqual(nonIndexBytes(sessionAfterBytes), nonIndexBytes(vault.initialKeyring));
  assert.deepEqual(nonIndexBytes(credAfterBytes), nonIndexBytes(vault.initialKeyring));

  sessionMasterCopy.fill(0);
  credDecoded.masterKey.fill(0);
  sessionStagedKey.fill(0);
  credStagedKey.fill(0);
  sessionEncKey.fill(0);
  credEncKey.fill(0);
});

test('recovery-key session runs zero scrypt KDF calls and rekeyAll accepts a session', t => {
  const vault = setupVault(t);
  resetKdfCallCountForTest();
  const session = unlockVault(vault.path, vault.vaultId, { recoveryKey: recoveryKey() });
  try {
    const decoded = decodeKeyring(readFileSync(vault.path), { session }, vault.vaultId);
    decoded.masterKey.fill(0);
    const replay = openVaultReplay(vault.directory, { session });
    try {
      assert.equal(consumeReplay(replay).blobs.length, 2);
    } finally {
      replay.close();
    }
    const staged = stageIndexKey(vault.path, vault.vaultId, { session }, 'dd'.repeat(16));
    staged.fill(0);
    retireIndexKey(vault.path, vault.vaultId, { session }, cases.ids.index);
    assert.equal(getKdfCallCountForTest(), 0);

    // rekeyAll with { session } runs scrypt only once (for the replacement passphrase wrap).
    rekeyAll(vault.path, vault.vaultId, { session }, {
      passphrase: 'TEST ONLY rekeyed passphrase',
      currentCollectionIds: [keyId],
      historicalCollectionIds: [],
    });
    assert.equal(getKdfCallCountForTest(), 1);
  } finally {
    session.dispose();
  }
});

test('dispose zeroes key material and rejects every later use with KEY; forged and mixed credentials fail KEY', t => {
  const vault = setupVault(t);
  const session = unlockVault(vault.path, vault.vaultId, { recoveryKey: recoveryKey() });
  assert.equal(session.disposed, false);
  assert.equal(isSessionMasterKeyZeroedForTest(session), false);

  // Dispose twice (idempotent).
  session.dispose();
  session.dispose();
  assert.equal(session.disposed, true);
  assert.equal(isSessionMasterKeyZeroedForTest(session), true);

  const beforeBytes = readFileSync(vault.path);
  resetKdfCallCountForTest();
  assert.throws(() => decodeKeyring(beforeBytes, { session }, vault.vaultId),
    error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => openVaultReplay(vault.directory, { session }),
    error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => stageIndexKey(vault.path, vault.vaultId, { session }, 'ee'.repeat(16)),
    error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => retireIndexKey(vault.path, vault.vaultId, { session }, cases.ids.index),
    error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => rekeyAll(vault.path, vault.vaultId, { session }, {
    passphrase: 'TEST ONLY unused',
    currentCollectionIds: [keyId],
    historicalCollectionIds: [],
  }), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.deepEqual(readFileSync(vault.path), beforeBytes);
  assert.equal(getKdfCallCountForTest(), 0);

  // Forged session, direct constructor abuse, mixed credentials, and nested unlockVault fail KEY.
  const forged = { vaultId: vault.vaultId, disposed: false, dispose() {} };
  assert.throws(() => new UnlockSession(vault.vaultId, Buffer.alloc(32), Symbol('forged')), { code: 'KEY' });
  assert.throws(() => decodeKeyring(beforeBytes, { session: forged }, vault.vaultId), { code: 'KEY' });
  assert.throws(() => decodeKeyring(beforeBytes, { session: null }, vault.vaultId), { code: 'KEY' });
  assert.throws(() => decodeKeyring(beforeBytes, { passphrase: cases.passphrase, session }, vault.vaultId), { code: 'KEY' });
  assert.throws(() => unlockVault(vault.path, vault.vaultId, { session }), { code: 'KEY' });
  assert.throws(() => unlockVault(vault.path, '00'.repeat(16), { passphrase: cases.passphrase }), { code: 'KEY' });
  assert.equal(getKdfCallCountForTest(), 0);
});

test('wrong vaultId, rekeyed keyring, and tampered keyring fail KEY or AUTH with no write', t => {
  const vaultA = setupVault(t, 'vault-a');
  const vaultB = setupVault(t, 'vault-b');

  // Re-encode vault B with a distinct vault_id so session binding is exercised end-to-end.
  const otherVaultId = '77'.repeat(16);
  const ringB = decodeKeyring(vaultB.initialKeyring, { recoveryKey: recoveryKey() }, vaultB.vaultId);
  const entriesB = ringB.keyring.keys.map(entry => entry.state === 'destroyed' ? entry : {
    ...entry, key: ringB.keys.get(entry.key_id), label: ringB.labels.get(entry.key_id),
  });
  const otherKeyringBytes = encodeKeyring(
    { vaultId: otherVaultId, version: 1, masterKey: ringB.masterKey, entries: entriesB },
    cases.passphrase,
    recoveryKey(),
  );
  writeFileSync(vaultB.path, otherKeyringBytes);
  const metaB = JSON.parse(readFileSync(join(vaultB.directory, 'VAULT.json'), 'utf8'));
  writeFileSync(join(vaultB.directory, 'VAULT.json'), canonical({ ...metaB, vault_id: otherVaultId }));
  ringB.masterKey.fill(0);

  const sessionA = unlockVault(vaultA.path, vaultA.vaultId, { recoveryKey: recoveryKey() });
  try {
    resetKdfCallCountForTest();
    // 1) Wrong vaultId (session bound to vaultA used against vaultB).
    assert.throws(() => decodeKeyring(otherKeyringBytes, { session: sessionA }, otherVaultId), { code: 'KEY' });
    assert.throws(() => openVaultReplay(vaultB.directory, { session: sessionA }), { code: 'KEY' });
    assert.throws(() => stageIndexKey(vaultB.path, otherVaultId, { session: sessionA }, 'aa'.repeat(16)), { code: 'KEY' });
    assert.throws(() => retireIndexKey(vaultB.path, otherVaultId, { session: sessionA }, cases.ids.index), { code: 'KEY' });
    assert.deepEqual(readFileSync(vaultB.path), otherKeyringBytes);
    assert.equal(getKdfCallCountForTest(), 0);

    // 2) Rekeyed keyring (same vaultId, new master key via rekeyAll).
    rekeyAll(vaultA.path, vaultA.vaultId, { passphrase: cases.passphrase }, {
      passphrase: 'TEST ONLY post-rekey passphrase',
      currentCollectionIds: [keyId],
      historicalCollectionIds: [],
    });
    const rekeyedBytes = readFileSync(vaultA.path);
    resetKdfCallCountForTest();
    assert.throws(() => decodeKeyring(rekeyedBytes, { session: sessionA }, vaultA.vaultId), { code: 'KEY' });
    assert.throws(() => openVaultReplay(vaultA.directory, { session: sessionA }), { code: 'KEY' });
    assert.throws(() => stageIndexKey(vaultA.path, vaultA.vaultId, { session: sessionA }, 'bb'.repeat(16)), { code: 'KEY' });
    assert.throws(() => retireIndexKey(vaultA.path, vaultA.vaultId, { session: sessionA }, cases.ids.index), { code: 'KEY' });
    assert.deepEqual(readFileSync(vaultA.path), rekeyedBytes);
    assert.equal(getKdfCallCountForTest(), 0);
  } finally {
    sessionA.dispose();
  }

  // 3) Tampered keyring (flipped MAC byte and tampered wrapped key with recomputed MAC).
  const vaultC = setupVault(t, 'vault-c');
  const sessionC = unlockVault(vaultC.path, vaultC.vaultId, { recoveryKey: recoveryKey() });
  try {
    const parsed = JSON.parse(readFileSync(vaultC.path, 'utf8'));
    const badMac = Buffer.from(parsed.mac, 'base64');
    badMac[0] ^= 0xff;
    const tamperedMacBytes = Buffer.from(canonical({ ...parsed, mac: badMac.toString('base64') }));
    writeFileSync(vaultC.path, tamperedMacBytes);
    resetKdfCallCountForTest();
    assert.throws(() => decodeKeyring(tamperedMacBytes, { session: sessionC }, vaultC.vaultId), { code: 'KEY' });
    assert.throws(() => openVaultReplay(vaultC.directory, { session: sessionC }), { code: 'KEY' });
    assert.throws(() => stageIndexKey(vaultC.path, vaultC.vaultId, { session: sessionC }, '12'.repeat(16)), { code: 'KEY' });
    assert.throws(() => retireIndexKey(vaultC.path, vaultC.vaultId, { session: sessionC }, cases.ids.index), { code: 'KEY' });
    assert.deepEqual(readFileSync(vaultC.path), tamperedMacBytes);
    assert.equal(getKdfCallCountForTest(), 0);

    // Tampered wrapped entry under a valid MAC (re-MAC'd with same MK) -> AUTH, no write.
    const orig = decodeKeyring(vaultC.initialKeyring, { recoveryKey: recoveryKey() }, vaultC.vaultId);
    const badEntryRing = JSON.parse(vaultC.initialKeyring.toString('utf8'));
    const target = badEntryRing.keys.find(entry => entry.key_id === cases.ids.index);
    const wrapped = Buffer.from(target.wrapped, 'base64');
    wrapped[wrapped.length - 1] ^= 0x01;
    target.wrapped = wrapped.toString('base64');
    const { mac: _oldMac, ...body } = badEntryRing;
    const macKey = derive(orig.masterKey, 'keyring-mac', Buffer.from(vaultC.vaultId, 'hex'));
    const reMac = createHmac('sha256', macKey).update(Buffer.from(canonical(body))).digest('base64');
    macKey.fill(0);
    orig.masterKey.fill(0);
    const tamperedWrapBytes = Buffer.from(canonical({ ...body, mac: reMac }));
    writeFileSync(vaultC.path, tamperedWrapBytes);
    assert.throws(() => decodeKeyring(tamperedWrapBytes, { session: sessionC }, vaultC.vaultId), { code: 'AUTH' });
    assert.throws(() => openVaultReplay(vaultC.directory, { session: sessionC }), { code: 'AUTH' });
    assert.throws(() => stageIndexKey(vaultC.path, vaultC.vaultId, { session: sessionC }, cases.ids.index), { code: 'AUTH' });
    assert.deepEqual(readFileSync(vaultC.path), tamperedWrapBytes);
    assert.equal(getKdfCallCountForTest(), 0);
  } finally {
    sessionC.dispose();
  }
});

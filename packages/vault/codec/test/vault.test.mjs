import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdirSync, mkdtempDisposableSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  createVault, encodeKeyring, encodeRecord, FRAME_BYTES, readVaultRecord, rekeyAll, sha256, unlockByRecovery,
  VaultWriter, verifyVault, verifyVaultDeep,
} from '../src/index.ts';
import { formatRecoveryKey } from '../src/recovery.ts';
import { checkFrameSize, FRAME_OVERHEAD } from '../src/record.ts';
import { blob, cases, event, fixture, identity, keyId, keyringPath, unlockFixture, writable } from './vault-fixture.mjs';

function makeVault(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-vault-'));
  t.after(() => { writable(temp.path); temp.remove(); });
  return { directory: temp.path, unlocked: fixture(temp.path) };
}

function withWriter(directory, unlocked, work) {
  const writer = VaultWriter.open(directory, unlocked);
  try {
    return work(writer);
  } finally {
    writer.release();
  }
}

const segment = (directory, number) => join(directory, 'segments', String(number).padStart(6, '0'));
const contents = result => result.plaintext.toString();
const cli = fileURLToPath(new URL('./vault-verify.mjs', import.meta.url));

test('new vault takes its identity and fixed signing key from V-2', () => {
  using temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-new-vault-'));
  const directory = join(temp.path, 'vault');
  const created = createVault(directory, { passphrase: 'TEST ONLY new vault passphrase' });
  const unlocked = unlockByRecovery(keyringPath(directory), created.vaultId, created.recoveryKey);
  assert.equal(verifyVault(directory).vault.vault_id, created.vaultId);
  assert.equal(withWriter(directory, unlocked, writer => writer.closeSegment()).segment, 0);
  assert.throws(() => createVault(directory, { passphrase: 'TEST ONLY another passphrase' }), { code: 'INVENTORY' });
});

test('append, read, seal, deduplicate, continue through an event-free segment, and read with Python', t => {
  const { directory, unlocked } = makeVault(t);
  const payload = 'TEST ONLY synthetic blob';
  const [first, stored, same, empty] = withWriter(directory, unlocked, writer => {
    const appended = writer.appendBatch([event('TEST ONLY first'), blob(payload), blob(payload), blob('')]);
    assert.equal(verifyVault(directory).open.lastEventSequence, 1);
    assert.equal(contents(readVaultRecord(directory, appended[1].location, unlocked)), payload);
    assert.equal(writer.closeSegment().segment, 1);
    return appended;
  });
  assert.equal(first.sequence, 1);
  assert.equal(stored.duplicate, false);
  assert.deepEqual(same, { ...stored, duplicate: true });
  assert.equal(stored.id.length, 64);
  assert.equal(readVaultRecord(directory, empty.location, unlocked).plaintext.length, 0);
  assert.equal(contents(readVaultRecord(directory, stored.location, unlocked)), payload);
  assert.equal(statSync(join(segment(directory, 1), 'MANIFEST.sig')).mode & 0o222, 0);

  const genesis = verifyVault(directory).position;
  const anchor = {
    epoch: 1, vaultId: identity.vaultId, manifestHash: genesis.hash, segment: genesis.segment,
    signingKeyFingerprint: sha256(identity.signingPublicKey),
  };
  assert.throws(() => verifyVault(directory, { anchor: { ...anchor, segment: 2 } }), { code: 'ANCHOR' });
  const [secondBlob, secondEvent] = withWriter(directory, unlockFixture(directory), writer => {
    assert.deepEqual(writer.appendBatch([blob(payload)])[0], { ...stored, duplicate: true });
    const [onlyBlob] = writer.appendBatch([blob('TEST ONLY segment two')]);
    assert.equal(writer.closeSegment().lastEventSequence, 1);
    const [nextEvent] = writer.appendBatch([event('TEST ONLY final')]);
    assert.equal(writer.closeSegment().segment, 3);
    return [onlyBlob, nextEvent];
  });
  const verified = verifyVaultDeep(directory, unlocked, { anchor });
  assert.equal(verified.position.lastEventSequence, 2);
  assert.deepEqual(verified.position, verifyVault(directory, { anchor }).position);
  const path = fileURLToPath(new URL('../../reference/check_vault.py', import.meta.url));
  const python = spawnSync(process.env.VAULT_TEST_PYTHON ?? 'python', ['-B', path, directory], {
    input: cases.recovery_key, encoding: 'utf8', timeout: 30_000,
  });
  assert.ifError(python.error);
  assert.equal(python.status, 0, python.stderr);
  const crossCheck = JSON.parse(python.stdout);
  const { segment: number, hash, lastEventSequence } = verified.position;
  assert.deepEqual(crossCheck.position, [number, hash, lastEventSequence]);
  assert.deepEqual(crossCheck.records, [first, stored, empty, secondBlob, secondEvent].map(
    result => readVaultRecord(directory, result.location, unlocked).plaintext.toString('hex'),
  ));

  const deep = spawnSync(process.execPath, [cli, '--deep', directory], {
    input: cases.passphrase, encoding: 'utf8', timeout: 30_000,
  });
  assert.ifError(deep.error);
  assert.equal(deep.status, 0, deep.stderr);
  assert.deepEqual(JSON.parse(deep.stdout).position, verified.position);
  unlinkSync(keyringPath(directory));
  const shallow = spawnSync(process.execPath, [cli, directory], { encoding: 'utf8', timeout: 30_000 });
  assert.ifError(shallow.error);
  assert.equal(shallow.status, 0, shallow.stderr);
  assert.deepEqual(JSON.parse(shallow.stdout).position, verified.position);
});

test('rekey keeps sealed history readable and scopes blob deduplication to a collection key', t => {
  const { directory, unlocked } = makeVault(t);
  const item = blob('TEST ONLY duplicated content across collections');
  const old = withWriter(directory, unlocked, writer => {
    const [stored] = writer.appendBatch([item]);
    writer.closeSegment();
    return stored;
  });
  const { recoveryKey, collectionIds } = rekeyAll(keyringPath(directory), identity.vaultId, {
    recoveryKey: formatRecoveryKey(Buffer.from(cases.recovery_key, 'hex')),
  }, { passphrase: 'TEST ONLY rotate the vault', currentCollectionIds: [keyId], historicalCollectionIds: [] });
  const rotated = unlockByRecovery(keyringPath(directory), identity.vaultId, recoveryKey);
  const [next, duplicate] = withWriter(directory, rotated, writer => {
    const newItem = { ...item, keyId: collectionIds.get(keyId) };
    const results = writer.appendBatch([newItem, newItem]);
    writer.closeSegment();
    return results;
  });
  assert.notEqual(old.id, next.id);
  assert.equal(next.duplicate, false);
  assert.deepEqual(duplicate, { ...next, duplicate: true });
  assert.equal(verifyVaultDeep(directory, rotated).position.segment, 2);
});

test('blob candidate indexing visits each sealed blob header once per writer session', t => {
  const { directory, unlocked } = makeVault(t);
  const sealed = blob('TEST ONLY sealed blob');
  withWriter(directory, unlocked, writer => {
    writer.appendBatch([sealed, blob('TEST ONLY sealed peer')]);
    writer.closeSegment();
    writer.appendBatch([blob('TEST ONLY next segment')]);
    writer.closeSegment();
    writer.appendBatch([blob('TEST ONLY recovered open')]);
  });
  let headers = 0;
  const writer = VaultWriter.open(directory, unlocked, { onSealedBlobHeader: () => { headers++; } });
  try {
    assert.equal(headers, 3);
    assert.equal(writer.appendBatch([blob('TEST ONLY recovered open')])[0].duplicate, true);
    for (let index = 0; index < 8; index++) {
      const item = blob(`TEST ONLY new blob ${index}`);
      const [stored, duplicate, fromSealed] = writer.appendBatch([item, item, sealed]);
      assert.equal(stored.duplicate, false);
      assert.deepEqual(duplicate, { ...stored, duplicate: true });
      assert.equal(fromSealed.location.segment, 1);
    }
    writer.closeSegment();
    assert.equal(writer.appendBatch([blob('TEST ONLY new blob 0')])[0].location.segment, 3);
    assert.equal(headers, 3);
  } finally {
    writer.release();
  }
});

// Re-encode a synthetic keyring so both the active and destroyed states are MAC-verified.
function setCollectionState(directory, unlocked, destroyed) {
  const collection = cases.ids.erased;
  const date = identity.createdAt;
  const entries = unlocked.keyring.keys.map(({ key_id, kind, parent, state, created_at, destroyed_at }) => {
    const entry = { key_id, kind, parent };
    if (key_id === collection) {
      return destroyed ? { ...entry, state: 'destroyed', destroyed_at: date }
        : { ...entry, state: 'active', created_at: date, key: Buffer.alloc(32, 0x42) };
    }
    if (state === 'destroyed') return { ...entry, state, destroyed_at };
    return { ...entry, state, created_at, key: unlocked.keys.get(key_id), label: unlocked.labels.get(key_id) };
  });
  writeFileSync(keyringPath(directory), encodeKeyring({
    vaultId: identity.vaultId, masterKey: unlocked.masterKey, version: destroyed ? 2 : 1, entries,
  }, cases.passphrase, Buffer.from(cases.recovery_key, 'hex')));
  return unlockFixture(directory);
}

test('deep verification reports erased counts only after checking later integrity and authentication', t => {
  const { directory, unlocked } = makeVault(t);
  const active = setCollectionState(directory, unlocked, false);
  const destroyedId = cases.ids.erased;
  const erasedLocation = withWriter(directory, active, writer => {
    const [stored] = writer.appendBatch([{ ...event('TEST ONLY erased'), keyId: destroyedId }]);
    writer.closeSegment();
    writer.appendBatch([event('TEST ONLY later active')]);
    writer.closeSegment();
    writer.appendBatch([{ ...blob('TEST ONLY erased open'), keyId: destroyedId }, event('TEST ONLY active open')]);
    return stored.location;
  });
  const erased = setCollectionState(directory, active, true);
  assert.throws(() => verifyVaultDeep(directory, erased), { code: 'ERASED', message: 'ERASED: 2 record(s)' });
  assert.throws(() => readVaultRecord(directory, erasedLocation, erased), { code: 'ERASED' });
  writable(directory);
  for (const [path, offset, code] of [
    [join(segment(directory, 1), 'events-0001.fvr'), 75, 'FILE_HASH'],
    [join(segment(directory, 2), 'events-0001.fvr'), 75, 'AUTH'],
    [join(segment(directory, 2), 'MANIFEST.sig'), 0, 'SIGNATURE'],
    [join(directory, 'HEAD.json'), 21, 'HEAD'],
    [join(directory, 'open', 'events-0001.fvr'), 75, 'AUTH'],
  ]) {
    flip(path, offset);
    assert.throws(() => verifyVaultDeep(directory, erased), { code });
    flip(path, offset);
  }
});

test('an open record survives destroyed-key recovery and is listed in the sealed manifest', t => {
  const { directory, unlocked } = makeVault(t);
  const active = setCollectionState(directory, unlocked, false);
  const destroyedId = cases.ids.erased;
  withWriter(directory, active, writer => {
    writer.appendBatch([{ ...event('TEST ONLY erased before seal'), keyId: destroyedId }, event('TEST ONLY active')]);
  });
  const erased = setCollectionState(directory, active, true);
  withWriter(directory, erased, writer => {
    assert.deepEqual(writer.repairs, []);
    assert.equal(writer.closeSegment().lastEventSequence, 2);
  });
  const manifest = JSON.parse(readFileSync(join(segment(directory, 1), 'MANIFEST.json')));
  assert.ok(manifest.key_ids.includes(destroyedId));
  assert.equal(verifyVault(directory).position.segment, 1);
  assert.throws(() => verifyVaultDeep(directory, erased), { code: 'ERASED', message: 'ERASED: 1 record(s)' });
});

test('a full non-final frame must leave room for a nonempty final frame', () => {
  const full = FRAME_BYTES + FRAME_OVERHEAD;
  for (let tail = 1; tail <= FRAME_OVERHEAD; tail++) {
    assert.throws(() => checkFrameSize(FRAME_BYTES, full + tail, 2, true), { code: 'LENGTH' });
  }
  checkFrameSize(FRAME_BYTES, full, 2, true);
  checkFrameSize(FRAME_BYTES, full + FRAME_OVERHEAD + 1, 2, true);
});

test('truncates and reports only a physically short open tail', async t => {
  for (const length of [0, 1, 68, 69, 91]) {
    await t.test(`short record at ${length} bytes`, inner => {
      const { directory, unlocked } = makeVault(inner);
      const [first] = withWriter(directory, unlocked, writer => writer.appendBatch([event('TEST ONLY intact')]));
      const path = join(directory, 'open', first.location.stream);
      const existing = readFileSync(path);
      const key = unlocked.collectionEncryptionKey(keyId);
      const tail = encodeRecord({ type: 1, keyId, context: 2n }, Buffer.from('{"seq":2,"body":"TEST ONLY incomplete"}'),
        identity.vaultId, key);
      key.fill(0);
      if (length === 0) {
        writeFileSync(join(directory, 'open', 'events-0002.fvr'), '');
      } else {
        writeFileSync(path, Buffer.concat([existing, tail.subarray(0, length)]));
      }
      assert.throws(() => verifyVault(directory), { code: 'LENGTH' });
      withWriter(directory, unlocked, writer => {
        assert.deepEqual(writer.repairs, [{
          stream: length ? first.location.stream : 'events-0002.fvr',
          offset: length ? existing.length : 0,
          removedBytes: length,
        }]);
        assert.deepEqual(readFileSync(path), existing);
        assert.equal(writer.appendBatch([event('TEST ONLY recovered')])[0].sequence, 2);
        writer.closeSegment();
      });
      assert.equal(verifyVaultDeep(directory, unlocked).position.lastEventSequence, 2);
    });
  }
});

test('recovers a short tail in each stream type after an interrupted mixed batch', t => {
  const { directory, unlocked } = makeVault(t);
  const entries = withWriter(directory, unlocked, writer => writer.appendBatch([
    event('TEST ONLY durable event'), blob('TEST ONLY durable blob'),
  ]));
  const key = unlocked.collectionEncryptionKey(keyId);
  const tails = [
    encodeRecord({ type: 1, keyId, context: 2n }, Buffer.from('{"seq":2}'), identity.vaultId, key),
    encodeRecord({ type: 2, keyId, context: 0n }, Buffer.from('TEST ONLY partial blob'), identity.vaultId, key),
  ];
  key.fill(0);
  const repairs = entries.map(({ location: { stream } }, index) => {
    const path = join(directory, 'open', stream);
    const intact = readFileSync(path);
    const short = tails[index].subarray(0, -1);
    writeFileSync(path, Buffer.concat([intact, short]));
    return { stream, offset: intact.length, removedBytes: short.length };
  });
  assert.throws(() => verifyVault(directory), { code: 'LENGTH' });
  withWriter(directory, unlocked, writer => {
    assert.deepEqual(writer.repairs, repairs);
    assert.equal(writer.appendBatch([event('TEST ONLY resumed')])[0].sequence, 2);
    writer.closeSegment();
  });
  assert.equal(verifyVaultDeep(directory, unlocked).position.lastEventSequence, 2);
});

function flip(path, offset) {
  const bytes = readFileSync(path);
  bytes[offset] ^= 1;
  writeFileSync(path, bytes);
}

const tamper = [
  ['flipped record bit', 'FILE_HASH', ({ events }) => flip(events, 75)],
  ['flipped manifest bit', 'SIGNATURE', ({ first }) => {
    const path = join(first, 'MANIFEST.json');
    flip(path, readFileSync(path).indexOf('foundry 0.1.0') + 10);
  }],
  ['flipped HEAD bit', 'HEAD', ({ directory }) => flip(join(directory, 'HEAD.json'), 21)],
  ['removed file', 'INVENTORY', ({ events }) => unlinkSync(events)],
  ['reordered records', 'SEQUENCE', ({ events }) => {
    const bytes = readFileSync(events);
    const next = 69 + Number(bytes.readBigUInt64BE(61));
    writeFileSync(events, Buffer.concat([bytes.subarray(next), bytes.subarray(0, next)]));
  }],
  ['swapped manifests', 'CHAIN', ({ first, second }) => {
    for (const name of ['MANIFEST.json', 'MANIFEST.sig']) {
      const a = join(first, name);
      const b = join(second, name);
      const earlier = readFileSync(a);
      writeFileSync(a, readFileSync(b));
      writeFileSync(b, earlier);
    }
  }],
  ['replayed same-size blob record', 'FILE_HASH', ({ first, second }) => {
    writeFileSync(join(second, 'pack-0001.fvr'), readFileSync(join(first, 'pack-0001.fvr')));
  }],
  ['truncated segment', 'FILE_SIZE', ({ events }) => writeFileSync(events, readFileSync(events).subarray(0, -1))],
  ['extra file', 'INVENTORY', ({ first }) => writeFileSync(join(first, 'pack-9999.fvr'), 'TEST ONLY extra')],
  ['extra file at the vault root', 'INVENTORY', ({ directory }) => writeFileSync(join(directory, 'extra'), 'TEST ONLY extra')],
  ['removed segment', 'CHAIN', ({ directory, first }) => renameSync(first, join(directory, 'keyring', 'removed'))],
];

test('tamper gate rejects changes to the authenticated inventory, chain, and HEAD', async t => {
  for (const [label, code, change] of tamper) {
    await t.test(label, inner => {
      const { directory, unlocked } = makeVault(inner);
      withWriter(directory, unlocked, writer => {
        writer.appendBatch([event('TEST ONLY one'), event('TEST ONLY two'), blob('TEST ONLY A')]);
        writer.closeSegment();
        writer.appendBatch([event('TEST ONLY three'), blob('TEST ONLY B')]);
        writer.closeSegment();
      });
      assert.equal(verifyVault(directory).position.segment, 2);
      writable(directory);
      const first = segment(directory, 1);
      change({ directory, first, second: segment(directory, 2), events: join(first, 'events-0001.fvr') });
      assert.throws(() => verifyVault(directory), { code });
    });
  }
});

test('public verification leaves open frames unsigned while deep verification and reads fail closed', t => {
  const { directory, unlocked } = makeVault(t);
  const [entry] = withWriter(directory, unlocked, writer => writer.appendBatch([blob('TEST ONLY authenticated')]));
  const stream = join(directory, 'open', entry.location.stream);
  flip(stream, 75);
  assert.equal(verifyVault(directory).open.files, 1);
  assert.throws(() => verifyVaultDeep(directory, unlocked), { code: 'AUTH' });
  assert.throws(() => readVaultRecord(directory, entry.location, unlocked), { code: 'AUTH' });
  assert.throws(() => VaultWriter.open(directory, unlocked), { code: 'AUTH' });
  const broken = readFileSync(stream);
  broken.writeUInt32BE(0xffffffff, 69);
  writeFileSync(stream, broken);
  assert.throws(() => VaultWriter.open(directory, unlocked), { code: 'LENGTH' });
  assert.deepEqual(readFileSync(stream), broken);
});

test('a replayed prior HEAD without an interrupted seal is refused by the writer', t => {
  const { directory, unlocked } = makeVault(t);
  const head = join(directory, 'HEAD.json');
  const old = readFileSync(head);
  withWriter(directory, unlocked, writer => {
    writer.appendBatch([event('TEST ONLY sealed')]);
    writer.closeSegment();
  });
  writeFileSync(head, old);
  assert.throws(() => VaultWriter.open(directory, unlocked), { code: 'HEAD' });
});

test('a second writer cannot enter while the vault lock is held', t => {
  const { directory, unlocked } = makeVault(t);
  withWriter(directory, unlocked, () => {
    assert.throws(() => VaultWriter.open(directory, unlocked), /database is locked/u);
  });
  withWriter(directory, unlocked, writer => assert.equal(writer.closeSegment().segment, 0));
});

const checkpoints = {
  append: ['before-write', 'after-write', 'before-batch-fsync', 'after-batch-fsync'],
  close: [
    'before-close-fsync', 'after-close-fsync', 'before-manifest-fsync', 'after-manifest-fsync',
    'before-signature-fsync', 'after-signature-fsync', 'before-signature-rename', 'after-signature-rename',
    'before-manifest-rename', 'after-manifest-rename', 'before-head-fsync', 'after-head-fsync',
    'before-segment-rename', 'after-segment-rename', 'before-head-update', 'after-head-update',
  ],
};
const childPath = fileURLToPath(new URL('./vault-crash-child.mjs', import.meta.url));

test('writers in different processes serialize through the vault lock', async t => {
  const { directory, unlocked } = makeVault(t);
  const child = spawn(process.execPath, [childPath, directory, 'hold'], {
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  const exit = once(child, 'close');
  try {
    const held = await Promise.race([
      once(child.stdout, 'data', { signal: AbortSignal.timeout(15_000) }).then(([chunk]) => chunk.toString().trim()),
      exit.then(() => { throw new Error('Child exited before acquiring the vault lock.'); }),
    ]);
    assert.equal(held, 'locked');
    const start = performance.now();
    withWriter(directory, unlocked, writer => {
      assert.equal(writer.closeSegment().segment, 0);
      assert.ok(performance.now() - start >= 100, 'Opening the vault should wait for the child lock.');
    });
    assert.deepEqual(await exit, [0, null]);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await exit;
    }
  }
});

async function killAt(directory, operation, point) {
  const child = spawn(process.execPath, [childPath, directory, operation, point], {
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  const exit = once(child, 'close');
  let stderr = '';
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  const abort = new AbortController();
  const deadline = setTimeout(() => abort.abort(), 15_000);
  try {
    const reached = await Promise.race([
      once(child.stdout, 'data', { signal: abort.signal }).then(([chunk]) => chunk.toString().trim()),
      exit.then(() => { throw new Error(`Writer exited before ${point}. ${stderr}`); }),
    ]);
    assert.equal(reached, point);
    assert.ok(child.kill('SIGKILL'));
    assert.deepEqual(await exit, [null, 'SIGKILL']);
  } finally {
    clearTimeout(deadline);
    abort.abort();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await exit;
    }
  }
}

test('pending HEAD is allowed only for an interrupted head replacement with no open directory', async t => {
  const { directory, unlocked } = makeVault(t);
  const pending = join(directory, 'HEAD.json.pending');
  const open = join(directory, 'open');
  withWriter(directory, unlocked, writer => writer.appendBatch([blob('TEST ONLY pending head')]));
  await killAt(directory, 'close', 'before-segment-rename');
  assert.throws(() => verifyVault(directory), { code: 'INVENTORY' });
  withWriter(directory, unlocked, writer => {
    assert.equal(writer.repairedHead, false);
    assert.throws(() => statSync(pending), { code: 'ENOENT' });
  });
  await killAt(directory, 'close', 'after-segment-rename');
  assert.equal(verifyVault(directory).position.segment, 1);
  mkdirSync(open);
  assert.throws(() => verifyVault(directory), { code: 'INVENTORY' });
  assert.throws(() => VaultWriter.open(directory, unlocked), { code: 'INVENTORY' });
});

test('killed appends and seals recover without losing closed history', async t => {
  for (const [operation, points] of Object.entries(checkpoints)) {
    for (const point of points) {
      await t.test(point, async inner => {
        const { directory, unlocked } = makeVault(inner);
        const original = withWriter(directory, unlocked, writer => {
          writer.appendBatch([event('TEST ONLY already sealed')]);
          const token = writer.closeSegment();
          if (operation === 'close') writer.appendBatch([event('TEST ONLY durable open tail')]);
          return token;
        });
        await killAt(directory, operation, point);
        const renamed = ['after-segment-rename', 'before-head-update', 'after-head-update'].includes(point);
        const expectedSequence = point === 'before-write' ? 1 : 2;
        withWriter(directory, unlocked, writer => {
          assert.equal(writer.repairedHead, renamed && point !== 'after-head-update');
          assert.deepEqual(writer.repairs.map(repair => repair.removedBytes), point === 'before-write' ? [0] : []);
          const recovered = verifyVaultDeep(directory, unlocked);
          assert.equal(recovered.position.segment, renamed ? 2 : 1);
          if (!renamed) assert.deepEqual(recovered.position, original);
          assert.equal(recovered.open.lastEventSequence, expectedSequence);
          assert.equal(writer.closeSegment().lastEventSequence, expectedSequence);
        });
        assert.deepEqual(verifyVault(directory).position, verifyVaultDeep(directory, unlocked).position);
        assert.equal(verifyVault(directory).position.lastEventSequence, expectedSequence);
      });
    }
  }
});

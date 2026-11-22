import assert from 'node:assert/strict';
import { appendFileSync, mkdtempDisposableSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { encodeRecord, FRAME_BYTES, openVaultReplay, VaultFormatError, VaultWriter, verifyVaultDeep } from '../src/index.ts';
import { setFrameKeyObserverForTest } from '../src/record-file.ts';
import { blob, cases, event, fixture, identity, keyId, keyringPath, writable } from './vault-fixture.mjs';

const credential = () => ({ recoveryKey: Buffer.from(cases.recovery_key, 'hex') });

function setup(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-replay-'));
  const directory = temp.path;
  const unlocked = fixture(directory);
  t.after(() => { writable(directory); temp.remove(); });
  return {
    directory,
    unlocked,
    write(work) {
      const writer = VaultWriter.open(directory, unlocked);
      try { return work(writer); } finally { writer.release(); }
    },
    capture(options) {
      const source = openVaultReplay(directory, credential(), options);
      t.after(() => source.close());
      return source;
    },
  };
}

function consume(iterator) {
  const items = [];
  for (let next = iterator.next(); ; next = iterator.next()) {
    if (next.done) return { items, ...next.value };
    items.push(next.value);
  }
}

test('replay repeats the sealed and open boundary across appends and sealing, in event seq order', t => {
  const vault = setup(t);
  const records = vault.write(writer => {
    const sealed = writer.appendBatch([event('TEST ONLY sealed'), blob('TEST ONLY sealed blob')]);
    writer.closeSegment();
    const kinds = ['consent.withdrawn', 'redaction.applied', 'key.destroyed', 'annotation.added'];
    return [...sealed, ...writer.appendBatch([
      ...kinds.map(kind => ({ type: 'event', keyId, event: { kind } })), blob('TEST ONLY open blob'),
    ])];
  });
  assert.throws(() => vault.capture({ anchor: { epoch: 1 } }), { code: 'ANCHOR' });
  const source = vault.capture();
  assert.equal(source.boundary.sealed.segment, 1);
  assert.equal(source.boundary.openSegment, 2);
  assert.equal(source.boundary.lastEventSequence, 5);
  const first = consume(source.replay());
  assert.deepEqual(first.items.filter(item => item.type === 'event').map(item => item.seq), [1, 2, 3, 4, 5]);
  assert.deepEqual(first.items.filter(item => item.type === 'blob').map(item => item.blobId), [records[1].id, records[6].id]);
  for (const item of first.items) {
    const { encodedLength, headerSha256, ...location } = item.location;
    assert.ok(encodedLength >= 89);
    assert.match(headerSha256, /^[0-9a-f]{64}$/);
    assert.ok(records.some(record => Object.keys(location).every(key => record.location[key] === location[key])));
  }
  vault.write(writer => {
    writer.appendBatch([event('TEST ONLY beyond cutoff'), blob('TEST ONLY beyond cutoff')]);
  });
  assert.deepEqual(consume(source.replay()), first);
  vault.write(writer => {
    writer.closeSegment();
    writer.appendBatch([event('TEST ONLY new open segment'), blob('TEST ONLY new open segment')]);
  });
  assert.deepEqual(consume(source.replay()), first);
  assert.deepEqual([...source.replay({ withdrawalsOnly: true })].map(item => item.seq), [2, 3, 4]);
  assert.equal(Buffer.concat([...source.streamBlob(first.items.at(-1).location)]).toString(), 'TEST ONLY open blob');
});

test('MAC-verified destroyed collection records are explicit skips in both passes', t => {
  const vault = setup(t);
  const erasedId = cases.ids.erased;
  const fields = { keyId: erasedId, type: 1, context: 1n };
  const erasedKey = Buffer.alloc(32);
  const erasedEvent = encodeRecord(fields, Buffer.from('{"seq":1}'), identity.vaultId, erasedKey);
  const erasedBlob = encodeRecord({ ...fields, type: 2, context: 0n }, Buffer.alloc(0), identity.vaultId, erasedKey);
  vault.write(writer => {
    writer.appendBatch([event('TEST ONLY live placeholder'), blob('TEST ONLY live placeholder')]);
  });
  writeFileSync(join(vault.directory, 'open', 'events-0001.fvr'), erasedEvent);
  writeFileSync(join(vault.directory, 'open', 'pack-0001.fvr'), erasedBlob);
  vault.write(writer => {
    writer.closeSegment();
    writer.appendBatch([event('TEST ONLY still readable')]);
  });
  const source = vault.capture();
  assert.equal(source.skipped, 2);
  for (const withdrawalsOnly of [false, true]) {
    const pass = consume(source.replay({ withdrawalsOnly }));
    assert.equal(pass.skipped, 2);
    const skips = pass.items.filter(item => item.type === 'skipped');
    assert.deepEqual(skips.map(item => [item.recordType, item.seq, item.keyId]), [['event', 1, erasedId], ['blob', undefined, erasedId]]);
    assert.throws(() => source.streamBlob(skips[1].location).next(), { code: 'ERASED' });
  }
  const path = keyringPath(vault.directory);
  const ring = JSON.parse(readFileSync(path));
  ring.mac = Buffer.alloc(32).toString('base64');
  writeFileSync(path, JSON.stringify(ring));
  assert.throws(() => vault.capture(), { code: 'MAC' });
});

test('capture and replay reject tampered tags and unknown or non-collection key IDs', t => {
  const vault = setup(t);
  const [record] = vault.write(writer => writer.appendBatch([event('TEST ONLY tamper')]));
  const path = join(vault.directory, 'open', record.location.stream);
  const original = readFileSync(path);
  const source = vault.capture();
  const changed = Buffer.from(original);
  changed[changed.length - 1] ^= 1;
  writeFileSync(path, changed);
  assert.throws(() => [...source.replay()], { code: 'AUTH' });
  assert.throws(() => vault.capture(), { code: 'AUTH' });
  for (const invalid of [cases.ids.index, cases.ids.profile, '00'.repeat(16)]) {
    const changed = Buffer.from(original);
    changed.set(Buffer.from(invalid, 'hex'), 5);
    writeFileSync(path, changed);
    assert.throws(() => vault.capture(), { code: 'KEY' });
    assert.throws(() => [...source.replay()], { code: 'KEY' });
  }
});

test('read-only capture ignores the same physically short open tails as writer recovery', t => {
  const vault = setup(t);
  vault.write(writer => writer.appendBatch([event('TEST ONLY complete'), blob('TEST ONLY complete')]));
  const files = ['events-0001.fvr', 'pack-0001.fvr'];
  const sizes = files.map(stream => {
    const path = join(vault.directory, 'open', stream);
    const bytes = statSync(path).size;
    appendFileSync(path, Buffer.from('FVR'));
    return bytes;
  });
  const source = vault.capture();
  assert.throws(() => verifyVaultDeep(vault.directory, vault.unlocked), { code: 'LENGTH' });
  assert.deepEqual(source.boundary.repairs, files.map((name, index) => ({ name, bytes: sizes[index], removedBytes: 3 })));
  assert.deepEqual(files.map(name => statSync(join(vault.directory, 'open', name)).size), sizes.map(n => n + 3));
  const first = [...source.replay()];
  const repaired = vault.write(writer => writer.repairs);
  assert.deepEqual(repaired, files.map((stream, index) => ({ stream, offset: sizes[index], removedBytes: 3 })));
  assert.deepEqual([...source.replay()], first);
});

test('blob streaming releases only authenticated frames and stops at a bad tag', t => {
  const vault = setup(t);
  const payload = Buffer.alloc(FRAME_BYTES + 1, 0x42);
  vault.write(writer => writer.appendBatch([blob(payload)]));
  const source = vault.capture();
  const [{ location }] = [...source.replay()];
  assert.deepEqual(Buffer.concat([...source.streamBlob(location)]), payload);
  const path = join(vault.directory, 'open', location.stream);
  const raw = readFileSync(path);
  raw[raw.length - 1] ^= 1;
  writeFileSync(path, raw);
  const stream = source.streamBlob(location);
  assert.deepEqual(stream.next().value, payload.subarray(0, FRAME_BYTES));
  assert.throws(() => stream.next(), { code: 'AUTH' });
  assert.throws(() => [...source.replay({ withdrawalsOnly: true })], { code: 'AUTH' });
});

test('replay detects a valid ciphertext replacement at a captured location', t => {
  const vault = setup(t);
  vault.write(writer => writer.appendBatch([blob('TEST ONLY first'), blob('TEST ONLY other')]));
  const source = vault.capture();
  const [{ location }, { location: second }] = [...source.replay()];
  assert.equal(location.encodedLength, second.encodedLength);
  const path = join(vault.directory, 'open', location.stream);
  const raw = readFileSync(path);
  raw.copyWithin(location.offset, second.offset, second.offset + second.encodedLength);
  writeFileSync(path, raw);
  assert.throws(() => source.streamBlob(location).next(), { code: 'FILE_HASH' });
  assert.throws(() => source.replay().next(), { code: 'FILE_HASH' });
});

test('close ends paused streamBlob and replay iterators, zeroes derived keys immediately, and rejects later reads', t => {
  const vault = setup(t);
  const payload = Buffer.alloc(FRAME_BYTES + 1, 0x42);
  vault.write(writer => writer.appendBatch([event('TEST ONLY paused replay'), blob(payload)]));
  const source = openVaultReplay(vault.directory, credential());
  t.after(() => source.close());
  const items = [...source.replay()];
  const blobItem = items.find(item => item.type === 'blob');
  assert.ok(blobItem);

  const pausedReplay = source.replay();
  const unstarted = source.streamBlob(blobItem.location);
  assert.equal(pausedReplay.next().done, false);

  const observed = [];
  setFrameKeyObserverForTest(keys => observed.push(keys));
  t.after(() => setFrameKeyObserverForTest(undefined));

  const stream = source.streamBlob(blobItem.location);
  const firstChunk = stream.next();
  assert.equal(firstChunk.done, false);
  assert.deepEqual(firstChunk.value, payload.subarray(0, FRAME_BYTES));
  firstChunk.value.fill(0);

  // Derived collection and record keys are live while the blob iterator is paused.
  assert.equal(observed.length, 1);
  assert.equal(observed[0].collectionKey.length, 32);
  assert.equal(observed[0].recordKey.length, 32);
  assert.ok(observed[0].collectionKey.some(byte => byte !== 0));
  assert.ok(observed[0].recordKey.some(byte => byte !== 0));

  // close() terminates active iterators so finally blocks wipe derived keys immediately.
  source.close();
  assert.deepEqual(observed[0].collectionKey, Buffer.alloc(32));
  assert.deepEqual(observed[0].recordKey, Buffer.alloc(32));

  // Any later next() fails with the existing closed error (KEY); return() stays safe.
  assert.throws(() => stream.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => pausedReplay.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => unstarted.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.equal(stream.return().done, true);
});

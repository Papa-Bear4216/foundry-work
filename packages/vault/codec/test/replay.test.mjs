import assert from 'node:assert/strict';
import { appendFileSync, mkdtempDisposableSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { encodeRecord, FRAME_BYTES, openVaultReplay, VaultFormatError, VaultWriter, verifyVaultDeep } from '../src/index.ts';
import { setFrameKeyObserverForTest } from '../src/record-file.ts';
import { activeReplayIteratorCountForTest } from '../src/vault-replay.ts';
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

test('close called from a location getter during another read returns normally, wipes paused keys, and fails the running read with KEY', t => {
  const vault = setup(t);
  const payload = Buffer.alloc(FRAME_BYTES + 1, 0x42);
  vault.write(writer => writer.appendBatch([event('TEST ONLY reentrant close'), blob(payload)]));
  const source = openVaultReplay(vault.directory, credential());
  t.after(() => source.close());
  const blobItem = [...source.replay()].find(item => item.type === 'blob');
  assert.ok(blobItem);

  const observed = [];
  setFrameKeyObserverForTest(keys => observed.push(keys));
  t.after(() => setFrameKeyObserverForTest(undefined));

  const paused = source.streamBlob(blobItem.location);
  const firstChunk = paused.next();
  assert.equal(firstChunk.done, false);
  firstChunk.value.fill(0);
  assert.equal(observed.length, 1);
  assert.ok(observed[0].collectionKey.some(byte => byte !== 0));
  assert.ok(observed[0].recordKey.some(byte => byte !== 0));

  // The getter runs inside the second read's next(), while that generator is running.
  let closeError = 'not called';
  const trapLocation = {
    ...blobItem.location,
    get segment() {
      try {
        source.close();
        closeError = undefined;
      } catch (error) {
        closeError = error;
      }
      return blobItem.location.segment;
    },
  };
  const running = source.streamBlob(trapLocation);
  assert.throws(() => running.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.equal(closeError, undefined);

  // The paused stream's derived keys are zeroed and the running read derived no new key.
  assert.deepEqual(observed[0].collectionKey, Buffer.alloc(32));
  assert.deepEqual(observed[0].recordKey, Buffer.alloc(32));
  assert.equal(observed.length, 1);
  assert.equal(activeReplayIteratorCountForTest(source), 0);

  // Every later read fails KEY.
  assert.throws(() => running.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => paused.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => source.replay().next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.throws(() => source.streamBlob(blobItem.location).next(),
    error => error instanceof VaultFormatError && error.code === 'KEY');
});

test('iterators join the active set on their first next, so 1,000 dropped unstarted iterators leave it empty', t => {
  const vault = setup(t);
  vault.write(writer => writer.appendBatch([event('TEST ONLY lazy tracking'), blob('TEST ONLY lazy tracking')]));
  const source = openVaultReplay(vault.directory, credential());
  t.after(() => source.close());
  const blobItem = [...source.replay()].find(item => item.type === 'blob');
  assert.ok(blobItem);
  assert.equal(activeReplayIteratorCountForTest(source), 0);

  for (let index = 0; index < 1000; index += 1) {
    if (index % 2 === 0) source.replay();
    else source.streamBlob(blobItem.location);
  }
  assert.equal(activeReplayIteratorCountForTest(source), 0);

  // A started iterator is tracked until it finishes.
  const started = source.replay();
  assert.equal(activeReplayIteratorCountForTest(source), 0);
  assert.equal(started.next().done, false);
  assert.equal(activeReplayIteratorCountForTest(source), 1);
  for (let next = started.next(); !next.done; next = started.next());
  assert.equal(activeReplayIteratorCountForTest(source), 0);

  // An iterator created before close() but first read after it still fails KEY and is never tracked.
  const createdBeforeClose = source.streamBlob(blobItem.location);
  source.close();
  assert.throws(() => createdBeforeClose.next(), error => error instanceof VaultFormatError && error.code === 'KEY');
  assert.equal(activeReplayIteratorCountForTest(source), 0);
});

const isKey = error => error instanceof VaultFormatError && error.code === 'KEY';

test('a reentrant next() or throw() on a running iterator leaves its tracking unchanged, so close() still wipes its keys', t => {
  const vault = setup(t);
  const payload = Buffer.alloc(FRAME_BYTES + 1, 0x42);
  vault.write(writer => writer.appendBatch([blob(payload)]));
  const observed = [];
  t.after(() => setFrameKeyObserverForTest(undefined));

  for (const reenter of [it => it.next(), it => it.throw(new Error('TEST ONLY reentrant throw'))]) {
    const source = openVaultReplay(vault.directory, credential());
    t.after(() => source.close());
    const [{ location }] = [...source.replay()];
    observed.length = 0;
    setFrameKeyObserverForTest(keys => observed.push(keys));

    let iterator;
    let caught = 'not called';
    const trapLocation = {
      ...location,
      get segment() {
        try {
          reenter(iterator);
          caught = undefined;
        } catch (error) {
          caught = error;
        }
        return location.segment;
      },
    };
    iterator = source.streamBlob(trapLocation);
    const first = iterator.next();
    assert.ok(caught instanceof TypeError && !(caught instanceof VaultFormatError));
    assert.equal(first.done, false);
    assert.deepEqual(first.value, payload.subarray(0, FRAME_BYTES));
    first.value.fill(0);
    assert.equal(activeReplayIteratorCountForTest(source), 1);
    assert.equal(observed.length, 1);
    assert.ok(observed[0].collectionKey.some(byte => byte !== 0));
    assert.ok(observed[0].recordKey.some(byte => byte !== 0));

    source.close();
    assert.deepEqual(observed[0].collectionKey, Buffer.alloc(32));
    assert.deepEqual(observed[0].recordKey, Buffer.alloc(32));
    assert.equal(activeReplayIteratorCountForTest(source), 0);
    assert.throws(() => iterator.next(), isKey);
  }
});

test('a running read closed by one getter fails KEY when a later getter throws; without close the getter error is rethrown', t => {
  const vault = setup(t);
  const payload = Buffer.alloc(FRAME_BYTES + 1, 0x42);
  vault.write(writer => writer.appendBatch([blob(payload)]));
  const observed = [];
  t.after(() => setFrameKeyObserverForTest(undefined));

  // Without close: the read rethrows the getter's own error object.
  const plain = openVaultReplay(vault.directory, credential());
  t.after(() => plain.close());
  const [{ location }] = [...plain.replay()];
  const own = new Error('TEST ONLY getter');
  const throwing = { ...location, get stream() { throw own; } };
  assert.throws(() => plain.streamBlob(throwing).next(), error => error === own);
  assert.equal(activeReplayIteratorCountForTest(plain), 0);

  // With close in getter A and a throw in later getter B: the read fails KEY.
  const source = openVaultReplay(vault.directory, credential());
  t.after(() => source.close());
  setFrameKeyObserverForTest(keys => observed.push(keys));
  const paused = source.streamBlob(location);
  const firstChunk = paused.next();
  assert.equal(firstChunk.done, false);
  firstChunk.value.fill(0);
  assert.equal(observed.length, 1);
  assert.ok(observed[0].collectionKey.some(byte => byte !== 0));
  assert.ok(observed[0].recordKey.some(byte => byte !== 0));

  const trapLocation = {
    ...location,
    get segment() {
      source.close();
      return location.segment;
    },
    get stream() {
      throw new Error('TEST ONLY getter');
    },
  };
  assert.throws(() => source.streamBlob(trapLocation).next(), isKey);
  assert.deepEqual(observed[0].collectionKey, Buffer.alloc(32));
  assert.deepEqual(observed[0].recordKey, Buffer.alloc(32));
  assert.equal(observed.length, 1);
  assert.equal(activeReplayIteratorCountForTest(source), 0);
});

test('close, return, next fails KEY on a never-started iterator; the other close and return orders keep their results', t => {
  // An iterator that ended before close() stays done. An iterator that close() ended while it was suspended fails KEY,
  // and so does a never-started iterator that is first returned after close().
  const vault = setup(t);
  const payload = Buffer.alloc(FRAME_BYTES + 1, 0x42);
  vault.write(writer => writer.appendBatch([event('TEST ONLY close return order'), blob(payload)]));
  const location = (() => {
    const source = openVaultReplay(vault.directory, credential());
    try {
      return [...source.replay()].find(item => item.type === 'blob').location;
    } finally {
      source.close();
    }
  })();
  const kinds = {
    replay: source => source.replay(),
    streamBlob: source => source.streamBlob(location),
  };
  const orders = [
    { name: 'never started: close, return, next', steps: ['close', 'return'], expectKey: true },
    { name: 'never started: return, close, next', steps: ['return', 'close'], expectKey: false },
    { name: 'started: close, return, next', steps: ['start', 'close', 'return'], expectKey: true },
    { name: 'started: return, close, next', steps: ['start', 'return', 'close'], expectKey: false },
    { name: 'never started: return, close, return, next', steps: ['return', 'close', 'return'], expectKey: false },
    { name: 'started: return, close, return, next', steps: ['start', 'return', 'close', 'return'], expectKey: false },
    { name: 'read to its end: close, return, next', steps: ['end', 'close', 'return'], expectKey: false },
    { name: 'never started: close, return, return, next', steps: ['close', 'return', 'return'], expectKey: true },
  ];
  for (const [kind, create] of Object.entries(kinds)) {
    for (const order of orders) {
      const source = openVaultReplay(vault.directory, credential());
      t.after(() => source.close());
      const iterator = create(source);
      for (const step of order.steps) {
        if (step === 'start') {
          const first = iterator.next();
          assert.equal(first.done, false, `${kind} ${order.name}`);
          if (Buffer.isBuffer(first.value)) first.value.fill(0);
        } else if (step === 'end') {
          let result = iterator.next();
          assert.equal(result.done, false, `${kind} ${order.name}`);
          while (!result.done) {
            if (Buffer.isBuffer(result.value)) result.value.fill(0);
            result = iterator.next();
          }
        } else if (step === 'close') {
          source.close();
        } else {
          iterator.return();
        }
      }
      if (order.expectKey) {
        assert.throws(() => iterator.next(), isKey, `${kind} ${order.name}`);
      } else {
        assert.deepEqual(iterator.next(), { done: true, value: undefined }, `${kind} ${order.name}`);
      }
      assert.equal(activeReplayIteratorCountForTest(source), 0, `${kind} ${order.name}`);
    }
  }
});

test('P-3 (V-3b item 1): streamBlob refuses a sealed pack whose size changed after capture', t => {
  const vault = setup(t);
  vault.write(writer => {
    writer.appendBatch([event('TEST ONLY size'), blob('TEST ONLY sealed size blob')]);
    writer.closeSegment();
  });
  const source = vault.capture();
  const item = consume(source.replay()).items.find(entry => entry.type === 'blob');
  assert.equal(Buffer.concat([...source.streamBlob(item.location)]).toString(), 'TEST ONLY sealed size blob');
  writable(vault.directory);
  appendFileSync(join(vault.directory, 'segments', '000001', item.location.stream), Buffer.from('TEST ONLY tail'));
  assert.throws(() => source.streamBlob(item.location).next(), { code: 'FILE_SIZE' });
});

test('streamBlob reads empty, small and multi-frame blobs, and two interleaved iterators never share a scanner', t => {
  const vault = setup(t);
  vault.write(writer => {
    writer.appendBatch([blob(''), blob('TEST ONLY small'), blob('x'.repeat(FRAME_BYTES + 5)), blob('y'.repeat(FRAME_BYTES * 2 + 7))]);
  });
  const source = vault.capture();
  const blobs = consume(source.replay()).items.filter(entry => entry.type === 'blob');
  assert.deepEqual(blobs.map(entry => Buffer.concat([...source.streamBlob(entry.location)]).length),
    [0, 15, FRAME_BYTES + 5, FRAME_BYTES * 2 + 7]);
  // Interleave two multi-frame iterators: a chunk of `a` (not copied) must survive a read of `b`. With one shared
  // frame buffer, `b`'s read would overwrite it.
  const a = source.streamBlob(blobs[2].location);
  const b = source.streamBlob(blobs[3].location);
  const got = { a: [], b: [] };
  for (let done = { a: false, b: false }; !done.a || !done.b;) {
    const nextA = done.a ? { done: true } : a.next();
    const nextB = done.b ? { done: true } : b.next();
    if (nextA.done) done.a = true; else got.a.push(Buffer.from(nextA.value.toString()));
    if (!nextA.done) assert.ok(nextA.value.every(byte => byte === 0x78), 'a chunk of a is intact after a read of b');
    if (nextB.done) done.b = true; else got.b.push(Buffer.from(nextB.value));
  }
  assert.equal(Buffer.concat(got.a).toString(), 'x'.repeat(FRAME_BYTES + 5));
  assert.equal(Buffer.concat(got.b).toString(), 'y'.repeat(FRAME_BYTES * 2 + 7));
});

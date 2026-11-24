import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { existsSync, mkdtempDisposableSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { decodeKeyring, openVaultReplay, retireIndexKey, UnlockSession, unlockVault } from 'vault';
import {
  applyIncremental, initializeSchema, openItemKeyLookup, openSqlDriver, rebuildIndex, search, searchIndex, updateIndex,
} from '../dist/index.js';
import { ids, note, syntheticVault, systemEvent, tombstone } from './fixture.mjs';

const scratchKey = () => Buffer.alloc(32, 234);

function fixture(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-v4-projection-'));
  const vault = syntheticVault(join(temp.path, 'vault'));
  const cleanup = [];
  t.after(() => {
    for (const close of cleanup) close();
    vault.writable();
    temp.remove();
  });
  const options = { directory: join(temp.path, 'index'), vaultDirectory: vault.directory, credential: vault.credential };
  return { vault, options, temp, cleanup };
}

function catalog(options) {
  const db = new DatabaseSync(join(options.directory, 'generations.sqlite'), { readOnly: true });
  try { return db.prepare('SELECT * FROM catalog').get(); } finally { db.close(); }
}

function generation(options, id) {
  return join(options.directory, `generation-${id}.sqlite`);
}

function readGeneration(vault, options, work) {
  const { active } = catalog(options);
  const ring = vault.unlock();
  const db = openSqlDriver(generation(options, active), { key: ring.keys.get(active) });
  try { return work(db); } finally {
    db.close();
    ring.masterKey.fill(0);
    for (const key of ring.keys.values()) key.fill(0);
  }
}

function canonical(db) {
  const tables = db.prepare(`
    SELECT name FROM pragma_table_list WHERE schema='main' AND type IN ('table', 'virtual')
      AND name NOT LIKE 'sqlite_%' ORDER BY name
  `).all();
  const contents = {};
  db.exec("CREATE VIRTUAL TABLE temp.term_positions USING fts5vocab(main, 'chunks_fts', 'instance')");
  db.exec("INSERT INTO chunks_fts(chunks_fts, rank) VALUES ('integrity-check', 1)");
  assert.equal(db.prepare("SELECT rtreecheck('places_rtree') AS ok").get().ok, 'ok');
  for (const { name } of [...tables, { name: 'term_positions' }]) {
    const quote = '"' + name.replaceAll('"', '""') + '"';
    contents[name] = db.prepare(`SELECT * FROM ${quote}`).all().map(row =>
      JSON.stringify(row, (_key, value) => ArrayBuffer.isView(value) ? Buffer.from(value).toString('hex') : value)).sort();
  }
  db.exec('DROP TABLE temp.term_positions');
  return contents;
}

test('two-pass rebuild equals real incremental batches across every table after withdrawal and key destruction', t => {
  const { vault, options, temp, cleanup } = fixture(t);
  const path = join(temp.path, 'incremental.sqlite');
  const incremental = openSqlDriver(path, { key: scratchKey(), create: true });
  cleanup.push(() => incremental.close());
  initializeSchema(incremental);
  const sync = () => {
    const input = openVaultReplay(vault.directory, vault.credential);
    const key = vault.tombstoneKey();
    try { return applyIncremental(incremental, input, {}, key); } finally {
      key.fill(0);
      input.close();
    }
  };
  let lostSeq;
  const redacted = 'TEST ONLY obsolete lantern fabrication';
  vault.write(writer => {
    lostSeq = note(writer, 'retired-note', 'TEST ONLY erased cobalt', { collection: 'test-erased', keyId: ids.erase });
    const liveSeq = note(writer, 'alpha', 'TEST ONLY searchable amber lamp', { body: {
      place: { ts: 1, lat_e7: 300000000, lng_e7: -900000000, accuracy_m: 12 },
    } });
    note(writer, 'redacted-note', redacted);
    note(writer, 'withdrawn-note', 'TEST ONLY withdrawn copper', { collection: 'test-withdrawn' });
    writer.appendBatch([
      systemEvent('node.created', { node_id: 'node-a', kind: 'topic', canonical_key: 'topic-a', evidence_event_seq: liveSeq }),
      systemEvent('node.created', { node_id: 'node-b', kind: 'topic', canonical_key: 'topic-b', evidence_event_seq: liveSeq }),
      systemEvent('node.created', { node_id: 'node-c', kind: 'topic', canonical_key: 'topic-c', evidence_event_seq: lostSeq }),
      systemEvent('edge.inferred', { src: 'node-a', dst: 'node-b', kind: 'related', evidence: [lostSeq, liveSeq], confidence: 0.8 }),
      systemEvent('layout.placed', { node_id: 'node-a', x: 7, y: 4 }),
      systemEvent('layout.placed', { node_id: 'node-c', x: 2, y: 8 }),
    ]);
    writer.closeSegment();
  });
  sync();
  assert.equal(search(incremental, 'cobalt').length, 1);
  incremental.prepare('INSERT INTO vectors VALUES (?, ?, ?, ?, ?)').run(
    lostSeq * 1024, 'test/model', 3, 0.01, Buffer.from([1, 2, 3]),
  );
  assert.equal(search(incremental, 'copper').length, 1);
  assert.equal(search(incremental, 'lantern').length, 1);
  assert.equal(rebuildIndex(options).skipped, 0);
  const first = catalog(options).active;

  vault.write(writer => {
    writer.appendBatch([
      systemEvent('consent.withdrawn', { collection: 'test-withdrawn' }),
      systemEvent('redaction.applied', { target_ref: 'redacted-note', tombstone: tombstone(vault, redacted) }),
      systemEvent('key.destroyed', { key_id: ids.erase }),
    ]);
    note(writer, 'reimported', redacted);
    note(writer, 'other', 'TEST ONLY searchable amber cabinet', {
      profile: 'other', collection: 'test-extra', tier: 'restricted', ts: '2026-02-01T00:00:00Z', source: 'test/export',
    });
  });
  vault.destroyCollection();
  const result = sync();
  assert.equal(result.skipped, 2);
  assert.equal(result.hiddenChanged, true);
  assert.equal(search(incremental, 'cobalt OR copper OR lantern').length, 0);
  assert.throws(() => searchIndex(options, 'cobalt'), /Working index is stale/);
  assert.equal(updateIndex(options).skipped, 2);
  assert.deepEqual(searchIndex(options, 'amber', {
    from: '2026-01-30', until: '2026-03-01', profile: 'other', collection: 'test-extra',
    tier: 'restricted', source: 'test/export',
  }).map(({ item_id, source, imported_at }) => [item_id, source, imported_at]),
  [['other', 'test/export', '2026-02-01T00:00:00.000Z']]);
  assert.equal(searchIndex(options, 'amber', { until: '2026-02-01' })[0].event_seq, 2);
  assert.equal(searchIndex(options, 'cobalt OR copper OR lantern').length, 0);
  assert.notEqual(catalog(options).active, first);
  assert.equal(vault.unlock().keyring.keys.find(key => key.key_id === first).state, 'destroyed');
  const rebuilt = readGeneration(vault, options, db => canonical(db));
  assert.deepEqual(rebuilt, canonical(incremental));
  assert.equal(rebuilt.graph_edge_evidence.length, 1);
  assert.equal(rebuilt.graph_positions.length, 1);
  assert.equal(rebuilt.vectors.length, 0);
  assert.ok(rebuilt.graph_events.every(row => !row.includes('topic-c')));
  assert.equal(rebuilt.places_rtree.length, 1);
});

test('rebuild resumes committed event and blob batches, publishes atomically, and retries retirement', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY initial quartz'));
  updateIndex(options);
  const old = catalog(options).active;
  vault.write(writer => {
    for (let i = 0; i < 160; i++) note(writer, `synthetic-${i}`, `TEST ONLY quartz ${i}`);
  });
  assert.throws(() => rebuildIndex({ ...options, projection: {
    checkpoint(phase, position) { if (phase === 'events' && position >= 128) throw new Error('TEST ONLY events'); },
  } }), /TEST ONLY events/);
  const staged = catalog(options).staged;
  assert.equal(catalog(options).active, old);
  assert.ok(existsSync(generation(options, staged)));
  assert.throws(() => rebuildIndex({ ...options, projection: {
    checkpoint(phase, position) { if (phase === 'blobs' && position > 0) throw new Error('TEST ONLY blobs'); },
  } }), /TEST ONLY blobs/);
  assert.equal(catalog(options).staged, staged);
  assert.throws(() => rebuildIndex({ ...options, afterPublish() { throw new Error('TEST ONLY publication'); } }),
    /TEST ONLY publication/);
  assert.equal(catalog(options).retiring, old);
  assert.equal(catalog(options).active, staged);
  assert.equal(vault.unlock().keyring.keys.find(key => key.key_id === old).state, 'active');
  assert.throws(() => searchIndex(options, 'quartz'), /Working index is stale/);
  updateIndex(options);
  const results = searchIndex(options, 'quartz', { limit: 200 });
  assert.equal(results.length, 161);
  assert.equal(catalog(options).retiring, null);
  assert.equal(vault.unlock().keyring.keys.find(key => key.key_id === old).state, 'destroyed');
  assert.equal(existsSync(generation(options, old)), false);
});

test('a changed replay boundary discards partial work and an older vault is rejected', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY boundary needle'));
  updateIndex(options);
  const olderRing = readFileSync(vault.keyring);
  assert.throws(() => rebuildIndex({ ...options, projection: {
    checkpoint() { throw new Error('TEST ONLY stop partial'); },
  } }), /TEST ONLY stop partial/);
  const stale = catalog(options).staged;
  vault.write(writer => {
    writer.appendBatch([systemEvent('redaction.applied', { target_ref: 'initial' })]);
    note(writer, 'visible', 'TEST ONLY boundary needle retained');
  });
  assert.throws(() => searchIndex(options, 'needle'), /Working index is stale/);
  updateIndex(options);
  assert.deepEqual(searchIndex(options, 'needle').map(hit => hit.item_id), ['visible']);
  assert.equal(vault.unlock().keyring.keys.find(key => key.key_id === stale).state, 'destroyed');
  writeFileSync(vault.keyring, olderRing);
  assert.throws(() => searchIndex(options, 'needle'), { code: 'PROJECTION' });
});

test('projection authenticates and clears all frames after a deriver stops early', t => {
  const { vault, temp, cleanup } = fixture(t);
  const original = 'TEST ONLY frame '.repeat(100_000);
  vault.write(writer => {
    note(writer, 'visible', original);
    writer.appendBatch([systemEvent('redaction.applied', { tombstone: tombstone(vault, 'TEST ONLY other bytes') })]);
  });
  const db = openSqlDriver(join(temp.path, 'frame.sqlite'), { key: scratchKey(), create: true });
  cleanup.push(() => db.close());
  initializeSchema(db);
  const input = openVaultReplay(vault.directory, vault.credential);
  const key = vault.tombstoneKey();
  const streams = [];
  const borrowed = [];
  try {
    applyIncremental(db, { ...input, *streamBlob(location) {
      const frames = [];
      streams.push(frames);
      for (const frame of input.streamBlob(location)) {
        assert.ok(frame.some(byte => byte !== 0));
        frames.push(frame);
        yield frame;
      }
    } }, { derive(_item, frames) {
      for (const frame of frames) {
        borrowed.push(frame);
        break;
      }
      return ['TEST ONLY derived frame'];
    } }, key);
    assert.deepEqual(streams.map(frames => frames.length), [2, 2]);
    assert.equal(borrowed[0], streams[1][0]);
    assert.ok(streams.flat().every(frame => frame.every(byte => byte === 0)));
    assert.equal(db.prepare('SELECT derived FROM items').get().derived, 1);
    assert.equal(db.prepare('SELECT count(*) AS n FROM blob_locator').get().n, 1);
  } finally {
    key.fill(0);
    input.close();
  }
});

test('a swallowed frame error rolls back the item, its provisional chunks and locator', t => {
  const { vault, temp, cleanup } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY prior state'));
  const db = openSqlDriver(join(temp.path, 'rollback.sqlite'), { key: scratchKey(), create: true });
  cleanup.push(() => db.close());
  initializeSchema(db);
  const baseline = openVaultReplay(vault.directory, vault.credential);
  try { applyIncremental(db, baseline); } finally { baseline.close(); }
  const previous = canonical(db);
  vault.write(writer => note(writer, 'new', 'TEST ONLY provisional frame'));
  const input = openVaultReplay(vault.directory, vault.credential);
  const failure = new Error('TEST ONLY stream failure');
  const borrowed = [];
  let swallowed;
  try {
    assert.throws(() => applyIncremental(db, { ...input, *streamBlob(location) {
      yield* input.streamBlob(location);
      throw failure;
    } }, { *derive(_item, frames) {
      try {
        for (const frame of frames) {
          borrowed.push(frame);
          yield 'TEST ONLY provisional chunk';
        }
      } catch (error) {
        swallowed = error;
      }
    } }), error => error === failure);
    assert.equal(swallowed, failure);
    assert.equal(borrowed.length, 1);
    assert.ok(borrowed[0].every(byte => byte === 0));
    assert.deepEqual(canonical(db), previous);
  } finally {
    input.close();
  }
});

function interruptRebuild(options) {
  assert.throws(() => rebuildIndex({ ...options, projection: { version: 1,
    checkpoint() { throw new Error('TEST ONLY interrupted rebuild'); },
  } }), /TEST ONLY interrupted rebuild/);
  return catalog(options).staged;
}

test('an interrupted create resumes from a zero-byte staged generation', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY staged quartz'));
  const staged = interruptRebuild(options);
  writeFileSync(generation(options, staged), '');
  assert.equal(updateIndex(options).lastEventSeq, 1);
  assert.equal(catalog(options).active, staged);
  assert.equal(searchIndex(options, 'quartz').length, 1);
});

test('update at the original deriver version recovers after interrupted stage abandonment', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY abandoned quartz'));
  updateIndex(options);
  const staged = interruptRebuild(options);
  // Emulate an old v2 rebuild killed after retiring the v1 key and deleting its file.
  retireIndexKey(vault.keyring, vault.vaultId, vault.credential, staged);
  unlinkSync(generation(options, staged));
  assert.equal(catalog(options).staged_version, 1);
  assert.equal(catalog(options).staged, staged);
  assert.equal(updateIndex(options).lastEventSeq, 1);
  assert.equal(catalog(options).staged, null);
  assert.notEqual(catalog(options).active, staged);
  assert.equal(searchIndex(options, 'quartz').length, 1);
});

test('a deriver-version rebuild reports hiddenChanged false', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY version change'));
  updateIndex(options);
  const first = catalog(options).active;
  const next = { ...options, projection: { version: 2, derive: () => ['TEST ONLY revised amber'] } };
  assert.equal(updateIndex(next).hiddenChanged, false);
  assert.notEqual(catalog(options).active, first);
  assert.equal(searchIndex(next, 'amber').length, 1);
});

// A-42: the index unlocks once per call. These tests instrument scryptSync via node:module's syncBuiltinESMExports and
// record every UnlockSession the index disposes by wrapping UnlockSession.prototype.dispose in this test process only.
function instrumentUnlock(t) {
  const originalDispose = UnlockSession.prototype.dispose;
  const originalScryptSync = crypto.scryptSync;
  const disposed = [];
  let kdfCalls = 0;
  UnlockSession.prototype.dispose = function dispose() {
    disposed.push(this);
    return originalDispose.call(this);
  };
  crypto.scryptSync = function countedScryptSync(...args) {
    kdfCalls += 1;
    return originalScryptSync.apply(this, args);
  };
  syncBuiltinESMExports();
  t.after(() => {
    UnlockSession.prototype.dispose = originalDispose;
    crypto.scryptSync = originalScryptSync;
    syncBuiltinESMExports();
  });
  return {
    counted(work) {
      const before = disposed.length;
      kdfCalls = 0;
      work();
      return { kdf: kdfCalls, sessions: disposed.slice(before) };
    },
  };
}

function assertSessionDisposed(vault, session, label) {
  assert.equal(session.disposed, true, `${label}: session.disposed is true`);
  assert.throws(
    () => decodeKeyring(readFileSync(vault.keyring), { session }, vault.vaultId),
    { name: 'VaultFormatError', code: 'KEY' },
    `${label}: disposed session cannot decode keyring`,
  );
}

function lookupOnce(options) {
  const lookup = openItemKeyLookup(options);
  lookup.close();
}

test('A-42: one KDF run per call with a passphrase, none with a recovery key or a caller session', t => {
  const { vault, options } = fixture(t);
  const { counted } = instrumentUnlock(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY unlock-once garnet'));

  // Positive control: the counter instrumented here observes scryptSync runs inside the vault package.
  const control = counted(() => unlockVault(vault.keyring, vault.vaultId, vault.passphraseCredential).dispose());
  assert.equal(control.kdf, 1);

  const passphrase = { ...options, credential: vault.passphraseCredential };
  const recovery = { ...options, credential: vault.credential };
  const calls = [
    ['updateIndex', o => updateIndex(o)],
    ['rebuildIndex', o => rebuildIndex(o)],
    ['searchIndex', o => assert.equal(searchIndex(o, 'garnet').length, 1)],
    ['openItemKeyLookup', o => lookupOnce(o)],
  ];
  for (const [name, call] of calls) {
    const withPassphrase = counted(() => call(passphrase));
    assert.equal(withPassphrase.kdf, 1, `${name} with a passphrase`);
    assert.equal(withPassphrase.sessions.length, 1, `${name} disposes one session`);
    assertSessionDisposed(vault, withPassphrase.sessions[0], `${name} passphrase session`);

    const withRecovery = counted(() => call(recovery));
    assert.equal(withRecovery.kdf, 0, `${name} with a recovery key`);
    assert.equal(withRecovery.sessions.length, 1, `${name} disposes one recovery session`);
    assertSessionDisposed(vault, withRecovery.sessions[0], `${name} recovery session`);
  }

  const session = unlockVault(vault.keyring, vault.vaultId, vault.passphraseCredential);
  t.after(() => session.dispose());
  const caller = { ...options, credential: { session } };
  for (const [name, call] of calls) {
    const withSession = counted(() => call(caller));
    assert.equal(withSession.kdf, 0, `${name} with a caller session`);
    assert.deepEqual(withSession.sessions, [], `${name} never disposes the caller session`);
    assert.equal(session.disposed, false, `${name} leaves the caller session open`);
  }
  // The caller's session is still usable afterwards.
  const ring = decodeKeyring(readFileSync(vault.keyring), { session }, vault.vaultId);
  ring.masterKey.fill(0);
  for (const key of ring.keys.values()) key.fill(0);
  assert.equal(session.disposed, false);
});

test('A-42: the internal session is disposed when a call fails with a typed or a thrown error', t => {
  const { vault, options } = fixture(t);
  const { counted } = instrumentUnlock(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY disposal garnet'));
  updateIndex(options);
  const passphrase = { ...options, credential: vault.passphraseCredential };

  // A thrown (non-index) error from inside the rebuild.
  const thrown = counted(() => assert.throws(() => rebuildIndex({ ...passphrase, projection: {
    checkpoint() { throw new Error('TEST ONLY stop'); },
  } }), /TEST ONLY stop/));
  assert.equal(thrown.sessions.length, 1);
  assertSessionDisposed(vault, thrown.sessions[0], 'rebuild thrown error');

  // A typed error: the stale search (the interrupted rebuild left a staged generation).
  const stale = counted(() => assert.throws(() => searchIndex(passphrase, 'garnet'), { code: 'PROJECTION' }));
  assert.equal(stale.sessions.length, 1);
  assertSessionDisposed(vault, stale.sessions[0], 'stale search error');
  updateIndex(options);

  // A typed error after unlock: a tampered catalog.
  const db = new DatabaseSync(join(options.directory, 'generations.sqlite'));
  try { db.exec("UPDATE catalog SET retiring='TEST ONLY not a key id' WHERE singleton=1"); } finally { db.close(); }
  for (const call of [() => updateIndex(passphrase), () => searchIndex(passphrase, 'garnet'), () => lookupOnce(passphrase)]) {
    const tampered = counted(() => assert.throws(call, { name: 'IndexError', code: 'FORMAT' }));
    assert.equal(tampered.sessions.length, 1);
    assertSessionDisposed(vault, tampered.sessions[0], 'tampered catalog error');
  }
});

test('A-42: a wrong passphrase fails with AUTH and a keyring changed during the call still fails', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'initial', 'TEST ONLY wrong-passphrase garnet'));
  updateIndex(options);
  const wrong = { ...options, credential: { passphrase: 'TEST ONLY not the passphrase' } };
  for (const call of [() => updateIndex(wrong), () => rebuildIndex(wrong), () => searchIndex(wrong, 'garnet'),
    () => lookupOnce(wrong)]) {
    assert.throws(call, { name: 'VaultFormatError', code: 'AUTH' });
  }

  let changed = false;
  assert.throws(() => rebuildIndex({ ...options, credential: vault.passphraseCredential, projection: {
    checkpoint() {
      if (changed) return;
      changed = true;
      vault.destroyCollection();
    },
  } }), { name: 'IndexError', code: 'PROJECTION', message: /changed during indexing/ });
  assert.ok(changed);
});

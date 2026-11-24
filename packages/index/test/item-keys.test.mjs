// V-7 phase 1 (A-36 (d)): the durable, index-backed item-key lookup and the item_keys projection.
import assert from 'node:assert/strict';
import { mkdtempDisposableSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { generateSyntheticMbox, importArchive, mailImporter, openArchive, writeZipArchive } from 'importers';
import { openVaultReplay, readVaultRecord, VaultWriter } from 'vault';
import { applyIncremental, initializeSchema, openItemKeyLookup, openSqlDriver, rebuildIndex, searchIndex, updateIndex } from '../dist/index.js';
import { ids, note, syntheticVault, systemEvent } from './fixture.mjs';

const MESSAGES = 10;
const BATCH = 4; // 10 messages -> import batches of 4, 4 and 2: the vault is larger than one batch.
const itemKey = n => n.toString(16).padStart(64, '0');

function fixture(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-v7-item-keys-'));
  const vault = syntheticVault(join(temp.path, 'vault'));
  t.after(() => {
    vault.writable();
    temp.remove();
  });
  const options = { directory: join(temp.path, 'index'), vaultDirectory: vault.directory, credential: vault.credential };
  return { vault, options, temp };
}

function catalog(options) {
  const db = new DatabaseSync(join(options.directory, 'generations.sqlite'), { readOnly: true });
  try { return db.prepare('SELECT * FROM catalog').get(); } finally { db.close(); }
}

function withGeneration(vault, options, id, work) {
  const ring = vault.unlock();
  const db = openSqlDriver(join(options.directory, `generation-${id}.sqlite`), { key: ring.keys.get(id) });
  try { return work(db); } finally {
    db.close();
    ring.masterKey.fill(0);
    for (const key of ring.keys.values()) key.fill(0);
  }
}

const rows = db => db.prepare('SELECT item_key FROM item_keys ORDER BY item_key').all().map(row => row.item_key);
const activeRows = (vault, options) => withGeneration(vault, options, catalog(options).active, rows);

/** Every body.item_key of item.imported events the replay yields (live keys only). */
function vaultItemKeys(vault) {
  const replay = openVaultReplay(vault.directory, vault.credential);
  try {
    const keys = [];
    for (const entry of replay.replay()) {
      if (entry.type === 'event' && entry.event.kind === 'item.imported' && entry.event.body.item_key) {
        keys.push(entry.event.body.item_key);
      }
    }
    return keys.sort();
  } finally {
    replay.close();
  }
}

async function importMail(vault, zipPath, extra = {}) {
  const unlocked = vault.unlock();
  const archive = await openArchive(zipPath);
  const writer = VaultWriter.open(vault.directory, unlocked);
  try {
    return await importArchive({
      archive, writer, importers: [mailImporter], resolveCollectionKeyId: () => ids.live,
      vaultDir: vault.directory, unlocked, readVaultRecord: extra.readVaultRecord ?? readVaultRecord,
      batchMaxItems: BATCH, itemKeys: extra.itemKeys,
    });
  } finally {
    writer.release();
    await archive.close();
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

/** Opens the index lookup, runs `work`, and closes the lookup in finally (the CLI pattern). */
async function withLookup(options, work) {
  const lookup = openItemKeyLookup(options);
  try {
    return await work(lookup);
  } finally {
    lookup.close();
  }
}

test('index-backed lookup: an import larger than one batch is recorded durably and a second import adds nothing', async t => {
  const { vault, options, temp } = fixture(t);
  const zipPath = join(temp.path, 'mail.zip');
  await writeZipArchive(zipPath, [{ path: 'Takeout/Mail/All mail.mbox', data: generateSyntheticMbox(MESSAGES, 4242), compression: 'deflate' }]);
  updateIndex(options); // empty vault: the CLI runs this catch-up update before every import

  const first = await withLookup(options, lookup => importMail(vault, zipPath, { itemKeys: lookup }));
  assert.equal(first.totalItemsImported, MESSAGES);
  // The lookup wrote the keys straight into the open generation; they persist after close and
  // equal the keys stored in the vault, before any index update has run.
  const stored = vaultItemKeys(vault);
  assert.equal(stored.length, MESSAGES);
  assert.deepEqual(activeRows(vault, options), stored);

  updateIndex(options);
  assert.deepEqual(activeRows(vault, options), stored, 'the projection adds the same rows (INSERT OR IGNORE)');

  // Second import: a reopened lookup knows every key, so nothing is added and the vault is never scanned.
  const reader = () => assert.fail('loadExistingItemKeys must not run when itemKeys is given');
  const second = await withLookup(options, lookup => importMail(vault, zipPath, { itemKeys: lookup, readVaultRecord: reader }));
  assert.equal(second.totalItemsImported, 0);
  assert.equal(second.totalItemsSkipped, MESSAGES);
  assert.deepEqual(vaultItemKeys(vault), stored);
  updateIndex(options);
  assert.deepEqual(activeRows(vault, options), stored);
});

test('a rebuild yields the same item_keys rows as the incremental path, including hidden items and destroyed keys', t => {
  const { vault, options, temp } = fixture(t);
  vault.write(writer => {
    for (let i = 1; i <= 150; i++) note(writer, `first-${i}`, `TEST ONLY first ${i}`, { body: { item_key: itemKey(i) } });
    note(writer, 'no-key', 'TEST ONLY event without an item key');
    note(writer, 'short-key', 'TEST ONLY malformed key', { body: { item_key: 'abc' } });
  });
  updateIndex(options);
  const firstGeneration = catalog(options).active;
  vault.write(writer => {
    for (let i = 151; i <= 300; i++) note(writer, `second-${i}`, `TEST ONLY second ${i}`, { body: { item_key: itemKey(i) } });
    note(writer, 'erased', 'TEST ONLY erased item', { keyId: ids.erase, collection: 'test-erased', body: { item_key: itemKey(999) } });
  });
  updateIndex(options);
  assert.equal(catalog(options).active, firstGeneration, 'the second update was incremental');
  const incremental = activeRows(vault, options);
  assert.equal(incremental.length, 301);
  assert.ok(incremental.includes(itemKey(999)));

  rebuildIndex(options);
  assert.notEqual(catalog(options).active, firstGeneration);
  assert.deepEqual(activeRows(vault, options), incremental);

  // Withdrawals hide items but keep their keys (same rule as the importer's vault scan). Raw incremental
  // projection with withdrawals must match a rebuild.
  vault.write(writer => {
    writer.appendBatch([
      systemEvent('consent.withdrawn', { collection: 'test-live' }),
      systemEvent('redaction.applied', { target_ref: 'first-1' }),
    ]);
  });
  const scratch = openSqlDriver(join(temp.path, 'scratch.sqlite'), { key: Buffer.alloc(32, 77), create: true });
  try {
    initializeSchema(scratch);
    const input = openVaultReplay(vault.directory, vault.credential);
    try { applyIncremental(scratch, input); } finally { input.close(); }
    rebuildIndex(options);
    assert.deepEqual(activeRows(vault, options), rows(scratch));
    assert.deepEqual(rows(scratch), incremental);
  } finally {
    scratch.close();
  }

  // A destroyed collection key contributes nothing: its events reach the projection as skipped records.
  vault.destroyCollection();
  updateIndex(options);
  const afterDestroy = activeRows(vault, options);
  assert.equal(afterDestroy.includes(itemKey(999)), false);
  assert.equal(afterDestroy.length, 300);
  rebuildIndex(options);
  assert.deepEqual(activeRows(vault, options), afterDestroy);
});

test('the lookup needs a current index, validates keys, and releases the writer lock on close', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => note(writer, 'one', 'TEST ONLY one', { body: { item_key: itemKey(1) } }));
  assert.throws(() => openItemKeyLookup(options), /Working index is stale/);
  updateIndex(options);
  vault.write(writer => note(writer, 'two', 'TEST ONLY two', { body: { item_key: itemKey(2) } }));
  assert.throws(() => openItemKeyLookup(options), { code: 'PROJECTION' });
  updateIndex(options); // a failed open left no lock behind

  const lookup = openItemKeyLookup(options);
  try {
    assert.equal(lookup.has(itemKey(1)), true);
    assert.equal(lookup.has(itemKey(2)), true);
    assert.equal(lookup.has(itemKey(3)), false);
    assert.throws(() => lookup.add('short'), { code: 'PROJECTION' });
    assert.throws(() => lookup.has(42), { code: 'PROJECTION' });
  } finally {
    lookup.close();
  }
  lookup.close(); // idempotent
  assert.throws(() => lookup.has(itemKey(1)), { code: 'CONFIG' });
  assert.equal(updateIndex(options).lastEventSeq, 2);
  assert.equal(searchIndex(options, 'two').length, 1);
});

test('an index at schema version 1 is replaced by a rebuild that fills item_keys', t => {
  const { vault, options } = fixture(t);
  vault.write(writer => {
    for (let i = 1; i <= 3; i++) note(writer, `old-${i}`, `TEST ONLY old schema ${i}`, { body: { item_key: itemKey(i) } });
  });
  updateIndex(options);
  const old = catalog(options).active;
  withGeneration(vault, options, old, db => db.exec('DROP TABLE item_keys; PRAGMA user_version = 1;'));
  assert.throws(() => searchIndex(options, 'schema'), { code: 'PROJECTION' });
  assert.throws(() => openItemKeyLookup(options), { code: 'PROJECTION' });

  updateIndex(options);
  assert.notEqual(catalog(options).active, old);
  assert.deepEqual(activeRows(vault, options), [itemKey(1), itemKey(2), itemKey(3)]);
  assert.equal(searchIndex(options, 'schema').length, 3);

  // A staged generation left by the older schema is started again, not resumed.
  assert.throws(() => rebuildIndex({ ...options, projection: {
    checkpoint() { throw new Error('TEST ONLY interrupted rebuild'); },
  } }), /TEST ONLY interrupted rebuild/);
  const staged = catalog(options).staged;
  withGeneration(vault, options, staged, db => db.exec('DROP TABLE item_keys; PRAGMA user_version = 1;'));
  rebuildIndex(options);
  assert.equal(catalog(options).active, staged);
  assert.deepEqual(activeRows(vault, options), [itemKey(1), itemKey(2), itemKey(3)]);
});

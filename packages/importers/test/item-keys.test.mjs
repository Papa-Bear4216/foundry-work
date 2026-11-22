// V-7 phase 1 (A-36 (d)): importArchive with a durable ItemKeyLookup never scans the vault, and adds a
// key only after the batch holding that item is durably appended.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import {
  decodeKeyring,
  encodeKeyring,
  initializeVault,
  readVaultRecord,
  signingPublicKey,
  VaultWriter,
} from '../../vault/codec/dist/index.js';
import {
  CONTACTS_SOURCE_ID, contactsImporter, generateSyntheticMbox, generateSyntheticVcards, importArchive, loadExistingItemKeys,
  mailImporter, openArchive, writeZipArchive,
} from '../dist/index.js';

/** Number of item events durably in the vault, sealed or open segment (read-only vault scan). */
function storedCount({ vaultDir, unlock }) {
  const unlocked = unlock();
  try {
    return loadExistingItemKeys(vaultDir, unlocked, readVaultRecord).size;
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

const MESSAGES = 10;
const BATCH = 4; // 10 messages -> batches of 4, 4 and 2: the vault is larger than one batch.

function removeTree(dir) {
  if (!existsSync(dir)) return;
  const walk = target => {
    chmodSync(target, 0o700);
    for (const entry of readdirSync(target, { withFileTypes: true })) {
      const full = join(target, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) chmodSync(full, 0o600);
    }
  };
  walk(dir);
  rmSync(dir, { recursive: true, force: true });
}

/** Synthetic vault unlocked by recovery key (no scrypt on unlock). */
function createVault(vaultDir, { secondCollection = false } = {}) {
  const vaultId = randomBytes(16).toString('hex');
  const createdAt = '2026-11-22T00:00:00Z';
  const recoveryKey = randomBytes(32);
  const signingSeed = randomBytes(32);
  const profileKeyId = randomBytes(16).toString('hex');
  const collectionKeyId = randomBytes(16).toString('hex');
  const secondCollectionKeyId = randomBytes(16).toString('hex');
  const keyring = join(vaultDir, 'keyring', 'keyring.json');
  mkdirSync(join(vaultDir, 'keyring'), { recursive: true });
  writeFileSync(keyring, encodeKeyring({
    vaultId,
    version: 1,
    masterKey: randomBytes(32),
    entries: [
      { key_id: randomBytes(16).toString('hex'), kind: 'signing', parent: 'master', state: 'active', created_at: createdAt, key: signingSeed },
      { key_id: profileKeyId, kind: 'profile', parent: 'master', state: 'active', created_at: createdAt, key: randomBytes(32), label: 'me' },
      { key_id: collectionKeyId, kind: 'collection', parent: profileKeyId, state: 'active', created_at: createdAt, key: randomBytes(32) },
      ...(secondCollection
        ? [{ key_id: secondCollectionKeyId, kind: 'collection', parent: profileKeyId, state: 'active', created_at: createdAt, key: randomBytes(32) }]
        : []),
    ],
  }, 'TEST ONLY v7 item-key passphrase', recoveryKey));
  initializeVault(vaultDir, { vaultId, createdAt, signingPublicKey: signingPublicKey(signingSeed) });
  return {
    collectionKeyId,
    ...(secondCollection ? { secondCollectionKeyId } : {}),
    unlock: () => decodeKeyring(readFileSync(keyring), { recoveryKey }, vaultId),
  };
}

async function setup(t, name) {
  const root = mkdtempSync(join(tmpdir(), `foundry-v7-${name}-`));
  t.after(() => removeTree(root));
  const zipPath = join(root, 'mail.zip');
  const vaultDir = join(root, 'vault');
  await writeZipArchive(zipPath, [{ path: 'Takeout/Mail/All mail.mbox', data: generateSyntheticMbox(MESSAGES, 707), compression: 'deflate' }]);
  const vault = createVault(vaultDir);
  return { zipPath, vaultDir, ...vault };
}

/** A durable-lookup stand-in that records every call. The index-backed one is tested in packages/index. */
function recordingLookup() {
  const keys = new Set();
  const added = [];
  return {
    keys,
    added,
    has: key => keys.has(key),
    add: key => {
      added.push(key);
      keys.add(key);
    },
  };
}

function countingReader() {
  const reader = (...args) => {
    reader.calls++;
    return readVaultRecord(...args);
  };
  reader.calls = 0;
  return reader;
}

async function runImport({ zipPath, vaultDir, collectionKeyId, unlock }, extra) {
  const unlocked = unlock();
  const archive = await openArchive(zipPath);
  const writer = VaultWriter.open(vaultDir, unlocked);
  try {
    return await importArchive({
      archive,
      writer: extra.wrapWriter ? extra.wrapWriter(writer) : writer,
      importers: extra.importers ?? [mailImporter],
      resolveCollectionKeyId: extra.resolveCollectionKeyId ?? (() => collectionKeyId),
      vaultDir,
      unlocked,
      readVaultRecord: extra.readVaultRecord ?? readVaultRecord,
      batchMaxItems: BATCH,
      itemKeys: extra.itemKeys,
      checkpoint: extra.checkpoint,
    });
  } finally {
    writer.release();
    await archive.close();
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

test('with itemKeys, importArchive never calls loadExistingItemKeys and a second import of a multi-batch vault adds nothing', async t => {
  const ctx = await setup(t, 'item-keys');
  const lookup = recordingLookup();

  const first = await runImport(ctx, { itemKeys: lookup, readVaultRecord: countingReader() });
  assert.equal(first.totalItemsImported, MESSAGES);
  assert.equal(lookup.added.length, MESSAGES);
  assert.equal(new Set(lookup.added).size, MESSAGES);
  assert.equal(storedCount(ctx), MESSAGES);

  // The vault now holds 10 item events. loadExistingItemKeys reads every one of them through
  // readVaultRecord, so a reader count of zero proves it was not called.
  const reader = countingReader();
  const second = await runImport(ctx, { itemKeys: lookup, readVaultRecord: reader });
  assert.equal(reader.calls, 0, 'loadExistingItemKeys must not run when itemKeys is given');
  assert.equal(second.totalItemsImported, 0);
  assert.equal(second.totalItemsSkipped, MESSAGES);
  assert.equal(second.totalEventsWritten, 0);
  assert.equal(lookup.added.length, MESSAGES, 'a re-import adds no key');
  assert.equal(storedCount(ctx), MESSAGES);

  // Control: without itemKeys the same reader IS used (the in-memory vault scan), and still adds nothing.
  const control = countingReader();
  const third = await runImport(ctx, { readVaultRecord: control });
  assert.ok(control.calls >= MESSAGES, `the vault scan reads every event (calls=${control.calls})`);
  assert.equal(third.totalItemsImported, 0);
});

function eventKeys(items) {
  return [...items].filter(op => op.type === 'event').map(op => op.event.body.item_key);
}

test('itemKeys.add runs only after its whole batch is durably appended; a failed batch adds no key', async t => {
  const ctx = await setup(t, 'item-keys-order');
  const lookup = recordingLookup();
  const durable = new Set();
  let calls = 0;
  const persistedFromFailedBatch = [];
  const wrapWriter = writer => ({
    appendBatch(items) {
      const ops = [...items];
      calls++;
      if (calls === 2) {
        // Batch 2: really persist its first item (blob + event), then fail the rest.
        writer.appendBatch(ops.slice(0, 2));
        persistedFromFailedBatch.push(...eventKeys(ops.slice(0, 2)));
        throw new Error('TEST ONLY append failure in batch 2');
      }
      const result = writer.appendBatch(ops);
      for (const key of eventKeys(ops)) durable.add(key);
      return result;
    },
    closeSegment: () => writer.closeSegment(),
  });
  const checkingLookup = {
    has: lookup.has,
    add(key) {
      assert.ok(durable.has(key), 'a key is added only after appendBatch returned for its batch');
      lookup.add(key);
    },
  };

  await assert.rejects(() => runImport(ctx, { itemKeys: checkingLookup, wrapWriter }), /TEST ONLY append failure/);
  assert.equal(lookup.added.length, BATCH, 'only the keys of batch 1 are recorded');
  assert.equal(persistedFromFailedBatch.length, 1);
  assert.equal(lookup.keys.has(persistedFromFailedBatch[0]), false,
    'an item stored by a failed batch is not recorded (the index update before the next import catches it up)');
  assert.equal(storedCount(ctx), BATCH + 1);
});

test('in the checkpoint path a batch that fails after some events adds no key from that batch', async t => {
  const ctx = await setup(t, 'item-keys-checkpoint');
  const lookup = recordingLookup();
  let seen = 0;
  const checkpoint = point => {
    if (point === 'after-blob-before-event' && ++seen === BATCH + 2) {
      throw new Error('TEST ONLY crash before the second event of batch 2');
    }
  };
  await assert.rejects(() => runImport(ctx, { itemKeys: lookup, checkpoint }), /TEST ONLY crash/);
  // Batch 1 (4 events) and the first event of batch 2 are stored; only batch 1's keys are recorded.
  assert.equal(storedCount(ctx), BATCH + 1);
  assert.equal(lookup.added.length, BATCH);
});

// V-7a (A-41): a resolver may return undefined ("no key for this collection yet"); such items are deferred.
const CONTACTS = 3;

function storedKeys({ vaultDir, unlock }) {
  const unlocked = unlock();
  try {
    return loadExistingItemKeys(vaultDir, unlocked, readVaultRecord);
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

test('a resolver returning undefined defers that collection; a second run with a key imports exactly the deferred items', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v7a-deferred-'));
  t.after(() => removeTree(root));
  const zipPath = join(root, 'takeout.zip');
  const vaultDir = join(root, 'vault');
  await writeZipArchive(zipPath, [
    { path: 'Takeout/Mail/All mail.mbox', data: generateSyntheticMbox(MESSAGES, 717), compression: 'deflate' },
    { path: 'Takeout/Contacts/contacts.vcf', data: generateSyntheticVcards(CONTACTS, 1717), compression: 'deflate' },
  ]);
  const ctx = { zipPath, vaultDir, ...createVault(vaultDir) };
  const importers = [mailImporter, contactsImporter];
  const lookup = recordingLookup();
  const asked = [];
  // The ten synthetic messages all fall in one year, so many deferred items share one collection name.
  const isContacts = name => name.startsWith(CONTACTS_SOURCE_ID + '/');

  const first = await runImport(ctx, {
    importers, itemKeys: lookup,
    resolveCollectionKeyId: name => {
      asked.push(name);
      return isContacts(name) ? ctx.collectionKeyId : undefined;
    },
  });
  const mailNames = asked.filter(name => !isContacts(name));
  assert.equal(mailNames.length, MESSAGES);
  assert.equal(new Set(mailNames).size, 1);
  assert.deepEqual(first.missingCollections, [mailNames[0]], 'the deferred collection is listed once');
  assert.equal(first.totalItemsDeferred, MESSAGES);
  assert.equal(first.totalItemsImported, CONTACTS);
  assert.equal(first.totalItemsSkipped, 0);
  assert.equal(first.totalItemsErrored, 0);
  assert.equal(first.totalEventsWritten, CONTACTS);
  assert.equal(first.totalBlobsWritten, CONTACTS);
  assert.equal(lookup.added.length, CONTACTS);
  assert.deepEqual(storedKeys(ctx), new Set(lookup.added), 'only stored items reach itemKeys; no deferred key does');

  const second = await runImport(ctx, { importers, itemKeys: lookup });
  assert.equal(second.totalItemsDeferred, 0);
  assert.deepEqual(second.missingCollections, []);
  assert.equal(second.totalItemsImported, MESSAGES, 'exactly the deferred items');
  assert.equal(second.totalItemsSkipped, CONTACTS, 'nothing twice');
  assert.equal(second.totalEventsWritten, MESSAGES);
  assert.equal(lookup.added.length, MESSAGES + CONTACTS);
  assert.equal(new Set(lookup.added).size, MESSAGES + CONTACTS);
  assert.deepEqual(storedKeys(ctx), new Set(lookup.added));

  const third = await runImport(ctx, { importers, itemKeys: lookup });
  assert.equal(third.totalItemsImported, 0);
  assert.equal(third.totalItemsDeferred, 0);
  assert.equal(storedCount(ctx), MESSAGES + CONTACTS);
});

// V-7a review round 1: the bounded reader must return a buffer the pipeline owns. Zeroing a deferred or
// skipped item must never wipe another item that shares the importer's backing Buffer.
const SHARED_TEXT = 'TEST ONLY shared item bytes for the owned-buffer regression';
const SHARED_ENTRY = 'Takeout/TestOnly/shared.bin';
const SHARED_SOURCE = 'test-only/shared';

/** Test importer: reads its entry into ONE Buffer and yields it as the stream of two items in different years. */
const sharedBufferImporter = {
  id: SHARED_SOURCE,
  matches: entry => entry.path === SHARED_ENTRY,
  async *split(entry) {
    const chunks = [];
    for await (const chunk of entry.open()) chunks.push(Buffer.from(chunk));
    const shared = Buffer.concat(chunks);
    const base = { mime: 'application/octet-stream', tags: [] };
    yield { ...base, bytes: Readable.from([shared]), path: 'shared/first.bin', sourceTs: '2020-01-01T00:00:00Z' };
    yield { ...base, bytes: Readable.from([shared]), path: 'shared/second.bin', sourceTs: '2021-01-01T00:00:00Z' };
  },
};

/** Decrypted plaintext of every blob record in the vault (sealed and open segments), via readVaultRecord. */
function storedBlobs({ vaultDir, unlock }) {
  const unlocked = unlock();
  const blobs = [];
  try {
    const scanDir = (dir, segment) => {
      if (!existsSync(dir)) return;
      for (const stream of readdirSync(dir).filter(f => f.endsWith('.fvr')).sort()) {
        const size = statSync(join(dir, stream)).size;
        let offset = 0;
        while (offset < size) {
          const rec = readVaultRecord(vaultDir, { segment, stream, offset }, unlocked);
          if (rec.type === 2) blobs.push(Buffer.from(rec.plaintext));
          const plainLen = rec.plaintext.length;
          const frames = plainLen === 0 ? 1 : Math.ceil(plainLen / 1_048_576);
          offset += 69 + plainLen + frames * 20; // FVR1 record length
        }
      }
    };
    const segDir = join(vaultDir, 'segments');
    let maxSeg = 0;
    if (existsSync(segDir)) {
      for (const seg of readdirSync(segDir).sort()) {
        maxSeg = Number.parseInt(seg, 10);
        scanDir(join(segDir, seg), maxSeg);
      }
    }
    scanDir(join(vaultDir, 'open'), maxSeg + 1);
    return blobs;
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

test('two items sharing one backing Buffer: deferring or skipping one never zeroes the other before it is stored', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v7a-shared-'));
  t.after(() => removeTree(root));
  const zipPath = join(root, 'takeout.zip');
  const vaultDir = join(root, 'vault');
  await writeZipArchive(zipPath, [{ path: SHARED_ENTRY, data: Buffer.from(SHARED_TEXT), compression: 'deflate' }]);
  const ctx = { zipPath, vaultDir, ...createVault(vaultDir, { secondCollection: true }) };
  const expected = Buffer.from(SHARED_TEXT); // independent copy: never the importer's shared Buffer
  const importers = [sharedBufferImporter];
  const lookup = recordingLookup();
  const first2020 = `${SHARED_SOURCE}/2020`;
  const second2021 = `${SHARED_SOURCE}/2021`;

  // Run 1: the 2020 item is pending when the 2021 item is deferred (and zeroed).
  const first = await runImport(ctx, {
    importers, itemKeys: lookup,
    resolveCollectionKeyId: name => (name === first2020 ? ctx.collectionKeyId : undefined),
  });
  assert.equal(first.totalItemsImported, 1);
  assert.equal(first.totalItemsDeferred, 1);
  assert.deepEqual(first.missingCollections, [second2021]);
  const afterFirst = storedBlobs(ctx);
  assert.equal(afterFirst.length, 1);
  assert.deepEqual(afterFirst[0], expected, 'the stored first item holds the original bytes, not zeros');

  // Run 2: the resolver now has a key for 2021. The 2020 item is skipped (and zeroed) first.
  const resolveBoth = name => (name === first2020 ? ctx.collectionKeyId : name === second2021 ? ctx.secondCollectionKeyId : undefined);
  const second = await runImport(ctx, { importers, itemKeys: lookup, resolveCollectionKeyId: resolveBoth });
  assert.equal(second.totalItemsImported, 1, 'only the deferred item');
  assert.equal(second.totalItemsSkipped, 1);
  assert.equal(second.totalItemsDeferred, 0);
  assert.equal(second.totalBlobsWritten, 1);
  const afterSecond = storedBlobs(ctx);
  assert.equal(afterSecond.length, 2);
  for (const blob of afterSecond) assert.deepEqual(blob, expected, 'every stored item holds the original bytes');

  // Run 3: nothing new.
  const third = await runImport(ctx, { importers, itemKeys: lookup, resolveCollectionKeyId: resolveBoth });
  assert.equal(third.totalItemsImported, 0);
  assert.equal(third.totalEventsWritten, 0);
  assert.equal(third.totalItemsDeferred, 0);
  assert.equal(storedBlobs(ctx).length, 2);
  assert.equal(storedCount(ctx), 2);
});

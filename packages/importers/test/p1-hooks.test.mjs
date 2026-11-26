// TEST ONLY: P-1 importer hook tests (fix round 1). Synthetic data only.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  encodeKeyring,
  initializeVault,
  openVaultReplay,
  readVaultRecord,
  signingPublicKey,
  unlockByPassphrase,
  VaultWriter,
} from '../../vault/codec/dist/index.js';
import { DEFAULT_IMPORTERS, importArchive, openArchive, writeMultiPartTakeoutFolder } from '../dist/index.js';

const PASSPHRASE = 'TEST ONLY p1 hooks passphrase';

function removeTree(dir) {
  if (!existsSync(dir)) return;
  const makeWritable = target => {
    chmodSync(target, 0o700);
    for (const entry of readdirSync(target, { withFileTypes: true })) {
      const full = join(target, entry.name);
      if (entry.isDirectory()) makeWritable(full);
      else if (entry.isFile()) chmodSync(full, 0o600);
    }
  };
  makeWritable(dir);
  rmSync(dir, { recursive: true, force: true });
}

/** A vault with one `me` profile key and one collection key (copied from pipeline.test.mjs, not imported). */
function createTestVault(vaultDir) {
  const vaultId = randomBytes(16).toString('hex');
  const createdAt = '2026-11-21T00:00:00Z';
  const signingSeed = randomBytes(32);
  const recoveryKey = randomBytes(32);
  const profileKeyId = randomBytes(16).toString('hex');
  const collectionKeyId = randomBytes(16).toString('hex');
  const keyringBytes = encodeKeyring(
    {
      vaultId,
      version: 1,
      masterKey: randomBytes(32),
      entries: [
        { key_id: randomBytes(16).toString('hex'), kind: 'signing', parent: 'master', state: 'active', created_at: createdAt, key: signingSeed },
        { key_id: profileKeyId, kind: 'profile', parent: 'master', state: 'active', created_at: createdAt, key: randomBytes(32), label: 'me' },
        { key_id: collectionKeyId, kind: 'collection', parent: profileKeyId, state: 'active', created_at: createdAt, key: randomBytes(32) },
      ],
    },
    PASSPHRASE,
    recoveryKey,
  );
  mkdirSync(join(vaultDir, 'keyring'), { recursive: true });
  writeFileSync(join(vaultDir, 'keyring', 'keyring.json'), keyringBytes);
  initializeVault(vaultDir, { vaultId, createdAt, signingPublicKey: signingPublicKey(signingSeed) });
  return { vaultId, collectionKeyId, recoveryKey };
}

function importedEvents(vaultDir, recoveryKey) {
  const replay = openVaultReplay(vaultDir, { recoveryKey });
  try {
    const out = [];
    for (const entry of replay.replay()) {
      if (entry.type === 'blob') break;
      if (entry.type === 'event' && entry.event.kind === 'item.imported') out.push(entry.event);
    }
    return out;
  } finally {
    replay.close();
  }
}

test('P-1 hook: an async resolveSensitivity result is awaited and stored', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-p1-hooks-'));
  t.after(() => removeTree(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  await writeMultiPartTakeoutFolder(archiveDir, { seed: 91, contactsCount: 2, calendarEvents: 1, mailMessages: 2 });
  const { vaultId, collectionKeyId, recoveryKey } = createTestVault(vaultDir);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, PASSPHRASE);

  const seen = [];
  const archive = await openArchive(archiveDir);
  const writer = VaultWriter.open(vaultDir, unlocked);
  let result;
  try {
    result = await importArchive({
      archive,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      resolveSensitivity: async (source, path, item) => {
        await new Promise(resolve => setImmediate(resolve));
        seen.push({ source, path, size: item?.plaintext.length });
        return source === 'google-takeout/mail' ? 'clinical' : 'private';
      },
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
  } finally {
    writer.release();
    await archive.close();
  }

  assert.equal(result.totalItemsImported, 5);
  assert.equal(seen.length, 5);
  assert.ok(seen.every(s => s.size > 0));
  const events = importedEvents(vaultDir, recoveryKey);
  assert.equal(events.length, 5);
  for (const ev of events) {
    assert.equal(ev.sensitivity, ev.source === 'google-takeout/mail' ? 'clinical' : 'private', ev.source);
  }
});

test('B4: importArchive rejects a non-generic profile with INVALID_PROFILE before reading or writing anything', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-p1-hooks-'));
  t.after(() => removeTree(root));
  const vaultDir = join(root, 'vault');
  const { vaultId, collectionKeyId } = createTestVault(vaultDir);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, PASSPHRASE);
  let writes = 0;
  let reads = 0;
  const writer = {
    appendBatch() {
      writes++;
      throw new Error('must not write');
    },
    closeSegment() {
      writes++;
    },
  };
  const archive = {
    get entries() {
      reads++;
      throw new Error('must not read the archive');
    },
    parts: ['synthetic.zip'],
    async close() {},
  };
  const collectionCalls = [];
  for (const profile of ['Someone', 'ME', '', 'me/child']) {
    await assert.rejects(
      importArchive({
        archive,
        writer,
        importers: DEFAULT_IMPORTERS,
        profile,
        resolveCollectionKeyId: name => {
          collectionCalls.push(name);
          return collectionKeyId;
        },
        vaultDir,
        unlocked,
        readVaultRecord,
      }),
      err => err.name === 'ImportError' && err.code === 'INVALID_PROFILE' && !String(err.message).includes('Someone'),
      JSON.stringify(profile),
    );
  }
  assert.equal(writes, 0);
  assert.equal(reads, 0);
  assert.equal(collectionCalls.length, 0);
  // Every generic profile still passes the check (it then reads the archive and fails on the stub).
  for (const profile of ['me', 'partner', 'child', 'other']) {
    await assert.rejects(
      importArchive({ archive, writer, importers: DEFAULT_IMPORTERS, profile, resolveCollectionKeyId: () => collectionKeyId, vaultDir, unlocked, readVaultRecord }),
      /must not read the archive/u,
    );
  }
  assert.equal(writes, 0);
});

test('B11: an item already in the vault does not call resolveSensitivity on re-import', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-p1-hooks-'));
  t.after(() => removeTree(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  await writeMultiPartTakeoutFolder(archiveDir, { seed: 93, contactsCount: 2, calendarEvents: 1, mailMessages: 2 });
  const { vaultId, collectionKeyId, recoveryKey } = createTestVault(vaultDir);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, PASSPHRASE);

  const runOnce = async calls => {
    const archive = await openArchive(archiveDir);
    const writer = VaultWriter.open(vaultDir, unlocked);
    try {
      return await importArchive({
        archive,
        writer,
        importers: DEFAULT_IMPORTERS,
        resolveCollectionKeyId: () => collectionKeyId,
        resolveSensitivity: async (source, path) => {
          calls.push(`${source} ${path}`);
          return 'personal';
        },
        vaultDir,
        unlocked,
        readVaultRecord,
      });
    } finally {
      writer.release();
      await archive.close();
    }
  };

  const first = [];
  const r1 = await runOnce(first);
  assert.equal(r1.totalItemsImported, 5);
  assert.equal(first.length, 5);
  const second = [];
  const r2 = await runOnce(second);
  assert.equal(r2.totalItemsImported, 0);
  assert.equal(r2.totalItemsSkipped, 5);
  assert.deepEqual(second, [], 'the resolver ran for items that were already stored');
  assert.equal(importedEvents(vaultDir, recoveryKey).length, 5);
});

test('B11: a deferred item (no collection key yet) does not call resolveSensitivity', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-p1-hooks-'));
  t.after(() => removeTree(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  await writeMultiPartTakeoutFolder(archiveDir, { seed: 94, contactsCount: 1, calendarEvents: 1, mailMessages: 1 });
  const { vaultId } = createTestVault(vaultDir);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, PASSPHRASE);
  const archive = await openArchive(archiveDir);
  const writer = VaultWriter.open(vaultDir, unlocked);
  const calls = [];
  let result;
  try {
    result = await importArchive({
      archive,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => undefined,
      resolveSensitivity: () => {
        calls.push(1);
        return 'personal';
      },
      vaultDir,
      unlocked,
      readVaultRecord,
    });
  } finally {
    writer.release();
    await archive.close();
  }
  assert.equal(result.totalItemsDeferred, 3);
  assert.equal(calls.length, 0);
});

test('P-1 hook: a synchronous resolveSensitivity result is stored as before', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-p1-hooks-'));
  t.after(() => removeTree(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  await writeMultiPartTakeoutFolder(archiveDir, { seed: 92, contactsCount: 1, calendarEvents: 1, mailMessages: 1 });
  const { vaultId, collectionKeyId, recoveryKey } = createTestVault(vaultDir);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, PASSPHRASE);
  const archive = await openArchive(archiveDir);
  const writer = VaultWriter.open(vaultDir, unlocked);
  try {
    await importArchive({
      archive,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      resolveSensitivity: () => 'clinical',
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
  } finally {
    writer.release();
    await archive.close();
  }
  const events = importedEvents(vaultDir, recoveryKey);
  assert.equal(events.length, 3);
  assert.ok(events.every(ev => ev.sensitivity === 'clinical'));
});

test('H1 (round 2): a resolver that changes one byte of the item fails the import with RESOLVER_MODIFIED_ITEM and writes nothing', async t => {
  // The first item: nothing was flushed before it, so "zero new events" is exact.
  for (const flipAt of [1]) {
    const root = mkdtempSync(join(tmpdir(), 'foundry-p1-hooks-'));
    t.after(() => removeTree(root));
    const archiveDir = join(root, 'takeout');
    const vaultDir = join(root, 'vault');
    await writeMultiPartTakeoutFolder(archiveDir, { seed: 95, contactsCount: 2, calendarEvents: 1, mailMessages: 2 });
    const { vaultId, collectionKeyId, recoveryKey } = createTestVault(vaultDir);
    const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, PASSPHRASE);
    const archive = await openArchive(archiveDir);
    const writer = VaultWriter.open(vaultDir, unlocked);
    let calls = 0;
    let changed;
    try {
      await assert.rejects(
        importArchive({
          archive,
          writer,
          importers: DEFAULT_IMPORTERS,
          resolveCollectionKeyId: () => collectionKeyId,
          resolveSensitivity: (source, path, item) => {
            calls++;
            if (calls === flipAt) {
              changed = item.plaintext;
              changed[0] ^= 0x01;
            }
            return 'personal';
          },
          vaultDir,
          unlocked,
          readVaultRecord,
          closeSegmentOnFinish: true,
        }),
        err => err.name === 'ImportError' && err.code === 'RESOLVER_MODIFIED_ITEM',
        `flip at item ${flipAt}`,
      );
    } finally {
      writer.release();
      await archive.close();
    }
    assert.equal(calls, flipAt, 'no later item is classified');
    assert.ok(changed.every(b => b === 0), 'the changed buffer is zeroed');
    assert.equal(importedEvents(vaultDir, recoveryKey).length, 0, `flip at item ${flipAt}: zero new events`);
  }
});

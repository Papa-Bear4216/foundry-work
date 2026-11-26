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

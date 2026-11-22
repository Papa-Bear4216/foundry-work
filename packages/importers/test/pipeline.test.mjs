import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  encodeKeyring,
  initializeVault,
  readVaultRecord,
  signingPublicKey,
  unlockByPassphrase,
  VaultWriter,
  verifyVault,
  verifyVaultDeep,
} from '../../vault/codec/dist/index.js';
import {
  DEFAULT_DERIVERS,
  DEFAULT_IMPORTERS,
  importArchive,
  openArchive,
  writeMultiPartTakeoutFolder,
} from '../dist/index.js';

function makeWritableAndRemove(dir) {
  const segments = join(dir, 'segments');
  if (existsSync(segments)) {
    for (const seg of readdirSync(segments, { withFileTypes: true })) {
      const segPath = join(segments, seg.name);
      if (!seg.isDirectory()) continue;
      chmodSync(segPath, 0o700);
      for (const f of readdirSync(segPath, { withFileTypes: true })) {
        if (f.isFile()) chmodSync(join(segPath, f.name), 0o600);
      }
    }
  }
  rmSync(dir, { recursive: true, force: true });
}

function createTestVaultWithCollections(vaultDir, passphrase) {
  const vaultId = randomBytes(16).toString('hex');
  const createdAt = '2026-11-21T00:00:00Z';
  const masterKey = randomBytes(32);
  const signingSeed = randomBytes(32);
  const recoveryKey = randomBytes(32);
  const profileKeyId = randomBytes(16).toString('hex');
  const profileKey = randomBytes(32);
  const collectionKeyId = randomBytes(16).toString('hex');
  const collectionKey = randomBytes(32);

  const keyringBytes = encodeKeyring(
    {
      vaultId,
      version: 1,
      masterKey,
      entries: [
        { key_id: randomBytes(16).toString('hex'), kind: 'signing', parent: 'master', state: 'active', created_at: createdAt, key: signingSeed },
        { key_id: profileKeyId, kind: 'profile', parent: 'master', state: 'active', created_at: createdAt, key: profileKey, label: 'me' },
        { key_id: collectionKeyId, kind: 'collection', parent: profileKeyId, state: 'active', created_at: createdAt, key: collectionKey },
      ],
    },
    passphrase,
    recoveryKey,
  );

  mkdirSync(join(vaultDir, 'keyring'), { recursive: true });
  writeFileSync(join(vaultDir, 'keyring', 'keyring.json'), keyringBytes);
  initializeVault(vaultDir, { vaultId, createdAt, signingPublicKey: signingPublicKey(signingSeed) });
  return { vaultId, collectionKeyId };
}

function readAllVaultRecords(vaultDir, unlocked) {
  const events = [];
  const blobsBySeqOrder = [];
  const scanDir = (dir, segment) => {
    if (!existsSync(dir)) return;
    const files = readdirSync(dir).filter(f => f.endsWith('.fvr')).sort();
    for (const stream of files) {
      const full = join(dir, stream);
      const size = statSync(full).size;
      let offset = 0;
      while (offset < size) {
        const rec = readVaultRecord(vaultDir, { segment, stream, offset }, unlocked);
        if (rec.type === 1) {
          events.push({ seq: Number(rec.context), json: JSON.parse(rec.plaintext.toString('utf8')) });
        } else if (rec.type === 2) {
          blobsBySeqOrder.push({ segment, stream, offset, plaintext: rec.plaintext });
        }
        // Advance using FVR1 record length formula: 69 + frames
        const plainLen = rec.plaintext.length;
        const frames = plainLen === 0 ? 1 : Math.ceil(plainLen / 1_048_576);
        offset += 69 + plainLen + frames * 20;
      }
    }
  };
  const segDir = join(vaultDir, 'segments');
  let maxSeg = 0;
  if (existsSync(segDir)) {
    const segs = readdirSync(segDir).sort();
    for (const seg of segs) {
      maxSeg = Number.parseInt(seg, 10);
      scanDir(join(segDir, seg), maxSeg);
    }
  }
  scanDir(join(vaultDir, 'open'), maxSeg + 1);
  return { events, blobs: blobsBySeqOrder };
}

function vaultByteSize(dir) {
  let total = 0;
  for (const sub of ['segments', 'open']) {
    const p = join(dir, sub);
    if (!existsSync(p)) continue;
    const walk = d => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        const full = join(d, e.name);
        if (e.isDirectory()) walk(full);
        else if (e.isFile()) total += statSync(full).size;
      }
    };
    walk(p);
  }
  return total;
}

test('imports multi-part Takeout into real V-3 vault, reconstructs mbox byte-for-byte, derives all items, and re-import adds nothing', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-pipeline-'));
  t.after(() => makeWritableAndRemove(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 integration passphrase';

  const fixture = await writeMultiPartTakeoutFolder(archiveDir, {
    seed: 555,
    contactsCount: 5,
    calendarEvents: 4,
    mailMessages: 6,
    forceZip64: true,
  });
  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  const warned = [];
  const archive1 = await openArchive(archiveDir);
  const writer1 = VaultWriter.open(vaultDir, unlocked);
  let firstRun;
  try {
    firstRun = await importArchive({
      archive: archive1,
      writer: writer1,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
      onUnrecognisedEntry: p => warned.push(p),
    });
  } finally {
    writer1.release();
    await archive1.close();
  }

  // 5 contacts + 1 calendar file + 6 mail messages = 12 imported items; 1 unrecognised HTML file
  assert.equal(firstRun.totalItemsImported, 12);
  assert.equal(firstRun.totalBlobsWritten, 12);
  assert.equal(firstRun.totalEventsWritten, 12);
  assert.equal(firstRun.totalItemsSkipped, 0);
  assert.deepEqual(firstRun.unrecognisedEntries, ['Takeout/archive_browser.html']);
  assert.deepEqual(warned, ['Takeout/archive_browser.html']);

  const verified1 = verifyVaultDeep(vaultDir, unlocked);
  assert.equal(verified1.position.segment, 1);
  assert.equal(verified1.position.lastEventSequence, 12);
  const bytesAfterFirst = vaultByteSize(vaultDir);

  // Verify every event carries profile, collection (<source>/<year>), sensitivity, and verify mbox byte-for-byte reconstruction
  const { events, blobs } = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(events.length, 12);
  assert.equal(blobs.length, 12);

  const mailEvents = events.filter(e => e.json.source === 'google-takeout/mail');
  assert.equal(mailEvents.length, 6);
  for (const ev of events) {
    assert.equal(ev.json.kind, 'item.imported');
    assert.equal(ev.json.profile, 'me');
    assert.equal(ev.json.sensitivity, 'personal');
    assert.ok(ev.json.collection.startsWith(`${ev.json.source}/`));
    assert.equal(ev.json.body.item_key.length, 64);
  }

  // Reconstruct mbox byte-for-byte from stored vault blobs!
  const mailBlobs = [];
  for (let i = 0; i < events.length; i++) {
    if (events[i].json.source === 'google-takeout/mail') {
      assert.ok(typeof events[i].json.body.mbox_separator === 'string');
      mailBlobs.push(blobs[i].plaintext);
    }
  }
  assert.ok(
    Buffer.concat(mailBlobs).equals(fixture.rawMail),
    'concatenation of decrypted mail blobs from vault must equal original mbox byte-for-byte',
  );

  // Run Stage-2 derivers over decrypted vault blobs to prove clean V-4/V-7 handoff
  const deriverById = new Map(DEFAULT_DERIVERS.map(d => [d.id, d]));
  let derivedTextCount = 0;
  for (let i = 0; i < events.length; i++) {
    const ev = events[i].json;
    const deriver = deriverById.get(ev.source);
    assert.ok(deriver);
    const storedItem = {
      eventSeq: ev.seq,
      source: ev.source,
      path: ev.body.path,
      mime: ev.body.mime,
      size: ev.body.size,
      blobId: ev.body.blob,
      profile: ev.profile,
      collection: ev.collection,
      sensitivity: ev.sensitivity,
      sourceTs: ev.body.source_ts,
      tags: ev.tags,
    };
    for await (const out of deriver.derive(storedItem, Readable.from([blobs[i].plaintext]))) {
      if (out.kind === 'text') derivedTextCount++;
    }
  }
  // 5 contacts + 4 calendar VEVENTs + 6 mail messages = 15 derived text entries
  assert.equal(derivedTextCount, 15);

  // RE-IMPORT ADDS NOTHING: second import appends 0 blobs and 0 events
  const archive2 = await openArchive(archiveDir);
  const writer2 = VaultWriter.open(vaultDir, unlocked);
  let secondRun;
  try {
    secondRun = await importArchive({
      archive: archive2,
      writer: writer2,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
  } finally {
    writer2.release();
    await archive2.close();
  }

  assert.equal(secondRun.totalItemsImported, 0);
  assert.equal(secondRun.totalBlobsWritten, 0);
  assert.equal(secondRun.totalEventsWritten, 0);
  assert.equal(secondRun.totalItemsSkipped, 12);
  assert.equal(verifyVault(vaultDir).position.lastEventSequence, 12);
  assert.equal(verifyVault(vaultDir).position.segment, 1);
  assert.equal(vaultByteSize(vaultDir), bytesAfterFirst, 're-import must add zero bytes to the vault');
});

test('resumes cleanly after injectable crash between blob write and event write without duplicating blobs or events', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-crash-ckpt-'));
  t.after(() => makeWritableAndRemove(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 crash checkpoint passphrase';

  await writeMultiPartTakeoutFolder(archiveDir, { seed: 666, contactsCount: 4, calendarEvents: 2, mailMessages: 4 });
  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  // Run 1: inject crash right after writing blob #4, before writing event #4.
  const archive1 = await openArchive(archiveDir);
  const writer1 = VaultWriter.open(vaultDir, unlocked);
  try {
    await assert.rejects(
      () =>
        importArchive({
          archive: archive1,
          writer: writer1,
          importers: DEFAULT_IMPORTERS,
          resolveCollectionKeyId: () => collectionKeyId,
          vaultDir,
          unlocked,
          readVaultRecord,
          checkpoint(point, info) {
            if (point === 'after-blob-before-event' && info.itemIndex === 4) {
              throw new Error('INJECTED_CRASH_POINT');
            }
          },
        }),
      /INJECTED_CRASH_POINT/,
    );
  } finally {
    writer1.release();
    await archive1.close();
  }

  // Vault now has 3 events and 4 blobs in open/!
  const midState = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(midState.events.length, 3);
  assert.equal(midState.blobs.length, 4);

  // Run 2: resume import -> skips items 1..3, deduplicates blob #4, appends event #4 and remaining 5..9!
  const archive2 = await openArchive(archiveDir);
  const writer2 = VaultWriter.open(vaultDir, unlocked);
  let resumed;
  try {
    resumed = await importArchive({
      archive: archive2,
      writer: writer2,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
  } finally {
    writer2.release();
    await archive2.close();
  }

  // Total items = 4 contacts + 1 calendar + 4 mail = 9
  assert.equal(resumed.totalItemsSkipped, 3);
  assert.equal(resumed.totalItemsImported, 6);
  assert.equal(resumed.totalBlobsDeduplicated, 1, 'blob #4 written before crash must be deduplicated on resume');
  assert.equal(resumed.totalBlobsWritten, 5);
  assert.equal(resumed.totalEventsWritten, 6);

  const finalState = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(finalState.events.length, 9);
  assert.equal(finalState.blobs.length, 9);
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 9);
});

test('resumes cleanly after a child process terminates abruptly halfway through import', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-crash-proc-'));
  t.after(() => makeWritableAndRemove(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 child crash passphrase';

  const fixture = await writeMultiPartTakeoutFolder(archiveDir, {
    seed: 777,
    contactsCount: 3,
    calendarEvents: 2,
    mailMessages: 5,
  });
  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const childScript = fileURLToPath(new URL('./crash-child.mjs', import.meta.url));

  // Spawn child that abruptly terminates via process.exit(42) right after item #5's blob write
  const crashRun = spawnSync(
    process.execPath,
    [childScript, archiveDir, vaultDir, vaultId, collectionKeyId, '5'],
    { input: passphrase, encoding: 'utf8', timeout: 30_000 },
  );
  assert.ifError(crashRun.error);
  assert.equal(crashRun.status, 42, crashRun.stderr);

  // Spawn resume run in a fresh child process
  const resumeRun = spawnSync(
    process.execPath,
    [childScript, archiveDir, vaultDir, vaultId, collectionKeyId, '0'],
    { input: passphrase, encoding: 'utf8', timeout: 30_000 },
  );
  assert.ifError(resumeRun.error);
  assert.equal(resumeRun.status, 0, resumeRun.stderr);

  const summary = JSON.parse(resumeRun.stdout);
  assert.equal(summary.totalItemsSkipped, 4);
  assert.equal(summary.totalItemsImported, 5);
  assert.equal(summary.totalBlobsDeduplicated, 1);
  assert.equal(summary.totalBlobsWritten, 4);

  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 9);

  const { events, blobs } = readAllVaultRecords(vaultDir, unlocked);
  const mailBlobs = [];
  for (let i = 0; i < events.length; i++) {
    if (events[i].json.source === 'google-takeout/mail') mailBlobs.push(blobs[i].plaintext);
  }
  assert.ok(Buffer.concat(mailBlobs).equals(fixture.rawMail));
});

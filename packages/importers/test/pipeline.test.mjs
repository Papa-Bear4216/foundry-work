import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
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
  ArchiveError,
  DEFAULT_DERIVERS,
  DEFAULT_IMPORTERS,
  generateSyntheticIcalendar,
  generateSyntheticMbox,
  generateSyntheticVcards,
  importArchive,
  ImportError,
  mailImporter,
  openArchive,
  syntheticEmail,
  writeMultiPartTakeoutFolder,
  writeStreamedZip64Archive,
  writeZipArchive,
} from '../dist/index.js';
import { crc32 } from 'node:zlib';
import { measurePeakRss } from './budget/peak-rss.mjs';

/** Recursively restores write permissions on all subdirectories (including nested vault/segments) before rmSync on POSIX. */
function makeWritableAndRemove(dir) {
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

  // 5 contacts + 1 calendar file + 6 mail messages = 12 imported items; 1 unrecognised HTML file; 3 parts seen
  assert.equal(firstRun.partsCount, 3);
  assert.deepEqual(firstRun.parts, fixture.parts);
  assert.equal(firstRun.totalItemsImported, 12);
  assert.equal(firstRun.totalBlobsWritten, 12);
  assert.equal(firstRun.totalEventsWritten, 12);
  assert.equal(firstRun.totalItemsSkipped, 0);
  assert.equal(firstRun.totalItemsErrored, 0);
  assert.deepEqual(firstRun.itemErrors, []);
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

  // RE-IMPORT ADDS NOTHING: two sequential public calls add nothing the second time
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

  assert.equal(secondRun.partsCount, 3);
  assert.equal(secondRun.totalItemsImported, 0);
  assert.equal(secondRun.totalBlobsWritten, 0);
  assert.equal(secondRun.totalEventsWritten, 0);
  assert.equal(secondRun.totalItemsSkipped, 12);
  assert.equal(verifyVault(vaultDir).position.lastEventSequence, 12);
  assert.equal(verifyVault(vaultDir).position.segment, 1);
  assert.equal(vaultByteSize(vaultDir), bytesAfterFirst, 're-import must add zero bytes to the vault');
});

test('aborts with typed error and zero vault writes when the last mbox entry has a corrupt CRC (Ruling 1)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-corrupt-crc-'));
  t.after(() => makeWritableAndRemove(root));
  const archiveDir = join(root, 'takeout');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 corrupt crc passphrase';

  await writeMultiPartTakeoutFolder(archiveDir, {
    seed: 801,
    contactsCount: 3,
    calendarEvents: 2,
    mailMessages: 25, // > 16 messages (would have flushed a batch before EOF without pre-validation!)
  });

  // Corrupt the CRC of the mbox entry in part 3 (both LFH and CD CRC flipped so openZipFile passes
  // and streaming validation catches CRC_MISMATCH on the final mbox entry).
  const part3Path = join(archiveDir, 'takeout-20261121T000000Z-003.zip');
  const buf = Buffer.from(readFileSync(part3Path));
  const lfhPos = buf.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  const cdPos = buf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  const badCrc = (buf.readUInt32LE(cdPos + 16) ^ 0xffffffff) >>> 0;
  buf.writeUInt32LE(badCrc, lfhPos + 14);
  buf.writeUInt32LE(badCrc, cdPos + 16);
  writeFileSync(part3Path, buf);

  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  const archive = await openArchive(archiveDir);
  const writer = VaultWriter.open(vaultDir, unlocked);
  let appendCalls = 0;
  const spyWriter = {
    appendBatch(items) {
      appendCalls++;
      return writer.appendBatch(items);
    },
    closeSegment() {
      return writer.closeSegment();
    },
  };

  try {
    await assert.rejects(
      () =>
        importArchive({
          archive,
          writer: spyWriter,
          importers: DEFAULT_IMPORTERS,
          resolveCollectionKeyId: () => collectionKeyId,
          vaultDir,
          unlocked,
          readVaultRecord,
        }),
      err => err instanceof ArchiveError && err.code === 'CRC_MISMATCH',
    );
  } finally {
    writer.release();
    await archive.close();
  }

  assert.equal(appendCalls, 0, 'corrupt archive must abort with zero vault append calls');
  const state = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(state.events.length, 0);
  assert.equal(state.blobs.length, 0);
  assert.equal(verifyVault(vaultDir).position.lastEventSequence, 0);
});

test('skips a 300 MiB stored mail message with typed ITEM_TOO_LARGE while keeping import peak under 256 MiB (Ruling 6)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-300mib-'));
  t.after(() => makeWritableAndRemove(root));
  const zipPath = join(root, 'oversize-mail.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 300mib passphrase';

  const targetHugeBytes = 300 * 1024 * 1024;
  const sender = syntheticEmail('huge-sender');
  const recipient = syntheticEmail('huge-recipient');
  const hugeHeader = Buffer.from(
    [
      'From 100001@xxx Mon Jan 01 12:00:00 +0000 2024',
      `From: <${sender}>`,
      `To: <${recipient}>`,
      'Date: Mon, 01 Jan 2024 12:00:00 +0000',
      'Subject: TEST ONLY 300 MiB oversized mail message',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      '',
    ].join('\r\n'),
    'utf8',
  );
  const fillerLine = Buffer.from('A'.repeat(1022) + '\r\n', 'ascii'); // 1 KiB
  const fillerChunk = Buffer.concat(Array.from({ length: 64 }, () => fillerLine)); // 64 KiB
  const smallSecondMsg = Buffer.from(
    [
      'From 100002@xxx Tue Jan 02 12:00:00 +0000 2024',
      `From: <${sender}>`,
      `To: <${recipient}>`,
      'Date: Tue, 02 Jan 2024 12:00:00 +0000',
      'Subject: TEST ONLY normal follow-up message',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Small valid message after 300 MiB over-limit message.\r\n',
    ].join('\r\n'),
    'utf8',
  );

  await writeZipArchive(zipPath, [
    {
      path: 'Takeout/Mail/Oversized.mbox',
      compression: 'store',
      data: async function* () {
        yield hugeHeader;
        let remaining = targetHugeBytes;
        while (remaining > 0) {
          const take = Math.min(remaining, fillerChunk.length);
          yield take === fillerChunk.length ? fillerChunk : fillerChunk.subarray(0, take);
          remaining -= take;
        }
        yield Buffer.from('\r\n', 'ascii');
        yield smallSecondMsg;
      },
    },
  ]);

  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const probeScript = fileURLToPath(new URL('./oversize-probe.mjs', import.meta.url));
  const measured = measurePeakRss(probeScript, [zipPath, vaultDir, vaultId, collectionKeyId], root, passphrase);
  assert.equal(measured.status, 0, measured.stderr);

  const { peakRssKiB, summary } = JSON.parse(measured.stdout);
  const externalPeakKiB = Math.round(measured.externalPeakKiB);
  const worstKiB = Math.max(peakRssKiB, externalPeakKiB);

  assert.equal(summary.totalItemsImported, 1, 'normal second message must still be imported');
  assert.equal(summary.totalItemsSkipped, 1);
  assert.equal(summary.totalItemsErrored, 1);
  assert.equal(summary.itemErrors.length, 1);
  assert.equal(summary.itemErrors[0].code, 'ITEM_TOO_LARGE');
  assert.equal(summary.itemErrors[0].itemPath, 'Takeout/Mail/Oversized.mbox#1');
  assert.ok(
    worstKiB <= 256 * 1024,
    `300 MiB over-limit mail import exceeded 256 MiB ceiling (worst=${(worstKiB / 1024).toFixed(2)} MiB).`,
  );
  assert.equal(verifyVault(vaultDir).position.lastEventSequence, 1);
});

test('requires vault-derived identity state, deduplicates within a batch, and adds no duplicate after an append throws (Ruling 9)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-ruling9-'));
  t.after(() => makeWritableAndRemove(root));
  const zipPath = join(root, 'mail.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 ruling9 passphrase';

  const rawMbox = generateSyntheticMbox(4, 909);
  await writeZipArchive(zipPath, [{ path: 'Takeout/Mail/All mail.mbox', data: rawMbox, compression: 'deflate' }]);
  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  // 1. Writer-only path (missing vaultDir/unlocked/readVaultRecord) must be rejected
  const archiveCheck = await openArchive(zipPath);
  const writerCheck = VaultWriter.open(vaultDir, unlocked);
  try {
    await assert.rejects(
      () =>
        importArchive({
          archive: archiveCheck,
          writer: writerCheck,
          importers: [mailImporter],
          resolveCollectionKeyId: () => collectionKeyId,
        }),
      TypeError,
    );
  } finally {
    writerCheck.release();
    await archiveCheck.close();
  }

  // 2. Intra-batch duplicate deduplication using a custom importer yielding the same item twice in one batch
  const dupImporter = {
    id: 'google-takeout/mail',
    matches: entry => entry.path.endsWith('.mbox'),
    async *split(entry) {
      const msg = Buffer.from(
        'From 1@xxx Mon Jan 01 00:00:00 +0000 2024\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: Dup\r\n\r\nBody\r\n',
        'utf8',
      );
      for (let i = 0; i < 2; i++) {
        yield {
          bytes: Readable.from([msg]),
          path: `${entry.path}#dup`,
          mime: 'message/rfc822',
          sourceTs: '2024-01-01T00:00:00Z',
          tags: ['mail'],
        };
      }
    },
  };
  const dupVaultDir = join(root, 'vault-dup');
  const { vaultId: dupVaultId, collectionKeyId: dupColKeyId } = createTestVaultWithCollections(dupVaultDir, passphrase);
  const dupUnlocked = unlockByPassphrase(join(dupVaultDir, 'keyring', 'keyring.json'), dupVaultId, passphrase);
  const dupArchive = await openArchive(zipPath);
  const dupWriter = VaultWriter.open(dupVaultDir, dupUnlocked);
  try {
    const dupRes = await importArchive({
      archive: dupArchive,
      writer: dupWriter,
      importers: [dupImporter],
      resolveCollectionKeyId: () => dupColKeyId,
      vaultDir: dupVaultDir,
      unlocked: dupUnlocked,
      readVaultRecord,
      batchMaxItems: 16,
    });
    assert.equal(dupRes.totalItemsImported, 1);
    assert.equal(dupRes.totalEventsWritten, 1);
    assert.equal(dupRes.totalItemsSkipped, 1);
  } finally {
    dupWriter.release();
    await dupArchive.close();
  }

  // 3. Throw AFTER an event append is persisted to the vault, followed by a retry -> zero duplicates!
  const archive1 = await openArchive(zipPath);
  const writer1 = VaultWriter.open(vaultDir, unlocked);
  let injected = false;
  const flakyWriter = {
    appendBatch(items) {
      const arr = [...items];
      if (!injected && arr.length >= 2) {
        injected = true;
        // Actually persist item #1 (blob + event) to the real V-3 vault, then throw mid-batch!
        writer1.appendBatch(arr.slice(0, 2));
        throw new Error('SIMULATED_THROW_AFTER_EVENT_APPEND');
      }
      return writer1.appendBatch(arr);
    },
    closeSegment() {
      return writer1.closeSegment();
    },
  };

  try {
    await assert.rejects(
      () =>
        importArchive({
          archive: archive1,
          writer: flakyWriter,
          importers: [mailImporter],
          resolveCollectionKeyId: () => collectionKeyId,
          vaultDir,
          unlocked,
          readVaultRecord,
        }),
      /SIMULATED_THROW_AFTER_EVENT_APPEND/,
    );
  } finally {
    writer1.release();
    await archive1.close();
  }

  // Confirm 1 event was already persisted before the throw
  const mid = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(mid.events.length, 1);
  assert.equal(mid.blobs.length, 1);

  // Retry import on the same vault -> skips already-persisted item #1, imports items #2..#4, zero duplicates!
  const archive2 = await openArchive(zipPath);
  const writer2 = VaultWriter.open(vaultDir, unlocked);
  let retryRes;
  try {
    retryRes = await importArchive({
      archive: archive2,
      writer: writer2,
      importers: [mailImporter],
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

  assert.equal(retryRes.totalItemsSkipped, 1);
  assert.equal(retryRes.totalItemsImported, 3);
  assert.equal(retryRes.totalEventsWritten, 3);
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 4);
  const finalRecords = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(finalRecords.events.length, 4);
  assert.equal(new Set(finalRecords.events.map(e => e.json.body.item_key)).size, 4);
});

test('counts and reports unfinished and nested vCard errors in ImportResult while continuing valid items (Ruling 10)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-vcard-errs-'));
  t.after(() => makeWritableAndRemove(root));
  const zipPath = join(root, 'bad-vcards.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 vcard errs passphrase';

  const vcfBytes = Buffer.from(
    [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Outer Broken',
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Valid Middle',
      'END:VCARD',
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Unfinished Tail',
      '',
    ].join('\r\n'),
    'utf8',
  );
  await writeZipArchive(zipPath, [{ path: 'Takeout/Contacts/contacts.vcf', data: vcfBytes, compression: 'deflate' }]);
  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  const archive = await openArchive(zipPath);
  const writer = VaultWriter.open(vaultDir, unlocked);
  let res;
  try {
    res = await importArchive({
      archive,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
  } finally {
    writer.release();
    await archive.close();
  }

  assert.equal(res.totalItemsImported, 1);
  assert.equal(res.totalItemsErrored, 2);
  assert.deepEqual(
    res.itemErrors.map(e => e.code),
    ['VCARD_NESTED_BEGIN', 'VCARD_UNFINISHED'],
  );
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 1);
});

test('resolves identical UTC collections across TZ environments (including rejected header fallback to mbox separator and calendar ZIP entry time under UTC vs Pacific/Auckland) and re-import adds nothing (Ruling 12, Round 2 Finding 9, Round 3 Finding 1)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-tz-'));
  t.after(() => makeWritableAndRemove(root));
  const zipPath = join(root, 'zoneless.zip');
  const vaultA = join(root, 'vault-utc');
  const vaultB = join(root, 'vault-auckland');
  const passphrase = 'TEST ONLY v5 tz passphrase';

  // Boundary timestamps near New Year WITHOUT time zones — host TZ would shift these across 2024/2025!
  const zonelessMbox = Buffer.from(
    [
      'From 1001@xxx 2024-12-31T23:30:00',
      `From: <${syntheticEmail('tz-sender')}>`,
      `To: <${syntheticEmail('tz-recipient')}>`,
      'Subject: TEST ONLY zone-less ISO separator near New Year',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'ISO separator body.\r\n',
      'From 1002@xxx Tue Dec 31 23:45:00 2024',
      `From: <${syntheticEmail('tz-sender')}>`,
      `To: <${syntheticEmail('tz-recipient')}>`,
      'Date: Tue, 31 Dec 2024 23:45:00',
      'Subject: TEST ONLY zone-less RFC 5322 date near New Year',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'RFC 5322 body.\r\n',
    ].join('\r\n'),
    'utf8',
  );
  // Round 2 Finding 9 & Round 3 Finding 1:
  // - Rejected `Date: 00:30:00 Jan-01-2024` with no mbox separator -> undated under both TZ=UTC and TZ=Pacific/Auckland.
  // - Rejected `Date: 00:30:00 Jan-01-2024` with a 2019 mbox separator -> falls back to 2019 under both TZs.
  const unsupportedDateMbox = Buffer.from(
    [
      `From: <${syntheticEmail('tz-sender')}>`,
      `To: <${syntheticEmail('tz-recipient')}>`,
      'Date: 00:30:00 Jan-01-2024',
      'Subject: TEST ONLY unsupported date without separator must be undated',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Unsupported date body.\r\n',
    ].join('\r\n'),
    'utf8',
  );
  const rejectedHeaderWithSepMbox = Buffer.from(
    [
      'From 1003@xxx Tue Dec 31 23:45:00 2019',
      `From: <${syntheticEmail('tz-sender')}>`,
      `To: <${syntheticEmail('tz-recipient')}>`,
      'Date: 00:30:00 Jan-01-2024',
      'Subject: TEST ONLY unsupported Date header falls back to 2019 mbox separator',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Fallback separator body.\r\n',
    ].join('\r\n'),
    'utf8',
  );
  const zonelessVcf = Buffer.from(
    [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Zone-less Contact',
      'REV:2024-12-31T23:30:00',
      'END:VCARD',
      '',
    ].join('\r\n'),
    'utf8',
  );
  const zonelessIcs = Buffer.from(
    [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'BEGIN:VEVENT',
      'UID:tz-test-1',
      'DTSTART:20241231T233000',
      'SUMMARY:Zone-less Event',
      'END:VEVENT',
      'END:VCALENDAR',
      '',
    ].join('\r\n'),
    'utf8',
  );
  // Round 3 Finding 1: calendar whose only event date is rejected by the grammar falls back to ZIP entry time (2021).
  const rejectedDateIcs = Buffer.from(
    [
      'BEGIN:VCALENDAR',
      'VERSION:2.0',
      'BEGIN:VEVENT',
      'UID:tz-test-rejected-1',
      'DTSTART:00:30:00 Jan-01-2024',
      'SUMMARY:Rejected Date Event',
      'END:VEVENT',
      'END:VCALENDAR',
      '',
    ].join('\r\n'),
    'utf8',
  );

  await writeZipArchive(zipPath, [
    { path: 'Takeout/Mail/Zoneless.mbox', data: zonelessMbox },
    { path: 'Takeout/Mail/UnsupportedDate.mbox', data: unsupportedDateMbox },
    { path: 'Takeout/Mail/RejectedHeaderWithSep.mbox', data: rejectedHeaderWithSepMbox },
    { path: 'Takeout/Contacts/Zoneless.vcf', data: zonelessVcf },
    { path: 'Takeout/Calendar/Zoneless.ics', data: zonelessIcs },
    {
      path: 'Takeout/Calendar/RejectedDate.ics',
      data: rejectedDateIcs,
      mtime: new Date('2021-12-31T23:30:00Z'),
    },
  ]);

  const vA = createTestVaultWithCollections(vaultA, passphrase);
  const vB = createTestVaultWithCollections(vaultB, passphrase);
  const tzChild = fileURLToPath(new URL('./tz-child.mjs', import.meta.url));

  const runInTz = (tz, vaultDir, info) => {
    const r = spawnSync(
      process.execPath,
      [tzChild, zipPath, vaultDir, info.vaultId, info.collectionKeyId],
      {
        input: passphrase,
        encoding: 'utf8',
        timeout: 30_000,
        env: { ...process.env, TZ: tz },
      },
    );
    assert.ifError(r.error);
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  };

  const utcRun = runInTz('UTC', vaultA, vA);
  const aucklandRun = runInTz('Pacific/Auckland', vaultB, vB);

  assert.equal(utcRun.summary.totalItemsImported, 7);
  assert.equal(aucklandRun.summary.totalItemsImported, 7);
  assert.deepEqual(utcRun.collections, aucklandRun.collections, 'collections and UTC timestamps must be identical under TZ=UTC and TZ=Pacific/Auckland');

  const unsupportedItem = utcRun.collections.find(c => c.path === 'Takeout/Mail/UnsupportedDate.mbox#1');
  assert.ok(unsupportedItem);
  assert.equal(unsupportedItem.collection, 'google-takeout/mail/undated');
  assert.equal(unsupportedItem.sourceTs, undefined);

  const fallbackMailItem = utcRun.collections.find(c => c.path === 'Takeout/Mail/RejectedHeaderWithSep.mbox#1');
  assert.ok(fallbackMailItem);
  assert.equal(fallbackMailItem.collection, 'google-takeout/mail/2019');
  assert.equal(fallbackMailItem.sourceTs, '2019-12-31T23:45:00Z');

  const fallbackCalItem = utcRun.collections.find(c => c.path === 'Takeout/Calendar/RejectedDate.ics');
  assert.ok(fallbackCalItem);
  assert.equal(fallbackCalItem.collection, 'google-takeout/calendar/2021');
  assert.equal(fallbackCalItem.sourceTs, '2021-12-31T23:30:00Z');

  const specialPaths = new Set([
    'Takeout/Mail/UnsupportedDate.mbox#1',
    'Takeout/Mail/RejectedHeaderWithSep.mbox#1',
    'Takeout/Calendar/RejectedDate.ics',
  ]);
  for (const item of utcRun.collections) {
    if (specialPaths.has(item.path)) continue;
    assert.ok(item.collection.endsWith('/2024'), `expected 2024 UTC collection, got ${item.collection}`);
  }

  // Re-import the SAME archive into vaultA under TZ=Pacific/Auckland -> adds nothing!
  const bytesBeforeReimport = vaultByteSize(vaultA);
  const crossTzReimport = runInTz('Pacific/Auckland', vaultA, vA);
  assert.equal(crossTzReimport.summary.totalItemsImported, 0);
  assert.equal(crossTzReimport.summary.totalBlobsWritten, 0);
  assert.equal(crossTzReimport.summary.totalEventsWritten, 0);
  assert.equal(crossTzReimport.summary.totalItemsSkipped, 7);
  assert.equal(vaultByteSize(vaultA), bytesBeforeReimport);
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

test('imports valid streamed ZIP64 archive (Python zipfile force_zip64 layout) and rejects descriptor CRC mismatch with zero vault writes (Round 2 Finding 1)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-r2-f1-'));
  t.after(() => makeWritableAndRemove(root));
  const validZip = join(root, 'streamed-zip64.zip');
  const corruptZip = join(root, 'streamed-zip64-bad-desc.zip');
  const vaultGood = join(root, 'vault-good');
  const vaultBad = join(root, 'vault-bad');
  const passphrase = 'TEST ONLY v5 r2 f1 passphrase';

  const vcfBytes = generateSyntheticVcards(3, 1201);
  const mboxBytes = generateSyntheticMbox(4, 1202);

  await writeStreamedZip64Archive(validZip, [
    { path: 'Takeout/Contacts/All Contacts.vcf', data: vcfBytes, compression: 'deflate' },
    { path: 'Takeout/Mail/All mail.mbox', data: mboxBytes, compression: 'deflate' },
  ]);
  await writeStreamedZip64Archive(corruptZip, [
    { path: 'Takeout/Contacts/All Contacts.vcf', data: vcfBytes, compression: 'deflate' },
    {
      path: 'Takeout/Mail/All mail.mbox',
      data: mboxBytes,
      compression: 'deflate',
      descriptorCrc: ((crc32(mboxBytes) ^ 0xffffffff) >>> 0),
    },
  ]);

  // 1. Valid streamed ZIP64 archive imports cleanly
  const goodMeta = createTestVaultWithCollections(vaultGood, passphrase);
  const goodUnlocked = unlockByPassphrase(join(vaultGood, 'keyring', 'keyring.json'), goodMeta.vaultId, passphrase);
  const goodArchive = await openArchive(validZip);
  const goodWriter = VaultWriter.open(vaultGood, goodUnlocked);
  try {
    const res = await importArchive({
      archive: goodArchive,
      writer: goodWriter,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => goodMeta.collectionKeyId,
      vaultDir: vaultGood,
      unlocked: goodUnlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
    assert.equal(res.totalItemsImported, 7);
    assert.equal(res.totalEventsWritten, 7);
  } finally {
    goodWriter.release();
    await goodArchive.close();
  }
  assert.equal(verifyVaultDeep(vaultGood, goodUnlocked).position.lastEventSequence, 7);

  // 2. Descriptor CRC mismatch -> typed ArchiveError, zero vault writes
  const badMeta = createTestVaultWithCollections(vaultBad, passphrase);
  const badUnlocked = unlockByPassphrase(join(vaultBad, 'keyring', 'keyring.json'), badMeta.vaultId, passphrase);
  await assert.rejects(
    async () => {
      const badArchive = await openArchive(corruptZip);
      const badWriter = VaultWriter.open(vaultBad, badUnlocked);
      try {
        await importArchive({
          archive: badArchive,
          writer: badWriter,
          importers: DEFAULT_IMPORTERS,
          resolveCollectionKeyId: () => badMeta.collectionKeyId,
          vaultDir: vaultBad,
          unlocked: badUnlocked,
          readVaultRecord,
        });
      } finally {
        badWriter.release();
        await badArchive.close();
      }
    },
    err => err instanceof ArchiveError && err.code === 'INVALID_DATA_DESCRIPTOR',
  );
  const badRecords = readAllVaultRecords(vaultBad, badUnlocked);
  assert.equal(badRecords.events.length, 0);
  assert.equal(badRecords.blobs.length, 0);
  assert.equal(verifyVault(vaultBad).position.lastEventSequence, 0);
});

test('rejects direct and single-folder import of Takeout part 002 (timestamped and timestamp-free) with zero writer calls while takeout-001 and standalone archives import normally (Round 2 Finding 3, Round 3 Finding 3 & Round 4)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-r2-f3-'));
  t.after(() => makeWritableAndRemove(root));
  const part2Path = join(root, 'takeout-20261121T000000Z-002.zip');
  const tsFreePart2Path = join(root, 'takeout-002.zip');
  const tsFreeSetPart2Path = join(root, 'takeout-set-002.zip');
  const tsFreePart2Dir = mkdtempSync(join(root, 'lone-takeout-002-dir-'));
  const tsFreePart1Path = join(root, 'takeout-001.zip');
  const singlePath = join(root, 'personal-export.zip');
  const calendar2024Path = join(root, 'Calendar-2024.zip');
  const mailBackupPath = join(root, 'mail-backup-002.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 r2 f3 passphrase';

  const vcf = generateSyntheticVcards(2, 1301);
  const vcfPart1 = generateSyntheticVcards(1, 1304);
  const ics = generateSyntheticIcalendar(1, 1302);
  const mbox = generateSyntheticMbox(1, 1303);
  await writeZipArchive(part2Path, [{ path: 'Takeout/Contacts/contacts.vcf', data: vcf, compression: 'deflate' }]);
  await writeZipArchive(tsFreePart2Path, [{ path: 'Takeout/Contacts/contacts.vcf', data: vcf, compression: 'deflate' }]);
  await writeZipArchive(tsFreeSetPart2Path, [{ path: 'Takeout/Contacts/contacts.vcf', data: vcf, compression: 'deflate' }]);
  await writeZipArchive(join(tsFreePart2Dir, 'takeout-002.zip'), [
    { path: 'Takeout/Contacts/contacts.vcf', data: vcf, compression: 'deflate' },
  ]);
  await writeZipArchive(tsFreePart1Path, [{ path: 'Takeout/Contacts/part1.vcf', data: vcfPart1, compression: 'deflate' }]);
  await writeZipArchive(singlePath, [{ path: 'Takeout/Contacts/contacts.vcf', data: vcf, compression: 'deflate' }]);
  await writeZipArchive(calendar2024Path, [{ path: 'Takeout/Calendar/year2024.ics', data: ics, compression: 'deflate' }]);
  await writeZipArchive(mailBackupPath, [{ path: 'Takeout/Mail/backup.mbox', data: mbox, compression: 'deflate' }]);

  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  let writerCalls = 0;
  const spyWriter = {
    appendBatch() {
      writerCalls += 1;
      throw new Error('writer must not be called for invalid multipart archive');
    },
    closeSegment() {
      writerCalls += 1;
      throw new Error('writer must not be called for invalid multipart archive');
    },
  };

  for (const invalidTarget of [part2Path, tsFreePart2Path, tsFreeSetPart2Path, tsFreePart2Dir]) {
    await assert.rejects(
      async () => {
        const archive = await openArchive(invalidTarget);
        try {
          await importArchive({
            archive,
            writer: spyWriter,
            importers: DEFAULT_IMPORTERS,
            resolveCollectionKeyId: () => collectionKeyId,
            vaultDir,
            unlocked,
            readVaultRecord,
          });
        } finally {
          await archive.close();
        }
      },
      err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART' && /part 1/i.test(err.message),
      `expected ${invalidTarget} to fail with INVALID_MULTIPART`,
    );
  }
  assert.equal(writerCalls, 0);
  const emptyRecords = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(emptyRecords.events.length, 0);
  assert.equal(emptyRecords.blobs.length, 0);

  for (const [zipFile, expectedNew] of [
    [tsFreePart1Path, 1],
    [singlePath, 2],
    [calendar2024Path, 1],
    [mailBackupPath, 1],
  ]) {
    const archive = await openArchive(zipFile);
    const writer = VaultWriter.open(vaultDir, unlocked);
    try {
      const res = await importArchive({
        archive,
        writer,
        importers: DEFAULT_IMPORTERS,
        resolveCollectionKeyId: () => collectionKeyId,
        vaultDir,
        unlocked,
        readVaultRecord,
        closeSegmentOnFinish: zipFile === mailBackupPath,
      });
      assert.equal(res.totalItemsImported, expectedNew);
    } finally {
      writer.release();
      await archive.close();
    }
  }
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 5);
});

test('rejects concurrent importArchive calls sharing one writer with typed BUSY error and zero duplicates (Round 2 Finding 8)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-r2-f8-'));
  t.after(() => makeWritableAndRemove(root));
  const zipPath = join(root, 'concurrent.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 r2 f8 passphrase';

  const rawMbox = generateSyntheticMbox(8, 1801);
  await writeZipArchive(zipPath, [{ path: 'Takeout/Mail/All mail.mbox', data: rawMbox, compression: 'deflate' }]);
  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  const archiveA = await openArchive(zipPath);
  const archiveB = await openArchive(zipPath);
  const writer = VaultWriter.open(vaultDir, unlocked);
  try {
    const [resA, resB] = await Promise.allSettled([
      importArchive({
        archive: archiveA,
        writer,
        importers: DEFAULT_IMPORTERS,
        resolveCollectionKeyId: () => collectionKeyId,
        vaultDir,
        unlocked,
        readVaultRecord,
      }),
      importArchive({
        archive: archiveB,
        writer,
        importers: DEFAULT_IMPORTERS,
        resolveCollectionKeyId: () => collectionKeyId,
        vaultDir,
        unlocked,
        readVaultRecord,
      }),
    ]);

    const fulfilled = [resA, resB].filter(r => r.status === 'fulfilled');
    const rejected = [resA, resB].filter(r => r.status === 'rejected');
    assert.equal(fulfilled.length, 1, 'exactly one concurrent import must succeed');
    assert.equal(rejected.length, 1, 'the overlapping import on the same writer must fail fast');
    assert.ok(rejected[0].reason instanceof ImportError);
    assert.equal(rejected[0].reason.code, 'BUSY');
    assert.equal(fulfilled[0].value.totalItemsImported, 8);

    // A failing import must also release the writer guard.
    await assert.rejects(
      () =>
        importArchive({
          archive: archiveB,
          writer,
          importers: DEFAULT_IMPORTERS,
          resolveCollectionKeyId: () => {
            throw new Error('INJECTED_KEY_LOOKUP_ERROR');
          },
          vaultDir,
          unlocked,
          readVaultRecord,
        }),
      /INJECTED_KEY_LOOKUP_ERROR/,
    );

    // After the first call completes (or fails), the writer guard must be released so sequential re-import works and adds nothing.
    const sequential = await importArchive({
      archive: archiveB,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
    assert.equal(sequential.totalItemsImported, 0);
    assert.equal(sequential.totalItemsSkipped, 8);
  } finally {
    writer.release();
    await archiveA.close();
    await archiveB.close();
  }

  const records = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(records.events.length, 8);
  assert.equal(records.blobs.length, 8);
  assert.equal(new Set(records.events.map(e => e.json.body.item_key)).size, 8);
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 8);
});

test('preserves two-digit year 0099 in vCard REV without shifting to 1999 or dropping to undated (Round 2 Finding 10)', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v5-r2-f10-'));
  t.after(() => makeWritableAndRemove(root));
  const zipPath = join(root, 'year99.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 r2 f10 passphrase';

  const vcfBytes = Buffer.from(
    ['BEGIN:VCARD', 'VERSION:3.0', 'FN:Year 99 Contact', 'REV:00990101T003000Z', 'END:VCARD', ''].join('\r\n'),
    'utf8',
  );
  await writeZipArchive(zipPath, [{ path: 'Takeout/Contacts/year99.vcf', data: vcfBytes, compression: 'deflate' }]);

  const { vaultId, collectionKeyId } = createTestVaultWithCollections(vaultDir, passphrase);
  const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);

  const archive = await openArchive(zipPath);
  const writer = VaultWriter.open(vaultDir, unlocked);
  try {
    const res = await importArchive({
      archive,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      closeSegmentOnFinish: true,
    });
    assert.equal(res.totalItemsImported, 1);
  } finally {
    writer.release();
    await archive.close();
  }

  const records = readAllVaultRecords(vaultDir, unlocked);
  assert.equal(records.events.length, 1);
  assert.equal(records.events[0].json.collection, 'google-takeout/contacts/0099');
  assert.equal(records.events[0].json.body.source_ts, '0099-01-01T00:30:00Z');
  assert.equal(verifyVaultDeep(vaultDir, unlocked).position.lastEventSequence, 1);
});

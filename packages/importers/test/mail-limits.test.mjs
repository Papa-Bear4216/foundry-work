// V-7 phase 1 (A-36 Finding 7): mailImporter.split enforces SplitOptions limits.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
  verifyVault,
} from '../../vault/codec/dist/index.js';
import { importArchive, mailImporter, openArchive, syntheticEmail, writeZipArchive } from '../dist/index.js';

const LIMIT = 2048;

function message(day, subject, bodyBytes) {
  const header = [
    `From 20000${day}@xxx Mon Jan 0${day} 12:00:00 +0000 2024`,
    `From: <${syntheticEmail(`limit-sender-${day}`)}>`,
    `To: <${syntheticEmail(`limit-recipient-${day}`)}>`,
    `Date: Mon, 0${day} Jan 2024 12:00:00 +0000`,
    `Subject: ${subject}`,
    'Content-Type: text/plain; charset="utf-8"',
    '',
    '',
  ].join('\r\n');
  const line = 'TEST ONLY synthetic body line for the mail limit test.\r\n';
  const body = line.repeat(Math.ceil(bodyBytes / line.length)).slice(0, bodyBytes);
  return Buffer.from(header + body + '\r\n', 'utf8');
}

const small1 = message(1, 'TEST ONLY first normal message', 200);
const huge = message(2, 'TEST ONLY over-limit message', 6 * LIMIT);
const small3 = message(3, 'TEST ONLY third normal message', 300);
const mbox = Buffer.concat([small1, huge, small3]);

function entryFromBuffer(path, buf, chunkSize) {
  return {
    path,
    size: buf.length,
    compressedSize: buf.length,
    open() {
      let off = 0;
      return new Readable({
        read() {
          if (off >= buf.length) {
            this.push(null);
            return;
          }
          const end = Math.min(off + chunkSize, buf.length);
          this.push(buf.subarray(off, end));
          off = end;
        },
      });
    },
  };
}

async function readAll(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

test('mail split skips one over-limit message between two normal ones with a typed ITEM_TOO_LARGE and keeps message numbers', async () => {
  assert.ok(small1.length < LIMIT && small3.length < LIMIT && huge.length > LIMIT);
  for (const chunkSize of [7, 500, 64 * 1024]) {
    const errors = [];
    const items = [];
    const entry = entryFromBuffer('Takeout/Mail/Limits.mbox', mbox, chunkSize);
    for await (const item of mailImporter.split(entry, { maxItemBytes: LIMIT, onItemError: e => errors.push(e) })) {
      items.push({ path: item.path, bytes: await readAll(item.bytes) });
    }
    assert.deepEqual(items.map(i => i.path), ['Takeout/Mail/Limits.mbox#1', 'Takeout/Mail/Limits.mbox#3'], `chunk ${chunkSize}`);
    assert.ok(items[0].bytes.equals(small1), `first message is byte-exact (chunk ${chunkSize})`);
    assert.ok(items[1].bytes.equals(small3), `third message is byte-exact (chunk ${chunkSize})`);
    assert.equal(errors.length, 1);
    assert.deepEqual({ ...errors[0], message: undefined }, {
      code: 'ITEM_TOO_LARGE',
      source: 'google-takeout/mail',
      entryPath: 'Takeout/Mail/Limits.mbox',
      itemPath: 'Takeout/Mail/Limits.mbox#2',
      message: undefined,
      limitBytes: LIMIT,
      observedBytes: huge.length,
    });
  }

  // Without options the default 64 MiB limit applies and all three messages are yielded byte-exact.
  const all = [];
  for await (const item of mailImporter.split(entryFromBuffer('Takeout/Mail/Limits.mbox', mbox, 4096))) {
    all.push(await readAll(item.bytes));
  }
  assert.ok(Buffer.concat(all).equals(mbox));
});

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

test('importArchive imports both normal mail messages and counts and lists the one over-limit message', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v7-mail-limit-'));
  t.after(() => removeTree(root));
  const zipPath = join(root, 'mail.zip');
  const vaultDir = join(root, 'vault');
  await writeZipArchive(zipPath, [{ path: 'Takeout/Mail/Limits.mbox', data: mbox, compression: 'deflate' }]);

  const vaultId = randomBytes(16).toString('hex');
  const createdAt = '2026-11-22T00:00:00Z';
  const recoveryKey = randomBytes(32);
  const signingSeed = randomBytes(32);
  const profileKeyId = randomBytes(16).toString('hex');
  const collectionKeyId = randomBytes(16).toString('hex');
  const keyring = join(vaultDir, 'keyring', 'keyring.json');
  mkdirSync(join(vaultDir, 'keyring'), { recursive: true });
  writeFileSync(keyring, encodeKeyring({
    vaultId, version: 1, masterKey: randomBytes(32), entries: [
      { key_id: randomBytes(16).toString('hex'), kind: 'signing', parent: 'master', state: 'active', created_at: createdAt, key: signingSeed },
      { key_id: profileKeyId, kind: 'profile', parent: 'master', state: 'active', created_at: createdAt, key: randomBytes(32), label: 'me' },
      { key_id: collectionKeyId, kind: 'collection', parent: profileKeyId, state: 'active', created_at: createdAt, key: randomBytes(32) },
    ],
  }, 'TEST ONLY v7 mail limit passphrase', recoveryKey));
  initializeVault(vaultDir, { vaultId, createdAt, signingPublicKey: signingPublicKey(signingSeed) });

  const unlocked = decodeKeyring(readFileSync(keyring), { recoveryKey }, vaultId);
  const archive = await openArchive(zipPath);
  const writer = VaultWriter.open(vaultDir, unlocked);
  const reported = [];
  let result;
  try {
    result = await importArchive({
      archive,
      writer,
      importers: [mailImporter],
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      maxItemBytes: LIMIT,
      onItemError: e => reported.push(e),
      closeSegmentOnFinish: true,
    });
  } finally {
    writer.release();
    await archive.close();
  }

  assert.equal(result.totalItemsImported, 2);
  assert.equal(result.totalItemsSkipped, 1);
  assert.equal(result.totalItemsErrored, 1);
  assert.equal(result.countsBySource['google-takeout/mail'].itemsSkipped, 1);
  assert.equal(result.itemErrors.length, 1);
  assert.equal(result.itemErrors[0].code, 'ITEM_TOO_LARGE');
  assert.equal(result.itemErrors[0].itemPath, 'Takeout/Mail/Limits.mbox#2');
  assert.equal(result.itemErrors[0].limitBytes, LIMIT);
  assert.equal(result.itemErrors[0].observedBytes, huge.length);
  assert.deepEqual(reported, result.itemErrors);
  assert.equal(verifyVault(vaultDir).position.lastEventSequence, 2);
});

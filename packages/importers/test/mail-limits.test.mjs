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
import {
  importArchive,
  isMboxSeparatorLine,
  MAIL_SOURCE_ID,
  mailImporter,
  openArchive,
  syntheticEmail,
  writeZipArchive,
} from '../dist/index.js';

const LIMIT = 2048;

function message(day, subject, bodyBytes, extraHeaders = []) {
  const header = [
    `From 20000${day}@xxx Mon Jan 0${day} 12:00:00 +0000 2024`,
    `From: <${syntheticEmail(`limit-sender-${day}`)}>`,
    `To: <${syntheticEmail(`limit-recipient-${day}`)}>`,
    `Date: Mon, 0${day} Jan 2024 12:00:00 +0000`,
    `Subject: ${subject}`,
    ...extraHeaders,
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

  const { unlocked, collectionKeyId } = createTestVault(vaultDir);
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

function createTestVault(vaultDir) {
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
  return { unlocked: decodeKeyring(readFileSync(keyring), { recoveryKey }, vaultId), collectionKeyId };
}

// Review round 1 finding #4: the header peek must not copy past the item limit.
const PEEK_LIMIT = 1024;
const peekSmall1 = message(1, 'TEST ONLY peek first', 100);
const peekLongHeader = message(2, 'TEST ONLY peek long header line', 50, [`X-Test-Only-Long: ${'h'.repeat(20000)}`]);
const peekSmall3 = message(3, 'TEST ONLY peek third', 100);
const peekLongBody = message(4, 'TEST ONLY peek long body', 20000);
const peekSmall5 = message(5, 'TEST ONLY peek fifth', 100);
const peekMbox = Buffer.concat([peekSmall1, peekLongHeader, peekSmall3, peekLongBody, peekSmall5]);

/** A source that hands over each chunk as its own Buffer, so the stream itself never joins chunks. */
function objectModeEntry(path, buf, chunkSize) {
  return {
    path,
    size: buf.length,
    compressedSize: buf.length,
    open() {
      let off = 0;
      return new Readable({
        objectMode: true,
        highWaterMark: 1,
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

/**
 * Counting wrapper: records the size of every Buffer created while `fn` runs, then restores Buffer.
 * With `withStacks`, each record also holds the call stack, so a test can tell which code allocated it.
 */
async function recordBufferAllocations(fn, { withStacks = false } = {}) {
  const methods = ['from', 'concat', 'alloc', 'allocUnsafe', 'allocUnsafeSlow'];
  const originals = new Map(methods.map(m => [m, Buffer[m]]));
  const sizes = [];
  for (const m of methods) {
    const original = originals.get(m);
    Buffer[m] = function countingAllocation(...args) {
      const result = original.apply(this, args);
      if (Buffer.isBuffer(result)) {
        sizes.push(withStacks ? { method: m, bytes: result.length, stack: new Error().stack ?? '' } : { method: m, bytes: result.length });
      }
      return result;
    };
  }
  try {
    await fn();
  } finally {
    for (const m of methods) Buffer[m] = originals.get(m);
  }
  return sizes;
}

test('mail header peek copies no more than the item limit for a long first header line or a long body chunk', async () => {
  for (const small of [peekSmall1, peekSmall3, peekSmall5]) assert.ok(small.length < PEEK_LIMIT);
  // A chunk much larger than the limit holds the whole long header line, so a copy-then-check peek would copy it.
  for (const chunkSize of [7, 500, 4096, 65536]) {
    const errors = [];
    const items = [];
    const sizes = await recordBufferAllocations(async () => {
      const entry = objectModeEntry('Takeout/Mail/Peek.mbox', peekMbox, chunkSize);
      for await (const item of mailImporter.split(entry, { maxItemBytes: PEEK_LIMIT, onItemError: e => errors.push(e) })) {
        items.push(item);
      }
    });
    // Item streams are read only after the split, outside the counting window.
    const bytes = [];
    for (const item of items) bytes.push(await readAll(item.bytes));

    const label = `chunk ${chunkSize}`;
    assert.deepEqual(items.map(i => i.path), [
      'Takeout/Mail/Peek.mbox#1',
      'Takeout/Mail/Peek.mbox#3',
      'Takeout/Mail/Peek.mbox#5',
    ], label);
    assert.ok(bytes[0].equals(peekSmall1), label);
    assert.ok(bytes[1].equals(peekSmall3), label);
    assert.ok(bytes[2].equals(peekSmall5), label);
    assert.deepEqual(errors.map(e => ({ ...e, message: undefined })), [
      {
        code: 'ITEM_TOO_LARGE', source: MAIL_SOURCE_ID, entryPath: 'Takeout/Mail/Peek.mbox',
        itemPath: 'Takeout/Mail/Peek.mbox#2', message: undefined, limitBytes: PEEK_LIMIT, observedBytes: peekLongHeader.length,
      },
      {
        code: 'ITEM_TOO_LARGE', source: MAIL_SOURCE_ID, entryPath: 'Takeout/Mail/Peek.mbox',
        itemPath: 'Takeout/Mail/Peek.mbox#4', message: undefined, limitBytes: PEEK_LIMIT, observedBytes: peekLongBody.length,
      },
    ], label);

    const largest = Math.max(0, ...sizes.map(s => s.bytes));
    // The ruling's bound: no buffer larger than the limit plus one chunk.
    assert.ok(largest <= PEEK_LIMIT + chunkSize, `${label}: largest buffer ${largest} bytes`);
    // For chunks of 4096 bytes and more the cursor never has to join two chunks (no chunk boundary falls in the
    // first five bytes of a line or inside a separator line), so every buffer here is a copy the splitter made
    // itself, and none of them may exceed the limit.
    if (chunkSize >= 4096) {
      assert.ok(largest <= PEEK_LIMIT, `${label}: splitter copied ${largest} bytes, ${JSON.stringify(sizes.filter(s => s.bytes > PEEK_LIMIT))}`);
    }
  }
});

// Review round 3 item 2: the LIVE buffer capacity of one message (header prefix plus message blocks) stays
// within the item limit plus one chunk, also when the limit falls between 64 KiB block boundaries.
const BLOCK_BYTES = 64 * 1024;
const CAPACITY_LIMIT = 2 * BLOCK_BYTES + 3000;

/** A synthetic message of exactly `total` bytes. */
function sizedMessage(day, subject, total) {
  const bodyBytes = total - message(day, subject, 0).length;
  const out = message(day, subject, bodyBytes);
  assert.equal(out.length, total);
  return out;
}

/** Reads a stream in flowing mode, so every chunk is one buffer the splitter pushed (no joins). */
function pushedChunks(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end', () => resolve(chunks));
    stream.on('error', reject);
  });
}

test('mail message blocks: total live capacity of one message stays within the item limit plus one chunk when the limit falls between block boundaries', async () => {
  const underLimit = sizedMessage(6, 'TEST ONLY capacity just under the limit', CAPACITY_LIMIT - 50);
  const atLimit = sizedMessage(7, 'TEST ONLY capacity exactly at the limit', CAPACITY_LIMIT);
  const overLimit = sizedMessage(8, 'TEST ONLY capacity one byte over the limit', CAPACITY_LIMIT + 1);
  const capacityMbox = Buffer.concat([underLimit, atLimit, overLimit]);
  // Precondition: the limit is not a multiple of the block size.
  assert.notEqual(CAPACITY_LIMIT % BLOCK_BYTES, 0);

  for (const chunkSize of [7, 500, 4096, 65536]) {
    const label = `chunk ${chunkSize}`;
    const errors = [];
    const entry = objectModeEntry('Takeout/Mail/Capacity.mbox', capacityMbox, chunkSize);
    const iterator = mailImporter.split(entry, { maxItemBytes: CAPACITY_LIMIT, onItemError: e => errors.push(e) })[Symbol.asyncIterator]();

    /** Runs one generator step inside the counting window; returns the step and the bytes the message blocks allocated. */
    const step = async () => {
      let result;
      const sizes = await recordBufferAllocations(async () => { result = await iterator.next(); }, { withStacks: true });
      const blockBytes = sizes.filter(s => s.stack.includes('MessageBlocks.')).reduce((sum, s) => sum + s.bytes, 0);
      return { result, blockBytes };
    };

    for (const expected of [underLimit, atLimit]) {
      const { result, blockBytes } = await step();
      assert.equal(result.done, false, label);
      const chunks = await pushedChunks(result.value.bytes);
      assert.ok(Buffer.concat(chunks).equals(expected), `${label}: message is byte-exact`);
      // The first pushed buffer is the header prefix; the splitter keeps it live while it fills the blocks.
      const headerBytes = chunks[0].length;
      // Positive control: the stack filter does see the block allocations.
      assert.ok(blockBytes >= expected.length - headerBytes, `${label}: block allocations seen (${blockBytes})`);
      const liveCapacity = headerBytes + blockBytes;
      const detail = `${expected.length}-byte message held ${liveCapacity} bytes of live capacity (header ${headerBytes}, blocks ${blockBytes}), limit ${CAPACITY_LIMIT}`;
      // The ruling's bound, and the tighter bound that blocks sized to the remaining budget give.
      assert.ok(liveCapacity <= CAPACITY_LIMIT + chunkSize, `${label}: ${detail}`);
      assert.ok(liveCapacity <= CAPACITY_LIMIT, `${label}: ${detail}`);
    }

    // The over-limit message is dropped; the blocks it allocated before the drop also stay within the limit.
    const last = await step();
    assert.equal(last.result.done, true, label);
    assert.ok(last.blockBytes <= CAPACITY_LIMIT + chunkSize, `${label}: dropped message allocated ${last.blockBytes} block bytes`);
    assert.deepEqual(errors.map(e => [e.code, e.itemPath, e.observedBytes]), [
      ['ITEM_TOO_LARGE', 'Takeout/Mail/Capacity.mbox#3', overLimit.length],
    ], label);
  }
});

/** Counts mail messages per mbox entry from the archive layout (one message per separator line). */
async function separatorCount(entry) {
  const data = await readAll(entry.open());
  let count = 0;
  let start = 0;
  while (start < data.length) {
    const nl = data.indexOf(0x0a, start);
    const end = nl === -1 ? data.length : nl + 1;
    if (isMboxSeparatorLine(data.subarray(start, end))) count++;
    start = end;
  }
  return count;
}

// Review round 1 finding #5: without `itemKeys`, checkpoint item numbers match origin/main, where every mail
// message (also an over-limit one) was yielded by the splitter and advanced the pipeline's item counter.
test('checkpoint item numbers after an over-limit mail message match the numbering before phase 1', async t => {
  const root = mkdtempSync(join(tmpdir(), 'foundry-v7-mail-checkpoint-'));
  t.after(() => removeTree(root));
  const zipPath = join(root, 'mail.zip');
  const vaultDir = join(root, 'vault');
  const first = Buffer.concat([message(4, 'TEST ONLY earlier entry one', 150), message(5, 'TEST ONLY earlier entry two', 150)]);
  await writeZipArchive(zipPath, [
    { path: 'Takeout/Mail/A.mbox', data: first, compression: 'deflate' },
    { path: 'Takeout/Mail/B.mbox', data: mbox, compression: 'deflate' },
  ]);

  const { unlocked, collectionKeyId } = createTestVault(vaultDir);
  const archive = await openArchive(zipPath);
  const writer = VaultWriter.open(vaultDir, unlocked);
  const calls = [];
  // Expected values as origin/main computes them: the counter advances once per message in archive order.
  const startOf = new Map();
  const totalOf = new Map();
  let running = 0;
  try {
    for (const entry of archive.entries) {
      startOf.set(entry.path, running);
      running += await separatorCount(entry);
      totalOf.set(entry.path, running);
    }
    await importArchive({
      archive,
      writer,
      importers: [mailImporter],
      resolveCollectionKeyId: () => collectionKeyId,
      vaultDir,
      unlocked,
      readVaultRecord,
      maxItemBytes: LIMIT,
      batchMaxItems: 1,
      checkpoint: (point, info) => calls.push({ point, ...info }),
      closeSegmentOnFinish: true,
    });
  } finally {
    writer.release();
    await archive.close();
  }

  const expected = [];
  for (const entry of archive.entries) {
    const count = totalOf.get(entry.path) - startOf.get(entry.path);
    for (let n = 1; n <= count; n++) {
      const itemPath = `${entry.path}#${n}`;
      if (itemPath === 'Takeout/Mail/B.mbox#2') continue; // the over-limit message is not stored
      const itemIndex = startOf.get(entry.path) + n;
      expected.push({ point: 'after-blob-before-event', itemIndex, entryPath: entry.path, itemPath, source: MAIL_SOURCE_ID });
      expected.push({ point: 'after-batch', itemIndex, entryPath: entry.path, itemPath, source: MAIL_SOURCE_ID });
    }
    expected.push({ point: 'after-entry', itemIndex: totalOf.get(entry.path), entryPath: entry.path, itemPath: entry.path, source: MAIL_SOURCE_ID });
  }
  assert.equal(totalOf.get('Takeout/Mail/B.mbox'), 5);
  assert.deepEqual(calls, expected);
});

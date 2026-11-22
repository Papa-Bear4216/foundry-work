import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { crc32, deflateRawSync } from 'node:zlib';
import {
  ArchiveError,
  comparePartNames,
  openArchive,
  openZipFile,
  openZipReader,
  validateArchivePath,
  writeMultiPartTakeoutFolder,
  writeZipArchive,
} from '../dist/index.js';

async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function makeTempDir(t, prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('reads stored and deflate entries from standard zip and forced zip64 archives', async t => {
  const dir = makeTempDir(t, 'foundry-zip-std-');
  const storedPayload = Buffer.from('TEST ONLY stored payload 0123456789\n', 'utf8');
  const deflatePayload = Buffer.from('TEST ONLY deflate payload '.repeat(400), 'utf8');

  for (const forceZip64 of [false, true]) {
    const zipPath = join(dir, forceZip64 ? 'z64.zip' : 'std.zip');
    await writeZipArchive(
      zipPath,
      [
        { path: 'Takeout/a.txt', data: storedPayload, compression: 'store' },
        { path: 'Takeout/sub/b.txt', data: deflatePayload, compression: 'deflate' },
      ],
      { forceZip64 },
    );

    const archive = await openZipFile(zipPath);
    try {
      assert.equal(archive.entries.length, 2);
      assert.equal(archive.entries[0].path, 'Takeout/a.txt');
      assert.equal(archive.entries[0].size, storedPayload.length);
      assert.equal(archive.entries[1].path, 'Takeout/sub/b.txt');
      assert.equal(archive.entries[1].size, deflatePayload.length);

      const gotA = await streamToBuffer(archive.entries[0].open());
      const gotB = await streamToBuffer(archive.entries[1].open());
      assert.ok(gotA.equals(storedPayload));
      assert.ok(gotB.equals(deflatePayload));
    } finally {
      await archive.close();
    }
  }
});

test('streams a real > 4 GiB uncompressed ZIP64 entry while enforcing bomb defaults', async t => {
  const dir = makeTempDir(t, 'foundry-zip64-4gib-');
  const zipPath = join(dir, 'over4gib.zip');
  // 4,300,000,000 bytes > 0xFFFFFFFF (4,294,967,295): requires ZIP64 64-bit uncompressed size.
  const targetSize = 4_300_000_000;
  const chunkSize = 1024 * 1024;
  const pattern = Buffer.alloc(chunkSize, 0x54); // 'T' - compresses ~1000:1 to ~4.2 MiB on disk.

  await writeZipArchive(zipPath, [
    {
      path: 'Takeout/huge-synthetic.bin',
      compression: 'deflate',
      deflateLevel: 1,
      data: async function* () {
        let remaining = targetSize;
        while (remaining > 0) {
          const take = Math.min(remaining, chunkSize);
          yield take === chunkSize ? pattern : pattern.subarray(0, take);
          remaining -= take;
        }
      },
    },
  ]);

  // Default bomb protection must reject >100:1 compression ratio immediately.
  await assert.rejects(
    () => openZipFile(zipPath),
    err => err instanceof ArchiveError && err.code === 'ENTRY_BOMB',
  );

  // With bomb ratio explicitly relaxed, stream all >4 GiB and verify 64-bit size & CRC-32.
  const archive = await openZipFile(zipPath, { maxCompressionRatio: Infinity });
  try {
    assert.equal(archive.entries.length, 1);
    assert.equal(archive.entries[0].size, targetSize);
    let readBytes = 0;
    for await (const chunk of archive.entries[0].open()) {
      readBytes += chunk.length;
    }
    assert.equal(readBytes, targetSize);
  } finally {
    await archive.close();
  }
});

test('reads ZIP64 archive with localHeaderOffset and cdOffset above 4 GiB (virtual >5 GiB offsets)', async () => {
  const baseOffset = 5n * 1024n * 1024n * 1024n; // 5 GiB > 0xFFFFFFFF
  const nameBuf = Buffer.from('Takeout/high-offset.txt', 'utf8');
  const payload = Buffer.from('TEST ONLY entry positioned past 5 GiB offset', 'utf8');
  const entryCrc = crc32(payload) >>> 0;

  const lfh = Buffer.alloc(30);
  lfh.writeUInt32LE(0x04034b50, 0);
  lfh.writeUInt16LE(45, 4);
  lfh.writeUInt16LE(0x0800, 6);
  lfh.writeUInt16LE(0, 8);
  lfh.writeUInt32LE(entryCrc, 14);
  lfh.writeUInt32LE(payload.length, 18);
  lfh.writeUInt32LE(payload.length, 22);
  lfh.writeUInt16LE(nameBuf.length, 26);
  lfh.writeUInt16LE(0, 28);
  const entryRegion = Buffer.concat([lfh, nameBuf, payload]);

  const cdOffset = baseOffset + BigInt(entryRegion.length);
  const z64Extra = Buffer.alloc(12);
  z64Extra.writeUInt16LE(0x0001, 0);
  z64Extra.writeUInt16LE(8, 2);
  z64Extra.writeBigUInt64LE(baseOffset, 4);

  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(45, 4);
  cd.writeUInt16LE(45, 6);
  cd.writeUInt16LE(0x0800, 8);
  cd.writeUInt16LE(0, 10);
  cd.writeUInt32LE(entryCrc, 16);
  cd.writeUInt32LE(payload.length, 20);
  cd.writeUInt32LE(payload.length, 24);
  cd.writeUInt16LE(nameBuf.length, 28);
  cd.writeUInt16LE(z64Extra.length, 30);
  cd.writeUInt32LE(0xffffffff, 42); // sentinel triggers ZIP64 localHeaderOffset lookup
  const cdRegion = Buffer.concat([cd, nameBuf, z64Extra]);

  const z64EocdOffset = cdOffset + BigInt(cdRegion.length);
  const z64Eocd = Buffer.alloc(56);
  z64Eocd.writeUInt32LE(0x06064b50, 0);
  z64Eocd.writeBigUInt64LE(44n, 4);
  z64Eocd.writeUInt16LE(45, 12);
  z64Eocd.writeUInt16LE(45, 14);
  z64Eocd.writeBigUInt64LE(1n, 24);
  z64Eocd.writeBigUInt64LE(1n, 32);
  z64Eocd.writeBigUInt64LE(BigInt(cdRegion.length), 40);
  z64Eocd.writeBigUInt64LE(cdOffset, 48);

  const locator = Buffer.alloc(20);
  locator.writeUInt32LE(0x07064b50, 0);
  locator.writeBigUInt64LE(z64EocdOffset, 8);
  locator.writeUInt32LE(1, 16);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0xffff, 8);
  eocd.writeUInt16LE(0xffff, 10);
  eocd.writeUInt32LE(0xffffffff, 12);
  eocd.writeUInt32LE(0xffffffff, 16);

  const tailBlob = Buffer.concat([entryRegion, cdRegion, z64Eocd, locator, eocd]);
  const totalSize = baseOffset + BigInt(tailBlob.length);

  const virtualReader = {
    size: totalSize,
    async readAt(offset, length) {
      const out = Buffer.alloc(length);
      if (offset + BigInt(length) <= baseOffset) return out;
      const start = offset < baseOffset ? baseOffset : offset;
      const sliceOffset = Number(start - baseOffset);
      const destOffset = Number(start - offset);
      const copyLen = Math.min(length - destOffset, tailBlob.length - sliceOffset);
      tailBlob.copy(out, destOffset, sliceOffset, sliceOffset + copyLen);
      return out;
    },
    async close() {},
  };

  const archive = await openZipReader(virtualReader);
  assert.equal(archive.entries.length, 1);
  assert.equal(archive.entries[0].path, 'Takeout/high-offset.txt');
  const got = await streamToBuffer(archive.entries[0].open());
  assert.ok(got.equals(payload));
});

test('presents a multi-part Takeout folder as one unified archive tree with numeric part ordering', async t => {
  const dir = makeTempDir(t, 'foundry-multipart-');
  const built = await writeMultiPartTakeoutFolder(dir, { seed: 77, contactsCount: 3, calendarEvents: 2, mailMessages: 3 });

  assert.deepEqual(
    ['takeout-x-010.zip', 'takeout-x-002.zip', 'takeout-x-001.zip'].sort(comparePartNames),
    ['takeout-x-001.zip', 'takeout-x-002.zip', 'takeout-x-010.zip'],
  );

  const archive = await openArchive(dir);
  try {
    assert.deepEqual(archive.parts, built.parts);
    assert.deepEqual(
      archive.entries.map(e => e.path),
      [
        'Takeout/Calendar/Synthetic.ics',
        'Takeout/Contacts/All Contacts/All Contacts.vcf',
        'Takeout/Mail/All mail.mbox',
        'Takeout/archive_browser.html',
      ],
    );
    const mailBytes = await streamToBuffer(archive.entries.find(e => e.path.endsWith('.mbox')).open());
    assert.ok(mailBytes.equals(built.rawMail));
  } finally {
    await archive.close();
  }
});

test('rejects malformed archives with typed errors and never writes outside memory', async t => {
  const dir = makeTempDir(t, 'foundry-malformed-');

  // 1. Path traversal / absolute paths
  for (const bad of ['../x', 'a/../../x', '/etc/passwd', 'C:\\evil.txt', 'a\\..\\b', 'bad\0name', 'a//b']) {
    assert.throws(
      () => validateArchivePath(bad),
      err => err instanceof ArchiveError && err.code === 'PATH_TRAVERSAL',
      `expected PATH_TRAVERSAL for ${JSON.stringify(bad)}`,
    );
  }

  const traversalZip = join(dir, 'traversal.zip');
  await writeZipArchive(traversalZip, [{ path: '../escape.txt', data: Buffer.from('nope') }]);
  await assert.rejects(
    () => openZipFile(traversalZip),
    err => err instanceof ArchiveError && err.code === 'PATH_TRAVERSAL',
  );

  // 2. Non-zip / too small
  const tiny = join(dir, 'tiny.zip');
  writeFileSync(tiny, Buffer.from('not a zip'));
  await assert.rejects(
    () => openZipFile(tiny),
    err => err instanceof ArchiveError && err.code === 'INVALID_FORMAT',
  );

  // 3. Truncated central directory
  const validPath = join(dir, 'base.zip');
  await writeZipArchive(validPath, [
    { path: 'Takeout/one.txt', data: Buffer.from('one') },
    { path: 'Takeout/two.txt', data: Buffer.from('two') },
  ]);
  const validBytes = readFileSync(validPath);
  const truncCd = Buffer.from(validBytes);
  // Corrupt CD size in EOCD to declare more bytes than exist before EOCD
  truncCd.writeUInt32LE(truncCd.length + 100, truncCd.length - 10);
  const truncPath = join(dir, 'trunc-cd.zip');
  writeFileSync(truncPath, truncCd);
  await assert.rejects(
    () => openZipFile(truncPath),
    err => err instanceof ArchiveError && err.code === 'TRUNCATED_CENTRAL_DIRECTORY',
  );

  // 4. Bad local header offset
  const badOffsetBuf = Buffer.from(validBytes);
  const cdPos = badOffsetBuf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  badOffsetBuf.writeUInt32LE(999_999, cdPos + 42);
  const badOffsetPath = join(dir, 'bad-offset.zip');
  writeFileSync(badOffsetPath, badOffsetBuf);
  await assert.rejects(
    () => openZipFile(badOffsetPath),
    err => err instanceof ArchiveError && err.code === 'BAD_OFFSET',
  );

  // 5. Overlapping entries (point entry #2's localHeaderOffset at entry #1's offset 0)
  const overlapBuf = Buffer.from(validBytes);
  const cd1 = overlapBuf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  const cd2 = overlapBuf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]), cd1 + 4);
  overlapBuf.writeUInt32LE(0, cd2 + 42);
  const overlapPath = join(dir, 'overlap.zip');
  writeFileSync(overlapPath, overlapBuf);
  await assert.rejects(
    () => openZipFile(overlapPath),
    err => err instanceof ArchiveError && err.code === 'OVERLAPPING_ENTRIES',
  );

  // 6. Undeclared entry bomb (CD claims 100 bytes uncompressed, actual deflate stream outputs 2 MiB)
  const real2MiB = Buffer.alloc(2 * 1024 * 1024, 0x41);
  const deflated2MiB = deflateRawSync(real2MiB, { level: 9 });
  const bombPath = join(dir, 'lying-bomb.zip');
  await writeZipArchive(bombPath, [{ path: 'Takeout/bomb.txt', data: real2MiB, compression: 'deflate', deflateLevel: 9 }]);
  const bombBuf = readFileSync(bombPath);
  const bombCd = bombBuf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  // Lie in CD: declare uncompressedSize = 100 while compressed payload actually inflates to 2 MiB.
  bombBuf.writeUInt32LE(100, bombCd + 24);
  const lyingBombPath = join(dir, 'lying-bomb-edited.zip');
  writeFileSync(lyingBombPath, bombBuf);
  const lyingArchive = await openZipFile(lyingBombPath);
  try {
    await assert.rejects(
      () => streamToBuffer(lyingArchive.entries[0].open()),
      err => err instanceof ArchiveError && err.code === 'ENTRY_BOMB',
    );
  } finally {
    await lyingArchive.close();
  }
  assert.ok(deflated2MiB.length < 10_000);

  // 7. CRC mismatch
  const crcBuf = Buffer.from(validBytes);
  const crcCd = crcBuf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  crcBuf.writeUInt32LE((crcBuf.readUInt32LE(crcCd + 16) ^ 0xffffffff) >>> 0, crcCd + 16);
  const crcPath = join(dir, 'bad-crc.zip');
  writeFileSync(crcPath, crcBuf);
  const crcArchive = await openZipFile(crcPath);
  try {
    await assert.rejects(
      () => streamToBuffer(crcArchive.entries[0].open()),
      err => err instanceof ArchiveError && err.code === 'CRC_MISMATCH',
    );
  } finally {
    await crcArchive.close();
  }

  // 8. Duplicate entry across multi-part folder
  const dupDir = makeTempDir(t, 'foundry-dup-parts-');
  await writeZipArchive(join(dupDir, 'takeout-001.zip'), [{ path: 'Takeout/dup.txt', data: Buffer.from('a') }]);
  await writeZipArchive(join(dupDir, 'takeout-002.zip'), [{ path: 'Takeout/dup.txt', data: Buffer.from('b') }]);
  await assert.rejects(
    () => openArchive(dupDir),
    err => err instanceof ArchiveError && err.code === 'DUPLICATE_ENTRY',
  );

  // 9. Empty directory
  const emptyDir = makeTempDir(t, 'foundry-empty-dir-');
  await assert.rejects(
    () => openArchive(emptyDir),
    err => err instanceof ArchiveError && err.code === 'EMPTY_ARCHIVE_DIR',
  );
});

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
  writeStreamedZip64Archive,
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

/** Builds a raw ZIP buffer with customizable per-entry flags, descriptors, and raw filename bytes. */
function buildRawZipBuffer(entries, options = {}) {
  const parts = [];
  const cdParts = [];
  let offset = 0;

  for (const spec of entries) {
    const lfhName = Buffer.isBuffer(spec.lfhName) ? spec.lfhName : Buffer.from(spec.lfhName ?? spec.path, 'utf8');
    const cdName = Buffer.isBuffer(spec.cdName) ? spec.cdName : Buffer.from(spec.cdName ?? spec.path, 'utf8');
    const raw = spec.data;
    const method = spec.compression === 'deflate' ? 8 : 0;
    const payload = spec.rawPayload ?? (method === 8 ? deflateRawSync(raw, { level: spec.deflateLevel ?? 1 }) : raw);
    const entryCrc = spec.crc ?? (crc32(raw) >>> 0);
    const compSize = spec.compSize ?? payload.length;
    const uncompSize = spec.uncompSize ?? raw.length;
    const flags = spec.flags ?? 0x0800;
    const lfhFlags = spec.lfhFlags ?? flags;
    const lfhOffset = offset;
    const bit3 = (flags & 0x0008) !== 0;

    const lfhExtra = spec.lfhExtra ?? Buffer.alloc(0);
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(spec.versionNeeded ?? (spec.zip64Descriptor ? 45 : 20), 4);
    lfh.writeUInt16LE(lfhFlags, 6);
    lfh.writeUInt16LE(spec.lfhMethod ?? method, 8);
    lfh.writeUInt16LE(0, 10);
    lfh.writeUInt16LE(0x5821, 12);
    lfh.writeUInt32LE(spec.lfhCrc ?? (bit3 ? 0 : entryCrc), 14);
    lfh.writeUInt32LE(spec.lfhCompSize ?? (bit3 ? 0 : compSize), 18);
    lfh.writeUInt32LE(spec.lfhUncompSize ?? (bit3 ? 0 : uncompSize), 22);
    lfh.writeUInt16LE(lfhName.length, 26);
    lfh.writeUInt16LE(lfhExtra.length, 28);

    parts.push(lfh, lfhName, lfhExtra, payload);
    offset += lfh.length + lfhName.length + lfhExtra.length + payload.length;

    if (bit3 && !spec.omitDescriptor) {
      const withSig = spec.descriptorWithSig !== false;
      const isZ64 = Boolean(spec.zip64Descriptor);
      const desc = Buffer.alloc((withSig ? 4 : 0) + (isZ64 ? 20 : 12));
      let p = 0;
      if (withSig) {
        desc.writeUInt32LE(0x08074b50, p);
        p += 4;
      }
      desc.writeUInt32LE(spec.descriptorCrc ?? entryCrc, p);
      if (isZ64) {
        desc.writeBigUInt64LE(BigInt(spec.descriptorCompSize ?? compSize), p + 4);
        desc.writeBigUInt64LE(BigInt(spec.descriptorUncompSize ?? uncompSize), p + 12);
      } else {
        desc.writeUInt32LE(spec.descriptorCompSize ?? compSize, p + 4);
        desc.writeUInt32LE(spec.descriptorUncompSize ?? uncompSize, p + 8);
      }
      parts.push(desc);
      offset += desc.length;
    }

    const cdExtra = spec.cdExtra ?? Buffer.alloc(0);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0);
    cd.writeUInt16LE(spec.versionNeeded ?? (spec.zip64Descriptor ? 45 : 20), 4);
    cd.writeUInt16LE(spec.versionNeeded ?? (spec.zip64Descriptor ? 45 : 20), 6);
    cd.writeUInt16LE(flags, 8);
    cd.writeUInt16LE(method, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0x5821, 14);
    cd.writeUInt32LE(entryCrc, 16);
    cd.writeUInt32LE(compSize, 20);
    cd.writeUInt32LE(uncompSize, 24);
    cd.writeUInt16LE(cdName.length, 28);
    cd.writeUInt16LE(cdExtra.length, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(spec.cdLfhOffset ?? lfhOffset, 42);
    cdParts.push(cd, cdName, cdExtra);
  }

  const cdOffset = offset;
  const cdBuf = Buffer.concat(cdParts);
  parts.push(cdBuf);
  offset += cdBuf.length;

  if (options.gapAfterCd) {
    parts.push(options.gapAfterCd);
    offset += options.gapAfterCd.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(options.eocdEntriesDisk ?? entries.length, 8);
  eocd.writeUInt16LE(options.eocdTotalEntries ?? entries.length, 10);
  eocd.writeUInt32LE(options.eocdCdSize ?? cdBuf.length, 12);
  eocd.writeUInt32LE(options.eocdCdOffset ?? cdOffset, 16);
  eocd.writeUInt16LE(0, 20);
  parts.push(eocd);

  return Buffer.concat(parts);
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

  // 5. Overlapping entries (point entry #2's localHeaderOffset at entry #1's offset 0, matching LFH fields)
  const overlapBuf = buildRawZipBuffer([
    { path: 'Takeout/one.txt', data: Buffer.from('one-payload') },
    { path: 'Takeout/one.txt', cdName: Buffer.from('Takeout/two.txt'), data: Buffer.from('two-payload') },
  ]);
  // Better: construct two entries with identical name bytes at same offset? No, duplicate name fails first;
  // instead point entry #2's LFH offset inside entry #1's payload with a fake LFH header embedded inside entry #1's payload!
  const fakeName = Buffer.from('Takeout/two.txt', 'utf8');
  const fakePayload = Buffer.from('two');
  const fakeCrc = crc32(fakePayload) >>> 0;
  const embeddedLfh = Buffer.alloc(30);
  embeddedLfh.writeUInt32LE(0x04034b50, 0);
  embeddedLfh.writeUInt16LE(20, 4);
  embeddedLfh.writeUInt16LE(0x0800, 6);
  embeddedLfh.writeUInt16LE(0, 8);
  embeddedLfh.writeUInt32LE(fakeCrc, 14);
  embeddedLfh.writeUInt32LE(fakePayload.length, 18);
  embeddedLfh.writeUInt32LE(fakePayload.length, 22);
  embeddedLfh.writeUInt16LE(fakeName.length, 26);
  embeddedLfh.writeUInt16LE(0, 28);
  const hostPayload = Buffer.concat([Buffer.from('prefix'), embeddedLfh, fakeName, fakePayload]);
  const entry1Name = Buffer.from('Takeout/one.txt', 'utf8');
  const embeddedOffset = 30 + entry1Name.length + 6;
  const trueOverlapBuf = buildRawZipBuffer([
    { path: 'Takeout/one.txt', data: hostPayload },
    { path: 'Takeout/two.txt', data: fakePayload, cdLfhOffset: embeddedOffset },
  ]);
  assert.ok(overlapBuf.length > 0);
  const overlapPath = join(dir, 'overlap.zip');
  writeFileSync(overlapPath, trueOverlapBuf);
  await assert.rejects(
    () => openZipFile(overlapPath),
    err => err instanceof ArchiveError && err.code === 'OVERLAPPING_ENTRIES',
  );

  // 6. Undeclared entry bomb (both LFH and CD lie: declare 100 bytes uncompressed while deflate stream outputs 2 MiB)
  const real2MiB = Buffer.alloc(2 * 1024 * 1024, 0x41);
  const deflated2MiB = deflateRawSync(real2MiB, { level: 9 });
  const lyingBombBuf = buildRawZipBuffer([
    {
      path: 'Takeout/bomb.txt',
      data: real2MiB,
      compression: 'deflate',
      rawPayload: deflated2MiB,
      compSize: deflated2MiB.length,
      uncompSize: 100,
    },
  ]);
  const lyingBombPath = join(dir, 'lying-bomb.zip');
  writeFileSync(lyingBombPath, lyingBombBuf);
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

  // 7. Streaming CRC mismatch (LFH and CD agree on wrong CRC; streaming payload detects CRC_MISMATCH)
  const payload7 = Buffer.from('TEST ONLY payload with bad crc');
  const badCrcBuf = buildRawZipBuffer([
    { path: 'Takeout/badcrc.txt', data: payload7, crc: ((crc32(payload7) ^ 0xffffffff) >>> 0) },
  ]);
  const crcPath = join(dir, 'bad-crc.zip');
  writeFileSync(crcPath, badCrcBuf);
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

test('rejects local and central header mismatches (filename, flags, CRC/sizes) and validates bit-3 descriptors (Ruling 2)', async t => {
  const dir = makeTempDir(t, 'foundry-ruling2-');

  // Name mismatch between local header and central directory
  const nameMismatchPath = join(dir, 'name-mismatch.zip');
  writeFileSync(
    nameMismatchPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/central.txt',
        lfhName: Buffer.from('Takeout/local.txt', 'utf8'),
        cdName: Buffer.from('Takeout/central.txt', 'utf8'),
        data: Buffer.from('TEST ONLY mismatch'),
      },
    ]),
  );
  await assert.rejects(
    () => openZipFile(nameMismatchPath),
    err => err instanceof ArchiveError && err.code === 'HEADER_MISMATCH',
  );

  // Flags mismatch
  const flagsMismatchPath = join(dir, 'flags-mismatch.zip');
  writeFileSync(
    flagsMismatchPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/flags.txt',
        data: Buffer.from('TEST ONLY flags'),
        flags: 0x0800,
        lfhFlags: 0x0000,
      },
    ]),
  );
  await assert.rejects(
    () => openZipFile(flagsMismatchPath),
    err => err instanceof ArchiveError && err.code === 'HEADER_MISMATCH',
  );

  // Missing data descriptor when bit 3 is set
  const missingDescPath = join(dir, 'missing-desc.zip');
  writeFileSync(
    missingDescPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/bit3-missing.txt',
        data: Buffer.from('TEST ONLY bit3 without descriptor'),
        flags: 0x0808,
        omitDescriptor: true,
      },
    ]),
  );
  await assert.rejects(
    () => openZipFile(missingDescPath),
    err => err instanceof ArchiveError && err.code === 'INVALID_DATA_DESCRIPTOR',
  );

  // Corrupt CRC inside data descriptor -> INVALID_DATA_DESCRIPTOR
  const badDescCrcPath = join(dir, 'bad-desc-crc.zip');
  writeFileSync(
    badDescCrcPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/first.txt',
        data: Buffer.from('TEST ONLY bit3 bad descriptor crc'),
        flags: 0x0808,
        descriptorWithSig: true,
        descriptorCrc: 0x12345678,
      },
    ]),
  );
  await assert.rejects(
    () => openZipFile(badDescCrcPath),
    err => err instanceof ArchiveError && err.code === 'INVALID_DATA_DESCRIPTOR',
  );

  // Valid ZIP32 (signed + unsigned) and ZIP64 (signed + unsigned) data descriptors succeed
  const validDescPath = join(dir, 'valid-desc.zip');
  const p1 = Buffer.from('TEST ONLY zip32 signed descriptor');
  const p2 = Buffer.from('TEST ONLY zip32 unsigned descriptor');
  const p3 = Buffer.from('TEST ONLY zip64 signed descriptor');
  const p4 = Buffer.from('TEST ONLY zip64 unsigned descriptor');
  writeFileSync(
    validDescPath,
    buildRawZipBuffer([
      { path: 'Takeout/d1.txt', data: p1, flags: 0x0808, descriptorWithSig: true, zip64Descriptor: false },
      { path: 'Takeout/d2.txt', data: p2, flags: 0x0808, descriptorWithSig: false, zip64Descriptor: false },
      { path: 'Takeout/d3.txt', data: p3, flags: 0x0808, descriptorWithSig: true, zip64Descriptor: true },
      { path: 'Takeout/d4.txt', data: p4, flags: 0x0808, descriptorWithSig: false, zip64Descriptor: true },
    ]),
  );
  const descArchive = await openZipFile(validDescPath);
  try {
    assert.equal(descArchive.entries.length, 4);
    assert.ok((await streamToBuffer(descArchive.entries[0].open())).equals(p1));
    assert.ok((await streamToBuffer(descArchive.entries[1].open())).equals(p2));
    assert.ok((await streamToBuffer(descArchive.entries[2].open())).equals(p3));
    assert.ok((await streamToBuffer(descArchive.entries[3].open())).equals(p4));
  } finally {
    await descArchive.close();
  }
});

test('rejects unexplained gaps after central directory, zeroed counts with retained directory, and inconsistent ZIP64 end records (Ruling 3)', async t => {
  const dir = makeTempDir(t, 'foundry-ruling3-');

  // 1. Zeroed classic EOCD counts and CD size while retaining the directory offset -> must NOT open as empty archive!
  const validPath = join(dir, 'valid.zip');
  await writeZipArchive(validPath, [{ path: 'Takeout/retained.txt', data: Buffer.from('TEST ONLY kept') }]);
  const zeroedBuf = Buffer.from(readFileSync(validPath));
  const eocdStart = zeroedBuf.length - 22;
  zeroedBuf.writeUInt16LE(0, eocdStart + 8);  // entries on disk = 0
  zeroedBuf.writeUInt16LE(0, eocdStart + 10); // total entries = 0
  zeroedBuf.writeUInt32LE(0, eocdStart + 12); // cdSize = 0 (cdOffset retained!)
  const zeroedPath = join(dir, 'zeroed-counts.zip');
  writeFileSync(zeroedPath, zeroedBuf);
  await assert.rejects(
    () => openZipFile(zeroedPath),
    err => err instanceof ArchiveError && err.code === 'INVALID_FORMAT',
  );

  // 2. Unexplained gap bytes between central directory and EOCD
  const gapPath = join(dir, 'cd-gap.zip');
  writeFileSync(
    gapPath,
    buildRawZipBuffer(
      [{ path: 'Takeout/item.txt', data: Buffer.from('TEST ONLY gap') }],
      { gapAfterCd: Buffer.alloc(16, 0xaa) },
    ),
  );
  await assert.rejects(
    () => openZipFile(gapPath),
    err => err instanceof ArchiveError && err.code === 'INVALID_FORMAT',
  );

  // 3. Inconsistent classic EOCD vs ZIP64 EOCD entry count
  const z64Path = join(dir, 'z64-valid.zip');
  await writeZipArchive(
    z64Path,
    [
      { path: 'Takeout/a.txt', data: Buffer.from('a') },
      { path: 'Takeout/b.txt', data: Buffer.from('b') },
    ],
    { forceZip64: true },
  );
  const inconsistentZ64 = Buffer.from(readFileSync(z64Path));
  const z64EocdPos = inconsistentZ64.length - 22;
  // Classic EOCD claims 1 entry while ZIP64 EOCD has 2 entries
  inconsistentZ64.writeUInt16LE(1, z64EocdPos + 8);
  inconsistentZ64.writeUInt16LE(1, z64EocdPos + 10);
  const inconsistentPath = join(dir, 'z64-inconsistent.zip');
  writeFileSync(inconsistentPath, inconsistentZ64);
  await assert.rejects(
    () => openZipFile(inconsistentPath),
    err => err instanceof ArchiveError && err.code === 'INVALID_FORMAT',
  );
});

test('requires deflate inflater to consume exact compressed size and enforces ratio on consumed bytes (Ruling 4)', async t => {
  const dir = makeTempDir(t, 'foundry-ruling4-');

  // 1. Valid small deflate stream + trailing garbage bytes -> SIZE_MISMATCH
  const smallOrig = Buffer.from('TEST ONLY deflate with trailing bytes', 'utf8');
  const smallDeflated = deflateRawSync(smallOrig, { level: 6 });
  const paddedSmall = Buffer.concat([smallDeflated, Buffer.alloc(64, 0x00)]);
  const trailingPath = join(dir, 'deflate-trailing.zip');
  writeFileSync(
    trailingPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/trailing.txt',
        data: smallOrig,
        compression: 'deflate',
        rawPayload: paddedSmall,
        compSize: paddedSmall.length,
        uncompSize: smallOrig.length,
      },
    ]),
  );
  const trailingArchive = await openZipFile(trailingPath);
  try {
    await assert.rejects(
      () => streamToBuffer(trailingArchive.entries[0].open()),
      err => err instanceof ArchiveError && err.code === 'SIZE_MISMATCH',
    );
  } finally {
    await trailingArchive.close();
  }

  // 1b. Valid deflate stream + >64 KiB trailing garbage bytes (multi-chunk) -> SIZE_MISMATCH
  const paddedMultiChunk = Buffer.concat([smallDeflated, Buffer.alloc(128 * 1024, 0x00)]);
  const trailingMultiPath = join(dir, 'deflate-trailing-multi.zip');
  writeFileSync(
    trailingMultiPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/trailing-multi.txt',
        data: smallOrig,
        compression: 'deflate',
        rawPayload: paddedMultiChunk,
        compSize: paddedMultiChunk.length,
        uncompSize: smallOrig.length,
      },
    ]),
  );
  const trailingMultiArchive = await openZipFile(trailingMultiPath);
  try {
    await assert.rejects(
      () => streamToBuffer(trailingMultiArchive.entries[0].open()),
      err => err instanceof ArchiveError && err.code === 'SIZE_MISMATCH',
    );
  } finally {
    await trailingMultiArchive.close();
  }

  // 2. Padded bomb: 2 MiB of 'A' deflates to ~2 KiB (>1000:1), padded with 30 KiB trailing bytes
  // so declared ratio looks like ~65:1 (<100:1), but consumed-byte ratio is >1000:1 -> ENTRY_BOMB!
  const bombOrig = Buffer.alloc(2 * 1024 * 1024, 0x41);
  const bombDeflated = deflateRawSync(bombOrig, { level: 9 });
  const paddedBomb = Buffer.concat([bombDeflated, Buffer.alloc(30 * 1024, 0x00)]);
  const paddedBombPath = join(dir, 'padded-bomb.zip');
  writeFileSync(
    paddedBombPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/padded-bomb.txt',
        data: bombOrig,
        compression: 'deflate',
        rawPayload: paddedBomb,
        compSize: paddedBomb.length,
        uncompSize: bombOrig.length,
      },
    ]),
  );
  const paddedArchive = await openZipFile(paddedBombPath);
  try {
    await assert.rejects(
      () => streamToBuffer(paddedArchive.entries[0].open()),
      err => err instanceof ArchiveError && err.code === 'ENTRY_BOMB',
    );
  } finally {
    await paddedArchive.close();
  }
});

test('rejects missing parts, mixed export prefixes, and duplicate ordinals in multi-part folders (Ruling 5)', async t => {
  // 1. Missing middle part (001 and 003 without 002)
  const missingMid = makeTempDir(t, 'foundry-missing-mid-');
  await writeZipArchive(join(missingMid, 'takeout-20261121T000000Z-001.zip'), [{ path: 'Takeout/a.txt', data: Buffer.from('a') }]);
  await writeZipArchive(join(missingMid, 'takeout-20261121T000000Z-003.zip'), [{ path: 'Takeout/c.txt', data: Buffer.from('c') }]);
  await assert.rejects(
    () => openArchive(missingMid),
    err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART',
  );

  // 2. Missing leading part (002 alone)
  const missingFirst = makeTempDir(t, 'foundry-missing-first-');
  await writeZipArchive(join(missingFirst, 'takeout-20261121T000000Z-002.zip'), [{ path: 'Takeout/b.txt', data: Buffer.from('b') }]);
  await assert.rejects(
    () => openArchive(missingFirst),
    err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART',
  );

  // 3. Mixed prefixes
  const mixedDir = makeTempDir(t, 'foundry-mixed-prefix-');
  await writeZipArchive(join(mixedDir, 'takeout-20261121T000000Z-001.zip'), [{ path: 'Takeout/a.txt', data: Buffer.from('a') }]);
  await writeZipArchive(join(mixedDir, 'takeout-20261122T000000Z-002.zip'), [{ path: 'Takeout/b.txt', data: Buffer.from('b') }]);
  await assert.rejects(
    () => openArchive(mixedDir),
    err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART',
  );

  // 4. Duplicate ordinals (-1.zip and -001.zip)
  const dupOrdDir = makeTempDir(t, 'foundry-dup-ord-');
  await writeZipArchive(join(dupOrdDir, 'takeout-20261121T000000Z-1.zip'), [{ path: 'Takeout/a.txt', data: Buffer.from('a') }]);
  await writeZipArchive(join(dupOrdDir, 'takeout-20261121T000000Z-001.zip'), [{ path: 'Takeout/b.txt', data: Buffer.from('b') }]);
  await assert.rejects(
    () => openArchive(dupOrdDir),
    err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART',
  );
});

test('compares raw name bytes for duplicate detection so distinct legacy non-UTF-8 entries do not collide (Ruling 13 / Finding 15)', async t => {
  const dir = makeTempDir(t, 'foundry-raw-dedup-');
  const rawName1 = Buffer.concat([Buffer.from('Takeout/item_', 'ascii'), Buffer.from([0xe8]), Buffer.from('.txt', 'ascii')]);
  const rawName2 = Buffer.concat([Buffer.from('Takeout/item_', 'ascii'), Buffer.from([0xe9]), Buffer.from('.txt', 'ascii')]);
  const zipPath = join(dir, 'legacy-names.zip');
  writeFileSync(
    zipPath,
    buildRawZipBuffer([
      { lfhName: rawName1, cdName: rawName1, flags: 0x0000, data: Buffer.from('first') },
      { lfhName: rawName2, cdName: rawName2, flags: 0x0000, data: Buffer.from('second') },
    ]),
  );

  const archive = await openZipFile(zipPath);
  try {
    assert.equal(archive.entries.length, 2);
    assert.ok((await streamToBuffer(archive.entries[0].open())).equals(Buffer.from('first')));
    assert.ok((await streamToBuffer(archive.entries[1].open())).equals(Buffer.from('second')));
  } finally {
    await archive.close();
  }
});

test('accepts streamed ZIP64 bit-3 entries with 0xffffffff local sizes and zero ZIP64-extra placeholders, and rejects descriptor mismatches (Round 2 Finding 1)', async t => {
  const dir = makeTempDir(t, 'foundry-r2-f1-');
  const storedData = Buffer.from('TEST ONLY streamed ZIP64 stored payload\n', 'utf8');
  const deflateData = Buffer.from('TEST ONLY streamed ZIP64 deflate payload '.repeat(200), 'utf8');

  // 1. Valid Python zipfile force_zip64=True non-seekable layout -> reads cleanly
  const validPath = join(dir, 'streamed-z64-valid.zip');
  await writeStreamedZip64Archive(validPath, [
    { path: 'Takeout/stored.txt', data: storedData, compression: 'store' },
    { path: 'Takeout/deflated.txt', data: deflateData, compression: 'deflate' },
  ]);
  const archive = await openArchive(validPath);
  try {
    assert.equal(archive.entries.length, 2);
    assert.ok((await streamToBuffer(archive.entries[0].open())).equals(storedData));
    assert.ok((await streamToBuffer(archive.entries[1].open())).equals(deflateData));
  } finally {
    await archive.close();
  }

  // 2. Same layout with descriptor CRC mismatch -> INVALID_DATA_DESCRIPTOR
  const badCrcPath = join(dir, 'streamed-z64-bad-crc.zip');
  await writeStreamedZip64Archive(badCrcPath, [
    {
      path: 'Takeout/deflated.txt',
      data: deflateData,
      compression: 'deflate',
      descriptorCrc: ((crc32(deflateData) ^ 0xffffffff) >>> 0),
    },
  ]);
  await assert.rejects(
    () => openArchive(badCrcPath),
    err => err instanceof ArchiveError && err.code === 'INVALID_DATA_DESCRIPTOR',
  );

  // 3. Same layout with descriptor uncompressed size mismatch -> INVALID_DATA_DESCRIPTOR
  const badSizePath = join(dir, 'streamed-z64-bad-size.zip');
  await writeStreamedZip64Archive(badSizePath, [
    {
      path: 'Takeout/stored.txt',
      data: storedData,
      compression: 'store',
      descriptorUncompressedSize: BigInt(storedData.length + 1),
    },
  ]);
  await assert.rejects(
    () => openArchive(badSizePath),
    err => err instanceof ArchiveError && err.code === 'INVALID_DATA_DESCRIPTOR',
  );

  // 4. Bit-3 entry with populated non-zero LFH ZIP64 size that disagrees with CD -> HEADER_MISMATCH
  const z64ExtraPopulated = Buffer.alloc(20);
  z64ExtraPopulated.writeUInt16LE(0x0001, 0);
  z64ExtraPopulated.writeUInt16LE(16, 2);
  z64ExtraPopulated.writeBigUInt64LE(BigInt(storedData.length + 7), 4);
  z64ExtraPopulated.writeBigUInt64LE(BigInt(storedData.length), 12);
  const badLfhSizePath = join(dir, 'streamed-z64-bad-lfh.zip');
  writeFileSync(
    badLfhSizePath,
    buildRawZipBuffer([
      {
        path: 'Takeout/populated-mismatch.txt',
        data: storedData,
        flags: 0x0808,
        versionNeeded: 45,
        lfhCompSize: 0xffffffff,
        lfhUncompSize: 0xffffffff,
        lfhExtra: z64ExtraPopulated,
        zip64Descriptor: true,
      },
    ]),
  );
  await assert.rejects(
    () => openArchive(badLfhSizePath),
    err => err instanceof ArchiveError && err.code === 'HEADER_MISMATCH',
  );

  // 5. Classic 32-bit CD + classic EOCD with bit-3 LFH 0xffffffff sizes, [0n, 0n] ZIP64 extra, and signed ZIP64 descriptor
  const z64ExtraZero = Buffer.alloc(20);
  z64ExtraZero.writeUInt16LE(0x0001, 0);
  z64ExtraZero.writeUInt16LE(16, 2);
  z64ExtraZero.writeBigUInt64LE(0n, 4);
  z64ExtraZero.writeBigUInt64LE(0n, 12);
  const classicCdStreamedPath = join(dir, 'streamed-z64-classic-cd.zip');
  writeFileSync(
    classicCdStreamedPath,
    buildRawZipBuffer([
      {
        path: 'Takeout/classic-cd-streamed.txt',
        data: storedData,
        flags: 0x0008,
        versionNeeded: 45,
        lfhCrc: 0,
        lfhCompSize: 0xffffffff,
        lfhUncompSize: 0xffffffff,
        lfhExtra: z64ExtraZero,
        zip64Descriptor: true,
      },
    ]),
  );
  const classicArch = await openArchive(classicCdStreamedPath);
  try {
    assert.equal(classicArch.entries.length, 1);
    assert.ok((await streamToBuffer(classicArch.entries[0].open())).equals(storedData));
  } finally {
    await classicArch.close();
  }
});

test('enforces Takeout part ordinal validation when opening a single file directly via openArchive (Round 2 Finding 3)', async t => {
  const dir = makeTempDir(t, 'foundry-r2-f3-');

  const part2 = join(dir, 'takeout-20261121T000000Z-002.zip');
  await writeZipArchive(part2, [{ path: 'Takeout/b.txt', data: Buffer.from('part 2 only') }]);
  await assert.rejects(
    () => openArchive(part2),
    err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART' && /part 1/i.test(err.message),
  );

  const part0 = join(dir, 'takeout-20261121T000000Z-000.zip');
  await writeZipArchive(part0, [{ path: 'Takeout/z.txt', data: Buffer.from('part 0 invalid') }]);
  await assert.rejects(
    () => openArchive(part0),
    err => err instanceof ArchiveError && err.code === 'INVALID_MULTIPART',
  );

  // Part 001 opened directly is allowed (missing final part is deferred per A-36)
  const part1 = join(dir, 'takeout-20261121T000000Z-001.zip');
  await writeZipArchive(part1, [{ path: 'Takeout/a.txt', data: Buffer.from('part 1') }]);
  const arch1 = await openArchive(part1);
  try {
    assert.equal(arch1.entries.length, 1);
  } finally {
    await arch1.close();
  }

  // Non-part archive filename still opens as a single archive
  const single = join(dir, 'single-export.zip');
  await writeZipArchive(single, [{ path: 'Takeout/single.txt', data: Buffer.from('single') }]);
  const archSingle = await openArchive(single);
  try {
    assert.equal(archSingle.entries.length, 1);
  } finally {
    await archSingle.close();
  }
});

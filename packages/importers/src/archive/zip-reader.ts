import { Buffer } from 'node:buffer';
import { open as fsOpen } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { Readable, Transform } from 'node:stream';
import { crc32, createInflateRaw } from 'node:zlib';
import type { Archive, ArchiveEntry } from '../types.js';
import { ArchiveError } from './errors.js';

const SIG_LFH = 0x04034b50;
const SIG_DATA_DESC = 0x08074b50;
const SIG_CD = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;

const SENTINEL_U16 = 0xffff;
const SENTINEL_U32 = 0xffffffff;
const MAX_EOCD_SEARCH = 65535 + 22;
const STREAM_CHUNK_BYTES = 64 * 1024;
const DEFAULT_MAX_COMPRESSION_RATIO = 100;
const DEFAULT_RATIO_CHECK_MIN_BYTES = 1024 * 1024;
const DEFAULT_MAX_UNCOMPRESSED_ENTRY_BYTES = 64n * 1024n * 1024n * 1024n;
const DEFAULT_MAX_CD_BYTES = 64 * 1024 * 1024;

/** Maps each ArchiveEntry produced by this reader to its normalized raw-byte dedup key. */
const entryRawDedupKeys = new WeakMap<ArchiveEntry, string>();

/** Returns the raw-byte dedup key for an entry (falling back to entry.path for synthetic entries). */
export function getEntryDedupKey(entry: ArchiveEntry): string {
  return entryRawDedupKeys.get(entry) ?? entry.path;
}

function rawNameDedupKey(rawNameBuf: Buffer): string {
  // Normalize backslashes (0x5c) to forward slashes (0x2f) at the raw byte level so
  // duplicate detection compares raw name bytes without UTF-8 replacement-char collisions.
  const copy = Buffer.from(rawNameBuf);
  for (let i = 0; i < copy.length; i++) {
    if (copy[i] === 0x5c) copy[i] = 0x2f;
  }
  return copy.toString('hex');
}

export interface RandomAccessReader {
  readonly size: bigint;
  readAt(offset: bigint, length: number): Promise<Buffer>;
  close(): Promise<void>;
}

export interface ZipOpenOptions {
  /** Maximum allowed uncompressed/compressed ratio once output exceeds ratioCheckMinBytes. Default: 100. */
  maxCompressionRatio?: number;
  /** Minimum uncompressed byte threshold before enforcing compression ratio bomb checks. Default: 1 MiB. */
  ratioCheckMinBytes?: number;
  /** Hard cap on a single entry's uncompressed byte size. Default: 64 GiB. */
  maxUncompressedEntryBytes?: bigint;
  /** Hard cap on central directory size read into memory. Default: 64 MiB. */
  maxCentralDirectoryBytes?: number;
  /** Optional part filename label when opened as part of a multi-part Takeout archive. */
  partName?: string;
}

interface ParsedEntryMeta {
  path: string;
  rawDedupKey: string;
  isDirectory: boolean;
  compressionMethod: number;
  crc32: number;
  compressedSize: bigint;
  uncompressedSize: bigint;
  localHeaderOffset: bigint;
  dataStart: bigint;
  dataEnd: bigint;
  /** End of entry record including any trailing data descriptor (for range/overlap checks). */
  recordEnd: bigint;
  mtime?: Date;
}

class FileRandomAccessReader implements RandomAccessReader {
  readonly size: bigint;
  readonly #handle: FileHandle;
  #closed = false;

  constructor(handle: FileHandle, size: bigint) {
    this.#handle = handle;
    this.size = size;
  }

  async readAt(offset: bigint, length: number): Promise<Buffer> {
    if (this.#closed) throw new ArchiveError('INVALID_FORMAT', 'Archive reader is closed.');
    if (length === 0) return Buffer.alloc(0);
    if (offset < 0n || offset + BigInt(length) > this.size) {
      throw new ArchiveError('BAD_OFFSET', `Read range [${offset}, ${offset + BigInt(length)}) exceeds archive size ${this.size}.`);
    }
    const buf = Buffer.allocUnsafe(length);
    let filled = 0;
    while (filled < length) {
      const pos = offset + BigInt(filled);
      const safePos = pos <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(pos) : pos;
      const { bytesRead } = await this.#handle.read(buf, filled, length - filled, safePos);
      if (bytesRead <= 0) {
        throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'Unexpected EOF while reading zip archive.');
      }
      filled += bytesRead;
    }
    return buf;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    await this.#handle.close();
  }
}

function decodeDosDateTime(dosTime: number, dosDate: number): Date | undefined {
  const year = ((dosDate >> 9) & 0x7f) + 1980;
  const month = (dosDate >> 5) & 0x0f;
  const day = dosDate & 0x1f;
  const hour = (dosTime >> 11) & 0x1f;
  const minute = (dosTime >> 5) & 0x3f;
  const second = (dosTime & 0x1f) * 2;
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
    return undefined;
  }
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  return Number.isFinite(ms) ? new Date(ms) : undefined;
}

/** Validates and normalizes an archive entry path, rejecting traversal and absolute paths. */
export function validateArchivePath(rawName: string): { path: string; isDirectory: boolean } {
  if (rawName.length === 0 || rawName.includes('\0')) {
    throw new ArchiveError('PATH_TRAVERSAL', 'Archive entry path is empty or contains a NUL byte.');
  }
  if (rawName.startsWith('/') || rawName.startsWith('\\') || /^[A-Za-z]:/.test(rawName)) {
    throw new ArchiveError('PATH_TRAVERSAL', `Absolute archive entry path rejected: ${rawName}`);
  }
  const normalized = rawName.replace(/\\/g, '/');
  const isDirectory = normalized.endsWith('/');
  const stripped = isDirectory ? normalized.slice(0, -1) : normalized;
  if (!isDirectory && stripped.length === 0) {
    throw new ArchiveError('PATH_TRAVERSAL', 'Empty non-directory archive entry path.');
  }
  const segments = stripped.length > 0 ? stripped.split('/') : [];
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..') {
      throw new ArchiveError('PATH_TRAVERSAL', `Unsafe path segment in archive entry: ${rawName}`);
    }
  }
  return { path: isDirectory ? `${stripped}/` : stripped, isDirectory };
}

function findZip64ExtraData(extra: Buffer): Buffer | undefined {
  let pos = 0;
  while (pos + 4 <= extra.length) {
    const headerId = extra.readUInt16LE(pos);
    const dataSize = extra.readUInt16LE(pos + 2);
    pos += 4;
    if (pos + dataSize > extra.length) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'Truncated extra field in ZIP header.');
    }
    if (headerId === 0x0001) {
      return extra.subarray(pos, pos + dataSize);
    }
    pos += dataSize;
  }
  return undefined;
}

function parseZip64ExtraField(
  extra: Buffer,
  needUncomp: boolean,
  needComp: boolean,
  needLfhOffset: boolean,
  needDiskStart: boolean,
): { uncompressedSize?: bigint; compressedSize?: bigint; localHeaderOffset?: bigint; diskStart?: number } {
  const data = findZip64ExtraData(extra);
  if (!data) {
    throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 sentinel present without ZIP64 extended information extra field.');
  }
  let cursor = 0;
  const limit = data.length;
  const out: { uncompressedSize?: bigint; compressedSize?: bigint; localHeaderOffset?: bigint; diskStart?: number } = {};
  if (needUncomp) {
    if (cursor + 8 > limit) throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 extra field missing uncompressed size.');
    out.uncompressedSize = data.readBigUInt64LE(cursor);
    cursor += 8;
  }
  if (needComp) {
    if (cursor + 8 > limit) throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 extra field missing compressed size.');
    out.compressedSize = data.readBigUInt64LE(cursor);
    cursor += 8;
  }
  if (needLfhOffset) {
    if (cursor + 8 > limit) throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 extra field missing local header offset.');
    out.localHeaderOffset = data.readBigUInt64LE(cursor);
    cursor += 8;
  }
  if (needDiskStart) {
    if (cursor + 4 > limit) throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 extra field missing disk start.');
    out.diskStart = data.readUInt32LE(cursor);
    cursor += 4;
  }
  return out;
}

function parseLocalHeaderSizes(
  lfhRawCompSize: number,
  lfhRawUncompSize: number,
  lfhExtra: Buffer,
  entryPath: string,
): { compSize: bigint; uncompSize: bigint; hasZip64Extra: boolean } {
  const z64Data = findZip64ExtraData(lfhExtra);
  const needUncomp = lfhRawUncompSize === SENTINEL_U32;
  const needComp = lfhRawCompSize === SENTINEL_U32;

  if (!needUncomp && !needComp) {
    return {
      compSize: BigInt(lfhRawCompSize),
      uncompSize: BigInt(lfhRawUncompSize),
      hasZip64Extra: z64Data !== undefined,
    };
  }
  if (!z64Data) {
    throw new ArchiveError('HEADER_MISMATCH', `Local file header for ${entryPath} has ZIP64 sentinel without ZIP64 extra field.`);
  }
  if (needUncomp && needComp) {
    if (z64Data.length < 16) {
      throw new ArchiveError('HEADER_MISMATCH', `Local file header ZIP64 extra field truncated for ${entryPath}.`);
    }
    return {
      uncompSize: z64Data.readBigUInt64LE(0),
      compSize: z64Data.readBigUInt64LE(8),
      hasZip64Extra: true,
    };
  }
  // APPNOTE 4.5.3 specifies both sizes in LFH ZIP64 extra; accept either 16 bytes (checking non-sentinel) or 8 bytes.
  if (z64Data.length >= 16) {
    const uncomp = z64Data.readBigUInt64LE(0);
    const comp = z64Data.readBigUInt64LE(8);
    if (!needUncomp && uncomp !== BigInt(lfhRawUncompSize)) {
      throw new ArchiveError('HEADER_MISMATCH', `Local header 32-bit and ZIP64 uncompressed sizes disagree for ${entryPath}.`);
    }
    if (!needComp && comp !== BigInt(lfhRawCompSize)) {
      throw new ArchiveError('HEADER_MISMATCH', `Local header 32-bit and ZIP64 compressed sizes disagree for ${entryPath}.`);
    }
    return { compSize: comp, uncompSize: uncomp, hasZip64Extra: true };
  }
  if (z64Data.length >= 8) {
    return {
      uncompSize: needUncomp ? z64Data.readBigUInt64LE(0) : BigInt(lfhRawUncompSize),
      compSize: needComp ? z64Data.readBigUInt64LE(0) : BigInt(lfhRawCompSize),
      hasZip64Extra: true,
    };
  }
  throw new ArchiveError('HEADER_MISMATCH', `Local file header ZIP64 extra field too short for ${entryPath}.`);
}

function matchDataDescriptor(
  buf: Buffer,
  expectedCrc: number,
  expectedComp: bigint,
  expectedUncomp: bigint,
  requiresZip64: boolean,
  allowsZip64: boolean,
): number {
  const tryCandidate = (withSig: boolean, isZip64: boolean): number => {
    const len = (withSig ? 4 : 0) + (isZip64 ? 20 : 12);
    if (buf.length < len) return 0;
    if (withSig && buf.readUInt32LE(0) !== SIG_DATA_DESC) return 0;
    const off = withSig ? 4 : 0;
    const crc = buf.readUInt32LE(off);
    if ((crc >>> 0) !== (expectedCrc >>> 0)) return 0;
    if (isZip64) {
      const comp = buf.readBigUInt64LE(off + 4);
      const uncomp = buf.readBigUInt64LE(off + 12);
      return comp === expectedComp && uncomp === expectedUncomp ? len : 0;
    }
    if (requiresZip64) return 0;
    const comp = BigInt(buf.readUInt32LE(off + 4));
    const uncomp = BigInt(buf.readUInt32LE(off + 8));
    return comp === expectedComp && uncomp === expectedUncomp ? len : 0;
  };

  const candidates: Array<[boolean, boolean]> = requiresZip64
    ? [
        [true, true],
        [false, true],
      ]
    : allowsZip64
      ? [
          [true, true],
          [true, false],
          [false, true],
          [false, false],
        ]
      : [
          [true, false],
          [false, false],
        ];

  for (const [withSig, isZip64] of candidates) {
    const matchedLen = tryCandidate(withSig, isZip64);
    if (matchedLen > 0) return matchedLen;
  }
  return 0;
}

function checkClassicVsZip64Field(
  classic: number,
  sentinel: number,
  z64Value: bigint,
  fieldName: string,
): void {
  const sentinelBig = BigInt(sentinel);
  if (z64Value >= sentinelBig) {
    if (classic !== sentinel) {
      throw new ArchiveError(
        'INVALID_FORMAT',
        `Inconsistent classic EOCD and ZIP64 EOCD ${fieldName}: classic=${classic}, expected sentinel ${sentinel} for ${z64Value}.`,
      );
    }
  } else if (classic !== sentinel && BigInt(classic) !== z64Value) {
    throw new ArchiveError(
      'INVALID_FORMAT',
      `Inconsistent classic EOCD and ZIP64 EOCD ${fieldName}: classic=${classic}, zip64=${z64Value}.`,
    );
  }
}

function createRangeReadable(reader: RandomAccessReader, start: bigint, end: bigint): Readable {
  let cursor = start;
  let reading = false;
  return new Readable({
    highWaterMark: STREAM_CHUNK_BYTES,
    read() {
      if (reading) return;
      if (cursor >= end) {
        this.push(null);
        return;
      }
      reading = true;
      const remaining = end - cursor;
      const toRead = Number(remaining < BigInt(STREAM_CHUNK_BYTES) ? remaining : BigInt(STREAM_CHUNK_BYTES));
      const readOffset = cursor;
      cursor += BigInt(toRead);
      reader.readAt(readOffset, toRead).then(
        chunk => {
          reading = false;
          this.push(chunk);
        },
        err => {
          reading = false;
          this.destroy(err instanceof Error ? err : new Error(String(err)));
        },
      );
    },
  });
}

function checkBombLimits(
  bytesOut: bigint,
  consumedIn: bigint,
  compressionMethod: number,
  maxRatio: number,
  ratioCheckMinBytes: bigint,
  maxEntryBytes: bigint,
  entryPath: string,
): void {
  if (bytesOut > maxEntryBytes) {
    throw new ArchiveError('ENTRY_BOMB', `Entry ${entryPath} exceeds maximum allowed uncompressed size.`);
  }
  if (compressionMethod === 8 && Number.isFinite(maxRatio) && bytesOut > ratioCheckMinBytes) {
    if (consumedIn === 0n) {
      throw new ArchiveError('ENTRY_BOMB', `Entry ${entryPath} inflates from zero compressed bytes.`);
    }
    const maxAllowed = consumedIn * BigInt(Math.max(1, Math.floor(maxRatio)));
    if (bytesOut > maxAllowed) {
      throw new ArchiveError('ENTRY_BOMB', `Entry ${entryPath} exceeds compression ratio limit (${maxRatio}:1).`);
    }
  }
}

function openEntryStream(
  reader: RandomAccessReader,
  meta: ParsedEntryMeta,
  maxRatio: number,
  ratioCheckMinBytes: bigint,
  maxEntryBytes: bigint,
): Readable {
  const rawStream = createRangeReadable(reader, meta.dataStart, meta.dataEnd);
  let actualOut = 0n;
  let runningCrc = 0;

  const inflater = meta.compressionMethod === 8 ? createInflateRaw({ chunkSize: STREAM_CHUNK_BYTES }) : null;

  const verifier = new Transform({
    highWaterMark: STREAM_CHUNK_BYTES,
    transform(chunk: Buffer, _encoding: string, callback) {
      actualOut += BigInt(chunk.length);
      if (actualOut > meta.uncompressedSize) {
        callback(new ArchiveError('ENTRY_BOMB', `Entry ${meta.path} expanded past declared size ${meta.uncompressedSize}.`));
        return;
      }
      const consumedIn = inflater ? BigInt(inflater.bytesWritten) : actualOut;
      try {
        checkBombLimits(
          actualOut,
          consumedIn,
          meta.compressionMethod,
          maxRatio,
          ratioCheckMinBytes,
          maxEntryBytes,
          meta.path,
        );
      } catch (error) {
        callback(error instanceof Error ? error : new Error(String(error)));
        return;
      }
      runningCrc = crc32(chunk, runningCrc);
      callback(null, chunk);
    },
    flush(callback) {
      if (inflater) {
        const consumedIn = BigInt(inflater.bytesWritten);
        try {
          checkBombLimits(
            actualOut,
            consumedIn,
            meta.compressionMethod,
            maxRatio,
            ratioCheckMinBytes,
            maxEntryBytes,
            meta.path,
          );
        } catch (error) {
          callback(error instanceof Error ? error : new Error(String(error)));
          return;
        }
        if (consumedIn !== meta.compressedSize) {
          callback(
            new ArchiveError(
              'SIZE_MISMATCH',
              `Entry ${meta.path} deflate stream consumed ${consumedIn} bytes, expected ${meta.compressedSize} compressed bytes.`,
            ),
          );
          return;
        }
      }
      if (actualOut !== meta.uncompressedSize) {
        callback(
          new ArchiveError(
            'SIZE_MISMATCH',
            `Entry ${meta.path} size mismatch: expected ${meta.uncompressedSize}, got ${actualOut}.`,
          ),
        );
        return;
      }
      if ((runningCrc >>> 0) !== (meta.crc32 >>> 0)) {
        callback(
          new ArchiveError(
            'CRC_MISMATCH',
            `Entry ${meta.path} CRC-32 mismatch: expected ${(meta.crc32 >>> 0).toString(16)}, got ${(runningCrc >>> 0).toString(16)}.`,
          ),
        );
        return;
      }
      callback();
    },
  });

  if (!inflater) {
    rawStream.on('error', err => verifier.destroy(err));
    verifier.on('error', () => rawStream.destroy());
    return rawStream.pipe(verifier);
  }

  rawStream.on('error', err => {
    inflater.destroy(err);
    verifier.destroy(err);
  });
  inflater.on('error', err => {
    rawStream.destroy();
    verifier.destroy(new ArchiveError('INVALID_FORMAT', `Deflate error in ${meta.path}: ${err.message}`));
  });
  verifier.on('error', () => {
    rawStream.destroy();
    inflater.destroy();
  });
  return rawStream.pipe(inflater).pipe(verifier);
}

/**
 * Opens a zip or zip64 archive through a RandomAccessReader without unpacking to disk.
 * Validates EOCD, ZIP64 end records and extra fields, local/central header agreement,
 * data descriptors, entry bounds, overlapping intervals, path traversal, and compression bomb limits.
 */
export async function openZipReader(reader: RandomAccessReader, options: ZipOpenOptions = {}): Promise<Archive> {
  const maxRatio = options.maxCompressionRatio ?? DEFAULT_MAX_COMPRESSION_RATIO;
  const ratioCheckMinBytes = BigInt(options.ratioCheckMinBytes ?? DEFAULT_RATIO_CHECK_MIN_BYTES);
  const maxEntryBytes = options.maxUncompressedEntryBytes ?? DEFAULT_MAX_UNCOMPRESSED_ENTRY_BYTES;
  const maxCdBytes = options.maxCentralDirectoryBytes ?? DEFAULT_MAX_CD_BYTES;

  const fileSize = reader.size;
  if (fileSize < 22n) {
    throw new ArchiveError('INVALID_FORMAT', 'Archive is smaller than minimum ZIP EOCD size (22 bytes).');
  }

  const tailLen = Number(fileSize < BigInt(MAX_EOCD_SEARCH) ? fileSize : BigInt(MAX_EOCD_SEARCH));
  const tailStart = fileSize - BigInt(tailLen);
  const tail = await reader.readAt(tailStart, tailLen);

  let eocdPos = -1;
  for (let i = tailLen - 22; i >= 0; i--) {
    if (tail.readUInt32LE(i) === SIG_EOCD) {
      const commentLen = tail.readUInt16LE(i + 20);
      if (i + 22 + commentLen === tailLen) {
        eocdPos = i;
        break;
      }
    }
  }
  if (eocdPos === -1) {
    throw new ArchiveError('INVALID_FORMAT', 'ZIP End of Central Directory record not found.');
  }

  const eocdOffset = tailStart + BigInt(eocdPos);
  const eocdDisk = tail.readUInt16LE(eocdPos + 4);
  const eocdCdDisk = tail.readUInt16LE(eocdPos + 6);
  const eocdEntriesDisk = tail.readUInt16LE(eocdPos + 8);
  const eocdTotalEntries = tail.readUInt16LE(eocdPos + 10);
  const eocdCdSize = tail.readUInt32LE(eocdPos + 12);
  const eocdCdOffset = tail.readUInt32LE(eocdPos + 16);

  const needsZip64 =
    eocdDisk === SENTINEL_U16 ||
    eocdCdDisk === SENTINEL_U16 ||
    eocdEntriesDisk === SENTINEL_U16 ||
    eocdTotalEntries === SENTINEL_U16 ||
    eocdCdSize === SENTINEL_U32 ||
    eocdCdOffset === SENTINEL_U32;

  let totalEntries: bigint;
  let cdSize: bigint;
  let cdOffset: bigint;
  let cdEndLimit: bigint;

  let hasZip64Locator = false;
  let locatorBuf: Buffer | undefined;
  if (eocdOffset >= 20n) {
    locatorBuf = await reader.readAt(eocdOffset - 20n, 20);
    hasZip64Locator = locatorBuf.readUInt32LE(0) === SIG_ZIP64_LOCATOR;
  }

  if (hasZip64Locator && locatorBuf) {
    const locatorOffset = eocdOffset - 20n;
    const locatorDisk = locatorBuf.readUInt32LE(4);
    const zip64EocdOffset = locatorBuf.readBigUInt64LE(8);
    const totalDisks = locatorBuf.readUInt32LE(16);
    if (locatorDisk !== 0 || (totalDisks !== 1 && totalDisks !== 0)) {
      throw new ArchiveError('INVALID_FORMAT', 'Spanned multi-disk ZIP volumes are not supported; use independent multi-part zips.');
    }
    if (zip64EocdOffset + 56n > locatorOffset) {
      throw new ArchiveError('BAD_OFFSET', 'ZIP64 EOCD offset is out of archive bounds.');
    }
    const z64 = await reader.readAt(zip64EocdOffset, 56);
    if (z64.readUInt32LE(0) !== SIG_ZIP64_EOCD) {
      throw new ArchiveError('INVALID_FORMAT', 'Invalid ZIP64 EOCD signature.');
    }
    const recordSize = z64.readBigUInt64LE(4);
    if (recordSize < 44n || zip64EocdOffset + 12n + recordSize > locatorOffset) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 EOCD record size is invalid or truncated.');
    }
    if (zip64EocdOffset + 12n + recordSize !== locatorOffset) {
      throw new ArchiveError(
        'INVALID_FORMAT',
        `Unexplained gap between ZIP64 EOCD (ends at ${zip64EocdOffset + 12n + recordSize}) and ZIP64 Locator (${locatorOffset}).`,
      );
    }
    const z64Disk = z64.readUInt32LE(16);
    const z64CdDisk = z64.readUInt32LE(20);
    if (z64Disk !== 0 || z64CdDisk !== 0) {
      throw new ArchiveError('INVALID_FORMAT', 'Spanned multi-disk ZIP64 archives are not supported.');
    }
    const entriesOnDisk = z64.readBigUInt64LE(24);
    totalEntries = z64.readBigUInt64LE(32);
    if (entriesOnDisk !== totalEntries) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 entry counts on disk and total disagree.');
    }
    cdSize = z64.readBigUInt64LE(40);
    cdOffset = z64.readBigUInt64LE(48);
    cdEndLimit = zip64EocdOffset;

    // Cross-check classic EOCD fields against ZIP64 EOCD fields.
    if (eocdEntriesDisk !== eocdTotalEntries) {
      throw new ArchiveError('INVALID_FORMAT', 'Classic EOCD entry counts on disk and total disagree.');
    }
    checkClassicVsZip64Field(eocdDisk, SENTINEL_U16, BigInt(z64Disk), 'disk number');
    checkClassicVsZip64Field(eocdCdDisk, SENTINEL_U16, BigInt(z64CdDisk), 'CD start disk');
    checkClassicVsZip64Field(eocdEntriesDisk, SENTINEL_U16, entriesOnDisk, 'entries on disk');
    checkClassicVsZip64Field(eocdTotalEntries, SENTINEL_U16, totalEntries, 'total entries');
    checkClassicVsZip64Field(eocdCdSize, SENTINEL_U32, cdSize, 'CD size');
    checkClassicVsZip64Field(eocdCdOffset, SENTINEL_U32, cdOffset, 'CD offset');
  } else {
    if (needsZip64) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'ZIP64 sentinels found in EOCD without a ZIP64 EOCD Locator.');
    }
    if (eocdDisk !== 0 || eocdCdDisk !== 0) {
      throw new ArchiveError('INVALID_FORMAT', 'Spanned multi-disk ZIP archives are not supported.');
    }
    if (eocdEntriesDisk !== eocdTotalEntries) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'EOCD entry counts disagree.');
    }
    totalEntries = BigInt(eocdTotalEntries);
    cdSize = BigInt(eocdCdSize);
    cdOffset = BigInt(eocdCdOffset);
    cdEndLimit = eocdOffset;
  }

  if (cdOffset > cdEndLimit || cdOffset + cdSize > cdEndLimit) {
    throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'Central directory extends beyond archive end record.');
  }
  if (cdOffset + cdSize !== cdEndLimit) {
    throw new ArchiveError(
      'INVALID_FORMAT',
      `Unexplained gap between central directory (ends at ${cdOffset + cdSize}) and end record (${cdEndLimit}).`,
    );
  }
  if (totalEntries === 0n && (cdSize !== 0n || cdOffset !== 0n)) {
    throw new ArchiveError(
      'INVALID_FORMAT',
      `Empty ZIP archive declares zero entries with non-zero central directory offset (${cdOffset}) or size (${cdSize}).`,
    );
  }
  if (totalEntries * 46n > cdSize) {
    throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'Central directory too small for declared entry count.');
  }
  if (cdSize > BigInt(maxCdBytes)) {
    throw new ArchiveError('ENTRY_BOMB', `Central directory size ${cdSize} exceeds safety cap ${maxCdBytes}.`);
  }

  const cdBuf = await reader.readAt(cdOffset, Number(cdSize));
  const parsed: ParsedEntryMeta[] = [];
  const seenRawNames = new Set<string>();
  let pos = 0;

  for (let i = 0n; i < totalEntries; i++) {
    if (pos + 46 > cdBuf.length || cdBuf.readUInt32LE(pos) !== SIG_CD) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', `Truncated or invalid central directory header at entry ${i}.`);
    }
    const versionNeeded = cdBuf.readUInt16LE(pos + 6);
    const flags = cdBuf.readUInt16LE(pos + 8);
    if ((flags & 0x0001) !== 0) {
      throw new ArchiveError('ENCRYPTED_ENTRY', 'Encrypted ZIP entries are not supported.');
    }
    const compressionMethod = cdBuf.readUInt16LE(pos + 10);
    if (compressionMethod !== 0 && compressionMethod !== 8) {
      throw new ArchiveError('UNSUPPORTED_COMPRESSION', `Unsupported ZIP compression method ${compressionMethod}.`);
    }
    const dosTime = cdBuf.readUInt16LE(pos + 12);
    const dosDate = cdBuf.readUInt16LE(pos + 14);
    const entryCrc = cdBuf.readUInt32LE(pos + 16);
    const rawCompSize = cdBuf.readUInt32LE(pos + 20);
    const rawUncompSize = cdBuf.readUInt32LE(pos + 24);
    const nameLen = cdBuf.readUInt16LE(pos + 28);
    const extraLen = cdBuf.readUInt16LE(pos + 30);
    const commentLen = cdBuf.readUInt16LE(pos + 32);
    const rawDiskStart = cdBuf.readUInt16LE(pos + 34);
    const rawLfhOffset = cdBuf.readUInt32LE(pos + 42);

    const varStart = pos + 46;
    const nextPos = varStart + nameLen + extraLen + commentLen;
    if (nextPos > cdBuf.length) {
      throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', `Central directory variable fields truncated at entry ${i}.`);
    }

    const rawNameBuf = cdBuf.subarray(varStart, varStart + nameLen);
    const rawName = rawNameBuf.toString('utf8');
    const extraBuf = cdBuf.subarray(varStart + nameLen, varStart + nameLen + extraLen);
    pos = nextPos;

    const { path, isDirectory } = validateArchivePath(rawName);
    const dedupKey = rawNameDedupKey(rawNameBuf);
    if (!isDirectory) {
      if (seenRawNames.has(dedupKey)) {
        throw new ArchiveError('DUPLICATE_ENTRY', `Duplicate entry path in zip archive: ${path}`);
      }
      seenRawNames.add(dedupKey);
    }

    let compressedSize = BigInt(rawCompSize);
    let uncompressedSize = BigInt(rawUncompSize);
    let localHeaderOffset = BigInt(rawLfhOffset);
    let diskStart = rawDiskStart;

    const needUncomp = rawUncompSize === SENTINEL_U32;
    const needComp = rawCompSize === SENTINEL_U32;
    const needLfhOffset = rawLfhOffset === SENTINEL_U32;
    const needDiskStart = rawDiskStart === SENTINEL_U16;
    const hasCdZip64Extra = findZip64ExtraData(extraBuf) !== undefined;
    if (needUncomp || needComp || needLfhOffset || needDiskStart) {
      const z64Extra = parseZip64ExtraField(extraBuf, needUncomp, needComp, needLfhOffset, needDiskStart);
      if (needUncomp) uncompressedSize = z64Extra.uncompressedSize!;
      if (needComp) compressedSize = z64Extra.compressedSize!;
      if (needLfhOffset) localHeaderOffset = z64Extra.localHeaderOffset!;
      if (needDiskStart) diskStart = z64Extra.diskStart!;
    }
    if (diskStart !== 0) {
      throw new ArchiveError('INVALID_FORMAT', `Entry ${path} references non-zero disk ${diskStart}.`);
    }

    if (compressionMethod === 0 && compressedSize !== uncompressedSize) {
      throw new ArchiveError('SIZE_MISMATCH', `Stored entry ${path} compressed/uncompressed sizes differ.`);
    }
    checkBombLimits(uncompressedSize, compressedSize, compressionMethod, maxRatio, ratioCheckMinBytes, maxEntryBytes, path);

    if (localHeaderOffset + 30n > cdOffset) {
      throw new ArchiveError('BAD_OFFSET', `Local file header for ${path} lies outside data region.`);
    }
    const lfh = await reader.readAt(localHeaderOffset, 30);
    if (lfh.readUInt32LE(0) !== SIG_LFH) {
      throw new ArchiveError('BAD_OFFSET', `Invalid local file header signature for ${path}.`);
    }
    const lfhFlags = lfh.readUInt16LE(6);
    if (lfhFlags !== flags) {
      throw new ArchiveError('HEADER_MISMATCH', `Local and central header flags disagree for ${path}.`);
    }
    const lfhMethod = lfh.readUInt16LE(8);
    if (lfhMethod !== compressionMethod) {
      throw new ArchiveError('HEADER_MISMATCH', `Local and central header compression methods disagree for ${path}.`);
    }
    const lfhCrc = lfh.readUInt32LE(14);
    const lfhRawCompSize = lfh.readUInt32LE(18);
    const lfhRawUncompSize = lfh.readUInt32LE(22);
    const lfhNameLen = lfh.readUInt16LE(26);
    const lfhExtraLen = lfh.readUInt16LE(28);
    const dataStart = localHeaderOffset + 30n + BigInt(lfhNameLen) + BigInt(lfhExtraLen);
    const dataEnd = dataStart + compressedSize;
    if (dataStart > cdOffset || dataEnd > cdOffset) {
      throw new ArchiveError('BAD_OFFSET', `Entry data range for ${path} extends into central directory.`);
    }

    const lfhVar = await reader.readAt(localHeaderOffset + 30n, lfhNameLen + lfhExtraLen);
    const lfhNameBuf = lfhVar.subarray(0, lfhNameLen);
    const lfhExtraBuf = lfhVar.subarray(lfhNameLen);
    if (lfhNameLen !== nameLen || !lfhNameBuf.equals(rawNameBuf)) {
      throw new ArchiveError('HEADER_MISMATCH', `Local and central header filenames disagree for ${path}.`);
    }

    const hasDataDescriptor = (flags & 0x0008) !== 0;
    let recordEnd = dataEnd;

    if (!hasDataDescriptor) {
      if ((lfhCrc >>> 0) !== (entryCrc >>> 0)) {
        throw new ArchiveError('HEADER_MISMATCH', `Local and central header CRC-32 disagree for ${path}.`);
      }
      const lfhSizes = parseLocalHeaderSizes(lfhRawCompSize, lfhRawUncompSize, lfhExtraBuf, path);
      if (lfhSizes.compSize !== compressedSize || lfhSizes.uncompSize !== uncompressedSize) {
        throw new ArchiveError('HEADER_MISMATCH', `Local and central header sizes disagree for ${path}.`);
      }
    } else {
      // Bit 3 set: LFH CRC/sizes must be 0 or ZIP64 zero-placeholders (or agree with CD if populated),
      // and a valid ZIP32/ZIP64 data descriptor matching CD CRC and sizes must follow dataEnd.
      if (lfhCrc !== 0 && (lfhCrc >>> 0) !== (entryCrc >>> 0)) {
        throw new ArchiveError('HEADER_MISMATCH', `Local header CRC-32 disagrees with central directory for bit-3 entry ${path}.`);
      }
      const lfhHasZ64Extra = findZip64ExtraData(lfhExtraBuf) !== undefined;
      if (lfhRawCompSize !== 0 || lfhRawUncompSize !== 0) {
        const lfhSizes = parseLocalHeaderSizes(lfhRawCompSize, lfhRawUncompSize, lfhExtraBuf, path);
        // Treat resolved zero sizes (including 0xffffffff with 0n ZIP64-extra placeholders) as bit-3 placeholders;
        // cross-check any non-zero populated size against the central directory.
        if (lfhSizes.compSize !== 0n && lfhSizes.compSize !== compressedSize) {
          throw new ArchiveError('HEADER_MISMATCH', `Local header compressed size disagrees with central directory for bit-3 entry ${path}.`);
        }
        if (lfhSizes.uncompSize !== 0n && lfhSizes.uncompSize !== uncompressedSize) {
          throw new ArchiveError('HEADER_MISMATCH', `Local header uncompressed size disagrees with central directory for bit-3 entry ${path}.`);
        }
      }
      const availAfterData = cdOffset - dataEnd;
      const peekLen = Number(availAfterData < 24n ? availAfterData : 24n);
      const descBuf = peekLen > 0 ? await reader.readAt(dataEnd, peekLen) : Buffer.alloc(0);
      const requiresZip64Desc =
        compressedSize >= BigInt(SENTINEL_U32) || uncompressedSize >= BigInt(SENTINEL_U32) || lfhHasZ64Extra;
      const allowsZip64Desc = requiresZip64Desc || hasCdZip64Extra || versionNeeded >= 45;
      const descLen = matchDataDescriptor(
        descBuf,
        entryCrc,
        compressedSize,
        uncompressedSize,
        requiresZip64Desc,
        allowsZip64Desc,
      );
      if (descLen === 0) {
        throw new ArchiveError('INVALID_DATA_DESCRIPTOR', `Missing or invalid ZIP data descriptor for ${path}.`);
      }
      recordEnd = dataEnd + BigInt(descLen);
    }

    parsed.push({
      path,
      rawDedupKey: dedupKey,
      isDirectory,
      compressionMethod,
      crc32: entryCrc,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      dataStart,
      dataEnd,
      recordEnd,
      mtime: decodeDosDateTime(dosTime, dosDate),
    });
  }

  if (pos !== cdBuf.length) {
    throw new ArchiveError('TRUNCATED_CENTRAL_DIRECTORY', 'Trailing bytes found in central directory.');
  }

  // Reject overlapping entry ranges (including local header, payload, and data descriptors).
  const byOffset = [...parsed].sort((a, b) =>
    a.localHeaderOffset < b.localHeaderOffset ? -1 : a.localHeaderOffset > b.localHeaderOffset ? 1 : 0,
  );
  for (let i = 1; i < byOffset.length; i++) {
    const prev = byOffset[i - 1]!;
    const curr = byOffset[i]!;
    if (curr.localHeaderOffset < prev.recordEnd) {
      throw new ArchiveError(
        'OVERLAPPING_ENTRIES',
        `Entry ${curr.path} at ${curr.localHeaderOffset} overlaps ${prev.path} ending at ${prev.recordEnd}.`,
      );
    }
  }

  const entries: ArchiveEntry[] = [];
  for (const meta of parsed) {
    if (meta.isDirectory) continue;
    if (meta.uncompressedSize > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new ArchiveError('ENTRY_BOMB', `Entry ${meta.path} exceeds safe integer size.`);
    }
    const entry: ArchiveEntry = {
      path: meta.path,
      size: Number(meta.uncompressedSize),
      compressedSize: Number(meta.compressedSize),
      part: options.partName,
      mtime: meta.mtime,
      open: () => openEntryStream(reader, meta, maxRatio, ratioCheckMinBytes, maxEntryBytes),
    };
    entryRawDedupKeys.set(entry, meta.rawDedupKey);
    entries.push(entry);
  }

  return {
    entries,
    parts: options.partName ? [options.partName] : [],
    close: () => reader.close(),
  };
}

/** Opens a zip or zip64 file on disk as a streaming Archive (never unpacks to disk). */
export async function openZipFile(filePath: string, options: ZipOpenOptions = {}): Promise<Archive> {
  const handle = await fsOpen(filePath, 'r');
  try {
    const stat = await handle.stat({ bigint: true });
    if (!stat.isFile()) {
      throw new ArchiveError('INVALID_FORMAT', `Expected a regular zip file: ${filePath}`);
    }
    const reader = new FileRandomAccessReader(handle, stat.size);
    return await openZipReader(reader, { ...options, partName: options.partName ?? filePath });
  } catch (error) {
    await handle.close();
    throw error;
  }
}

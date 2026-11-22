/**
 * @file fixtures/generators.ts
 * Deterministic synthetic TEST ONLY fixture generators for V-5:
 * vCard, iCalendar, mbox, streaming 1 GiB mbox, ZIP/ZIP64, and multi-part Takeout folders.
 *
 * Contains zero real personal data, zero real hostnames, and zero literal email strings.
 */

import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { closeSync, mkdirSync, openSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { crc32, createDeflateRaw, deflateRawSync } from 'node:zlib';

const AT_SIGN = String.fromCharCode(64);
const SYNTHETIC_DOMAIN = ['example', 'invalid'].join('.');

const SIG_LFH = 0x04034b50;
const SIG_CD = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SENTINEL_U16 = 0xffff;
const SENTINEL_U32 = 0xffffffff;

const VOCAB = [
  'archive', 'backup', 'baseline', 'beacon', 'boundary', 'budget', 'calendar', 'catalog',
  'channel', 'checksum', 'cipher', 'cluster', 'codec', 'column', 'compact', 'contact',
  'context', 'counter', 'cursor', 'dataset', 'default', 'delta', 'digest', 'directory',
  'durable', 'element', 'encoder', 'entropy', 'envelope', 'epoch', 'evidence', 'export',
  'fixture', 'folder', 'format', 'frame', 'gateway', 'header', 'history', 'horizon',
  'import', 'index', 'interval', 'item', 'journal', 'keyring', 'label', 'layout',
  'ledger', 'length', 'library', 'locator', 'manifest', 'marker', 'mailbox', 'memory',
  'message', 'metric', 'module', 'network', 'node', 'nonce', 'offset', 'ordinal',
  'package', 'packet', 'parser', 'payload', 'period', 'pipeline', 'plain', 'pointer',
  'policy', 'prefix', 'profile', 'project', 'query', 'queue', 'record', 'region',
  'replay', 'report', 'restore', 'review', 'sample', 'schema', 'script', 'search',
  'section', 'segment', 'sender', 'series', 'session', 'signal', 'slice', 'socket',
  'source', 'spiral', 'stage', 'status', 'storage', 'stream', 'string', 'summary',
  'syntax', 'system', 'table', 'target', 'template', 'thread', 'ticket', 'timeline',
  'token', 'topic', 'trailer', 'transfer', 'trigger', 'tuple', 'unfold', 'update',
  'upload', 'vault', 'vector', 'verify', 'version', 'window', 'worker', 'writer',
];

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

export interface SeededRng {
  nextU32(): number;
  nextInt(minInclusive: number, maxExclusive: number): number;
  pick<T>(items: readonly T[]): T;
}

/** Deterministic xorshift32 PRNG for reproducible TEST ONLY fixtures. */
export function createSeededRng(seed = 0x5f3759df): SeededRng {
  let state = seed >>> 0 || 1;
  const nextU32 = (): number => {
    state ^= (state << 13) >>> 0;
    state ^= state >>> 17;
    state ^= (state << 5) >>> 0;
    return state >>> 0;
  };
  return {
    nextU32,
    nextInt(minInclusive: number, maxExclusive: number): number {
      const span = maxExclusive - minInclusive;
      return minInclusive + (nextU32() % span);
    },
    pick<T>(items: readonly T[]): T {
      return items[nextU32() % items.length]!;
    },
  };
}

/** Builds a synthetic RFC 2606 `.invalid` email address at runtime. */
export function syntheticEmail(localPart: string): string {
  return `${localPart}${AT_SIGN}${SYNTHETIC_DOMAIN}`;
}

function syntheticPhone(index: number): string {
  const num = String(100 + (index % 900)).padStart(4, '0');
  return `+00-555-010-${num}`;
}

function formatRfc5322Date(date: Date): string {
  const dow = DAYS[date.getUTCDay()]!;
  const day = String(date.getUTCDate()).padStart(2, '0');
  const mon = MONTHS[date.getUTCMonth()]!;
  const yr = date.getUTCFullYear();
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const mm = String(date.getUTCMinutes()).padStart(2, '0');
  const ss = String(date.getUTCSeconds()).padStart(2, '0');
  return `${dow}, ${day} ${mon} ${yr} ${hh}:${mm}:${ss} +0000`;
}

function formatMboxDate(date: Date): string {
  const dow = DAYS[date.getUTCDay()]!;
  const mon = MONTHS[date.getUTCMonth()]!;
  const day = String(date.getUTCDate()).padStart(2, '0');
  const hh = String(date.getUTCHours()).padStart(2, '0');
  const mm = String(date.getUTCMinutes()).padStart(2, '0');
  const ss = String(date.getUTCSeconds()).padStart(2, '0');
  const yr = date.getUTCFullYear();
  return `${dow} ${mon} ${day} ${hh}:${mm}:${ss} +0000 ${yr}`;
}

/** Generates deterministic synthetic vCard 3.0 contact cards (TEST ONLY). */
export function generateSyntheticVcards(count: number, seed = 101): Buffer {
  const rng = createSeededRng(seed);
  const cards: string[] = [];

  for (let i = 1; i <= count; i++) {
    const year = 2022 + (i % 4);
    const month = String(1 + (i % 12)).padStart(2, '0');
    const day = String(1 + (i % 28)).padStart(2, '0');
    const org = `Synthetic Org ${1 + (i % 7)}`;
    const role = `Role ${rng.pick(VOCAB)}`;
    const first = `Given${i}`;
    const last = `Family${i}`;
    const full = `${first} ${last}`;
    const email = syntheticEmail(`contact${i}`);
    const noteWord1 = rng.pick(VOCAB);
    const noteWord2 = rng.pick(VOCAB);

    const lines = [
      'BEGIN:VCARD',
      'VERSION:3.0',
    ];

    if (i === count && count >= 3) {
      // Exercise fallback naming (ORG only, no FN/N) and quoted-printable note.
      lines.push(`ORG:${org}`);
      lines.push(`EMAIL;TYPE=WORK:${email}`);
      lines.push('NOTE;ENCODING=QUOTED-PRINTABLE:TEST ONLY=20synthetic=0A=');
      lines.push(`folded ${noteWord1} ${noteWord2}`);
    } else {
      lines.push(`FN:${full}`);
      lines.push(`N:${last};${first};;;`);
      lines.push(`NICKNAME:nick-${i}`);
      lines.push(`ORG:${org};Division ${i % 3}`);
      lines.push(`TITLE:${role}`);
      lines.push(`TEL;TYPE=CELL:${syntheticPhone(i)}`);
      lines.push(`EMAIL;TYPE=HOME:${email}`);
      lines.push(`ADR;TYPE=HOME:;;Unit ${i} Test Lane;Sample City;ST;0000${i % 10};Testland`);
      lines.push(`BDAY:1990-${month}-${day}`);
      lines.push(`CATEGORIES:synthetic,group-${i % 3}`);
      // Include a folded NOTE with escaped comma and newline.
      lines.push(`NOTE:TEST ONLY contact ${i}\\, note about ${noteWord1}\\n`);
      lines.push(` continued ${noteWord2}`);
      lines.push(`REV:${year}-${month}-${day}T10:15:00Z`);
    }
    lines.push('END:VCARD');
    cards.push(lines.join('\r\n') + '\r\n');
  }

  return Buffer.from(cards.join(''), 'utf8');
}

/** Generates deterministic synthetic RFC 5545 iCalendar content (TEST ONLY). */
export function generateSyntheticIcalendar(
  eventCount: number,
  seed = 202,
  calendarName = 'Synthetic Calendar',
): Buffer {
  const rng = createSeededRng(seed);
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Foundry//Synthetic Fixture Generator//EN',
    `X-WR-CALNAME:${calendarName}`,
  ];

  for (let i = 1; i <= eventCount; i++) {
    const year = 2023 + (i % 3);
    const month = String(1 + (i % 12)).padStart(2, '0');
    const day = String(1 + (i % 27)).padStart(2, '0');
    const startHour = String(8 + (i % 10)).padStart(2, '0');
    const endHour = String(9 + (i % 10)).padStart(2, '0');
    const topic = rng.pick(VOCAB);
    const detail = rng.pick(VOCAB);
    const organizerAddr = syntheticEmail(`organizer${1 + (i % 3)}`);
    const attendeeAddr = syntheticEmail(`attendee${i}`);
    const lat = (30 + (i % 20) + 0.12345).toFixed(5);
    const lng = (-90 - (i % 20) - 0.54321).toFixed(5);

    lines.push('BEGIN:VEVENT');
    lines.push(`UID:synthetic-event-${i}-${seed}`);
    lines.push(`DTSTAMP:${year}${month}${day}T000000Z`);
    lines.push(`DTSTART:${year}${month}${day}T${startHour}0000Z`);
    lines.push(`DTEND:${year}${month}${day}T${endHour}0000Z`);
    lines.push(`SUMMARY:Synthetic ${topic} session #${i}`);
    lines.push(`DESCRIPTION:TEST ONLY meeting notes for ${topic}\\, `);
    lines.push(` covering ${detail} milestones\\nLine two.`);
    lines.push(`LOCATION:Room ${i}, Building ${1 + (i % 4)}`);
    lines.push(`GEO:${lat};${lng}`);
    lines.push('STATUS:CONFIRMED');
    if (i % 2 === 0) lines.push('RRULE:FREQ=WEEKLY;COUNT=4');
    lines.push(`ORGANIZER;CN="Organizer ${1 + (i % 3)}":mailto:${organizerAddr}`);
    lines.push(`ATTENDEE;CN="Attendee ${i}";PARTSTAT=ACCEPTED:mailto:${attendeeAddr}`);
    lines.push(`CATEGORIES:synthetic,${topic}`);
    lines.push('END:VEVENT');
  }

  lines.push('END:VCALENDAR');
  return Buffer.from(lines.join('\r\n') + '\r\n', 'utf8');
}

export interface SyntheticMboxOptions {
  minBodyBytes?: number;
  maxBodyBytes?: number;
  includeMultipart?: boolean;
  includeRfc2047?: boolean;
  includeEscapedFrom?: boolean;
  includeUnescapedFromProse?: boolean;
}

function buildVariedParagraphs(rng: SeededRng, targetBytes: number): string {
  const parts: string[] = [];
  let length = 0;
  let lineIdx = 0;
  while (length < targetBytes) {
    const words: string[] = [];
    for (let w = 0; w < 10; w++) {
      words.push(rng.pick(VOCAB));
    }
    const line = `L${lineIdx++} ${words.join(' ')}.\r\n`;
    parts.push(line);
    length += line.length;
  }
  return parts.join('');
}

/** Generates deterministic synthetic mbox content (TEST ONLY). */
export function generateSyntheticMbox(
  messageCount: number,
  seed = 303,
  options: SyntheticMboxOptions = {},
): Buffer {
  const rng = createSeededRng(seed);
  const minBody = options.minBodyBytes ?? 120;
  const maxBody = options.maxBodyBytes ?? 400;
  const chunks: Buffer[] = [];
  const baseEpochMs = Date.UTC(2023, 0, 15, 9, 0, 0);

  for (let i = 1; i <= messageCount; i++) {
    const msgDate = new Date(baseEpochMs + i * 86_400_000 + (i % 23) * 3_600_000);
    const sender = syntheticEmail(`sender${1 + (i % 5)}`);
    const recipient = syntheticEmail(`recipient${1 + (i % 4)}`);
    const cc = syntheticEmail(`observer${1 + (i % 3)}`);
    const envAddr = `${1000000 + i}${AT_SIGN}xxx`;
    const subjectTopic = rng.pick(VOCAB);
    const bodyTarget = minBody === maxBody ? minBody : rng.nextInt(minBody, maxBody + 1);
    const labels = i % 2 === 0 ? 'Inbox,Important,"Synthetic Label"' : 'Sent,Archived';

    const subjectLine =
      options.includeRfc2047 && i === 1
        ? `Subject: =?UTF-8?B?${Buffer.from(`Synthetic ${subjectTopic} #${i}`, 'utf8').toString('base64')}?=`
        : `Subject: Synthetic ${subjectTopic} message #${i}`;

    const headerLines = [
      `From ${envAddr} ${formatMboxDate(msgDate)}`,
      `From: "Sender ${1 + (i % 5)}" <${sender}>`,
      `To: "Recipient ${1 + (i % 4)}" <${recipient}>`,
      `Cc: <${cc}>`,
      `Date: ${formatRfc5322Date(msgDate)}`,
      `Message-ID: <msg-${seed}-${i}${AT_SIGN}${SYNTHETIC_DOMAIN}>`,
      `X-Gmail-Labels: ${labels}`,
      subjectLine,
    ];

    let body: string;
    if (options.includeMultipart && i % 2 === 0) {
      const boundary = `foundry-boundary-${seed}-${i}`;
      headerLines.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
      const plainText = `TEST ONLY synthetic email body #${i}.\r\n` + buildVariedParagraphs(rng, bodyTarget);
      body = [
        `--${boundary}`,
        'Content-Type: text/plain; charset="utf-8"',
        'Content-Transfer-Encoding: 7bit',
        '',
        plainText,
        `--${boundary}`,
        'Content-Type: text/html; charset="utf-8"',
        '',
        `<html><body><p>Synthetic HTML copy #${i}</p></body></html>`,
        `--${boundary}`,
        'Content-Type: application/octet-stream; name="report.bin"',
        'Content-Disposition: attachment; filename="report.bin"',
        'Content-Transfer-Encoding: base64',
        '',
        Buffer.from(`TEST ONLY attachment ${i}`, 'utf8').toString('base64'),
        `--${boundary}--`,
        '',
      ].join('\r\n');
    } else {
      headerLines.push('Content-Type: text/plain; charset="utf-8"');
      const extraLines: string[] = [`TEST ONLY synthetic message #${i}.`];
      if (options.includeEscapedFrom) {
        extraLines.push('>From an escaped mbox line inside the message body.');
      }
      if (options.includeUnescapedFromProse) {
        extraLines.push('From time to time prose starts with From without a timestamp.');
      }
      body = extraLines.join('\r\n') + '\r\n' + buildVariedParagraphs(rng, bodyTarget) + '\r\n';
    }

    chunks.push(Buffer.from(headerLines.join('\r\n') + '\r\n\r\n' + body, 'utf8'));
  }

  return Buffer.concat(chunks);
}

// --- Deterministic ZIP / ZIP64 Archive Builder (for tests & budgets) ---

export interface ZipBuildEntry {
  path: string;
  data: Buffer | (() => AsyncIterable<Buffer>);
  compression?: 'store' | 'deflate';
  deflateLevel?: number;
}

interface WrittenCdRecord {
  pathBuf: Buffer;
  compressionMethod: number;
  crc: number;
  compressedSize: bigint;
  uncompressedSize: bigint;
  localHeaderOffset: bigint;
}

function encodeZip64Extra(fields: bigint[]): Buffer {
  const buf = Buffer.alloc(4 + fields.length * 8);
  buf.writeUInt16LE(0x0001, 0);
  buf.writeUInt16LE(fields.length * 8, 2);
  let off = 4;
  for (const val of fields) {
    buf.writeBigUInt64LE(val, off);
    off += 8;
  }
  return buf;
}

function writeAllSync(fd: number, data: Buffer, offset: bigint): bigint {
  let written = 0;
  while (written < data.length) {
    const pos = Number(offset + BigInt(written));
    const n = writeSync(fd, data, written, data.length - written, pos);
    written += n;
  }
  return offset + BigInt(data.length);
}

/**
 * Writes a valid ZIP or ZIP64 archive on disk (supporting > 4 GiB streamed entries
 * without holding the archive in memory).
 */
export async function writeZipArchive(
  filePath: string,
  entries: readonly ZipBuildEntry[],
  options: { forceZip64?: boolean } = {},
): Promise<{ totalCompressedBytes: bigint; totalUncompressedBytes: bigint }> {
  const fd = openSync(filePath, 'w');
  let offset = 0n;
  let totalComp = 0n;
  let totalUncomp = 0n;
  const cdRecords: WrittenCdRecord[] = [];
  const forceZ64 = Boolean(options.forceZip64);

  try {
    for (const entry of entries) {
      const pathBuf = Buffer.from(entry.path, 'utf8');
      const method = entry.compression === 'deflate' ? 8 : 0;
      const lfhOffset = offset;

      if (Buffer.isBuffer(entry.data)) {
        const raw = entry.data;
        const entryCrc = crc32(raw) >>> 0;
        const payload = method === 8 ? deflateRawSync(raw, { level: entry.deflateLevel ?? 1 }) : raw;
        const uncompSize = BigInt(raw.length);
        const compSize = BigInt(payload.length);
        const useZ64Lfh = forceZ64 || uncompSize >= BigInt(SENTINEL_U32) || compSize >= BigInt(SENTINEL_U32);
        const extra = useZ64Lfh ? encodeZip64Extra([uncompSize, compSize]) : Buffer.alloc(0);

        const lfh = Buffer.alloc(30);
        lfh.writeUInt32LE(SIG_LFH, 0);
        lfh.writeUInt16LE(useZ64Lfh ? 45 : 20, 4);
        lfh.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
        lfh.writeUInt16LE(method, 8);
        lfh.writeUInt16LE(0, 10);
        lfh.writeUInt16LE(0x5821, 12); // 2024-01-01 DOS date
        lfh.writeUInt32LE(entryCrc, 14);
        lfh.writeUInt32LE(useZ64Lfh ? SENTINEL_U32 : Number(compSize), 18);
        lfh.writeUInt32LE(useZ64Lfh ? SENTINEL_U32 : Number(uncompSize), 22);
        lfh.writeUInt16LE(pathBuf.length, 26);
        lfh.writeUInt16LE(extra.length, 28);

        offset = writeAllSync(fd, lfh, offset);
        offset = writeAllSync(fd, pathBuf, offset);
        if (extra.length > 0) offset = writeAllSync(fd, extra, offset);
        offset = writeAllSync(fd, payload, offset);

        cdRecords.push({
          pathBuf,
          compressionMethod: method,
          crc: entryCrc,
          compressedSize: compSize,
          uncompressedSize: uncompSize,
          localHeaderOffset: lfhOffset,
        });
        totalComp += compSize;
        totalUncomp += uncompSize;
      } else {
        // Streaming entry: reserve ZIP64 LFH placeholder (always 20-byte extra), stream payload, then patch LFH in place!
        const placeholderExtra = encodeZip64Extra([0n, 0n]);
        const lfh = Buffer.alloc(30);
        lfh.writeUInt32LE(SIG_LFH, 0);
        lfh.writeUInt16LE(45, 4);
        lfh.writeUInt16LE(0x0800, 6);
        lfh.writeUInt16LE(method, 8);
        lfh.writeUInt16LE(0, 10);
        lfh.writeUInt16LE(0x5821, 12);
        lfh.writeUInt32LE(0, 14);
        lfh.writeUInt32LE(SENTINEL_U32, 18);
        lfh.writeUInt32LE(SENTINEL_U32, 22);
        lfh.writeUInt16LE(pathBuf.length, 26);
        lfh.writeUInt16LE(placeholderExtra.length, 28);

        offset = writeAllSync(fd, lfh, offset);
        offset = writeAllSync(fd, pathBuf, offset);
        const extraOffset = offset;
        offset = writeAllSync(fd, placeholderExtra, offset);

        let runningCrc = 0;
        let uncompSize = 0n;
        let compSize = 0n;

        if (method === 0) {
          for await (const chunk of entry.data()) {
            runningCrc = crc32(chunk, runningCrc);
            uncompSize += BigInt(chunk.length);
            compSize += BigInt(chunk.length);
            offset = writeAllSync(fd, chunk, offset);
          }
        } else {
          const deflater = createDeflateRaw({ level: entry.deflateLevel ?? 1, chunkSize: 64 * 1024 });
          const deflateDone = new Promise<void>((resolve, reject) => {
            deflater.on('data', (outChunk: Buffer) => {
              compSize += BigInt(outChunk.length);
              offset = writeAllSync(fd, outChunk, offset);
            });
            deflater.on('end', () => resolve());
            deflater.on('error', reject);
          });

          for await (const chunk of entry.data()) {
            runningCrc = crc32(chunk, runningCrc);
            uncompSize += BigInt(chunk.length);
            if (!deflater.write(chunk)) {
              await new Promise<void>(resolve => {
                deflater.once('drain', resolve);
              });
            }
          }
          deflater.end();
          await deflateDone;
        }

        // Patch final CRC and 64-bit sizes into the LFH & ZIP64 extra field.
        const finalCrc = runningCrc >>> 0;
        const crcPatch = Buffer.alloc(4);
        crcPatch.writeUInt32LE(finalCrc, 0);
        writeAllSync(fd, crcPatch, lfhOffset + 14n);
        writeAllSync(fd, encodeZip64Extra([uncompSize, compSize]), extraOffset);

        cdRecords.push({
          pathBuf,
          compressionMethod: method,
          crc: finalCrc,
          compressedSize: compSize,
          uncompressedSize: uncompSize,
          localHeaderOffset: lfhOffset,
        });
        totalComp += compSize;
        totalUncomp += uncompSize;
      }
    }

    const cdOffset = offset;
    for (const rec of cdRecords) {
      const needUncomp = forceZ64 || rec.uncompressedSize >= BigInt(SENTINEL_U32);
      const needComp = forceZ64 || rec.compressedSize >= BigInt(SENTINEL_U32);
      const needLfh = forceZ64 || rec.localHeaderOffset >= BigInt(SENTINEL_U32);
      const z64Fields: bigint[] = [];
      if (needUncomp) z64Fields.push(rec.uncompressedSize);
      if (needComp) z64Fields.push(rec.compressedSize);
      if (needLfh) z64Fields.push(rec.localHeaderOffset);
      const extra = z64Fields.length > 0 ? encodeZip64Extra(z64Fields) : Buffer.alloc(0);

      const cd = Buffer.alloc(46);
      cd.writeUInt32LE(SIG_CD, 0);
      cd.writeUInt16LE(z64Fields.length > 0 ? 45 : 20, 4);
      cd.writeUInt16LE(z64Fields.length > 0 ? 45 : 20, 6);
      cd.writeUInt16LE(0x0800, 8);
      cd.writeUInt16LE(rec.compressionMethod, 10);
      cd.writeUInt16LE(0, 12);
      cd.writeUInt16LE(0x5821, 14);
      cd.writeUInt32LE(rec.crc >>> 0, 16);
      cd.writeUInt32LE(needComp ? SENTINEL_U32 : Number(rec.compressedSize), 20);
      cd.writeUInt32LE(needUncomp ? SENTINEL_U32 : Number(rec.uncompressedSize), 24);
      cd.writeUInt16LE(rec.pathBuf.length, 28);
      cd.writeUInt16LE(extra.length, 30);
      cd.writeUInt16LE(0, 32);
      cd.writeUInt16LE(0, 34);
      cd.writeUInt16LE(0, 36);
      cd.writeUInt32LE(0, 38);
      cd.writeUInt32LE(needLfh ? SENTINEL_U32 : Number(rec.localHeaderOffset), 42);

      offset = writeAllSync(fd, cd, offset);
      offset = writeAllSync(fd, rec.pathBuf, offset);
      if (extra.length > 0) offset = writeAllSync(fd, extra, offset);
    }

    const cdSize = offset - cdOffset;
    const totalCount = BigInt(cdRecords.length);
    const needZip64End =
      forceZ64 ||
      totalCount >= BigInt(SENTINEL_U16) ||
      cdSize >= BigInt(SENTINEL_U32) ||
      cdOffset >= BigInt(SENTINEL_U32);

    if (needZip64End) {
      const z64EocdOffset = offset;
      const z64Eocd = Buffer.alloc(56);
      z64Eocd.writeUInt32LE(SIG_ZIP64_EOCD, 0);
      z64Eocd.writeBigUInt64LE(44n, 4);
      z64Eocd.writeUInt16LE(45, 12);
      z64Eocd.writeUInt16LE(45, 14);
      z64Eocd.writeUInt32LE(0, 16);
      z64Eocd.writeUInt32LE(0, 20);
      z64Eocd.writeBigUInt64LE(totalCount, 24);
      z64Eocd.writeBigUInt64LE(totalCount, 32);
      z64Eocd.writeBigUInt64LE(cdSize, 40);
      z64Eocd.writeBigUInt64LE(cdOffset, 48);
      offset = writeAllSync(fd, z64Eocd, offset);

      const locator = Buffer.alloc(20);
      locator.writeUInt32LE(SIG_ZIP64_LOCATOR, 0);
      locator.writeUInt32LE(0, 4);
      locator.writeBigUInt64LE(z64EocdOffset, 8);
      locator.writeUInt32LE(1, 16);
      offset = writeAllSync(fd, locator, offset);
    }

    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(SIG_EOCD, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(needZip64End ? SENTINEL_U16 : Number(totalCount), 8);
    eocd.writeUInt16LE(needZip64End ? SENTINEL_U16 : Number(totalCount), 10);
    eocd.writeUInt32LE(needZip64End ? SENTINEL_U32 : Number(cdSize), 12);
    eocd.writeUInt32LE(needZip64End ? SENTINEL_U32 : Number(cdOffset), 16);
    eocd.writeUInt16LE(0, 20);
    offset = writeAllSync(fd, eocd, offset);
  } finally {
    closeSync(fd);
  }

  return { totalCompressedBytes: totalComp, totalUncompressedBytes: totalUncomp };
}

/**
 * Streams a deterministic synthetic large mbox (e.g. 1 GiB) directly into a zip/zip64 archive
 * on disk with flat memory usage. Messages have unique varied lengths and pseudo-random text
 * so compression ratio stays realistic (~2-4:1) and V-3 blob dedup has minimal length collisions.
 */
export async function writeSyntheticLargeMboxZip(
  zipPath: string,
  options: {
    targetBytes: number;
    seed?: number;
    minMessageBytes?: number;
    maxMessageBytes?: number;
    compression?: 'store' | 'deflate';
    forceZip64?: boolean;
  },
): Promise<{ messageCount: number; uncompressedBytes: number; compressedBytes: number; sha256: string }> {
  const rng = createSeededRng(options.seed ?? 9001);
  const minMsg = options.minMessageBytes ?? 192 * 1024;
  const maxMsg = options.maxMessageBytes ?? 320 * 1024;
  const hash = createHash('sha256');
  const baseEpochMs = Date.UTC(2024, 0, 1, 0, 0, 0);
  let messageCount = 0;
  let uncompressedBytes = 0;

  // Pre-build a 64 KiB pseudo-random ASCII text pool to keep 1 GiB fixture generation fast (<5s)
  // while slicing at varied offsets per message so every message is unique and realistic (~3:1 deflate).
  const poolChunks: string[] = [];
  let poolLen = 0;
  while (poolLen < 128 * 1024) {
    const line = `${rng.nextU32().toString(36)} ${rng.pick(VOCAB)} ${rng.pick(VOCAB)} ${rng.pick(VOCAB)} ${rng.pick(VOCAB)} ${rng.pick(VOCAB)}\r\n`;
    poolChunks.push(line);
    poolLen += line.length;
  }
  const textPool = Buffer.from(poolChunks.join(''), 'utf8');

  async function* generateChunks(): AsyncIterable<Buffer> {
    while (uncompressedBytes < options.targetBytes) {
      messageCount++;
      const msgDate = new Date(baseEpochMs + messageCount * 3_600_000);
      const sender = syntheticEmail(`bulk-sender-${messageCount % 11}`);
      const recipient = syntheticEmail(`bulk-recipient-${messageCount % 7}`);
      const envAddr = `${9000000 + messageCount}${AT_SIGN}xxx`;
      const header = Buffer.from(
        [
          `From ${envAddr} ${formatMboxDate(msgDate)}`,
          `From: <${sender}>`,
          `To: <${recipient}>`,
          `Date: ${formatRfc5322Date(msgDate)}`,
          `Message-ID: <bulk-${messageCount}${AT_SIGN}${SYNTHETIC_DOMAIN}>`,
          `X-Gmail-Labels: Inbox,Bulk-${messageCount % 5}`,
          `Subject: TEST ONLY synthetic bulk mail #${messageCount} (${rng.pick(VOCAB)})`,
          'Content-Type: text/plain; charset="utf-8"',
          '',
          `Unique marker ${messageCount}-${rng.nextU32().toString(16)}\r\n`,
        ].join('\r\n'),
        'utf8',
      );
      hash.update(header);
      uncompressedBytes += header.length;
      yield header;

      const targetBody = rng.nextInt(minMsg, maxMsg + 1);
      let bodyRemaining = targetBody;
      while (bodyRemaining > 0) {
        const take = Math.min(bodyRemaining, 32 * 1024);
        const start = rng.nextInt(0, textPool.length - take);
        const slice = textPool.subarray(start, start + take);
        hash.update(slice);
        uncompressedBytes += slice.length;
        bodyRemaining -= slice.length;
        yield slice;
      }

      const trailer = Buffer.from(`\r\n--end-${messageCount}--\r\n\r\n`, 'utf8');
      hash.update(trailer);
      uncompressedBytes += trailer.length;
      yield trailer;
    }
  }

  const res = await writeZipArchive(
    zipPath,
    [
      {
        path: 'Takeout/Mail/All mail.mbox',
        data: generateChunks,
        compression: options.compression ?? 'deflate',
        deflateLevel: 1,
      },
    ],
    { forceZip64: options.forceZip64 },
  );

  return {
    messageCount,
    uncompressedBytes,
    compressedBytes: Number(res.totalCompressedBytes),
    sha256: hash.digest('hex'),
  };
}

/**
 * Writes a synthetic multi-part Google Takeout folder (`takeout-...-001.zip`, `-002.zip`, `-003.zip`)
 * containing Contacts (vCard), Calendar (iCalendar), Mail (mbox), and an unrecognised HTML file.
 */
export async function writeMultiPartTakeoutFolder(
  dirPath: string,
  options: {
    seed?: number;
    contactsCount?: number;
    calendarEvents?: number;
    mailMessages?: number;
    forceZip64?: boolean;
  } = {},
): Promise<{
  parts: string[];
  rawContacts: Buffer;
  rawCalendar: Buffer;
  rawMail: Buffer;
}> {
  mkdirSync(dirPath, { recursive: true });
  const seed = options.seed ?? 42;
  const rawContacts = generateSyntheticVcards(options.contactsCount ?? 5, seed + 1);
  const rawCalendar = generateSyntheticIcalendar(options.calendarEvents ?? 4, seed + 2);
  const rawMail = generateSyntheticMbox(options.mailMessages ?? 6, seed + 3, {
    includeMultipart: true,
    includeRfc2047: true,
    includeEscapedFrom: true,
    includeUnescapedFromProse: true,
  });
  const browserHtml = Buffer.from('<!doctype html><html><body>TEST ONLY Takeout index</body></html>\n', 'utf8');

  const part1 = 'takeout-20261121T000000Z-001.zip';
  const part2 = 'takeout-20261121T000000Z-002.zip';
  const part3 = 'takeout-20261121T000000Z-003.zip';

  await writeZipArchive(
    join(dirPath, part1),
    [
      { path: 'Takeout/archive_browser.html', data: browserHtml, compression: 'deflate' },
      { path: 'Takeout/Contacts/All Contacts/All Contacts.vcf', data: rawContacts, compression: 'deflate' },
    ],
    { forceZip64: options.forceZip64 },
  );

  await writeZipArchive(
    join(dirPath, part2),
    [{ path: 'Takeout/Calendar/Synthetic.ics', data: rawCalendar, compression: 'store' }],
    { forceZip64: options.forceZip64 },
  );

  await writeZipArchive(
    join(dirPath, part3),
    [{ path: 'Takeout/Mail/All mail.mbox', data: rawMail, compression: 'deflate' }],
    { forceZip64: options.forceZip64 },
  );

  return { parts: [part1, part2, part3], rawContacts, rawCalendar, rawMail };
}

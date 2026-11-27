/**
 * `foundry vault export-iso`: a streamed ISO 9660 image of the sealed vault for write-once media (BD-R, M-DISC),
 * Architecture 8.1. Pure TypeScript, no dependencies.
 *
 * Profile (A-44):
 * - ECMA-119 / ISO 9660 Level 3: 2,048-byte sectors, one primary volume descriptor, one Joliet supplementary
 *   volume descriptor (UCS-2 level 3, escape sequence `%/E`), a terminator, L and M path tables for both trees.
 * - Primary tree: Level 2 identifiers made from d-characters (upper case, `-` and other characters become `_`,
 *   version `;1`), for readers without Joliet. Joliet tree: the exact vault names (`segments/000001/events-0001.fvr`)
 *   with `;1`, which Windows and Linux strip. No Rock Ridge.
 * - A file of 4 GiB or more is stored as consecutive extents with the multi-extent flag (Level 3); each extent but
 *   the last is a whole number of sectors.
 * - Contents: `VAULT.json`, `HEAD.json` (the verified sealed head), `segments/<n>/` (`MANIFEST.json`,
 *   `MANIFEST.sig`, every `*.fvr`) for every sealed segment, and `keyring/keyring.json` only on explicit opt-in.
 *   The open segment is not exported. The image is written under a temporary name, every file is re-hashed from the
 *   finished image, and only then is it renamed to the output name.
 */
import { Buffer } from 'node:buffer';
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, openSync, readFileSync, readSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { check, sha256 } from './bytes.ts';
import { chainAnchor } from './anchor.ts';
import { renameWithRetry, syncDirectory } from './keyring-file.ts';
import { decodeManifest } from './manifest.ts';
import { SecondCopyError } from './second-copy.ts';
import { headBytes, MANIFEST, metadata, segmentName, SIGNATURE, statIfPresent, VAULT_METADATA } from './vault-directory.ts';
import type { VaultAnchor } from './vault-directory.ts';
import { verifyVault } from './vault-reader.ts';

export const SECTOR_BYTES = 2048;
/** The largest extent: the 32-bit length field, rounded down to whole sectors. */
export const MAX_EXTENT_BYTES = 0xfffff800;
/** The most sections (extents) one file may have: the Linux isofs reader's limit (`fs/isofs/inode.c`). */
export const MAX_FILE_SECTIONS = 100;
const STREAM_BUFFER_BYTES = 1024 * 1024;

type Source = { path: string; sha256: string } | { bytes: Buffer };

interface IsoFile {
  kind: 'file';
  name: string;
  size: number;
  source: Source;
  extents: { sector: number; length: number }[];
}

interface IsoDirectory {
  kind: 'directory';
  name: string;
  children: (IsoFile | IsoDirectory)[];
  parent: IsoDirectory | undefined;
  location: Record<Tree, { sector: number; size: number; number: number }>;
}

type Tree = 'primary' | 'joliet';
const TREES: readonly Tree[] = ['primary', 'joliet'];

function both16(target: Buffer, offset: number, value: number): void {
  target[offset] = value & 0xff;
  target[offset + 1] = (value >>> 8) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function le32(target: Buffer, offset: number, value: number): void {
  for (let i = 0; i < 4; i++) target[offset + i] = (value >>> (8 * i)) & 0xff;
}

function be32(target: Buffer, offset: number, value: number): void {
  for (let i = 0; i < 4; i++) target[offset + 3 - i] = (value >>> (8 * i)) & 0xff;
}

function both32(target: Buffer, offset: number, value: number): void {
  check(Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff, 'LENGTH');
  le32(target, offset, value);
  be32(target, offset + 4, value);
}

function ucs2(text: string): Buffer {
  const out = Buffer.alloc(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    check(code < 0xd800 || code > 0xdfff, 'SCHEMA');
    out[i * 2] = code >>> 8;
    out[i * 2 + 1] = code & 0xff;
  }
  return out;
}

/** Fill a text field: ASCII padded with spaces, or UCS-2 padded with U+0020. */
function textField(target: Buffer, offset: number, length: number, text: string, tree: Tree): void {
  if (tree === 'primary') {
    const bytes = Buffer.from(text.padEnd(length, ' ').slice(0, length));
    target.set(bytes, offset);
  } else {
    const bytes = ucs2(text.padEnd(Math.floor(length / 2), ' ').slice(0, Math.floor(length / 2)));
    target.set(bytes, offset);
    if (length % 2) target[offset + length - 1] = 0x20;
  }
}

/** The Level 2 primary identifier: d-characters, one dot for files, version `;1`. */
export function primaryIdentifier(name: string, directory: boolean): string {
  const upper = name.toUpperCase();
  if (directory) {
    const id = upper.replace(/[^A-Z0-9_]/gu, '_');
    check(id.length >= 1 && id.length <= 31, 'SCHEMA');
    return id;
  }
  const dot = upper.lastIndexOf('.');
  const base = (dot < 0 ? upper : upper.slice(0, dot)).replace(/[^A-Z0-9_]/gu, '_');
  const extension = (dot < 0 ? '' : upper.slice(dot + 1)).replace(/[^A-Z0-9_]/gu, '_');
  const id = `${base}.${extension};1`;
  check(base.length + extension.length >= 1 && base.length + extension.length <= 30, 'SCHEMA');
  return id;
}

function identifier(entry: IsoFile | IsoDirectory, tree: Tree): Buffer {
  const directory = entry.kind === 'directory';
  if (tree === 'primary') return Buffer.from(primaryIdentifier(entry.name, directory));
  const id = ucs2(directory ? entry.name : `${entry.name};1`);
  check(id.length <= 128, 'SCHEMA');
  return id;
}

function compareBytes(a: Buffer, b: Buffer): number {
  const length = Math.min(a.length, b.length);
  for (let i = 0; i < length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}

function sortedChildren(directory: IsoDirectory, tree: Tree): (IsoFile | IsoDirectory)[] {
  return [...directory.children].sort((a, b) => compareBytes(identifier(a, tree), identifier(b, tree)));
}

function recordingDate(now: Date): Buffer {
  return Buffer.from([now.getUTCFullYear() - 1900, now.getUTCMonth() + 1, now.getUTCDate(), now.getUTCHours(),
    now.getUTCMinutes(), now.getUTCSeconds(), 0]);
}

function volumeDate(now: Date): Buffer {
  const pad = (value: number, width = 2) => String(value).padStart(width, '0');
  const text = `${pad(now.getUTCFullYear(), 4)}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}`
    + `${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}00`;
  return Buffer.concat([Buffer.from(text), Buffer.from([0])]);
}

const UNUSED_DATE = Buffer.concat([Buffer.from('0'.repeat(16)), Buffer.from([0])]);

function directoryRecord(id: Buffer, sector: number, length: number, flags: number, date: Buffer): Buffer {
  const size = 33 + id.length + (id.length % 2 === 0 ? 1 : 0);
  const record = Buffer.alloc(size);
  record[0] = size;
  both32(record, 2, sector);
  both32(record, 10, length);
  record.set(date, 18);
  record[25] = flags;
  both16(record, 28, 1);
  record[32] = id.length;
  record.set(id, 33);
  return record;
}

/** Every record of one directory extent, in order, with their extent locations filled in. */
function directoryRecords(directory: IsoDirectory, tree: Tree, date: Buffer): Buffer[] {
  const self = directory.location[tree];
  const parent = (directory.parent ?? directory).location[tree];
  const records = [
    directoryRecord(Buffer.from([0]), self.sector, self.size, 0x02, date),
    directoryRecord(Buffer.from([1]), parent.sector, parent.size, 0x02, date),
  ];
  for (const child of sortedChildren(directory, tree)) {
    const id = identifier(child, tree);
    if (child.kind === 'directory') {
      records.push(directoryRecord(id, child.location[tree].sector, child.location[tree].size, 0x02, date));
    } else {
      child.extents.forEach((extent, index) => {
        const last = index === child.extents.length - 1;
        records.push(directoryRecord(id, extent.sector, extent.length, last ? 0 : 0x80, date));
      });
    }
  }
  return records;
}

/** Pack records into whole sectors; a record never crosses a sector boundary. */
function packRecords(records: readonly Buffer[]): { size: number; place: (target: Buffer) => void } {
  const offsets: number[] = [];
  let offset = 0;
  for (const record of records) {
    if ((offset % SECTOR_BYTES) + record.length > SECTOR_BYTES) offset = Math.ceil(offset / SECTOR_BYTES) * SECTOR_BYTES;
    offsets.push(offset);
    offset += record.length;
  }
  const size = Math.max(SECTOR_BYTES, Math.ceil(offset / SECTOR_BYTES) * SECTOR_BYTES);
  return { size, place: target => records.forEach((record, i) => target.set(record, offsets[i]!)) };
}

/** Breadth-first directory order: by level, then parent number, then identifier (ECMA-119 6.9.1). */
function directoryOrder(root: IsoDirectory, tree: Tree): IsoDirectory[] {
  const order = [root];
  for (let i = 0; i < order.length; i++) {
    for (const child of sortedChildren(order[i]!, tree)) if (child.kind === 'directory') order.push(child);
  }
  return order;
}

function pathTable(order: readonly IsoDirectory[], tree: Tree, bigEndian: boolean): Buffer {
  const parts: Buffer[] = [];
  for (const directory of order) {
    const id = directory.parent ? identifier(directory, tree) : Buffer.from([0]);
    const record = Buffer.alloc(8 + id.length + (id.length % 2));
    record[0] = id.length;
    const { sector } = directory.location[tree];
    const parentNumber = (directory.parent ?? directory).location[tree].number;
    if (bigEndian) {
      be32(record, 2, sector);
      record[6] = parentNumber >>> 8;
      record[7] = parentNumber & 0xff;
    } else {
      le32(record, 2, sector);
      record[6] = parentNumber & 0xff;
      record[7] = parentNumber >>> 8;
    }
    record.set(id, 8);
    parts.push(record);
  }
  return Buffer.concat(parts);
}

function volumeDescriptor(
  type: 1 | 2, tree: Tree, totalSectors: number, tables: { size: number; l: number; m: number },
  root: Buffer, now: Date, volumeId: string,
): Buffer {
  const sector = Buffer.alloc(SECTOR_BYTES);
  sector[0] = type;
  sector.set(Buffer.from('CD001'), 1);
  sector[6] = 1;
  textField(sector, 8, 32, '', tree);
  textField(sector, 40, 32, volumeId, tree);
  both32(sector, 80, totalSectors);
  if (type === 2) sector.set(Buffer.from('%/E'), 88);
  both16(sector, 120, 1);
  both16(sector, 124, 1);
  both16(sector, 128, SECTOR_BYTES);
  both32(sector, 132, tables.size);
  le32(sector, 140, tables.l);
  be32(sector, 148, tables.m);
  sector.set(root, 156);
  textField(sector, 190, 128, '', tree);
  textField(sector, 318, 128, '', tree);
  textField(sector, 446, 128, '', tree);
  textField(sector, 574, 128, tree === 'primary' ? 'FOUNDRY VAULT EXPORT' : 'Foundry vault export', tree);
  textField(sector, 702, 37, '', tree);
  textField(sector, 739, 37, '', tree);
  textField(sector, 776, 37, '', tree);
  const date = volumeDate(now);
  sector.set(date, 813);
  sector.set(date, 830);
  sector.set(UNUSED_DATE, 847);
  sector.set(UNUSED_DATE, 864);
  sector[881] = 1;
  return sector;
}

class SequentialWriter {
  readonly fd: number;
  position = 0;

  constructor(fd: number) {
    this.fd = fd;
  }

  write(bytes: Buffer): void {
    let written = 0;
    while (written < bytes.length) {
      const count = writeSync(this.fd, bytes, written, bytes.length - written, this.position + written);
      check(count > 0, 'LENGTH');
      written += count;
    }
    this.position += bytes.length;
  }

  padTo(offset: number): void {
    check(offset >= this.position, 'LENGTH');
    const zero = Buffer.alloc(Math.min(STREAM_BUFFER_BYTES, Math.max(1, offset - this.position)));
    while (this.position < offset) this.write(zero.subarray(0, Math.min(zero.length, offset - this.position)));
  }
}

export interface IsoEntryInput {
  /** Path components below the image root, for example `['segments', '000001', 'MANIFEST.json']`. */
  path: string[];
  size: number;
  source: Source;
}

export interface WriteIsoOptions {
  now?: Date;
  volumeId?: string;
  /** TEST ONLY: a smaller extent limit (whole sectors) so multi-extent files can be tested without 4 GiB. */
  maxExtentBytes?: number;
}

function buildTree(entries: readonly IsoEntryInput[]): { root: IsoDirectory; files: IsoFile[] } {
  const blank = () => ({ sector: 0, size: 0, number: 0 });
  const root: IsoDirectory = { kind: 'directory', name: '', children: [], parent: undefined, location: { primary: blank(), joliet: blank() } };
  const files: IsoFile[] = [];
  for (const entry of entries) {
    check(entry.path.length >= 1 && entry.path.every(part => /^[A-Za-z0-9._-]{1,64}$/u.test(part)), 'SCHEMA');
    let directory = root;
    for (const part of entry.path.slice(0, -1)) {
      let next = directory.children.find((child): child is IsoDirectory => child.kind === 'directory' && child.name === part);
      if (!next) {
        check(!directory.children.some(child => child.name === part), 'SCHEMA');
        next = { kind: 'directory', name: part, children: [], parent: directory, location: { primary: blank(), joliet: blank() } };
        directory.children.push(next);
      }
      directory = next;
    }
    const name = entry.path.at(-1)!;
    check(!directory.children.some(child => child.name === name), 'SCHEMA');
    check(Number.isSafeInteger(entry.size) && entry.size >= 0, 'LENGTH');
    const file: IsoFile = { kind: 'file', name, size: entry.size, source: entry.source, extents: [] };
    directory.children.push(file);
    files.push(file);
  }
  // Primary identifiers must stay unique after the d-character mapping.
  const check2 = (directory: IsoDirectory) => {
    const ids = directory.children.map(child => identifier(child, 'primary').toString());
    check(new Set(ids).size === ids.length, 'SCHEMA');
    for (const child of directory.children) if (child.kind === 'directory') check2(child);
  };
  check2(root);
  return { root, files };
}

/**
 * Write the image to `output` (created, never overwritten). Returns the image size. The sources of `path` entries
 * are streamed and checked against their SHA-256; every file is re-hashed from the finished image.
 */
export function writeIsoImage(output: string, entries: readonly IsoEntryInput[], options: WriteIsoOptions = {}): number {
  const now = options.now ?? new Date();
  const maxExtent = options.maxExtentBytes ?? MAX_EXTENT_BYTES;
  check(Number.isSafeInteger(maxExtent) && maxExtent > 0 && maxExtent % SECTOR_BYTES === 0 && maxExtent <= MAX_EXTENT_BYTES, 'LENGTH');
  const volumeId = options.volumeId ?? 'FOUNDRY';
  const { root, files } = buildTree(entries);
  const date = recordingDate(now);

  // Layout: 16 system sectors, three descriptors, four path tables, directory extents of each tree, file data.
  const orders = { primary: directoryOrder(root, 'primary'), joliet: directoryOrder(root, 'joliet') };
  for (const tree of TREES) orders[tree].forEach((directory, i) => { directory.location[tree].number = i + 1; });
  // File extents first need their count only (records' sizes do not depend on locations).
  for (const file of files) {
    const count = Math.max(1, Math.ceil(file.size / maxExtent));
    // Linux isofs reads at most 100 sections of one multi-extent file (fs/isofs/inode.c); refuse more.
    if (count > MAX_FILE_SECTIONS) throw new SecondCopyError('ISO_TOO_MANY_EXTENTS');
    file.extents = Array.from({ length: count }, (_, i) => ({ sector: 0, length: Math.min(maxExtent, file.size - i * maxExtent) }));
  }
  const tables = {
    primary: pathTable(orders.primary, 'primary', false).length,
    joliet: pathTable(orders.joliet, 'joliet', false).length,
  };
  let sector = 19;
  const tableSectors: Record<Tree, { l: number; m: number }> = { primary: { l: 0, m: 0 }, joliet: { l: 0, m: 0 } };
  for (const tree of TREES) {
    const span = Math.max(1, Math.ceil(tables[tree] / SECTOR_BYTES));
    tableSectors[tree] = { l: sector, m: sector + span };
    sector += span * 2;
  }
  for (const tree of TREES) {
    for (const directory of orders[tree]) {
      const { size } = packRecords(directoryRecords(directory, tree, date));
      directory.location[tree].size = size;
      directory.location[tree].sector = sector;
      sector += size / SECTOR_BYTES;
    }
  }
  for (const file of files) {
    for (const extent of file.extents) {
      extent.sector = file.size === 0 ? 0 : sector;
      sector += Math.ceil(extent.length / SECTOR_BYTES);
    }
  }
  const totalSectors = sector;

  output = resolve(output);
  if (statIfPresent(output)) throw new SecondCopyError('OUTPUT_EXISTS');
  const pending = `${output}.pending-${randomBytes(8).toString('hex')}`;
  const fd = openSync(pending, 'wx+', 0o600);
  let done = false;
  try {
    const writer = new SequentialWriter(fd);
    writer.padTo(16 * SECTOR_BYTES);
    for (const tree of TREES) {
      const rootRecord = directoryRecord(Buffer.from([0]), root.location[tree].sector, root.location[tree].size, 0x02, date);
      const table = { size: tables[tree], ...tableSectors[tree] };
      writer.write(volumeDescriptor(tree === 'primary' ? 1 : 2, tree, totalSectors, table, rootRecord, now,
        tree === 'primary' ? volumeId.toUpperCase().replace(/[^A-Z0-9_]/gu, '_') : volumeId));
    }
    const terminator = Buffer.alloc(SECTOR_BYTES);
    terminator[0] = 255;
    terminator.set(Buffer.from('CD001'), 1);
    terminator[6] = 1;
    writer.write(terminator);
    for (const tree of TREES) {
      for (const bigEndian of [false, true]) {
        writer.padTo((bigEndian ? tableSectors[tree].m : tableSectors[tree].l) * SECTOR_BYTES);
        writer.write(pathTable(orders[tree], tree, bigEndian));
      }
    }
    for (const tree of TREES) {
      for (const directory of orders[tree]) {
        writer.padTo(directory.location[tree].sector * SECTOR_BYTES);
        const packed = packRecords(directoryRecords(directory, tree, date));
        const extent = Buffer.alloc(packed.size);
        packed.place(extent);
        writer.write(extent);
      }
    }
    const buffer = Buffer.allocUnsafe(STREAM_BUFFER_BYTES);
    for (const file of files) {
      if (file.size === 0) continue;
      writer.padTo(file.extents[0]!.sector * SECTOR_BYTES);
      if ('bytes' in file.source) {
        check(file.source.bytes.length === file.size, 'FILE_SIZE');
        writer.write(file.source.bytes);
        continue;
      }
      const input = openSync(file.source.path, 'r');
      try {
        check(fstatSync(input).size === file.size, 'FILE_SIZE');
        const hash = createHash('sha256');
        for (let offset = 0; offset < file.size;) {
          const count = readSync(input, buffer, 0, Math.min(buffer.length, file.size - offset), offset);
          check(count > 0, 'LENGTH');
          hash.update(buffer.subarray(0, count));
          writer.write(buffer.subarray(0, count));
          offset += count;
        }
        check(hash.digest('hex') === file.source.sha256, 'FILE_HASH');
      } finally {
        closeSync(input);
      }
    }
    writer.padTo(totalSectors * SECTOR_BYTES);
    fsyncSync(fd);
    // Re-read every file from the finished image (extents are contiguous) and compare its hash.
    for (const file of files) {
      const expected = 'bytes' in file.source ? sha256(file.source.bytes) : file.source.sha256;
      const hash = createHash('sha256');
      const start = (file.extents[0]?.sector ?? 0) * SECTOR_BYTES;
      for (let offset = 0; offset < file.size;) {
        const count = readSync(fd, buffer, 0, Math.min(buffer.length, file.size - offset), start + offset);
        check(count > 0, 'LENGTH');
        hash.update(buffer.subarray(0, count));
        offset += count;
      }
      check(hash.digest('hex') === expected, 'FILE_HASH');
    }
    done = true;
  } finally {
    closeSync(fd);
    if (!done) {
      try { unlinkSync(pending); } catch { /* keep the first failure */ }
    }
  }
  renameWithRetry(pending, output);
  syncDirectory(dirname(output));
  return totalSectors * SECTOR_BYTES;
}

export interface ExportIsoResult {
  head: { segment: number; hash: string };
  segments: number;
  files: number;
  imageBytes: number;
  keyringIncluded: boolean;
  /** Records in the open segment, which an export never contains. */
  openFiles: number;
  anchor: VaultAnchor;
}

/**
 * Export the sealed chain of `vaultDirectory` to an ISO image. Keyless: the chain is verified without any secret
 * first. The keyring is left out unless `includeKeyring` is true (D-18, A-9): a key burned to a disc can never be
 * destroyed, so erasure could no longer reach that disc.
 */
export function exportVaultIso(
  vaultDirectory: string, output: string,
  { includeKeyring = false, ...options }: { includeKeyring?: boolean } & WriteIsoOptions = {},
): ExportIsoResult {
  vaultDirectory = resolve(vaultDirectory);
  const verified = verifyVault(vaultDirectory);
  const meta = metadata(vaultDirectory);
  const publicKey = Buffer.from(meta.signing_public_key, 'base64');
  const entries: IsoEntryInput[] = [];
  const vaultBytes = readFileSync(join(vaultDirectory, VAULT_METADATA));
  entries.push({ path: [VAULT_METADATA], size: vaultBytes.length, source: { bytes: vaultBytes } });
  const head = headBytes(verified.position);
  entries.push({ path: ['HEAD.json'], size: head.length, source: { bytes: head } });
  let files = 2;
  for (let segment = 1; segment <= verified.position.segment; segment++) {
    const name = segmentName(segment);
    const folder = join(vaultDirectory, 'segments', name);
    const manifestBytes = readFileSync(join(folder, MANIFEST));
    const signature = readFileSync(join(folder, SIGNATURE));
    const manifest = decodeManifest(manifestBytes, signature, publicKey);
    entries.push({ path: ['segments', name, MANIFEST], size: manifestBytes.length, source: { bytes: manifestBytes } });
    entries.push({ path: ['segments', name, SIGNATURE], size: signature.length, source: { bytes: signature } });
    for (const file of manifest.files) {
      entries.push({ path: ['segments', name, file.name], size: file.bytes, source: { path: join(folder, file.name), sha256: file.sha256 } });
    }
    files += 2 + manifest.files.length;
  }
  if (includeKeyring) {
    const keyring = readFileSync(join(vaultDirectory, 'keyring', 'keyring.json'));
    entries.push({ path: ['keyring', 'keyring.json'], size: keyring.length, source: { bytes: keyring } });
    files++;
  }
  const imageBytes = writeIsoImage(output, entries, { volumeId: `FOUNDRY_${meta.vault_id.slice(0, 8)}`, ...options });
  return {
    head: { segment: verified.position.segment, hash: verified.position.hash },
    segments: verified.position.segment,
    files,
    imageBytes,
    keyringIncluded: includeKeyring,
    openFiles: verified.open.files,
    anchor: chainAnchor(meta.vault_id, meta.signing_public_key, verified.position),
  };
}

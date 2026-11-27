import { Buffer } from 'node:buffer';
import { chmodSync, closeSync, fsyncSync, lstatSync, openSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { platform } from 'node:process';
import { canonical, check, hex, integer, object, parseCanonical, sha256, VaultFormatError } from './bytes.ts';
import { renameWithRetry, syncDirectory } from './keyring-file.ts';
import {
  checkManifestLink, checkManifestRecords, decodeManifest, decodeVaultMetadata, GENESIS_HASH, streamOrdinal,
} from './manifest.ts';
import type { ChainPosition, ManifestFile } from './manifest.ts';
import { readExactly, StreamScanner, streamFile } from './record-file.ts';
import type { DiskRecord, UnlockedKeyring } from './record-file.ts';

export const MANIFEST = 'MANIFEST.json';
export const SIGNATURE = 'MANIFEST.sig';
export const MANIFEST_PENDING = MANIFEST + '.pending';
export const SIGNATURE_PENDING = SIGNATURE + '.pending';
export const HEAD = 'HEAD.json';
export const HEAD_PENDING = HEAD + '.pending';
export const VAULT_METADATA = 'VAULT.json';
export const LOCK = '.writer.lock.sqlite';
export const GENESIS: ChainPosition = { segment: 0, hash: GENESIS_HASH, lastEventSequence: 0 };
export const OPEN_ARTIFACTS = [MANIFEST, SIGNATURE, MANIFEST_PENDING, SIGNATURE_PENDING];
export type VaultMetadata = ReturnType<typeof decodeVaultMetadata>;
type InspectRecord = (stream: string, record: DiskRecord) => void;

export interface VaultAnchor {
  vaultId: string;
  epoch: 1;
  segment: number;
  manifestHash: string;
  signingKeyFingerprint: string;
}

export interface VerifyOptions {
  anchor?: VaultAnchor;
  /** P-3: the folder is a Mode B second copy, so its root may hold `COPY.json` (A-44). */
  secondCopy?: boolean;
}

export function statIfPresent(path: string): ReturnType<typeof lstatSync> | undefined {
  try {
    return lstatSync(path);
  } catch (error) {
    if ((error as { code?: string }).code !== 'ENOENT') throw error;
    return undefined;
  }
}

function readDocument(path: string, code: 'HEAD' | 'INVENTORY' | 'SIGNATURE' = 'INVENTORY', limit = Infinity): Buffer {
  check(statIfPresent(path)?.isFile(), code);
  return streamFile(path, (fd, size) => {
    check(size <= limit, code);
    const raw = Buffer.allocUnsafe(size);
    readExactly(fd, raw, 0);
    return raw;
  });
}

export function metadata(directory: string): VaultMetadata {
  return decodeVaultMetadata(readDocument(join(directory, VAULT_METADATA), 'INVENTORY', 256));
}

export function writePending(path: string, bytes: Buffer, beforeSync?: () => void): void {
  const fd = openSync(path, 'wx', 0o600);
  try {
    writeFileSync(fd, bytes);
    beforeSync?.();
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function removePending(path: string): boolean {
  const stat = statIfPresent(path);
  if (!stat) return false;
  check(stat.isFile(), 'INVENTORY');
  unlinkSync(path);
  return true;
}

/** P-3 (A-44): the copy identity file in the root of a Mode B second copy, and its pending name. */
export const COPY_IDENTITY = 'COPY.json';
export const COPY_IDENTITY_PENDING = COPY_IDENTITY + '.pending';

/**
 * The root may hold only these entries (links are refused: a Dirent of a link is neither a file nor a folder).
 * `secondCopy` (P-3 second copies only) also allows the copy identity file; a working vault never holds one.
 */
export function checkRootInventory(directory: string, secondCopy = false): void {
  const directories = ['keyring', 'segments', 'open'];
  const files = [VAULT_METADATA, HEAD, HEAD_PENDING, LOCK, LOCK + '-journal', LOCK + '-wal', LOCK + '-shm',
    ...(secondCopy ? [COPY_IDENTITY, COPY_IDENTITY_PENDING] : [])];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    check((entry.isDirectory() && directories.includes(entry.name)) || (entry.isFile() && files.includes(entry.name)),
      'INVENTORY');
  }
}

export function headBytes(position: ChainPosition): Buffer {
  return Buffer.from(canonical({ segment: position.segment, manifest_sha256: position.hash }));
}

export function readHead(directory: string, name = HEAD, errorCode: 'HEAD' | 'INVENTORY' = 'HEAD') {
  try {
    const value = parseCanonical(readDocument(join(directory, name), 'HEAD', 128));
    object(value, 'segment manifest_sha256');
    integer(value.segment);
    hex(value.manifest_sha256, 32);
    return { segment: value.segment, hash: value.manifest_sha256 };
  } catch (error) {
    if (!(error instanceof VaultFormatError)) throw error;
    throw new VaultFormatError(errorCode);
  }
}

export function headMatches(head: ReturnType<typeof readHead>, position: ChainPosition): boolean {
  return head.segment === position.segment && head.hash === position.hash;
}

export function publishHead(directory: string, position: ChainPosition): void {
  writePending(join(directory, HEAD_PENDING), headBytes(position));
  replaceHead(directory);
}

export function replaceHead(directory: string): void {
  renameWithRetry(join(directory, HEAD_PENDING), join(directory, HEAD));
  syncDirectory(directory);
}

export function segmentName(segment: number): string {
  integer(segment, 1);
  return String(segment).padStart(6, '0');
}

export function streamType(name: string): 1 | 2 {
  check(/^(events|pack)-[0-9]{4,16}\.fvr$/u.test(name) && name.endsWith('.fvr'), 'INVENTORY');
  const ordinal = streamOrdinal(name);
  check(Number.isSafeInteger(ordinal) && ordinal > 0
    && name.slice(name.indexOf('-') + 1, -4) === String(ordinal).padStart(4, '0'), 'INVENTORY');
  return name.startsWith('events-') ? 1 : 2;
}

export function streamNames(directory: string, artifacts: readonly string[]): string[] {
  check(lstatSync(directory).isDirectory(), 'INVENTORY');
  const names: string[] = [];
  for (const file of readdirSync(directory, { withFileTypes: true })) {
    check(file.isFile(), 'INVENTORY');
    if (!artifacts.includes(file.name)) {
      streamType(file.name);
      names.push(file.name);
    }
  }
  return names.sort((a, b) => streamType(a) - streamType(b) || streamOrdinal(a) - streamOrdinal(b));
}

export function scanStreams(
  directory: string, names: string[], previous: number, scanner: StreamScanner, unlocked?: UnlockedKeyring,
  expected?: ManifestFile[], inspect?: InspectRecord, limits?: ReadonlyMap<string, number>,
) {
  const keyIds = new Set<string>();
  const files: ManifestFile[] = [];
  const incomplete: { name: string; bytes: number; removedBytes: number }[] = [];
  let last = previous;
  let first: number | null = null;
  let totalBytes = 0;
  let erased = 0;
  const byName = expected && new Map(expected.map(file => [file.name, file]));
  for (const name of names) {
    const type = streamType(name);
    const result = streamFile(join(directory, name), (fd, physicalSize) => {
      const size = limits?.get(name) ?? physicalSize;
      check(size <= physicalSize, 'FILE_SIZE');
      const wanted = byName?.get(name);
      if (wanted) check(size === wanted.bytes, 'FILE_SIZE');
      const scanned = scanner.scan(fd, size, type, record => {
        inspect?.(name, record);
        keyIds.add(record.keyId);
        if (type === 1) {
          check(record.context === BigInt(++last), 'SEQUENCE');
          first ??= last;
        }
      }, unlocked);
      if (wanted) {
        check(scanned.shortAt === undefined, 'LENGTH');
        check(scanned.sha256 === wanted.sha256, 'FILE_HASH');
      }
      if (scanned.shortAt !== undefined || size === 0) {
        incomplete.push({ name, bytes: scanned.bytes, removedBytes: size - scanned.bytes });
      }
      return scanned;
    });
    if (result.bytes > 0) files.push({ name, bytes: result.bytes, sha256: result.sha256 });
    totalBytes += result.bytes;
    erased += result.erased;
  }
  return {
    files: files.sort((a, b) => a.name < b.name ? -1 : 1), keyIds, first, last, totalBytes, incomplete, erased,
  };
}

export function scanSealed(
  directory: string, vault: VaultMetadata, scanner: StreamScanner, unlocked?: UnlockedKeyring, anchor?: VaultAnchor,
  inspect?: (segment: number, ...args: Parameters<InspectRecord>) => void,
  verified?: (segment: number, files: ManifestFile[]) => void,
  /** P-3 second-copy session only: leave out this segment folder (an unfinished copy, checked by the caller). */
  exclude?: number,
) {
  const root = join(directory, 'segments');
  check(statIfPresent(root)?.isDirectory(), 'INVENTORY');
  const segments = readdirSync(root, { withFileTypes: true }).map(entry => {
    const number = Number(entry.name);
    check(entry.isDirectory() && Number.isSafeInteger(number) && number > 0 && entry.name === segmentName(number),
      'INVENTORY');
    return number;
  }).filter(number => number !== exclude).sort((a, b) => a - b);
  const publicKey = Buffer.from(vault.signing_public_key, 'base64');
  if (anchor) {
    check(anchor.epoch === 1 && anchor.vaultId === vault.vault_id && anchor.signingKeyFingerprint === sha256(publicKey)
      && Number.isSafeInteger(anchor.segment) && anchor.segment >= 0 && anchor.segment <= segments.length, 'ANCHOR');
    if (anchor.segment === 0) check(anchor.manifestHash === GENESIS_HASH, 'ANCHOR');
  }
  let position = GENESIS;
  let previous = GENESIS;
  let erased = 0;
  for (const number of segments) {
    check(number === position.segment + 1, 'CHAIN');
    const path = join(root, segmentName(number));
    const bytes = readDocument(join(path, MANIFEST));
    const manifest = decodeManifest(bytes, readDocument(join(path, SIGNATURE), 'SIGNATURE', 64), publicKey);
    checkManifestLink(manifest, vault.vault_id, position);
    const names = streamNames(path, [MANIFEST, SIGNATURE]);
    check(names.length === manifest.files.length
      && [...names].sort().every((name, index) => name === manifest.files[index].name), 'INVENTORY');
    const result = scanStreams(path, names, position.lastEventSequence, scanner, unlocked, manifest.files,
      inspect && ((name, record) => inspect(number, name, record)));
    erased += result.erased;
    checkManifestRecords(manifest, result.keyIds, result.first, result.last);
    previous = position;
    position = { segment: number, hash: sha256(bytes), lastEventSequence: result.last };
    if (anchor?.segment === number) check(anchor.manifestHash === position.hash, 'ANCHOR');
    verified?.(number, manifest.files);
  }
  return { position, previous, erased };
}

export function scanOpen(
  directory: string, last: number, scanner: StreamScanner, unlocked?: UnlockedKeyring, recovering = false,
  inspect?: InspectRecord, limits?: ReadonlyMap<string, number>,
) {
  if (limits?.size === 0 || !limits && !statIfPresent(directory)) {
    return { last, files: [], totalBytes: 0, incomplete: [], erased: 0 };
  }
  const names = limits ? [...limits.keys()] : streamNames(directory, recovering ? OPEN_ARTIFACTS : []);
  const result = scanStreams(directory, names, last, scanner, unlocked, undefined, inspect, limits);
  if (!recovering) {
    check(result.incomplete.length === 0, 'LENGTH');
  } else {
    for (const tail of result.incomplete) {
      check(tail.name === names.findLast(name => streamType(name) === streamType(tail.name)), 'LENGTH');
    }
  }
  return result;
}

export function checkVerifiedHead(directory: string, position: ChainPosition, previous: ChainPosition): void {
  const head = readHead(directory);
  if (statIfPresent(join(directory, HEAD_PENDING))) {
    check(position.segment > 0 && headMatches(head, previous) && !statIfPresent(join(directory, 'open'))
      && headMatches(readHead(directory, HEAD_PENDING, 'INVENTORY'), position), 'INVENTORY');
  } else {
    check(headMatches(head, position), 'HEAD');
  }
}

export function makeReadOnly(directory: string): void {
  for (const name of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, name.name);
    const mode = lstatSync(path).mode & 0o777;
    if (mode & 0o222) chmodSync(path, mode & ~0o222);
  }
  if (platform !== 'win32') {
    const mode = lstatSync(directory).mode & 0o777;
    if (mode & 0o222) chmodSync(directory, mode & ~0o222);
  }
}

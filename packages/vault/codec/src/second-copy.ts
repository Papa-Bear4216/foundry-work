/**
 * Mode B second copy: an offline drive that is writable only during a vault session (Architecture 8.1, 8.2; Product 8).
 *
 * Session steps (Architecture 8.1), in two phases (P-3 fix round 1, ruling R18-2):
 *
 * Phase 1, keyless and read-only (nothing on the drive or the working device is written, no lock is taken):
 *  1. Detect the target folder, refuse a file system with a 4 GiB file limit (FAT), read VAULT.json and refuse a
 *     different vault, and read `COPY.json`: its `copy_id` must be the selected record's (`COPY_MISMATCH`, R18-3).
 *  2. Check the type of every root and keyring entry (a link is refused), bound every read of a drive file, and
 *     verify every manifest, signature, file hash and the whole chain without any secret. When `SESSION.json` (an
 *     interrupted session, R19-2) exists, every segment folder after the head it names is uncommitted: those folders
 *     are only type-checked, never read, and the committed chain must end at that head. R20-1: when `HEAD.json`
 *     names a later segment (a stop after the head was published), that head ends the committed chain instead and
 *     must verify as its exact end; only the folders after it are uncommitted. Without `SESSION.json`, a trailing
 *     segment folder without a manifest (an interrupted session of an earlier version) is left out of this check.
 *  3. Compare the drive's verified chain with the head recorded on the working device for this copy, and with the
 *     working vault's own chain. Older than recorded: `ROLLBACK_DETECTED`. A different manifest hash at the same
 *     segment number: `TAMPER_DETECTED`. Only after this comparison is `HEAD.json` (a convenience copy that is never
 *     trusted) classified: it must name a verified chain position at or after the recorded head.
 *
 * Phase 2, after phase 1 passed (R19-7): a write-access check that writes nothing, the drive's writer lock, a
 * re-check that the drive did not change, the writability probe (a hardware write-protect switch still on is
 * reported as `WRITE_PROTECTED`), then recovery of an interrupted session: its uncommitted segment folders are
 * removed, a pending head is discarded, and every committed segment (recorded ones included) is made read-only
 * again, durably, and checked. `HEAD.json` is not written here.
 *  4. Close the open segment on the working device (`seal`), then write `SESSION.json` (the session's durable
 *     "in progress" state: the verified head it starts from), unless the interrupted session's one is still there.
 *  5. Copy each missing segment in order: stream files first, then `MANIFEST.sig`, then `MANIFEST.json` through a
 *     pending name and a rename, with fsync of every file and (on POSIX) of the segment folder and `segments/`.
 *  6. Re-read every copied segment from the drive: exact file names, the manifest hash, every stream hash; the chain
 *     head is derived from those bytes.
 *  7. Mark the copied segments read-only and check them, write `keyring/keyring.json` (temp file, fsync, rename)
 *     and read it back, write `HEAD.json` (also when no segment was copied and it was behind), and only then remove
 *     `SESSION.json`. R20-1: on POSIX every segment whose modes were set or checked in this session (phase 2
 *     included) and the keyring file and folder are synced before the head, whether or not this session changed
 *     them.
 *  8. and 9. are done by the caller with the returned result: append `copy.sealed`, record the new head on the
 *     working device, and print the anchor.
 *
 * The working-device register is a projection of the `copy.registered` and `copy.sealed` events (R18-2): a missing,
 * unreadable or flagged register is rebuilt from a keyed replay, never silently treated as empty.
 *
 * The chain is only tamper-evident (Architecture 8.2): it shows a change, it cannot stop one; an exact copy of a
 * drive cannot be told from the original, and an out-of-date recorded head cannot reveal the loss of segments
 * written after it.
 */
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  accessSync, chmodSync, closeSync, constants, fstatSync, fsyncSync, mkdirSync, openSync, readFileSync,
  opendirSync, readSync, realpathSync, rmdirSync, statfsSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
import { dirname, join, posix, resolve, win32 } from 'node:path';
import type { PlatformPath } from 'node:path';
import { platform as hostPlatform } from 'node:process';
import { canonical, check, hex, integer, object, parseCanonical, sha256, timestamp, VaultFormatError } from './bytes.ts';
import type { Json } from './bytes.ts';
import { chainAnchor } from './anchor.ts';
import type { Unlock } from './keyring.ts';
import { acquireWriterLock, renameWithRetry, syncDirectory } from './keyring-file.ts';
import { checkManifestLink, checkManifestRecords, decodeManifest, GENESIS_HASH } from './manifest.ts';
import type { ChainPosition, ManifestFile } from './manifest.ts';
import { StreamScanner } from './record-file.ts';
import type { UnlockedKeyring } from './record-file.ts';
import {
  checkRootInventory, COPY_IDENTITY, COPY_IDENTITY_PENDING, COPY_SESSION, COPY_SESSION_PENDING, HEAD, HEAD_PENDING,
  headMatches, LOCK, makeReadOnly,
  MANIFEST, MANIFEST_PENDING, metadata, publishHead, readHead, scanSealed, scanStreams, segmentName, SIGNATURE,
  statIfPresent, streamNames, VAULT_METADATA, writePending,
} from './vault-directory.ts';
import type { VaultAnchor, VaultMetadata } from './vault-directory.ts';
import { openVaultReplay } from './vault-replay.ts';
import { initializeVault, VaultWriter } from './vault-writer.ts';

export type SecondCopyErrorCode =
  | 'FILESYSTEM_UNSUPPORTED' | 'WRITE_PROTECTED' | 'ROLLBACK_DETECTED' | 'TAMPER_DETECTED' | 'VAULT_MISMATCH'
  | 'NOT_A_COPY' | 'TARGET_NOT_EMPTY' | 'TARGET_UNSUITABLE' | 'COPY_BUSY' | 'COPY_VERIFY_FAILED'
  | 'WORKING_VAULT_DAMAGED' | 'OUTPUT_EXISTS' | 'REGISTER' | 'COPY_UNKNOWN' | 'COPY_AMBIGUOUS' | 'INVALID_LABEL' | 'INVALID_CADENCE'
  | 'SCHEDULER_UNSUPPORTED' | 'SCHEDULER_FAILED' | 'ISO_TOO_MANY_EXTENTS' | 'COPY_MISMATCH' | 'OUTPUT_UNSUITABLE'
  | 'KEYRING_INVALID' | 'COPY_UNVERIFIABLE';

/** A typed second-copy failure. `reason` is a fixed token (never a path or user text). */
export class SecondCopyError extends Error {
  readonly code: SecondCopyErrorCode;
  readonly reason: string | undefined;

  constructor(code: SecondCopyErrorCode, reason?: string) {
    super(reason === undefined ? code : `${code}: ${reason}`);
    this.name = 'SecondCopyError';
    this.code = code;
    this.reason = reason;
  }
}

function errorCode(error: unknown): string | undefined {
  return (error as { code?: unknown } | null)?.code as string | undefined;
}

function nowStamp(now: Date): string {
  const text = now.toISOString().replace(/\.\d{3}Z$/u, 'Z');
  timestamp(text);
  return text;
}

const READ_ONLY_CODES = ['EROFS', 'EACCES', 'EPERM'];

/** Run `work`; a write refused by the medium or its permissions becomes `WRITE_PROTECTED`. */
function writeProtected<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    if (READ_ONLY_CODES.includes(errorCode(error) ?? '')) throw new SecondCopyError('WRITE_PROTECTED');
    throw error;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// External commands (fsutil, schtasks, systemctl, crontab, notify-send): always explicit arguments, never a shell.

export interface CommandResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

export type CommandRunner = (command: string, args: readonly string[], input?: string) => CommandResult;

/** Runs a program with `shell: false`. A program that cannot be started gives status `null`. */
export const defaultRunner: CommandRunner = (command, args, input) => {
  const result = spawnSync(command, args, {
    shell: false, encoding: 'utf8', windowsHide: true, timeout: 30_000, ...(input === undefined ? {} : { input }),
  });
  if (result.error) return { status: null, stdout: '', stderr: '' };
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
};

// ---------------------------------------------------------------------------------------------------------------
// Step 1: the file system.

export interface FileSystemReport {
  /** Lowercase file-system name, or undefined when it could not be detected. */
  type: string | undefined;
  method: 'statfs' | 'mountinfo' | 'fsutil' | 'injected' | 'none';
}

export type FileSystemProbe = (path: string) => FileSystemReport;

let fatCache: ReadonlySet<string> | undefined;
/** File systems with a 4 GiB file-size limit (every FAT variant). Built on first use (R18-8 D2). */
export function fatFileSystems(): ReadonlySet<string> {
  return fatCache ??= new Set(['vfat', 'msdos', 'fat', 'fat12', 'fat16', 'fat32', 'umsdos', 'uvfat']);
}

let magicCache: ReadonlyMap<number, string> | undefined;
/** Linux `statfs` magic numbers (`linux/magic.h`). vfat and msdos share `MSDOS_SUPER_MAGIC`. Built on first use. */
function linuxMagic(): ReadonlyMap<number, string> {
  return magicCache ??= new Map([
    [0x4d44, 'vfat'], [0x2011bab0, 'exfat'], [0xef53, 'ext4'], [0x5346544e, 'ntfs3'], [0x9123683e, 'btrfs'],
    [0x58465342, 'xfs'], [0x01021994, 'tmpfs'], [0xf2f52010, 'f2fs'], [0x2fc12fc1, 'zfs'], [0xca451a4e, 'bcachefs'],
    [0x6969, 'nfs'], [0xff534d42, 'cifs'], [0xfe534d42, 'smb2'], [0x794c7630, 'overlay'], [0x15013346, 'udf'],
    [0x9660, 'iso9660'], [0x3153464a, 'jfs'], [0x52654973, 'reiserfs'],
  ]);
}

function unescapeMount(value: string): string {
  return value.replace(/\\([0-7]{3})/gu, (_, octal: string) => String.fromCharCode(parseInt(octal, 8)));
}

/** The fstype of the longest mount point that holds `path`, from `/proc/self/mountinfo`. */
export function mountInfoType(path: string, mountinfo: string): string | undefined {
  let best: { point: string; type: string } | undefined;
  for (const line of mountinfo.split('\n')) {
    const separator = line.indexOf(' - ');
    if (separator < 0) continue;
    const fields = line.slice(0, separator).split(' ');
    const type = line.slice(separator + 3).split(' ')[0];
    const point = fields[4] === undefined ? undefined : unescapeMount(fields[4]);
    if (!point || !type) continue;
    const inside = point === '/' || path === point || path.startsWith(point.endsWith('/') ? point : point + '/');
    if (inside && (!best || point.length > best.point.length)) best = { point, type };
  }
  return best?.type.toLowerCase();
}

/**
 * The file-system name from `fsutil fsinfo volumeinfo` output, read by its exact key `File System Name` (R18-5).
 * A value under any other key (for example a volume label that reads "NTFS") is never used. Localized output has
 * another key, so the type is unknown there and the caller warns instead of claiming the drive is safe (A-44).
 */
export function fsutilType(output: string): string | undefined {
  for (const line of output.split(/\r?\n/u)) {
    const colon = line.indexOf(':');
    if (colon < 0 || line.slice(0, colon).trim() !== 'File System Name') continue;
    const value = line.slice(colon + 1).trim();
    return value === '' ? undefined : value.toLowerCase();
  }
  return undefined;
}

/** Detect the file system that holds `path` (an existing path). Never throws for an undetectable type. */
export function probeFileSystem(path: string, { platform = hostPlatform, run = defaultRunner }: { platform?: string; run?: CommandRunner } = {}): FileSystemReport {
  if (platform === 'win32') {
    // Windows path rules even on another host (an injected platform in tests): `E:\x` is absolute here.
    const root = win32.parse(win32.resolve(path)).root;
    if (!/^[A-Za-z]:\\$/u.test(root)) return { type: undefined, method: 'none' };
    const result = run('fsutil', ['fsinfo', 'volumeinfo', root.slice(0, 2)]);
    const type = result.status === 0 ? fsutilType(result.stdout) : undefined;
    return { type, method: type ? 'fsutil' : 'none' };
  }
  if (platform === 'linux') {
    let magic: string | undefined;
    try {
      magic = linuxMagic().get(statfsSync(path).type >>> 0);
    } catch {
      magic = undefined;
    }
    if (magic) return { type: magic, method: 'statfs' };
    try {
      const type = mountInfoType(realpathSync(path), readFileSync('/proc/self/mountinfo', 'utf8'));
      return { type, method: type ? 'mountinfo' : 'none' };
    } catch {
      return { type: undefined, method: 'none' };
    }
  }
  return { type: undefined, method: 'none' };
}

/** Refuse FAT (4 GiB file limit, Architecture 4.1 and A-20). An undetected type is allowed and reported. */
export function checkFileSystem(report: FileSystemReport): FileSystemReport {
  if (report.type !== undefined && fatFileSystems().has(report.type)) throw new SecondCopyError('FILESYSTEM_UNSUPPORTED', 'fat');
  return report;
}

// ---------------------------------------------------------------------------------------------------------------
// Product 5 step 4: both copies on one physical disk.

export type DiskRelation = 'same-volume' | 'same-disk' | 'different-disk' | 'unknown';

function linuxDisk(dev: bigint): string | undefined {
  const major = ((dev >> 8n) & 0xfffn) | ((dev >> 32n) & ~0xfffn);
  const minor = (dev & 0xffn) | ((dev >> 12n) & ~0xffn);
  try {
    const device = realpathSync(`/sys/dev/block/${major}:${minor}`);
    return statIfPresent(join(device, 'partition')) ? dirname(device) : device;
  } catch {
    return undefined;
  }
}

/**
 * Whether two existing paths are on the same volume or physical disk, where the platform tells. Equal device
 * numbers mean one volume on both platforms. On Linux the partition's parent block device names the disk; on
 * Windows two different volumes give `unknown` (telling their disk needs administrator tools).
 */
export function diskRelation(a: string, b: string, platform = hostPlatform): DiskRelation {
  let devA: bigint;
  let devB: bigint;
  try {
    devA = statSync(a, { bigint: true }).dev;
    devB = statSync(b, { bigint: true }).dev;
  } catch {
    return 'unknown';
  }
  if (devA === devB) return 'same-volume';
  if (platform !== 'linux') return 'unknown';
  const diskA = linuxDisk(devA);
  const diskB = linuxDisk(devB);
  if (!diskA || !diskB) return 'unknown';
  return diskA === diskB ? 'same-disk' : 'different-disk';
}

// ---------------------------------------------------------------------------------------------------------------
// Bounded reads of files that may come from an untrusted drive.

/** The largest `MANIFEST.json` a second copy may hold (a manifest lists a few files; this is generous). */
export const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_COPY_IDENTITY_BYTES = 256;

/**
 * The bytes of a regular file of at most `limit` bytes, or undefined when nothing is there. A link, folder or other
 * entry, or a larger file, fails `INVENTORY` before it is opened; the size is checked again on the open descriptor.
 */
function readRegularFile(path: string, limit: number): Buffer | undefined {
  const stat = statIfPresent(path);
  if (!stat) return undefined;
  check(stat.isFile() && stat.size <= limit, 'INVENTORY');
  const fd = openSync(path, 'r');
  try {
    const opened = fstatSync(fd);
    check(opened.isFile() && opened.size <= limit, 'INVENTORY');
    const bytes = Buffer.allocUnsafe(opened.size);
    for (let offset = 0; offset < bytes.length;) {
      const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
      check(count > 0, 'LENGTH');
      offset += count;
    }
    return bytes;
  } finally {
    closeSync(fd);
  }
}

// R20-4 (39): drive folders are listed one entry at a time (`opendirSync`), never as one array, and a folder with
// more entries than a valid one can hold stops the command with a fixed error before the next entry is read.

/** A copy root holds at most its inventory: `keyring/`, `segments/`, `open/` and 11 named files (A-44). */
export const MAX_ROOT_ENTRIES = 14;
/**
 * The smallest canonical `files` entry of a manifest: `{"bytes":89,"name":"pack-0001.fvr","sha256":"<64 hex>"}` is
 * 111 bytes, plus the comma before the next entry (`bytes` is at least 89, a name at least 13 characters).
 */
const MIN_MANIFEST_ENTRY_BYTES = 112;
/**
 * A segment folder holds `MANIFEST.json`, `MANIFEST.json.pending`, `MANIFEST.sig` and one stream file per manifest
 * entry; a manifest within `MAX_MANIFEST_BYTES` lists at most `MAX_MANIFEST_BYTES / 112` entries (9,365 in all).
 * The drive's `keyring/` folder uses the same cap (it holds `keyring.json`, its lock files and temp files).
 */
export const MAX_SEGMENT_ENTRIES = Math.floor(MAX_MANIFEST_BYTES / MIN_MANIFEST_ENTRY_BYTES) + 3;

let segmentEntryCapForTest: number | undefined;
/** TEST ONLY: lower the segment and keyring folder cap (undefined restores `MAX_SEGMENT_ENTRIES`). */
export function setSegmentEntryCapForTest(cap: number | undefined): void {
  segmentEntryCapForTest = cap;
}

type FolderEntry = { name: string; isFile(): boolean; isDirectory(): boolean };

/** Visit each entry of `folder`, at most `cap` of them; one more fails (`tooMany`, else `COPY_VERIFY_FAILED`). */
function eachEntry(folder: string, cap: number, visit: (entry: FolderEntry) => void, tooMany?: () => never): number {
  const dir = opendirSync(folder, { bufferSize: 32 });
  let count = 0;
  try {
    for (let entry = dir.readSync(); entry !== null; entry = dir.readSync()) {
      if (++count > cap) {
        tooMany?.();
        throw new SecondCopyError('COPY_VERIFY_FAILED', 'TOO_MANY_ENTRIES');
      }
      visit(entry);
    }
  } finally {
    dir.closeSync();
  }
  return count;
}

/** The entries of a segment folder or of the drive's keyring folder, bounded (R20-4). */
function eachSegmentEntry(folder: string, visit: (entry: FolderEntry) => void): number {
  return eachEntry(folder, segmentEntryCapForTest ?? MAX_SEGMENT_ENTRIES, visit);
}

/** True when `folder` holds no entry (only the first entry is read). */
function emptyFolder(folder: string): boolean {
  const dir = opendirSync(folder, { bufferSize: 32 });
  try {
    return dir.readSync() === null;
  } finally {
    dir.closeSync();
  }
}

function manifestHash(directory: string, segment: number): string | undefined {
  if (segment === 0) return GENESIS_HASH;
  const bytes = readRegularFile(join(directory, 'segments', segmentName(segment), MANIFEST), MAX_MANIFEST_BYTES);
  return bytes === undefined ? undefined : sha256(bytes);
}

/** Remove `path` when it is a regular file; anything else there fails `INVENTORY`. */
function removeRegularFile(path: string): boolean {
  const stat = statIfPresent(path);
  if (!stat) return false;
  check(stat.isFile(), 'INVENTORY');
  unlinkSync(path);
  return true;
}

// ---------------------------------------------------------------------------------------------------------------
// The working device's register of second copies (Architecture 5.4 keyring-copy register and 8.1 step 8).

export const REGISTER_FORMAT = 'foundry-second-copies/1';
export const CADENCES = ['daily', 'weekly', 'monthly', 'manual'] as const;
export type Cadence = (typeof CADENCES)[number];
/** Days between reminders for each cadence (`manual` never reminds). */
export const CADENCE_DAYS: Readonly<Record<Cadence, number | null>> = { daily: 1, weekly: 7, monthly: 30, manual: null };
/** Product 8 and D-8: a persistent banner after 14 days without a seal. */
export const OVERDUE_DAYS = 14;
export const MAX_REGISTER_BYTES = 1024 * 1024;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/u;

export interface CopyHead {
  segment: number;
  manifest_sha256: string;
  sealed_at: string;
}

export interface CopyRecord {
  copy_id: string;
  label: string;
  created_at: string;
  head: CopyHead | null;
  keyring: { version: number; written_at: string } | null;
}

export interface CopyRegister {
  format: typeof REGISTER_FORMAT;
  vault_id: string;
  cadence: Cadence;
  copies: CopyRecord[];
  last_check: { checked_at: string; verify: 'ok' | 'failed' | 'skipped' } | null;
  /**
   * True when this file may be behind the vault's `copy.*` events: it was created by a keyless command while no
   * register existed, or a keyed command is between appending an event and writing the register. The next keyed
   * second-copy command rebuilds the copies from a replay of the events (R18-2).
   */
  needs_replay: boolean;
}

export function assertCadence(value: unknown): Cadence {
  if (typeof value !== 'string' || !(CADENCES as readonly string[]).includes(value)) throw new SecondCopyError('INVALID_CADENCE');
  return value as Cadence;
}

/** A label is a short generic tag (letters, digits, `.`, `_`, `-`), never a personal name or a path. */
export function assertCopyLabel(value: unknown): string {
  if (typeof value !== 'string' || !LABEL.test(value)) throw new SecondCopyError('INVALID_LABEL');
  return value;
}

function validateRegister(value: unknown, vaultId: string): CopyRegister {
  try {
    object(value, 'format vault_id cadence copies last_check needs_replay');
    check(value.format === REGISTER_FORMAT && value.vault_id === vaultId && typeof value.needs_replay === 'boolean');
    assertCadence(value.cadence);
    check(Array.isArray(value.copies));
    const ids = new Set<string>();
    const labels = new Set<string>();
    for (const copy of value.copies) {
      object(copy, 'copy_id label created_at head keyring');
      hex(copy.copy_id, 16);
      const label = assertCopyLabel(copy.label);
      timestamp(copy.created_at);
      check(!ids.has(copy.copy_id) && !labels.has(label));
      ids.add(copy.copy_id);
      labels.add(label);
      if (copy.head !== null) {
        object(copy.head, 'segment manifest_sha256 sealed_at');
        integer(copy.head.segment);
        hex(copy.head.manifest_sha256, 32);
        timestamp(copy.head.sealed_at);
        if (copy.head.segment === 0) check(copy.head.manifest_sha256 === GENESIS_HASH);
      }
      if (copy.keyring !== null) {
        object(copy.keyring, 'version written_at');
        integer(copy.keyring.version, 1);
        timestamp(copy.keyring.written_at);
      }
    }
    if (value.last_check !== null) {
      object(value.last_check, 'checked_at verify');
      timestamp(value.last_check.checked_at);
      check(['ok', 'failed', 'skipped'].includes(value.last_check.verify as string));
    }
    return value as unknown as CopyRegister;
  } catch (error) {
    if (error instanceof SecondCopyError || error instanceof VaultFormatError) throw new SecondCopyError('REGISTER');
    throw error;
  }
}

export function emptyRegister(vaultId: string, needsReplay = false): CopyRegister {
  hex(vaultId, 16);
  return { format: REGISTER_FORMAT, vault_id: vaultId, cadence: 'weekly', copies: [], last_check: null, needs_replay: needsReplay };
}

function parseRegister(path: string, vaultId: string): CopyRegister | undefined {
  let bytes: Buffer | undefined;
  let value: Json;
  try {
    bytes = readRegularFile(path, MAX_REGISTER_BYTES);
    if (bytes === undefined) return undefined;
    value = parseCanonical(bytes);
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('REGISTER');
    throw error;
  }
  return validateRegister(value, vaultId);
}

/**
 * Read the register (keyless). A missing file is an empty register flagged `needs_replay`: this device cannot tell
 * without a key whether the vault's events name a copy. A damaged file fails `REGISTER`.
 */
export function readCopyRegister(path: string, vaultId: string): CopyRegister {
  return parseRegister(path, vaultId) ?? emptyRegister(vaultId, true);
}

export interface RegisterState {
  /** The register as read; for a missing or damaged file, an empty one flagged `needs_replay`. */
  register: CopyRegister;
  /** The file was readable (its cadence and last check are kept by a rebuild). */
  readable: boolean;
  /** A keyed command must rebuild the copies from the events before it uses them. */
  rebuild: boolean;
}

/** For keyed commands: the register and whether it must be rebuilt from the events (missing, damaged or flagged). */
export function loadCopyRegister(path: string, vaultId: string): RegisterState {
  try {
    const register = parseRegister(path, vaultId);
    if (register === undefined) return { register: emptyRegister(vaultId, true), readable: false, rebuild: true };
    return { register, readable: true, rebuild: register.needs_replay };
  } catch (error) {
    if (error instanceof SecondCopyError && error.code === 'REGISTER') {
      return { register: emptyRegister(vaultId, true), readable: false, rebuild: true };
    }
    throw error;
  }
}

/** Replace the register atomically: unique temp file, fsync, rename, folder sync. Larger than the read limit: `REGISTER`. */
export function writeCopyRegister(path: string, register: CopyRegister): void {
  validateRegister(JSON.parse(JSON.stringify(register)), register.vault_id);
  const bytes = Buffer.from(canonical(register as unknown as Json));
  // The reader refuses a file above this size, so a larger one is never written (the last readable one stays).
  if (bytes.length > MAX_REGISTER_BYTES) throw new SecondCopyError('REGISTER', 'too-large');
  const pending = `${path}.pending-${randomBytes(16).toString('hex')}`;
  writePending(pending, bytes);
  try {
    renameWithRetry(pending, path);
  } catch (error) {
    try { unlinkSync(pending); } catch { /* keep the first failure */ }
    throw error;
  }
  syncDirectory(dirname(path));
}

/** A new random copy identity (16 bytes, hex). */
export function newCopyId(): string {
  return randomBytes(16).toString('hex');
}

export function addCopyRecord(
  register: CopyRegister, label: string | undefined, now: Date, copyId: string = newCopyId(),
): { register: CopyRegister; copy: CopyRecord } {
  let name = label === undefined ? undefined : assertCopyLabel(label);
  if (name === undefined) {
    for (let n = 1; name === undefined; n++) if (!register.copies.some(copy => copy.label === `copy-${n}`)) name = `copy-${n}`;
  }
  if (register.copies.some(copy => copy.label === name)) throw new SecondCopyError('INVALID_LABEL', 'taken');
  hex(copyId, 16);
  const copy: CopyRecord = { copy_id: copyId, label: name, created_at: nowStamp(now), head: null, keyring: null };
  return { register: { ...register, copies: [...register.copies, copy] }, copy };
}

/** The copy a command acts on: the named one, or the only one. */
export function selectCopy(register: CopyRegister, label?: string): CopyRecord {
  if (label !== undefined) {
    const copy = register.copies.find(entry => entry.label === assertCopyLabel(label));
    if (!copy) throw new SecondCopyError('COPY_UNKNOWN');
    return copy;
  }
  if (register.copies.length === 0) throw new SecondCopyError('COPY_UNKNOWN', 'none');
  if (register.copies.length > 1) throw new SecondCopyError('COPY_AMBIGUOUS');
  return register.copies[0]!;
}

export function recordSeal(register: CopyRegister, copyId: string, result: Pick<SealResult, 'head' | 'sealedAt' | 'keyringVersion'>): CopyRegister {
  return {
    ...register,
    copies: register.copies.map(copy => copy.copy_id !== copyId ? copy : {
      ...copy,
      head: { segment: result.head.segment, manifest_sha256: result.head.hash, sealed_at: result.sealedAt },
      keyring: { version: result.keyringVersion, written_at: result.sealedAt },
    }),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Events: the register is a projection of `copy.registered` and `copy.sealed` (R18-2).

export const COPY_REGISTERED = 'copy.registered';
export const COPY_SEALED = 'copy.sealed';

export interface CopyEvent {
  kind: unknown;
  ts: unknown;
  body: unknown;
}

/** The body of `copy.registered` (counts, ids and the label only). */
export function copyRegisteredBody(
  copy: CopyRecord, cadence: Cadence, adoptedFrom: string | null | undefined,
): Record<string, Json> {
  return {
    copy_id: copy.copy_id, label: copy.label, cadence, adopted: adoptedFrom !== undefined,
    previous_copy_id: adoptedFrom ?? null,
  };
}

/** The body of `copy.sealed`: everything the register needs, plus counts and hashes (Architecture 4.3). */
export function copySealedBody(copy: CopyRecord, cadence: Cadence, result: SealResult): Record<string, Json> {
  return {
    copy_id: copy.copy_id, label: copy.label, cadence, previous_segment: result.previous.segment,
    segment: result.head.segment, manifest_sha256: result.head.hash, sealed_at: result.sealedAt,
    keyring_version: result.keyringVersion, segments_copied: result.segmentsCopied, files_copied: result.filesCopied,
    bytes_copied: result.bytesCopied,
  };
}

/**
 * Build the copies from `copy.*` events in vault order. Idempotent: an event seen twice changes nothing. The cadence
 * and last check come from `base` (a readable register) when given, else the cadence of the last event. A malformed
 * event is skipped.
 */
export function registerFromEvents(vaultId: string, events: Iterable<CopyEvent>, base?: CopyRegister): CopyRegister {
  const copies = new Map<string, CopyRecord>();
  let cadence: Cadence | undefined;
  const claim = (id: string, label: string) => {
    for (const [other, record] of copies) if (other !== id && record.label === label) copies.delete(other);
  };
  for (const event of events) {
    try {
      const body = event.body as Record<string, Json>;
      check(body !== null && typeof body === 'object' && !Array.isArray(body));
      hex(body.copy_id, 16);
      timestamp(event.ts);
      const label = assertCopyLabel(body.label);
      const id = body.copy_id;
      if (event.kind === COPY_REGISTERED) {
        if (!copies.has(id)) {
          claim(id, label);
          copies.set(id, { copy_id: id, label, created_at: event.ts, head: null, keyring: null });
        }
      } else if (event.kind === COPY_SEALED) {
        integer(body.segment);
        hex(body.manifest_sha256, 32);
        timestamp(body.sealed_at);
        integer(body.keyring_version, 1);
        if (body.segment === 0) check(body.manifest_sha256 === GENESIS_HASH);
        let record = copies.get(id);
        if (!record) {
          claim(id, label);
          record = { copy_id: id, label, created_at: event.ts, head: null, keyring: null };
          copies.set(id, record);
        }
        record.head = { segment: body.segment, manifest_sha256: body.manifest_sha256, sealed_at: body.sealed_at };
        record.keyring = { version: body.keyring_version, written_at: body.sealed_at };
      } else {
        continue;
      }
      if (typeof body.cadence === 'string' && (CADENCES as readonly string[]).includes(body.cadence)) cadence = body.cadence as Cadence;
    } catch (error) {
      if (error instanceof VaultFormatError || error instanceof SecondCopyError) continue;
      throw error;
    }
  }
  const register: CopyRegister = {
    format: REGISTER_FORMAT, vault_id: vaultId, cadence: base?.cadence ?? cadence ?? 'weekly',
    copies: [...copies.values()], last_check: base?.last_check ?? null, needs_replay: false,
  };
  return validateRegister(JSON.parse(JSON.stringify(register)), vaultId);
}

/**
 * Rebuild the register from a keyed, read-only replay of the working vault (`me`'s `system` events). The replay
 * refuses a vault with an unfinished write; the caller reports that (it may not recover the vault first, R18-2).
 */
export function replayCopyRegister(vaultDirectory: string, credential: Unlock, base?: CopyRegister): CopyRegister {
  const vaultId = metadata(vaultDirectory).vault_id;
  const source = openVaultReplay(vaultDirectory, credential);
  const events: CopyEvent[] = [];
  try {
    for (const item of source.replay()) {
      if (item.type !== 'event') continue;
      const { kind, profile, collection, ts, body } = item.event;
      if ((kind === COPY_REGISTERED || kind === COPY_SEALED) && profile === 'me' && collection === 'system') events.push({ kind, ts, body });
    }
  } finally {
    source.close();
  }
  return registerFromEvents(vaultId, events, base);
}

export interface CopyStatus {
  copyId: string;
  label: string;
  head: CopyHead | null;
  /** Whole days since the last seal, or since the copy was set up when it was never sealed. */
  daysUnsealed: number;
  due: boolean;
  overdue: boolean;
  keyringVersion: number | null;
  /** False when the copy holds an older keyring than the working device (a key erased since then is still on it). */
  keyringCurrent: boolean | null;
}

export interface RegisterStatus {
  cadence: Cadence;
  copies: CopyStatus[];
  due: boolean;
  overdue: boolean;
  banner: string | undefined;
  /** The register may be behind the vault's events (rebuilt by the next keyed second-copy command). */
  needsReplay: boolean;
}

const DAY_MS = 86_400_000;

/** Seal age, due and overdue state per copy (Product 8: a persistent banner past 14 days unsealed). */
export function copyRegisterStatus(register: CopyRegister, now: Date, currentKeyringVersion?: number): RegisterStatus {
  const interval = CADENCE_DAYS[register.cadence];
  const copies = register.copies.map(copy => {
    const since = new Date(copy.head?.sealed_at ?? copy.created_at).valueOf();
    const daysUnsealed = Math.max(0, Math.floor((now.valueOf() - since) / DAY_MS));
    const neverSealed = copy.head === null;
    return {
      copyId: copy.copy_id, label: copy.label, head: copy.head, daysUnsealed,
      due: neverSealed || (interval !== null && daysUnsealed >= interval),
      overdue: daysUnsealed >= OVERDUE_DAYS,
      keyringVersion: copy.keyring?.version ?? null,
      keyringCurrent: currentKeyringVersion === undefined || copy.keyring === null ? null : copy.keyring.version === currentKeyringVersion,
    };
  });
  const overdue = copies.filter(copy => copy.overdue);
  let banner: string | undefined;
  if (copies.length === 0) {
    banner = register.needs_replay
      ? 'No second copy is recorded on this device. If one was set up, `foundry vault seal <folder>` rebuilds the record '
        + 'from the vault; otherwise run `foundry vault copy init <folder>` on an offline drive.'
      : 'No second copy is set up. Run `foundry vault copy init <folder>` on an offline drive.';
  } else if (overdue.length > 0) {
    const days = Math.max(...overdue.map(copy => copy.daysUnsealed));
    banner = `SECOND COPY OVERDUE: ${overdue.length === 1 ? `copy "${overdue[0]!.label}" was` : `${overdue.length} copies were`} `
      + `last sealed ${days} day(s) ago (limit ${OVERDUE_DAYS}). Connect the drive and run \`foundry vault seal <folder>\`.`;
  }
  return {
    cadence: register.cadence, copies, due: copies.length === 0 || copies.some(copy => copy.due), overdue: overdue.length > 0,
    banner, needsReplay: register.needs_replay,
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Target placement.

export interface TargetOptions {
  platform?: string;
  run?: CommandRunner;
  /** TEST ONLY hook: replaces the file-system probe so FAT refusal is testable on any OS. */
  probe?: FileSystemProbe;
}

/** Path rules of the platform being checked (an injected `win32` on a Linux host still uses Windows rules). */
function pathApi(platform: string): PlatformPath {
  return platform === 'win32' ? win32 : posix;
}

function folded(path: string, platform: string): string {
  return platform === 'win32' ? path.toLowerCase() : path;
}

/**
 * The canonical form of `path`: the real path of its nearest existing ancestor (links, junctions and Windows short
 * names resolved), followed by the components that do not exist yet. Both sides of a containment check go through
 * this, so an existing path and a new one are compared in the same form.
 */
export function canonicalPath(path: string, platform: string = hostPlatform): string {
  const api = pathApi(platform);
  const absolute = api.resolve(path);
  const missing: string[] = [];
  let current = absolute;
  for (;;) {
    try {
      const real = realpathSync.native(current);
      return missing.length === 0 ? real : api.join(real, ...missing.reverse());
    } catch (error) {
      if (!['ENOENT', 'ENOTDIR'].includes(errorCode(error) ?? '') && platform === hostPlatform) throw error;
    }
    const parent = api.dirname(current);
    if (parent === current) return absolute;
    missing.push(api.basename(current));
    current = parent;
  }
}

/** True when `child` is `parent` or below it, compared by whole path components (a name such as `..x` is a child). */
function within(parent: string, child: string, platform: string): boolean {
  const api = pathApi(platform);
  const rel = api.relative(folded(parent, platform), folded(child, platform));
  if (rel === '') return true;
  if (api.isAbsolute(rel)) return false;
  return rel.split(api.sep)[0] !== '..';
}

/** True when `path` is `folder` or below it, after both are canonicalised (links resolved). */
export function pathInside(folder: string, path: string, platform: string = hostPlatform): boolean {
  return within(canonicalPath(folder, platform), canonicalPath(path, platform), platform);
}

/** The copy must be its own folder: not a volume root, not inside the working home's vault and not around it. */
function checkPlacement(workingVault: string, target: string, platform: string): void {
  const api = pathApi(platform);
  const working = canonicalPath(workingVault, platform);
  const real = canonicalPath(target, platform);
  for (const path of [target, real]) {
    if (folded(path, platform) === folded(api.parse(path).root, platform) || path === api.dirname(path)) {
      throw new SecondCopyError('TARGET_UNSUITABLE', 'volume-root');
    }
  }
  if (within(working, real, platform) || within(real, working, platform)) throw new SecondCopyError('TARGET_UNSUITABLE', 'overlaps-vault');
}

function nearestExisting(path: string): string {
  let current = path;
  while (!statIfPresent(current)) {
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return current;
}

function sameVault(target: VaultMetadata, working: VaultMetadata): boolean {
  return target.vault_id === working.vault_id && target.signing_public_key === working.signing_public_key
    && target.created_at === working.created_at;
}

function targetMetadata(target: string, working: VaultMetadata): VaultMetadata {
  if (!statIfPresent(join(target, VAULT_METADATA))?.isFile()) throw new SecondCopyError('NOT_A_COPY');
  let meta: VaultMetadata;
  try {
    meta = metadata(target);
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('NOT_A_COPY', 'metadata');
    throw error;
  }
  if (!sameVault(meta, working)) throw new SecondCopyError('VAULT_MISMATCH');
  return meta;
}

// ---------------------------------------------------------------------------------------------------------------
// The copy identity on the drive (R18-3).

const COPY_FORMAT = 'foundry-copy/1';

/** The `copy_id` in the drive's `COPY.json`, or undefined when there is none. Bounded, keyless. */
export function readCopyIdentity(target: string, vaultId: string): string | undefined {
  let value: Json;
  try {
    const bytes = readRegularFile(join(target, COPY_IDENTITY), MAX_COPY_IDENTITY_BYTES);
    if (bytes === undefined) return undefined;
    value = parseCanonical(bytes);
    object(value, 'format vault_id copy_id');
    check(value.format === COPY_FORMAT);
    hex(value.copy_id, 16);
    hex(value.vault_id, 16);
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', 'INVENTORY');
    throw error;
  }
  if (value.vault_id !== vaultId) throw new SecondCopyError('VAULT_MISMATCH');
  return value.copy_id;
}

/** Write `COPY.json` atomically: pending name, fsync, rename, folder sync. */
function writeCopyIdentity(target: string, vaultId: string, copyId: string): void {
  hex(copyId, 16);
  const bytes = Buffer.from(canonical({ format: COPY_FORMAT, vault_id: vaultId, copy_id: copyId }));
  const pending = join(target, COPY_IDENTITY_PENDING);
  removeRegularFile(pending);
  writePending(pending, bytes);
  renameWithRetry(pending, join(target, COPY_IDENTITY));
  syncDirectory(target);
}

// ---------------------------------------------------------------------------------------------------------------
// The `copy init` transaction on the working device (R19-3).

const INIT_INTENT_FORMAT = 'foundry-copy-init/1';
const MAX_INIT_INTENT_BYTES = 1024;

/**
 * An unfinished `copy init`: the new record and the target it is bound to (the SHA-256 of the target's canonical
 * path, case-folded on Windows; the path itself is never written). It is written before `copy.registered`, so a
 * retry on the same target finishes this record, and it is removed once the folder is done.
 */
export interface CopyInitIntent {
  copy_id: string;
  label: string;
  created_at: string;
  target_sha256: string;
  /** `--adopt`: the folder held a copy of this vault, with `previous_copy_id` (null: it had no `COPY.json`). */
  adopt: boolean;
  previous_copy_id: string | null;
}

/** The identity of a target folder for an init intent: the hash of its canonical path (case-folded on Windows). */
export function copyTargetKey(target: string, platform: string = hostPlatform): string {
  return sha256(Buffer.from(folded(canonicalPath(target, platform), platform)));
}

/** The pending init, or undefined when there is none. An unreadable or malformed file counts as none. */
export function readInitIntent(path: string, vaultId: string): CopyInitIntent | undefined {
  try {
    const bytes = readRegularFile(path, MAX_INIT_INTENT_BYTES);
    if (bytes === undefined) return undefined;
    const value = parseCanonical(bytes);
    object(value, 'format vault_id copy_id label created_at target_sha256 adopt previous_copy_id');
    check(value.format === INIT_INTENT_FORMAT && value.vault_id === vaultId && typeof value.adopt === 'boolean');
    hex(value.copy_id, 16);
    assertCopyLabel(value.label);
    timestamp(value.created_at);
    hex(value.target_sha256, 32);
    if (value.previous_copy_id !== null) hex(value.previous_copy_id, 16);
    const { copy_id, label, created_at, target_sha256, adopt, previous_copy_id } = value as unknown as CopyInitIntent;
    return { copy_id, label, created_at, target_sha256, adopt, previous_copy_id };
  } catch (error) {
    if (error instanceof VaultFormatError || error instanceof SecondCopyError) return undefined;
    throw error;
  }
}

/** Write the init intent atomically (unique temp file, fsync, rename, folder sync). */
export function writeInitIntent(path: string, vaultId: string, intent: CopyInitIntent): void {
  const bytes = Buffer.from(canonical({ format: INIT_INTENT_FORMAT, vault_id: vaultId, ...intent } as unknown as Json));
  const pending = `${path}.pending-${randomBytes(16).toString('hex')}`;
  writePending(pending, bytes);
  try {
    renameWithRetry(pending, path);
  } catch (error) {
    try { unlinkSync(pending); } catch { /* keep the first failure */ }
    throw error;
  }
  syncDirectory(dirname(path));
}

/** Remove a finished init intent (a missing file is fine). */
export function clearInitIntent(path: string): void {
  if (removeRegularFile(path)) syncDirectory(dirname(path));
}

// ---------------------------------------------------------------------------------------------------------------
// `vault copy init`.

/** What an interrupted `copy init` may leave in the folder before `VAULT.json` exists. */
const INIT_FILES = [COPY_IDENTITY, COPY_IDENTITY_PENDING, HEAD, HEAD_PENDING, VAULT_METADATA + '.pending', LOCK,
  LOCK + '-journal', LOCK + '-wal', LOCK + '-shm'];

export interface CopyTargetState {
  /** `empty`: no folder, or an empty one. `interrupted`: Foundry's own unfinished `copy init`. `copy`: a copy of this vault. */
  state: 'empty' | 'interrupted' | 'copy';
  /** The `copy_id` in the folder's `COPY.json` (undefined when it has none). */
  copyId: string | undefined;
  fileSystem: FileSystemReport;
}

/** Keyless and read-only: what the folder holds, after the placement and file-system checks. */
export function inspectCopyTarget(workingVault: string, target: string, options: TargetOptions = {}): CopyTargetState {
  const platform = options.platform ?? hostPlatform;
  workingVault = resolve(workingVault);
  target = resolve(target);
  const working = metadata(workingVault);
  checkPlacement(workingVault, target, platform);
  // R19-1: the probe gets the fully resolved path (junctions and links followed to their final volume).
  const fileSystem = checkFileSystem((options.probe ?? (path => probeFileSystem(path, options)))(
    canonicalPath(nearestExisting(target), platform)));
  const stat = statIfPresent(target);
  if (!stat) return { state: 'empty', copyId: undefined, fileSystem };
  if (!stat.isDirectory()) throw new SecondCopyError('TARGET_UNSUITABLE', 'not-a-folder');
  // R20-4: no copy root and no init folder holds more than its inventory, so a fuller folder is not empty.
  const entries: FolderEntry[] = [];
  eachEntry(target, MAX_ROOT_ENTRIES, entry => { entries.push(entry); }, () => { throw new SecondCopyError('TARGET_NOT_EMPTY'); });
  if (entries.length === 0) return { state: 'empty', copyId: undefined, fileSystem };
  if (entries.some(entry => entry.name === VAULT_METADATA)) {
    targetMetadata(target, working);
    try {
      checkRootInventory(target, true);
    } catch (error) {
      if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
      throw error;
    }
    return { state: 'copy', copyId: readCopyIdentity(target, working.vault_id), fileSystem };
  }
  const own = entries.every(entry => (entry.isFile() && INIT_FILES.includes(entry.name))
    || (entry.isDirectory() && entry.name === 'segments' && emptyFolder(join(target, 'segments'))));
  if (!own) throw new SecondCopyError('TARGET_NOT_EMPTY');
  const copyId = readCopyIdentity(target, working.vault_id);
  if (copyId !== undefined) return { state: 'interrupted', copyId, fileSystem };
  // `COPY.json` is written first, so without it only its own pending file can be Foundry's.
  if (entries.every(entry => entry.name === COPY_IDENTITY_PENDING)) return { state: 'empty', copyId: undefined, fileSystem };
  throw new SecondCopyError('TARGET_NOT_EMPTY');
}

export interface InitOptions extends TargetOptions {
  /** The id of the register record for this copy; written to `COPY.json`. */
  copyId: string;
  /** Take over a copy of this vault whose `COPY.json` names another (or no) id: it gets `copyId` (R18-3). */
  adopt?: boolean;
  /** TEST ONLY crash point after `COPY.json` is written, before the vault layout. */
  checkpoint?: (point: 'init-after-identity') => void;
}

export interface CopyInitResult {
  /** A new copy was written in an empty folder. */
  created: boolean;
  /** An interrupted `copy init` of this record was completed, or the folder already was this record's copy. */
  resumed: boolean;
  /** `--adopt` only: the id the folder held before (null when it had no `COPY.json`). */
  adoptedFrom: string | null | undefined;
  fileSystem: FileSystemReport;
  disk: DiskRelation;
}

/**
 * Prepare a folder as the Mode B second copy of record `copyId`. Keyless. `COPY.json` is written first, then the
 * vault layout (`initializeVault`, which completes its own interrupted run), so a retry recognises Foundry's own
 * unfinished folder. A copy of this vault with another id is refused (`COPY_MISMATCH`) unless `adopt` is set.
 */
export function initSecondCopy(workingVault: string, target: string, options: InitOptions): CopyInitResult {
  const platform = options.platform ?? hostPlatform;
  workingVault = resolve(workingVault);
  target = resolve(target);
  const working = metadata(workingVault);
  const inspected = inspectCopyTarget(workingVault, target, options);
  let created = false;
  let resumed = false;
  let adoptedFrom: string | null | undefined;
  writeProtected(() => {
    if (inspected.state === 'empty') {
      mkdirSync(target, { recursive: true, mode: 0o700 });
      writeCopyIdentity(target, working.vault_id, options.copyId);
      options.checkpoint?.('init-after-identity');
      initializeVault(target, {
        vaultId: working.vault_id, createdAt: working.created_at, signingPublicKey: Buffer.from(working.signing_public_key, 'base64'),
      });
      created = true;
    } else if (inspected.state === 'interrupted') {
      if (inspected.copyId !== options.copyId) throw new SecondCopyError('COPY_MISMATCH', 'interrupted-init');
      removeRegularFile(join(target, COPY_IDENTITY_PENDING));
      initializeVault(target, {
        vaultId: working.vault_id, createdAt: working.created_at, signingPublicKey: Buffer.from(working.signing_public_key, 'base64'),
      });
      resumed = true;
    } else if (inspected.copyId === options.copyId) {
      resumed = true;
    } else if (options.adopt) {
      adoptedFrom = inspected.copyId ?? null;
      writeCopyIdentity(target, working.vault_id, options.copyId);
    } else {
      throw new SecondCopyError('COPY_MISMATCH', 'adopt-required');
    }
  });
  return { created, resumed, adoptedFrom, fileSystem: inspected.fileSystem, disk: diskRelation(workingVault, target, platform) };
}

// ---------------------------------------------------------------------------------------------------------------
// The vault session.

export type CopyCheckpoint =
  | 'after-stream-files' | 'after-signature' | 'after-manifest-pending' | 'after-manifest-rename'
  | 'after-read-back' | 'after-chmod' | 'after-read-only' | 'after-keyring-rename' | 'after-keyring'
  | 'after-session-end' | 'after-head-update';

/** What a session makes durable on the drive (R20-1), as reported to the TEST ONLY `onSync` observer. */
export type CopySync = 'segment-file' | 'segment-dir' | 'keyring-file' | 'keyring-dir' | 'head-published' | 'session-removed';

export interface SessionOptions extends TargetOptions {
  /** The head recorded on this working device for this copy (null or absent: never sealed). */
  recorded?: { segment: number; hash: string } | null;
  /** The selected record's id: the drive's `COPY.json` must hold it (`COPY_MISMATCH`). Absent: not checked. */
  copyId?: string;
  /** TEST ONLY crash points. A throw here stops the session at that point, like a pulled drive. */
  checkpoint?: (point: CopyCheckpoint, segment: number) => void;
  /**
   * TEST ONLY observer: called, in order, each time the session decides to sync something on the drive, before the
   * platform check (so the decision is visible on Windows too, where folder syncs do nothing).
   */
  onSync?: (event: CopySync, segment: number) => void;
  /** TEST ONLY: runs after phase 1 (read-only) and before phase 2 (lock, recovery). */
  afterInspection?: () => void;
}

export interface SealResult {
  previous: { segment: number; hash: string };
  head: { segment: number; hash: string };
  sealedAt: string;
  segmentsCopied: number;
  filesCopied: number;
  bytesCopied: number;
  keyringVersion: number;
  /** False when the drive already held exactly this keyring. */
  keyringWritten: boolean;
  anchor: VaultAnchor;
}

export interface SessionReport {
  fileSystem: FileSystemReport;
  disk: DiskRelation;
  /** The verified head of the drive before this session. */
  driveHead: { segment: number; hash: string };
  /**
   * The first segment folder an interrupted session left uncommitted (or unfinished), removed after the step-3 check
   * and copied again by this session.
   */
  removedPartialSegment: number | undefined;
  /** `HEAD.json` was behind the verified chain (an interrupted session); `seal` rewrites it last (R19-2). */
  completedHead: boolean;
  /** Committed segments (recorded ones included) that were writable and were made read-only again. */
  protectedSegments: number;
}

const KEYRING_ENTRY = /^keyring\.json(?:\.lock\.sqlite(?:-journal|-wal|-shm)?|\.pending-[0-9a-f]{32})?$/u;

/** Every entry of the drive's `keyring/` folder must be a regular file with a name a keyring writer uses. */
function checkDriveKeyring(target: string): void {
  const folder = join(target, 'keyring');
  const stat = statIfPresent(folder);
  if (!stat) return;
  check(stat.isDirectory(), 'INVENTORY');
  eachSegmentEntry(folder, entry => check(entry.isFile() && KEYRING_ENTRY.test(entry.name), 'INVENTORY'));
}

/**
 * Segment folder numbers on the drive (every entry must be a real folder with a segment name). Listed one entry at
 * a time and kept as numbers only; `segments/` has no format cap (a long history is valid).
 */
function segmentFolders(target: string): number[] {
  const root = join(target, 'segments');
  check(statIfPresent(root)?.isDirectory(), 'INVENTORY');
  const numbers: number[] = [];
  eachEntry(root, Number.MAX_SAFE_INTEGER, entry => {
    const number = Number(entry.name);
    check(entry.isDirectory() && Number.isSafeInteger(number) && number > 0 && entry.name === segmentName(number), 'INVENTORY');
    numbers.push(number);
  });
  return numbers.sort((a, b) => a - b);
}

/** The highest segment folder when it has no manifest. Its contents must be what an interrupted copy leaves. */
function findPartialSegment(target: string, folders: readonly number[]): number | undefined {
  const last = folders.at(-1);
  if (last === undefined) return undefined;
  const folder = join(target, 'segments', segmentName(last));
  if (statIfPresent(join(folder, MANIFEST))) return undefined;
  eachSegmentEntry(folder, entry => {
    const allowed = entry.isFile() && (entry.name === SIGNATURE || entry.name === MANIFEST_PENDING
      || /^(?:events|pack)-[0-9]{4,16}\.fvr$/u.test(entry.name));
    check(allowed, 'INVENTORY');
  });
  return last;
}

const SEGMENT_ENTRY = /^(?:MANIFEST\.json(?:\.pending)?|MANIFEST\.sig|(?:events|pack)-[0-9]{4,16}\.fvr)$/u;

/** An uncommitted segment folder may hold only regular files with the names a copy writes (it is never read). */
function checkUncommitted(folder: string): void {
  eachSegmentEntry(folder, entry => check(entry.isFile() && SEGMENT_ENTRY.test(entry.name), 'INVENTORY'));
}

const SESSION_FORMAT = 'foundry-copy-session/1';
const MAX_SESSION_BYTES = 256;

/**
 * R19-2: the drive's durable "session in progress" state (`SESSION.json`): the verified head the session started
 * from. While it exists, every segment folder after that head is uncommitted, and the next session removes and copies
 * it again. Bounded and keyless; undefined when there is none.
 */
function readSessionState(target: string): { segment: number; hash: string } | undefined {
  const bytes = readRegularFile(join(target, COPY_SESSION), MAX_SESSION_BYTES);
  if (bytes === undefined) return undefined;
  const value = parseCanonical(bytes);
  object(value, 'format segment manifest_sha256');
  check(value.format === SESSION_FORMAT, 'INVENTORY');
  integer(value.segment);
  hex(value.manifest_sha256, 32);
  if (value.segment === 0) check(value.manifest_sha256 === GENESIS_HASH, 'INVENTORY');
  return { segment: value.segment, hash: value.manifest_sha256 };
}

/**
 * R20-1 (54): the head `HEAD.json` names when it is after `base` (the segment of `SESSION.json`), else undefined. A
 * missing or unreadable `HEAD.json` gives undefined here; the head classification after step 3 reports it.
 */
function publishedBeyond(target: string, base: number): { segment: number; hash: string } | undefined {
  let head: { segment: number; hash: string };
  try {
    head = readHead(target);
  } catch (error) {
    if (error instanceof VaultFormatError) return undefined;
    throw error;
  }
  return head.segment > base ? head : undefined;
}

/** Write `SESSION.json` atomically (pending name, fsync, rename, folder sync) before the first change of a session. */
function writeSessionState(target: string, position: ChainPosition): void {
  const pending = join(target, COPY_SESSION_PENDING);
  removeRegularFile(pending);
  writePending(pending, Buffer.from(canonical({ format: SESSION_FORMAT, segment: position.segment, manifest_sha256: position.hash })));
  renameWithRetry(pending, join(target, COPY_SESSION));
  syncDirectory(target);
}

/** The TEST ONLY hooks of one session that the drive-protection steps report to. */
interface SessionHooks {
  point: (name: CopyCheckpoint, segment: number) => void;
  sync: (event: CopySync, segment: number) => void;
}

/**
 * R20-5 (53): file systems whose folders keep their write bits whatever `chmod` asks (Linux exFAT keeps directory
 * write bits and ignores the change). There only the segment FILES carry the read-only state (exFAT's read-only
 * attribute); every other file system also has its segment folders checked. FAT variants never reach this code:
 * they are refused in step 1.
 */
const FILE_MODES_ONLY: ReadonlySet<string> = new Set(['exfat']);

/** True when the probed file system keeps folder write bits, so only file modes are set and checked (R20-5). */
function fileModesOnly(fileSystem: FileSystemReport): boolean {
  return fileSystem.type !== undefined && FILE_MODES_ONLY.has(fileSystem.type);
}

/** Remove the write bits of every file of a segment folder (the folder's own mode is left alone, R20-5). */
function makeFilesReadOnly(folder: string): void {
  eachSegmentEntry(folder, entry => {
    const path = join(folder, entry.name);
    const mode = statIfPresent(path)!.mode & 0o777;
    if (mode & 0o222) chmodSync(path, mode & ~0o222);
  });
}

/**
 * Make a segment folder read-only again when any entry is writable, then make its mode bits durable on POSIX (fsync
 * of every file and of the folder) and check them. R20-1 (46): the sync runs whether or not this call changed a
 * mode, because a mode change of an interrupted session can look right and still be lost by a power cut. With
 * `filesOnly` (R20-5, exFAT) only the files are made read-only and checked; they and the folder are still synced.
 */
function protectSegment(folder: string, segment: number, hooks: SessionHooks, filesOnly: boolean): boolean {
  const changed = writable(folder, filesOnly);
  if (changed) {
    if (filesOnly) makeFilesReadOnly(folder);
    else makeReadOnly(folder);
  }
  hooks.point('after-chmod', segment);
  eachSegmentEntry(folder, entry => {
    check(entry.isFile(), 'INVENTORY');
    hooks.sync('segment-file', segment);
    syncFile(join(folder, entry.name));
  });
  hooks.sync('segment-dir', segment);
  syncDirectory(folder);
  check(!writable(folder, filesOnly), 'INVENTORY');
  return changed;
}

/**
 * Every manifest and signature on the drive is a regular file within its size limit, before any is read. R20-4:
 * each folder's entry count is checked first, so the whole-folder listing of the chain scan stays bounded.
 */
function checkManifestSizes(target: string, folders: readonly number[]): void {
  for (const number of folders) {
    const folder = join(target, 'segments', segmentName(number));
    eachSegmentEntry(folder, () => {});
    for (const [name, limit] of [[MANIFEST, MAX_MANIFEST_BYTES], [SIGNATURE, 64], [MANIFEST_PENDING, MAX_MANIFEST_BYTES]] as const) {
      const stat = statIfPresent(join(folder, name));
      if (stat) check(stat.isFile() && stat.size <= limit, 'INVENTORY');
    }
  }
}

function removeFolder(folder: string): void {
  check(statIfPresent(folder)?.isDirectory(), 'INVENTORY');
  chmodSync(folder, 0o700);
  // The names are collected first (bounded), so no entry is removed while the folder is being listed.
  const names: string[] = [];
  eachSegmentEntry(folder, entry => {
    // Only regular files are ever made writable and removed; a link is never followed by chmod.
    check(entry.isFile(), 'INVENTORY');
    names.push(entry.name);
  });
  for (const name of names) {
    const path = join(folder, name);
    chmodSync(path, 0o600);
    unlinkSync(path);
  }
  syncDirectory(folder);
  rmdirSync(folder);
}

/** Any write bit on the segment's files, or (POSIX, unless `filesOnly`) on the folder itself. */
function writable(folder: string, filesOnly: boolean): boolean {
  if (hostPlatform !== 'win32' && !filesOnly && statSync(folder).mode & 0o222) return true;
  let found = false;
  eachSegmentEntry(folder, entry => {
    if (!found && statIfPresent(join(folder, entry.name))!.mode & 0o222) found = true;
  });
  return found;
}

/** Step 3: the drive against the recorded head and against the working chain. Throws before any change. */
function compareHeads(
  workingVault: string, target: string, drive: ChainPosition, expected: { segment: number; hash: string },
  partial: number | undefined,
): void {
  if (drive.segment < expected.segment) throw new SecondCopyError('ROLLBACK_DETECTED', 'drive-older-than-recorded');
  if (expected.segment > 0 && manifestHash(target, expected.segment) !== expected.hash) {
    throw new SecondCopyError('TAMPER_DETECTED', 'recorded-segment-differs');
  }
  for (let segment = 1; segment <= drive.segment; segment++) {
    const workingHash = manifestHash(workingVault, segment);
    if (workingHash === undefined) throw new SecondCopyError('ROLLBACK_DETECTED', 'working-older-than-drive');
    if (workingHash !== manifestHash(target, segment)) throw new SecondCopyError('TAMPER_DETECTED', 'chains-differ');
  }
  if (partial !== undefined && partial <= expected.segment) throw new SecondCopyError('TAMPER_DETECTED', 'recorded-segment-incomplete');
}

interface Inspection {
  meta: VaultMetadata;
  copyId: string | undefined;
  folders: number[];
  partial: number | undefined;
  /** The drive's "session in progress" state (R19-2), and the uncommitted segment folders after it. */
  session: { segment: number; hash: string } | undefined;
  uncommitted: number[];
  position: ChainPosition;
  previous: ChainPosition;
  expected: { segment: number; hash: string };
  /** `HEAD.json` names the verified head (`current`) or an earlier chain position at or after the recorded head. */
  head: 'current' | 'behind';
}

/**
 * What the drive is checked against: the working vault (its identity and signing key, its chain, the recorded head
 * and the selected copy id), or only a printed anchor (R19-4: a person with the drive and the anchor, no Foundry home).
 */
type DriveTrust =
  | { workingVault: string; working: VaultMetadata; recorded: { segment: number; hash: string } | null | undefined; copyId: string | undefined }
  | { anchor: VaultAnchor };

function anchoredMetadata(target: string): VaultMetadata {
  if (!statIfPresent(join(target, VAULT_METADATA))?.isFile()) throw new SecondCopyError('NOT_A_COPY');
  try {
    return metadata(target);
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('NOT_A_COPY', 'metadata');
    throw error;
  }
}

/**
 * Phase 1 (steps 1 to 3 and the head classification): keyless, read-only and bounded (every manifest, signature and
 * identity file is size-checked before it is read). With an anchor, the anchor is the trust input: the chain must
 * hold the anchored segment with the anchored hash under the anchored signing key.
 */
function inspectDrive(target: string, trust: DriveTrust): Inspection {
  const anchor = 'anchor' in trust ? trust.anchor : undefined;
  const meta = 'anchor' in trust ? anchoredMetadata(target) : targetMetadata(target, trust.working);
  const expected = 'anchor' in trust
    ? { segment: trust.anchor.segment, hash: trust.anchor.manifestHash }
    : trust.recorded ?? { segment: 0, hash: GENESIS_HASH };
  integer(expected.segment);
  hex(expected.hash, 32);
  let copyId: string | undefined;
  let folders: number[];
  let partial: number | undefined;
  let session: Inspection['session'];
  let published: { segment: number; hash: string } | undefined;
  let uncommitted: number[] = [];
  let position: ChainPosition;
  let previous: ChainPosition;
  try {
    eachEntry(target, MAX_ROOT_ENTRIES, () => {});
    checkRootInventory(target, true);
    copyId = readCopyIdentity(target, meta.vault_id);
    if (!('anchor' in trust) && trust.copyId !== undefined && copyId !== trust.copyId) {
      throw new SecondCopyError('COPY_MISMATCH', copyId === undefined ? 'missing' : 'different');
    }
    check(!statIfPresent(join(target, 'open')), 'INVENTORY');
    checkDriveKeyring(target);
    for (const name of [HEAD_PENDING, COPY_IDENTITY_PENDING, COPY_SESSION_PENDING]) {
      const stat = statIfPresent(join(target, name));
      if (stat) check(stat.isFile(), 'INVENTORY');
    }
    session = readSessionState(target);
    folders = segmentFolders(target);
    if (session !== undefined) {
      // R19-2: an interrupted session's segments are uncommitted: never read, only type-checked, then removed.
      // R20-1 (54): `SESSION.json` is removed only after `HEAD.json` is durably published, so a head after the
      // session's base means the stop came between the two. The published head then decides: the segments up to it
      // are committed (and must verify, ending exactly at that head), the ones after it are uncommitted.
      published = publishedBeyond(target, session.segment);
      const base = published?.segment ?? session.segment;
      uncommitted = folders.filter(number => number > base);
      for (const number of uncommitted) checkUncommitted(join(target, 'segments', segmentName(number)));
    } else {
      partial = findPartialSegment(target, folders);
    }
    checkManifestSizes(target, folders.filter(number => !uncommitted.includes(number)));
    ({ position, previous } = scanSealed(target, meta, new StreamScanner(), undefined, anchor, undefined, undefined,
      uncommitted[0] ?? partial));
    if (partial !== undefined) check(partial === position.segment + 1, 'INVENTORY');
    if (published !== undefined) check(published.segment === position.segment && published.hash === position.hash, 'HEAD');
  } catch (error) {
    if (error instanceof VaultFormatError) {
      if (error.code === 'ANCHOR') throw error;
      throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
    }
    throw error;
  }
  // Step 3 comes before any judgement of HEAD.json: a lost newest segment with a surviving HEAD is a rollback.
  if (!('anchor' in trust)) compareHeads(trust.workingVault, target, position, expected, partial);
  // The committed chain ends exactly where the interrupted session started, or (R20-1) at its verified published
  // head, which then lies after the session's base on the same chain.
  if (session !== undefined && (published === undefined
    ? session.segment !== position.segment || session.hash !== position.hash
    : manifestHash(target, session.segment) !== session.hash)) {
    throw new SecondCopyError('COPY_VERIFY_FAILED', 'INVENTORY');
  }
  let head: Inspection['head'];
  try {
    const recordedHead = readHead(target);
    if (headMatches(recordedHead, position)) {
      head = 'current';
    } else {
      check(recordedHead.segment >= expected.segment && recordedHead.segment < position.segment
        && manifestHash(target, recordedHead.segment) === recordedHead.hash, 'HEAD');
      head = 'behind';
    }
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code === 'INVENTORY' ? 'INVENTORY' : 'HEAD');
    throw error;
  }
  return { meta, copyId, folders, partial, session, uncommitted, position, previous, expected, head };
}

/** Before the drive lock, without writing anything: the root and the keyring folder accept writes. */
function writableCheck(target: string): void {
  writeProtected(() => {
    accessSync(target, constants.W_OK);
    const keyring = join(target, 'keyring');
    if (statIfPresent(keyring)) accessSync(keyring, constants.W_OK);
  });
}

/** After the lock and the re-check (R19-7): the medium accepts writes, without leaving anything lasting. */
function writableProbe(target: string): void {
  writeProtected(() => {
    const keyring = join(target, 'keyring');
    if (!statIfPresent(keyring)) mkdirSync(keyring, { mode: 0o700 });
    check(statIfPresent(keyring)?.isDirectory(), 'INVENTORY');
    accessSync(keyring, constants.W_OK);
    // The probe uses the abandoned-temp-file name the session removes, so a crash here leaves nothing lasting.
    const probe = join(keyring, `keyring.json.pending-${randomBytes(16).toString('hex')}`);
    const fd = openSync(probe, 'wx', 0o600);
    try {
      writeSync(fd, Buffer.from('probe'), 0, 5, 0);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    unlinkSync(probe);
  });
}

function takeTargetLock(target: string) {
  try {
    return acquireWriterLock(join(target, LOCK));
  } catch (error) {
    if (READ_ONLY_CODES.includes(errorCode(error) ?? '')) throw new SecondCopyError('WRITE_PROTECTED');
    const message = error instanceof Error ? error.message : '';
    // node:sqlite reports a read-only medium as ERR_SQLITE_ERROR, not as an errno code.
    if (/readonly|read-only|unable to open/iu.test(message)) throw new SecondCopyError('WRITE_PROTECTED');
    if (/locked|busy/iu.test(message)) throw new SecondCopyError('COPY_BUSY');
    throw error;
  }
}

/** After the lock: the drive is still what phase 1 verified. */
function recheck(target: string, inspection: Inspection, vaultId: string): void {
  try {
    const folders = segmentFolders(target);
    check(folders.length === inspection.folders.length && folders.every((n, i) => n === inspection.folders[i]), 'INVENTORY');
    check(manifestHash(target, inspection.position.segment) === inspection.position.hash, 'CHAIN');
    check(readCopyIdentity(target, vaultId) === inspection.copyId, 'INVENTORY');
    const session = readSessionState(target);
    check(session?.segment === inspection.session?.segment && session?.hash === inspection.session?.hash, 'INVENTORY');
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', 'CHANGED');
    throw error;
  }
}

function copyStream(source: string, destination: string, file: ManifestFile, buffer: Buffer): void {
  const input = openSync(source, 'r');
  try {
    check(fstatSync(input).size === file.bytes, 'FILE_SIZE');
    const output = openSync(destination, 'wx', 0o600);
    try {
      const hash = createHash('sha256');
      let offset = 0;
      while (offset < file.bytes) {
        const count = readSync(input, buffer, 0, Math.min(buffer.length, file.bytes - offset), offset);
        check(count > 0, 'LENGTH');
        const chunk = buffer.subarray(0, count);
        hash.update(chunk);
        let written = 0;
        while (written < count) {
          const step = writeSync(output, chunk, written, count - written, offset + written);
          check(step > 0, 'LENGTH');
          written += step;
        }
        offset += count;
      }
      check(hash.digest('hex') === file.sha256, 'FILE_HASH');
      fsyncSync(output);
    } finally {
      closeSync(output);
    }
  } finally {
    closeSync(input);
  }
}

function keyringVersionOf(bytes: Buffer, vaultId: string): number {
  const value = parseCanonical(bytes);
  check(value !== null && typeof value === 'object' && !Array.isArray(value) && value.vault_id === vaultId, 'KEY');
  integer(value.version, 1);
  return value.version;
}

/** fsync one regular file. POSIX only: a Windows flush needs write access, and Windows folder syncs do nothing. */
function syncFile(path: string): void {
  if (hostPlatform === 'win32') return;
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Write the working keyring to the drive unless the drive holds exactly these bytes. The drive file is read only
 * when its size equals the working keyring's, and then only that many bytes, so a huge planted file costs nothing.
 * R20-1 (35): the keyring file and its folder are synced in both cases, so a rename of an interrupted session that
 * was never synced is durable before any head names the new segments.
 */
function publishDriveKeyring(
  target: string, bytes: Buffer, sync: (event: CopySync) => void, afterRename: () => void,
): boolean {
  const folder = join(target, 'keyring');
  const destination = join(folder, 'keyring.json');
  const stat = statIfPresent(destination);
  if (stat) {
    check(stat.isFile(), 'INVENTORY');
    if (stat.size === bytes.length && readRegularFile(destination, bytes.length)?.equals(bytes)) {
      sync('keyring-file');
      syncFile(destination);
      sync('keyring-dir');
      syncDirectory(folder);
      return false;
    }
  }
  const pending = join(folder, `keyring.json.pending-${randomBytes(16).toString('hex')}`);
  try {
    sync('keyring-file');
    writePending(pending, bytes);
    renameWithRetry(pending, destination);
  } catch (error) {
    try { unlinkSync(pending); } catch { /* keep the first failure */ }
    throw error;
  }
  afterRename();
  sync('keyring-dir');
  syncDirectory(folder);
  // R19-2: the keyring that landed is re-checked before any head names the new segments.
  check(readRegularFile(destination, bytes.length)?.equals(bytes), 'KEY');
  return true;
}

export const COPY_BUFFER_BYTES = 1024 * 1024;

/** Phase 1 of a session (steps 1 to 3): keyless and read-only, nothing written on either side, no lock taken. */
function inspectSession(workingVault: string, target: string, options: SessionOptions) {
  const platform = options.platform ?? hostPlatform;
  const working = metadata(workingVault);
  checkPlacement(workingVault, target, platform);
  if (!statIfPresent(target)?.isDirectory()) throw new SecondCopyError('NOT_A_COPY');
  // R19-1: the probe gets the fully resolved path (junctions and links followed to their final volume).
  const fileSystem = checkFileSystem((options.probe ?? (path => probeFileSystem(path, options)))(canonicalPath(target, platform)));
  const inspection = inspectDrive(target, { workingVault, working, recorded: options.recorded, copyId: options.copyId });
  return { working, fileSystem, inspection };
}

/**
 * Phase 1 only (R19-7): the CLI runs this before it takes the working-home lock, so a rollback, tamper or damaged
 * drive is refused before anything is written on either side. The session repeats it under the locks.
 */
export function checkSecondCopySession(workingVault: string, target: string, options: SessionOptions = {}): void {
  inspectSession(resolve(workingVault), resolve(target), options);
}

/** What `verifySecondCopy` checked: the committed chain head of the drive. */
export interface CopyCheck {
  segment: number;
  hash: string;
  /** Segment folders of an interrupted session that were left out (they are not part of the copy yet). */
  uncommitted: number;
}

/**
 * `vault verify-copy` (R19-4): the session's bounded, read-only, keyless inspection, and nothing else. Against the
 * working vault: its identity and signing key, the selected copy id, the recorded head as an ancestor of the drive's
 * chain, and the working chain. Against an anchor alone: the anchor's vault, signing key, segment and hash.
 */
export function verifySecondCopy(
  target: string,
  trust: { workingVault: string; recorded: { segment: number; hash: string }; copyId: string } | { anchor: VaultAnchor },
): CopyCheck {
  target = resolve(target);
  let inspection: Inspection;
  if ('anchor' in trust) {
    if (!statIfPresent(target)?.isDirectory()) throw new SecondCopyError('NOT_A_COPY');
    inspection = inspectDrive(target, { anchor: trust.anchor });
  } else {
    const workingVault = resolve(trust.workingVault);
    const working = metadata(workingVault);
    checkPlacement(workingVault, target, hostPlatform);
    if (!statIfPresent(target)?.isDirectory()) throw new SecondCopyError('NOT_A_COPY');
    inspection = inspectDrive(target, { workingVault, working, recorded: trust.recorded, copyId: trust.copyId });
  }
  return { segment: inspection.position.segment, hash: inspection.position.hash, uncommitted: inspection.uncommitted.length };
}

/**
 * Steps 1 to 3 (phase 1, keyless and read-only), then phase 2: the drive lock, a re-check, the writability probe and
 * the recovery of an interrupted session (R19-7). On success the drive is verified, consistent with the recorded
 * head and the working chain, and locked for this session; `seal` then runs steps 4 to 7.
 */
export function openSecondCopySession(workingVault: string, target: string, options: SessionOptions = {}) {
  const platform = options.platform ?? hostPlatform;
  workingVault = resolve(workingVault);
  target = resolve(target);
  // Phase 1: steps 1 to 3, nothing written on either side.
  const { working, fileSystem, inspection } = inspectSession(workingVault, target, options);
  options.afterInspection?.();
  const hooks: SessionHooks = {
    point: (name, segment) => options.checkpoint?.(name, segment),
    sync: (event, segment) => options.onSync?.(event, segment),
  };
  // R20-5 (53): on exFAT only the segment files carry the read-only state.
  const filesOnly = fileModesOnly(fileSystem);
  // Phase 2: no write before the lock; the probe file only after the re-check.
  writableCheck(target);
  const lock = takeTargetLock(target);
  try {
    recheck(target, inspection, working.vault_id);
    writableProbe(target);
    const { meta, partial, uncommitted } = inspection;
    const drive = inspection.position;
    let protectedSegments = 0;
    writeProtected(() => {
      try {
        // R19-2: an interrupted session's uncommitted segments (and an older unfinished folder) are removed and are
        // copied again below; the committed segments and their seals are untouched.
        for (const segment of [...uncommitted].reverse()) removeFolder(join(target, 'segments', segmentName(segment)));
        if (partial !== undefined) removeFolder(join(target, 'segments', segmentName(partial)));
        if (uncommitted.length > 0 || partial !== undefined) syncDirectory(join(target, 'segments'));
        // A pending head is never trusted or read: the verified chain decides what HEAD.json must say.
        removeRegularFile(join(target, HEAD_PENDING));
        removeRegularFile(join(target, COPY_IDENTITY_PENDING));
        removeRegularFile(join(target, COPY_SESSION_PENDING));
        const pendingKeyrings: string[] = [];
        eachSegmentEntry(join(target, 'keyring'), entry => {
          if (/^keyring\.json\.pending-[0-9a-f]{32}$/u.test(entry.name)) pendingKeyrings.push(entry.name);
        });
        for (const name of pendingKeyrings) removeRegularFile(join(target, 'keyring', name));
        // R19-2, R20-1 (46): every committed segment, recorded ones included, is read-only again, synced, and checked.
        for (let segment = 1; segment <= drive.segment; segment++) {
          if (protectSegment(join(target, 'segments', segmentName(segment)), segment, hooks, filesOnly)) protectedSegments++;
        }
        syncDirectory(target);
      } catch (error) {
        if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
        throw error;
      }
    });
    // HEAD.json is not touched here: a head that is behind is rewritten by `seal`, after the keyring (R19-2, 35).
    const report: SessionReport = {
      fileSystem, disk: diskRelation(workingVault, target, platform),
      driveHead: { segment: drive.segment, hash: drive.hash }, removedPartialSegment: uncommitted[0] ?? partial,
      completedHead: inspection.head === 'behind', protectedSegments,
    };
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      lock.close();
    };

    /** Steps 4 to 7. `unlocked` must belong to the working vault (it signs nothing here; it closes the open segment). */
    const seal = (unlocked: UnlockedKeyring, { now = () => new Date(), writer }: { now?: () => Date; writer?: string } = {}): SealResult => {
      check(!released, 'KEY');
      const point = hooks.point;
      // Step 4. Opening the writer verifies the working chain's structure and hashes; damage there stops the session.
      let closed: ChainPosition;
      try {
        const vaultWriter = VaultWriter.open(workingVault, unlocked, writer === undefined ? {} : { writer });
        try {
          closed = vaultWriter.closeSegment();
        } finally {
          vaultWriter.release();
        }
      } catch (error) {
        if (error instanceof VaultFormatError && error.code !== 'KEY') throw new SecondCopyError('WORKING_VAULT_DAMAGED', error.code);
        throw error;
      }
      check(closed.segment >= drive.segment, 'CHAIN');
      // R19-2: one durable "in progress" state before the first change of this session (kept when an interrupted
      // session left it with the verified head as its base, checked in phase 1; R20-1: rewritten with that head when
      // its base is older because the interrupted session stopped after publishing its head).
      const marker = inspection.session;
      if (marker === undefined || marker.segment !== drive.segment || marker.hash !== drive.hash) {
        writeProtected(() => writeSessionState(target, drive));
      }
      const publicKey = Buffer.from(meta.signing_public_key, 'base64');
      const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
      let position: ChainPosition = drive;
      const copied: { segment: number; files: ManifestFile[]; start: ChainPosition; hash: string }[] = [];
      let filesCopied = 0;
      let bytesCopied = 0;
      // Step 5.
      for (let segment = drive.segment + 1; segment <= closed.segment; segment++) {
        const name = segmentName(segment);
        const source = join(workingVault, 'segments', name);
        const destination = join(target, 'segments', name);
        let bytes: Buffer;
        let signature: Buffer;
        let files: ManifestFile[];
        let next: ChainPosition;
        try {
          bytes = readFileSync(join(source, MANIFEST));
          signature = readFileSync(join(source, SIGNATURE));
          const manifest = decodeManifest(bytes, signature, publicKey);
          checkManifestLink(manifest, meta.vault_id, position);
          const names = streamNames(source, [MANIFEST, SIGNATURE]);
          check(names.length === manifest.files.length
            && [...names].sort().every((entry, index) => entry === manifest.files[index]!.name), 'INVENTORY');
          files = manifest.files;
          next = { segment, hash: sha256(bytes), lastEventSequence: manifest.last_event_seq ?? position.lastEventSequence };
        } catch (error) {
          if (error instanceof VaultFormatError) throw new SecondCopyError('WORKING_VAULT_DAMAGED', error.code);
          throw error;
        }
        writeProtected(() => {
          mkdirSync(destination, { mode: 0o700 });
          // The new folder's entry is durable before anything that depends on it is written.
          syncDirectory(join(target, 'segments'));
        });
        for (const file of files) {
          try {
            copyStream(join(source, file.name), join(destination, file.name), file, buffer);
          } catch (error) {
            if (error instanceof VaultFormatError) throw new SecondCopyError('WORKING_VAULT_DAMAGED', error.code);
            throw error;
          }
          filesCopied++;
          bytesCopied += file.bytes;
        }
        point('after-stream-files', segment);
        writePending(join(destination, SIGNATURE), signature);
        point('after-signature', segment);
        writePending(join(destination, MANIFEST_PENDING), bytes);
        syncDirectory(destination);
        point('after-manifest-pending', segment);
        renameWithRetry(join(destination, MANIFEST_PENDING), join(destination, MANIFEST));
        syncDirectory(destination);
        syncDirectory(join(target, 'segments'));
        point('after-manifest-rename', segment);
        filesCopied += 2;
        bytesCopied += bytes.length + signature.length;
        copied.push({ segment, files, start: position, hash: next.hash });
        position = next;
      }
      // Step 6: re-read everything that landed on the drive; the head is derived from those bytes.
      let derived: ChainPosition = drive;
      try {
        const scanner = new StreamScanner();
        for (const { segment, start, hash } of copied) {
          const folder = join(target, 'segments', segmentName(segment));
          const bytes = readRegularFile(join(folder, MANIFEST), MAX_MANIFEST_BYTES);
          check(bytes !== undefined, 'INVENTORY');
          check(sha256(bytes) === hash, 'FILE_HASH');
          const signature = readRegularFile(join(folder, SIGNATURE), 64);
          check(signature !== undefined, 'INVENTORY');
          const manifest = decodeManifest(bytes, signature, publicKey);
          checkManifestLink(manifest, meta.vault_id, derived);
          const names = streamNames(folder, [MANIFEST, SIGNATURE]);
          check(names.length === manifest.files.length
            && [...names].sort().every((entry, index) => entry === manifest.files[index]!.name), 'INVENTORY');
          const scanned = scanStreams(folder, names, derived.lastEventSequence, scanner, undefined, manifest.files);
          checkManifestRecords(manifest, scanned.keyIds, scanned.first, scanned.last);
          derived = { segment, hash: sha256(bytes), lastEventSequence: scanned.last };
        }
        check(derived.segment === position.segment && derived.hash === position.hash, 'CHAIN');
      } catch (error) {
        if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
        throw error;
      }
      point('after-read-back', position.segment);
      // Step 7: read-only (durable and checked), keyring (synced and re-read), HEAD.json, then the end of the session.
      const keyringBytes = readFileSync(join(workingVault, 'keyring', 'keyring.json'));
      const keyringVersion = keyringVersionOf(keyringBytes, meta.vault_id);
      let keyringWritten: boolean;
      try {
        for (const { segment } of copied) protectSegment(join(target, 'segments', segmentName(segment)), segment, hooks, filesOnly);
        point('after-read-only', position.segment);
        keyringWritten = writeProtected(() => publishDriveKeyring(target, keyringBytes,
          event => hooks.sync(event, position.segment), () => point('after-keyring-rename', position.segment)));
      } catch (error) {
        if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
        throw error;
      }
      point('after-keyring', position.segment);
      // R20-1 (54): HEAD.json is published durably first; only then is the session state removed. A stop before the
      // head lands leaves the new segments for the next session to remove; a stop after it leaves a published head
      // after the session's base, and the next session takes that verified head as the end of the committed chain.
      if (copied.length > 0 || inspection.head === 'behind') {
        hooks.sync('head-published', position.segment);
        publishHead(target, position);
      }
      point('after-head-update', position.segment);
      writeProtected(() => {
        hooks.sync('session-removed', position.segment);
        removeRegularFile(join(target, COPY_SESSION));
        syncDirectory(target);
      });
      point('after-session-end', position.segment);
      return {
        previous: { segment: drive.segment, hash: drive.hash },
        head: { segment: position.segment, hash: position.hash },
        sealedAt: nowStamp(now()),
        segmentsCopied: copied.length,
        filesCopied,
        bytesCopied,
        keyringVersion,
        keyringWritten,
        anchor: chainAnchor(meta.vault_id, meta.signing_public_key, position),
      };
    };
    return { report, seal, release };
  } catch (error) {
    lock.close();
    throw error;
  }
}

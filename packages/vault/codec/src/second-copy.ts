/**
 * Mode B second copy: an offline drive that is writable only during a vault session (Architecture 8.1, 8.2; Product 8).
 *
 * Session steps (Architecture 8.1):
 *  1. Detect the target folder, refuse a file system with a 4 GiB file limit (FAT), read VAULT.json and refuse a
 *     different vault.
 *  2. Check that the drive is writable (a hardware write-protect switch still on is reported as `WRITE_PROTECTED`)
 *     and verify every manifest, signature, file hash and the whole chain without any secret. A trailing segment
 *     folder without a manifest (an interrupted earlier session) is left out of this check.
 *  3. Compare the drive's verified chain with the head recorded on the working device for this copy, and with the
 *     working vault's own chain. Older than recorded: `ROLLBACK_DETECTED`. A different manifest hash at the same
 *     segment number: `TAMPER_DETECTED`. Nothing on the drive or the working device is changed before this passes.
 *     Only then is the unfinished segment folder of step 2 removed.
 *  4. Close the open segment on the working device.
 *  5. Copy each missing segment in order: stream files first, then `MANIFEST.sig`, then `MANIFEST.json` through a
 *     pending name and a rename, with fsync of every file and (on POSIX) of the folders. A crash leaves earlier
 *     segments untouched.
 *  6. Re-read and re-hash every copied file and manifest on the drive.
 *  7. Mark the copied segments read-only, write `keyring/keyring.json` (temp file, fsync, rename) and `HEAD.json`.
 *  8. and 9. are done by the caller with the returned result: record the new head on the working device, append
 *     `copy.sealed`, and print the anchor.
 *
 * The chain is tamper-evident, not tamper-proof (Architecture 8.2): an exact copy of a drive cannot be told from the
 * original, and an out-of-date recorded head cannot reveal the loss of segments written after it.
 */
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync, closeSync, fstatSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, readSync,
  realpathSync, rmdirSync, statfsSync, statSync, unlinkSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, win32 } from 'node:path';
import { platform as hostPlatform } from 'node:process';
import { canonical, check, hex, integer, object, parseCanonical, sha256, timestamp, VaultFormatError } from './bytes.ts';
import type { Json } from './bytes.ts';
import { chainAnchor } from './anchor.ts';
import { acquireWriterLock, publishKeyring, renameWithRetry, syncDirectory } from './keyring-file.ts';
import { checkManifestLink, checkManifestRecords, decodeManifest, GENESIS_HASH } from './manifest.ts';
import type { ChainPosition, ManifestFile } from './manifest.ts';
import { StreamScanner } from './record-file.ts';
import type { UnlockedKeyring } from './record-file.ts';
import {
  checkRootInventory, checkVerifiedHead, HEAD_PENDING, headBytes, headMatches, LOCK, makeReadOnly,
  MANIFEST, MANIFEST_PENDING, metadata, readHead, replaceHead, scanSealed, scanStreams, segmentName, SIGNATURE,
  statIfPresent, streamNames, VAULT_METADATA, writePending,
} from './vault-directory.ts';
import type { VaultAnchor, VaultMetadata } from './vault-directory.ts';
import { initializeVault, VaultWriter } from './vault-writer.ts';

export type SecondCopyErrorCode =
  | 'FILESYSTEM_UNSUPPORTED' | 'WRITE_PROTECTED' | 'ROLLBACK_DETECTED' | 'TAMPER_DETECTED' | 'VAULT_MISMATCH'
  | 'NOT_A_COPY' | 'TARGET_NOT_EMPTY' | 'TARGET_UNSUITABLE' | 'COPY_BUSY' | 'COPY_VERIFY_FAILED'
  | 'WORKING_VAULT_DAMAGED' | 'OUTPUT_EXISTS' | 'REGISTER' | 'COPY_UNKNOWN' | 'COPY_AMBIGUOUS' | 'INVALID_LABEL' | 'INVALID_CADENCE'
  | 'SCHEDULER_UNSUPPORTED' | 'SCHEDULER_FAILED';

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

// ---------------------------------------------------------------------------------------------------------------
// External commands (fsutil, schtasks, systemctl, crontab): always explicit arguments, never a shell.

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

/** File systems with a 4 GiB file-size limit (every FAT variant). */
export const FAT_FILE_SYSTEMS: ReadonlySet<string> = new Set(['vfat', 'msdos', 'fat', 'fat12', 'fat16', 'fat32', 'umsdos', 'uvfat']);

/** Linux `statfs` magic numbers (`linux/magic.h`). vfat and msdos share `MSDOS_SUPER_MAGIC`. */
const LINUX_MAGIC: ReadonlyMap<number, string> = new Map([
  [0x4d44, 'vfat'], [0x2011bab0, 'exfat'], [0xef53, 'ext4'], [0x5346544e, 'ntfs3'], [0x9123683e, 'btrfs'],
  [0x58465342, 'xfs'], [0x01021994, 'tmpfs'], [0xf2f52010, 'f2fs'], [0x2fc12fc1, 'zfs'], [0xca451a4e, 'bcachefs'],
  [0x6969, 'nfs'], [0xff534d42, 'cifs'], [0xfe534d42, 'smb2'], [0x794c7630, 'overlay'], [0x15013346, 'udf'],
  [0x9660, 'iso9660'], [0x3153464a, 'jfs'], [0x52654973, 'reiserfs'],
]);

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

/** The file-system name from `fsutil fsinfo volumeinfo` output. Labels are localized, so only the value is matched. */
export function fsutilType(output: string): string | undefined {
  for (const line of output.split(/\r?\n/u)) {
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const value = line.slice(colon + 1).trim();
    if (/^(?:NTFS|FAT32|FAT16|FAT12|FAT|exFAT|ReFS|UDF|CDFS)$/iu.test(value)) return value.toLowerCase();
  }
  return undefined;
}

/** Detect the file system that holds `path` (an existing path). Never throws for an undetectable type. */
export function probeFileSystem(path: string, { platform = hostPlatform, run = defaultRunner }: { platform?: string; run?: CommandRunner } = {}): FileSystemReport {
  if (platform === 'win32') {
    const root = win32.parse(resolve(path)).root;
    if (!/^[A-Za-z]:\\$/u.test(root)) return { type: undefined, method: 'none' };
    const result = run('fsutil', ['fsinfo', 'volumeinfo', root.slice(0, 2)]);
    const type = result.status === 0 ? fsutilType(result.stdout) : undefined;
    return { type, method: type ? 'fsutil' : 'none' };
  }
  if (platform === 'linux') {
    let magic: string | undefined;
    try {
      magic = LINUX_MAGIC.get(statfsSync(path).type >>> 0);
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
  if (report.type !== undefined && FAT_FILE_SYSTEMS.has(report.type)) throw new SecondCopyError('FILESYSTEM_UNSUPPORTED', 'fat');
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
// The working device's register of second copies (Architecture 5.4 keyring-copy register and 8.1 step 8).

export const REGISTER_FORMAT = 'foundry-second-copies/1';
export const CADENCES = ['daily', 'weekly', 'monthly', 'manual'] as const;
export type Cadence = (typeof CADENCES)[number];
/** Days between reminders for each cadence (`manual` never reminds). */
export const CADENCE_DAYS: Readonly<Record<Cadence, number | null>> = { daily: 1, weekly: 7, monthly: 30, manual: null };
/** Product 8 and D-8: a persistent banner after 14 days without a seal. */
export const OVERDUE_DAYS = 14;
const MAX_REGISTER_BYTES = 1024 * 1024;
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
    object(value, 'format vault_id cadence copies last_check');
    check(value.format === REGISTER_FORMAT && value.vault_id === vaultId);
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

export function emptyRegister(vaultId: string): CopyRegister {
  hex(vaultId, 16);
  return { format: REGISTER_FORMAT, vault_id: vaultId, cadence: 'weekly', copies: [], last_check: null };
}

/** Read the register (a missing file is an empty register with the weekly default cadence). */
export function readCopyRegister(path: string, vaultId: string): CopyRegister {
  const stat = statIfPresent(path);
  if (!stat) return emptyRegister(vaultId);
  if (!stat.isFile() || stat.size > MAX_REGISTER_BYTES) throw new SecondCopyError('REGISTER');
  let value: Json;
  try {
    value = parseCanonical(readFileSync(path));
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('REGISTER');
    throw error;
  }
  return validateRegister(value, vaultId);
}

/** Replace the register atomically: unique temp file, fsync, rename, folder sync. */
export function writeCopyRegister(path: string, register: CopyRegister): void {
  validateRegister(JSON.parse(JSON.stringify(register)), register.vault_id);
  const bytes = Buffer.from(canonical(register as unknown as Json));
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

export function addCopyRecord(register: CopyRegister, label: string | undefined, now: Date): { register: CopyRegister; copy: CopyRecord } {
  let name = label === undefined ? undefined : assertCopyLabel(label);
  if (name === undefined) {
    for (let n = 1; name === undefined; n++) if (!register.copies.some(copy => copy.label === `copy-${n}`)) name = `copy-${n}`;
  }
  if (register.copies.some(copy => copy.label === name)) throw new SecondCopyError('INVALID_LABEL', 'taken');
  const copy: CopyRecord = { copy_id: randomBytes(16).toString('hex'), label: name, created_at: nowStamp(now), head: null, keyring: null };
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

export function recordSeal(register: CopyRegister, copyId: string, result: SealResult): CopyRegister {
  return {
    ...register,
    copies: register.copies.map(copy => copy.copy_id !== copyId ? copy : {
      ...copy,
      head: { segment: result.head.segment, manifest_sha256: result.head.hash, sealed_at: result.sealedAt },
      keyring: { version: result.keyringVersion, written_at: result.sealedAt },
    }),
  };
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
    banner = 'No second copy is set up. Run `foundry vault copy init <folder>` on an offline drive.';
  } else if (overdue.length > 0) {
    const days = Math.max(...overdue.map(copy => copy.daysUnsealed));
    banner = `SECOND COPY OVERDUE: ${overdue.length === 1 ? `copy "${overdue[0]!.label}" was` : `${overdue.length} copies were`} `
      + `last sealed ${days} day(s) ago (limit ${OVERDUE_DAYS}). Connect the drive and run \`foundry vault seal <folder>\`.`;
  }
  return { cadence: register.cadence, copies, due: copies.length === 0 || copies.some(copy => copy.due), overdue: overdue.length > 0, banner };
}

// ---------------------------------------------------------------------------------------------------------------
// Target placement and `vault copy init`.

export interface TargetOptions {
  platform?: string;
  run?: CommandRunner;
  /** TEST ONLY hook: replaces the file-system probe so FAT refusal is testable on any OS. */
  probe?: FileSystemProbe;
}

function folded(path: string, platform: string): string {
  return platform === 'win32' ? path.toLowerCase() : path;
}

function within(parent: string, child: string, platform: string): boolean {
  const rel = relative(folded(parent, platform), folded(child, platform));
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function realOrResolved(path: string): string {
  try {
    return realpathSync.native(path);
  } catch {
    return resolve(path);
  }
}

/** The copy must be its own folder: not a volume root, not inside the working home's vault and not around it. */
function checkPlacement(workingVault: string, target: string, platform: string): void {
  const root = platform === 'win32' ? win32.parse(target).root : '/';
  if (folded(target, platform) === folded(root, platform) || target === dirname(target)) {
    throw new SecondCopyError('TARGET_UNSUITABLE', 'volume-root');
  }
  const working = realOrResolved(workingVault);
  const real = realOrResolved(target);
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

export interface CopyInitResult {
  /** False when the folder already held a copy of this vault (it is registered again, unchanged). */
  created: boolean;
  fileSystem: FileSystemReport;
  disk: DiskRelation;
}

/** Prepare an empty folder (or adopt an existing copy of the same vault) as a Mode B second copy. Keyless. */
export function initSecondCopy(workingVault: string, target: string, options: TargetOptions = {}): CopyInitResult {
  const platform = options.platform ?? hostPlatform;
  workingVault = resolve(workingVault);
  target = resolve(target);
  const working = metadata(workingVault);
  checkPlacement(workingVault, target, platform);
  const existing = nearestExisting(target);
  const fileSystem = checkFileSystem((options.probe ?? (path => probeFileSystem(path, options)))(existing));
  const stat = statIfPresent(target);
  if (stat && !stat.isDirectory()) throw new SecondCopyError('TARGET_UNSUITABLE', 'not-a-folder');
  const entries = stat ? readdirSync(target, { withFileTypes: true }) : [];
  let created = false;
  if (entries.length > 0) {
    if (!entries.some(entry => entry.name === VAULT_METADATA)) throw new SecondCopyError('TARGET_NOT_EMPTY');
    targetMetadata(target, working);
  } else {
    try {
      mkdirSync(target, { recursive: true, mode: 0o700 });
      initializeVault(target, {
        vaultId: working.vault_id, createdAt: working.created_at,
        signingPublicKey: Buffer.from(working.signing_public_key, 'base64'),
      });
    } catch (error) {
      if (['EROFS', 'EACCES', 'EPERM'].includes(errorCode(error) ?? '')) throw new SecondCopyError('WRITE_PROTECTED');
      throw error;
    }
    created = true;
  }
  return { created, fileSystem, disk: diskRelation(workingVault, target, platform) };
}

// ---------------------------------------------------------------------------------------------------------------
// The vault session.

export type CopyCheckpoint =
  | 'after-stream-files' | 'after-signature' | 'after-manifest-pending' | 'after-head-pending'
  | 'after-manifest-rename' | 'after-head-update' | 'after-read-only' | 'after-keyring';

export interface SessionOptions extends TargetOptions {
  /** The head recorded on this working device for this copy (null or absent: never sealed). */
  recorded?: { segment: number; hash: string } | null;
  /** TEST ONLY crash points. A throw here stops the session at that point, like a pulled drive. */
  checkpoint?: (point: CopyCheckpoint, segment: number) => void;
}

export interface SealResult {
  previous: { segment: number; hash: string };
  head: { segment: number; hash: string };
  sealedAt: string;
  segmentsCopied: number;
  filesCopied: number;
  bytesCopied: number;
  keyringVersion: number;
  anchor: VaultAnchor;
}

export interface SessionReport {
  fileSystem: FileSystemReport;
  disk: DiskRelation;
  /** The verified head of the drive before this session. */
  driveHead: { segment: number; hash: string };
  /** An unfinished segment folder left by an interrupted session, removed after the step-3 check. */
  removedPartialSegment: number | undefined;
  /** A drive head left pending by an interrupted session and completed after the step-3 check. */
  completedHead: boolean;
}

function writableProbe(target: string): void {
  const keyring = join(target, 'keyring');
  // The probe uses the abandoned-temp-file name that keyring writers remove, so a crash here leaves nothing lasting.
  const probe = join(keyring, `keyring.json.pending-${randomBytes(16).toString('hex')}`);
  try {
    mkdirSync(keyring, { recursive: true, mode: 0o700 });
    const fd = openSync(probe, 'wx', 0o600);
    try {
      writeSync(fd, Buffer.from('probe'), 0, 5, 0);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    unlinkSync(probe);
  } catch (error) {
    if (['EROFS', 'EACCES', 'EPERM'].includes(errorCode(error) ?? '')) throw new SecondCopyError('WRITE_PROTECTED');
    throw error;
  }
}

function takeTargetLock(target: string) {
  try {
    return acquireWriterLock(join(target, LOCK));
  } catch (error) {
    if (['EROFS', 'EACCES', 'EPERM'].includes(errorCode(error) ?? '')) throw new SecondCopyError('WRITE_PROTECTED');
    if (error instanceof Error && /locked|busy/iu.test(error.message)) throw new SecondCopyError('COPY_BUSY');
    throw error;
  }
}

/** The highest segment folder when it has no manifest. Its contents must be what an interrupted copy leaves. */
function findPartialSegment(target: string): number | undefined {
  const root = join(target, 'segments');
  if (!statIfPresent(root)?.isDirectory()) return undefined;
  const numbers = readdirSync(root, { withFileTypes: true })
    .map(entry => Number(entry.name))
    .filter(number => Number.isSafeInteger(number) && number > 0);
  if (numbers.length === 0) return undefined;
  const last = Math.max(...numbers);
  const folder = join(root, segmentName(last));
  if (!statIfPresent(folder)?.isDirectory() || statIfPresent(join(folder, MANIFEST))) return undefined;
  for (const entry of readdirSync(folder, { withFileTypes: true })) {
    const allowed = entry.isFile() && (entry.name === SIGNATURE || entry.name === MANIFEST_PENDING
      || /^(?:events|pack)-[0-9]{4,16}\.fvr$/u.test(entry.name));
    if (!allowed) throw new SecondCopyError('COPY_VERIFY_FAILED', 'INVENTORY');
  }
  return last;
}

function removeFolder(folder: string): void {
  chmodSync(folder, 0o700);
  for (const entry of readdirSync(folder, { withFileTypes: true })) {
    const path = join(folder, entry.name);
    chmodSync(path, 0o600);
    unlinkSync(path);
  }
  syncDirectory(folder);
  rmdirSync(folder);
}

function manifestHash(directory: string, segment: number): string | undefined {
  const path = join(directory, 'segments', segmentName(segment), MANIFEST);
  return statIfPresent(path)?.isFile() ? sha256(readFileSync(path)) : undefined;
}

/** Step 2: keyless verification of the drive, leaving out an unfinished trailing segment folder. */
function verifyDrive(target: string, working: VaultMetadata, partial: number | undefined) {
  const meta = targetMetadata(target, working);
  try {
    checkRootInventory(target);
    check(!statIfPresent(join(target, 'open')), 'INVENTORY');
    const { position, previous } = scanSealed(target, meta, new StreamScanner(), undefined, undefined, undefined, undefined, partial);
    // HEAD.json is a convenience copy that is never trusted on its own (Architecture 4.1). With an unfinished
    // trailing folder, its check waits until step 3 has compared the verified chain; it only decides whether that
    // folder is what an interrupted session leaves (HEAD names the last verified segment, a pending head names
    // the unfinished one).
    let partialConsistent = true;
    if (partial === undefined) {
      checkVerifiedHead(target, position, previous);
    } else {
      check(partial === position.segment + 1, 'INVENTORY');
      partialConsistent = headMatches(readHead(target), position) && (!statIfPresent(join(target, HEAD_PENDING))
        || readHead(target, HEAD_PENDING, 'INVENTORY').segment === partial);
    }
    return { meta, position, previous, partialConsistent };
  } catch (error) {
    if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
    throw error;
  }
}

/** Step 3: the drive against the recorded head and against the working chain. Throws before any change. */
function compareHeads(
  workingVault: string, target: string, drive: ChainPosition, recorded: { segment: number; hash: string } | null | undefined,
  partial: number | undefined,
): void {
  const expected = recorded ?? { segment: 0, hash: GENESIS_HASH };
  integer(expected.segment);
  hex(expected.hash, 32);
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

export const COPY_BUFFER_BYTES = 1024 * 1024;

/**
 * Steps 1 to 3 of a vault session on `target`, keyless. On success the drive is verified, consistent with the
 * recorded head and with the working chain, and locked for this session; `seal` then runs steps 4 to 7.
 */
export function openSecondCopySession(workingVault: string, target: string, options: SessionOptions = {}) {
  const platform = options.platform ?? hostPlatform;
  workingVault = resolve(workingVault);
  target = resolve(target);
  const working = metadata(workingVault);
  checkPlacement(workingVault, target, platform);
  if (!statIfPresent(target)?.isDirectory()) throw new SecondCopyError('NOT_A_COPY');
  // Step 1.
  const fileSystem = checkFileSystem((options.probe ?? (path => probeFileSystem(path, options)))(target));
  targetMetadata(target, working);
  // Step 2: writability first, so a switch left on is reported plainly, then the lock and the keyless check.
  writableProbe(target);
  const lock = takeTargetLock(target);
  try {
    const partial = findPartialSegment(target);
    const { meta, position: drive, previous: drivePrevious, partialConsistent } = verifyDrive(target, working, partial);
    // Step 3.
    compareHeads(workingVault, target, drive, options.recorded, partial);
    if (!partialConsistent) throw new SecondCopyError('COPY_VERIFY_FAILED', 'HEAD');
    // Only now may the drive change: finish or roll back what an interrupted session left.
    let completedHead = false;
    if (partial !== undefined) {
      if (statIfPresent(join(target, HEAD_PENDING))) unlinkSync(join(target, HEAD_PENDING));
      removeFolder(join(target, 'segments', segmentName(partial)));
      syncDirectory(join(target, 'segments'));
      syncDirectory(target);
    } else if (statIfPresent(join(target, HEAD_PENDING))) {
      replaceHead(target);
      completedHead = true;
    }
    const report: SessionReport = {
      fileSystem, disk: diskRelation(workingVault, target, platform),
      driveHead: { segment: drive.segment, hash: drive.hash }, removedPartialSegment: partial, completedHead,
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
      const point = (name: CopyCheckpoint, segment: number) => options.checkpoint?.(name, segment);
      // Step 4.
      // Opening the writer verifies the working chain's structure and hashes; damage there stops the session.
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
      const publicKey = Buffer.from(meta.signing_public_key, 'base64');
      const buffer = Buffer.allocUnsafe(COPY_BUFFER_BYTES);
      let position: ChainPosition = drive;
      let previous: ChainPosition = drivePrevious;
      const copied: { segment: number; files: ManifestFile[]; start: ChainPosition }[] = [];
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
        mkdirSync(destination, { mode: 0o700 });
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
        writePending(join(target, HEAD_PENDING), headBytes(next));
        syncDirectory(target);
        point('after-head-pending', segment);
        renameWithRetry(join(destination, MANIFEST_PENDING), join(destination, MANIFEST));
        syncDirectory(destination);
        syncDirectory(join(target, 'segments'));
        point('after-manifest-rename', segment);
        replaceHead(target);
        point('after-head-update', segment);
        filesCopied += 2;
        bytesCopied += bytes.length + signature.length;
        copied.push({ segment, files, start: position });
        previous = position;
        position = next;
      }
      // Step 6: re-read and re-hash what landed on the drive.
      try {
        const scanner = new StreamScanner();
        for (const { segment, start } of copied) {
          const folder = join(target, 'segments', segmentName(segment));
          const bytes = readFileSync(join(folder, MANIFEST));
          const manifest = decodeManifest(bytes, readFileSync(join(folder, SIGNATURE)), publicKey);
          checkManifestLink(manifest, meta.vault_id, start);
          const names = streamNames(folder, [MANIFEST, SIGNATURE]);
          check(names.length === manifest.files.length, 'INVENTORY');
          const scanned = scanStreams(folder, names, start.lastEventSequence, scanner, undefined, manifest.files);
          checkManifestRecords(manifest, scanned.keyIds, scanned.first, scanned.last);
        }
        checkVerifiedHead(target, position, previous);
      } catch (error) {
        if (error instanceof VaultFormatError) throw new SecondCopyError('COPY_VERIFY_FAILED', error.code);
        throw error;
      }
      // Step 7.
      for (const { segment } of copied) makeReadOnly(join(target, 'segments', segmentName(segment)));
      point('after-read-only', position.segment);
      const keyringBytes = readFileSync(join(workingVault, 'keyring', 'keyring.json'));
      const keyringVersion = keyringVersionOf(keyringBytes, meta.vault_id);
      const destination = join(target, 'keyring', 'keyring.json');
      mkdirSync(join(target, 'keyring'), { recursive: true, mode: 0o700 });
      const existing = statIfPresent(destination)?.isFile() ? readFileSync(destination) : undefined;
      if (!existing?.equals(keyringBytes)) publishKeyring(destination, keyringBytes, existing);
      point('after-keyring', position.segment);
      check(headMatches(readHead(target), position), 'HEAD');
      return {
        previous: { segment: drive.segment, hash: drive.hash },
        head: { segment: position.segment, hash: position.hash },
        sealedAt: nowStamp(now()),
        segmentsCopied: copied.length,
        filesCopied,
        bytesCopied,
        keyringVersion,
        anchor: chainAnchor(meta.vault_id, meta.signing_public_key, position),
      };
    };
    return { report, seal, release };
  } catch (error) {
    lock.close();
    throw error;
  }
}


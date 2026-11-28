/**
 * The six command bodies. They run in the worker thread (or inline in tests); the main thread owns argument parsing,
 * the lock, prompts and the wall-clock limit.
 *
 * Unlock once (design 4.5): every keyed command opens ONE `UnlockSession`, passes `{ session }` to every vault and
 * index call, and disposes it in `finally`. KDF runs: `init` 1, `vault reset-passphrase` 1, keyed commands 1 with a
 * passphrase and 0 with a recovery key. Packages are loaded on demand, so `vault verify` never loads the SQLite addon.
 */
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';
import process from 'node:process';
import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';
import type { IndexStoreOptions } from 'foundry-index';
import type { ConsentRecord, ProfileId, UserSensitivityRule } from 'foundry-profiles';
import type { ImportResult } from 'importers';
import type { UnlockSession } from 'vault';
// Types only (erased): the P-3 modules themselves load through `await import('vault/second-copy')` in their handlers.
import type { CommandRunner, CopyCheckpoint, FileSystemProbe } from 'vault/second-copy';
import { SECOND_COPY_COMMANDS } from './args.ts';
import type { CommandName, SearchFilters } from './args.ts';
import { CliError, debugText, errorLine, isRecoveryFormatError, mapError } from './errors.ts';
import { fixedFileError, homeSystemError, isSystemError, withFixedFileErrors, withHomeSystemErrors } from './files.ts';

export const PROFILE: ProfileId = 'me';
/** `ensureCollectionKeys` accepts at most this many distinct names per call. */
export const MAX_NAMES_PER_CALL = 4096;

export interface CommandSecrets {
  passphrase?: Uint8Array;
  recoveryKey?: Uint8Array;
  newPassphrase?: Uint8Array;
}

export interface CommandRequest {
  command: CommandName;
  home: string;
  debug: boolean;
  json: boolean;
  path?: string;
  query?: string;
  targetProfile?: string;
  targetCollection?: string;
  importProfile?: string;
  importCollection?: string;
  displayName?: string;
  basis?: string;
  note?: string;
  childPrompts?: boolean;
  /** `profile list` / `consent list` only: print display names and consent notes (P-1 fix round 1, B7). */
  reveal?: boolean;
  filters: SearchFilters;
  /** P-3 second-copy commands (see `args.ts`). */
  target?: string;
  output?: string;
  label?: string;
  copyLabel?: string;
  anchorSvg?: string;
  qrInvert?: boolean;
  includeKeyring?: boolean;
  cadence?: string;
  verifyChain?: boolean;
  /** `vault copy init --adopt`: take over a copy of this vault that holds another copy id (R18-3). */
  adopt?: boolean;
  /** `vault verify-copy --anchor`: the compact anchor text (validated by `parseAnchor`). */
  anchor?: string;
  /** Keyed commands: which secret unlocks the vault. */
  credential?: 'passphrase' | 'recovery';
  secrets: CommandSecrets;
}

export interface CommandIo {
  out(text: string): void;
  err(text: string): void;
}

/** Test hooks reachable only through the programmatic API (never argv or environment). */
export interface TestHooks {
  /** Enter a deliberately stuck synchronous section right before the command's main library call. */
  stallSync?: boolean;
  /** Leave a timer running in the body's thread (proves the command does not wait for it). */
  leakHandle?: boolean;
  /** Throw a plain Error whose message quotes every secret (proves crash text never carries a secret). */
  throwWithSecret?: boolean;
  /** `init`: fail after the vault is built in its temporary folder, before the rename to `H/vault`. */
  failBeforeInitRename?: boolean;
  /**
   * `init`: the staging-marker write fails (after the preflight and the lock) with a Node-style `ENAMETOOLONG` error
   * whose message and `path` quote the marker path.
   */
  failInitMarkerWrite?: boolean;
  /** `import`: the final index update throws an errno-style error whose message quotes every secret. */
  failFinalIndexUpdate?: boolean;
  /** `import`: Run B throws an errno-style error at its start (after any archive check, before it stores). */
  failRunB?: boolean;
  /** `import`: the index update between Run A and Run B throws an errno-style error whose message quotes every secret. */
  failBetweenRunsUpdate?: boolean;
  /**
   * `import`: throws an errno-style error after the `collection.created` binding events are appended and before
   * any collection key is created (P-1 fix round 1, B3).
   */
  failAfterCollectionBinding?: boolean;
  /**
   * `import`: called with the archive path after Run A has closed the archive, before Run B (it may change a part).
   * A function: it cannot cross into the worker thread, so only the inline path (`runCli` with `inline`) can use it.
   */
  betweenRuns?: (archivePath: string) => void;
  /** P-3, inline only: replaces the drive's file-system probe (so FAT refusal is testable on any OS). */
  secondCopyProbe?: FileSystemProbe;
  /** P-3, inline only: a crash point inside the copy (`vault seal`), like a pulled drive. */
  copyCheckpoint?: (point: CopyCheckpoint, segment: number) => void;
  /** P-3, inline only: records scheduler argv instead of running `schtasks`, `systemctl` or `crontab`. */
  schedulerRunner?: CommandRunner;
  /** P-3: the scheduler platform and Linux config folder to use (default: this OS and `$XDG_CONFIG_HOME`). */
  schedulerPlatform?: string;
  schedulerConfigHome?: string;
  /** P-3: the environment and bus-socket check the Linux reminder notification uses (default: this process). */
  reminderEnv?: Readonly<Record<string, string | undefined>>;
  /** P-3: make the `--anchor-svg` write fail after the seal is committed. */
  failAnchorSvgWrite?: boolean;
  reminderBusExists?: (path: string) => boolean;
  /** P-3: the current time as an ISO string (status, reminder). */
  now?: string;
}

/** An errno-style error (maps to `IO`) whose message quotes the given secrets: test hooks only. */
function hookError(what: string, secrets: readonly string[]): Error {
  return Object.assign(new Error(`test hook: ${what}: ${secrets.join(' | ')}`), { code: 'EIO' });
}

export function homePaths(home: string) {
  const vault = join(home, 'vault');
  return { vault, index: join(home, 'index'), keyring: join(vault, 'keyring', 'keyring.json') };
}

function asBuffer(bytes: Uint8Array | undefined): Buffer | undefined {
  return bytes === undefined ? undefined : Buffer.from(bytes.buffer as ArrayBuffer, bytes.byteOffset, bytes.length);
}

function text(bytes: Uint8Array | undefined, what: string): string {
  const buffer = asBuffer(bytes);
  if (buffer === undefined) throw new CliError('INTERNAL', `the ${what} was not read`);
  return buffer.toString('utf8');
}

function stall(hooks: TestHooks): void {
  if (hooks.stallSync) for (;;) { /* deliberately stuck synchronous section (test hook) */ }
}

export type ImportStage = 'before' | 'runA' | 'between' | 'runB' | 'final' | 'done';

class Context {
  readonly paths: ReturnType<typeof homePaths>;
  /** Events this command durably appended (counted when the vault writer's `appendBatch` returns). */
  storedEvents = 0;
  /**
   * Stage of `import`, tracked apart from `storedEvents`: `before` (catch-up, archive resolution), `runA` (from the
   * start of Run A), `between` (collection keys and the index update between the runs), `runB`, `final` (the final
   * index update) and `done` (the final index update finished).
   */
  importStage: ImportStage = 'before';
  /** `vault reset-passphrase` failed in a way that may follow the atomic keyring replacement. */
  resetMayBeDone = false;
  /** `init` failed before the rename and left its staging folder (this name, inside H). */
  initLeftover: string | undefined;

  constructor(readonly request: CommandRequest, readonly io: CommandIo, readonly hooks: TestHooks) {
    this.paths = homePaths(request.home);
  }

  out(value: string | object): void {
    this.io.out(typeof value === 'string' ? value : JSON.stringify(value) + '\n');
  }
}

async function vaultId(ctx: Context): Promise<string> {
  const { decodeVaultMetadata } = await import('vault');
  return decodeVaultMetadata(withFixedFileErrors(() => readFileSync(join(ctx.paths.vault, 'VAULT.json')))).vault_id;
}

async function openSession(ctx: Context, id: string): Promise<UnlockSession> {
  const { decodeRecoveryKey, unlockVault } = await import('vault');
  if (ctx.request.credential === 'recovery') {
    const raw = decodeRecoveryKey(text(ctx.request.secrets.recoveryKey, 'recovery key'));
    try {
      return unlockVault(ctx.paths.keyring, id, { recoveryKey: raw });
    } finally {
      raw.fill(0);
    }
  }
  return unlockVault(ctx.paths.keyring, id, { passphrase: text(ctx.request.secrets.passphrase, 'passphrase') });
}

async function indexOptions(ctx: Context, session: UnlockSession): Promise<IndexStoreOptions> {
  const { loadProjection } = await import('./derive.ts');
  const base = await loadProjection();
  return {
    directory: ctx.paths.index, vaultDirectory: ctx.paths.vault, credential: { session },
    projection: { ...base, checkpoint: () => maybeCollectGarbage() },
  };
}

/** Run `work` with one session that is disposed in `finally`. */
async function keyed<T>(ctx: Context, work: (session: UnlockSession, id: string) => Promise<T>): Promise<T> {
  const id = await vaultId(ctx);
  const session = await openSession(ctx, id);
  try {
    return await work(session, id);
  } finally {
    session.dispose();
  }
}

function requireNewPassphrase(ctx: Context): string {
  const value = text(ctx.request.secrets.newPassphrase, 'new passphrase');
  if (value.length === 0) throw new CliError('EMPTY_PASSPHRASE', 'the new passphrase must not be empty');
  return value;
}

/** Names in H that start with this make `init` refuse (its staging folders, a leftover, or a look-alike). */
export const INIT_PREFIX = '.init-';
/** The marker `init` writes first into every staging folder it creates (it names the folder as init's own). */
export const INIT_MARKER = '.foundry-init-owner';

/** The exact marker content for the staging folder `name`: a fixed line and the folder's own random name. */
export function initMarkerContent(name: string): string {
  return `foundry init staging folder\n${name}\n`;
}

/** TEST ONLY: the Node-style error of a failed staging-marker write; its message and `path` quote the marker path. */
function markerWriteHookError(path: string): Error {
  return Object.assign(new Error(`ENAMETOOLONG: name too long, open '${path}'`), {
    code: 'ENAMETOOLONG', errno: -36, syscall: 'open', path,
  });
}

/**
 * After a failure before the rename: remove ONLY what this run created, and only while that is provably all there
 * is. The folder must hold nothing but this run's marker (or nothing, if the marker was never created); then the
 * marker is unlinked and the folder removed with a NON-recursive `rmdir` (which itself fails on anything else).
 * True if the folder is gone. Any doubt or error: false, and everything stays.
 */
function removeOwnStaging(staging: string, markerCreated: boolean, fs: typeof import('node:fs')): boolean {
  try {
    const names = fs.readdirSync(staging);
    const expected = markerCreated ? [INIT_MARKER] : [];
    if (names.length !== expected.length || names.some((name, i) => name !== expected[i])) return false;
    if (markerCreated) {
      const marker = join(staging, INIT_MARKER);
      if (!fs.lstatSync(marker).isFile()) return false;
      fs.unlinkSync(marker);
    }
    fs.rmdirSync(staging);
    return true;
  } catch {
    return false;
  }
}

/**
 * `init` never deletes a folder it did not just create, and never deletes recursively. Under the lock (any `.init-*`
 * folder in H was refused by the preflight in `cli.ts`):
 * 1. create `H/.init-<random>` and write the marker into it FIRST;
 * 2. build the vault in `H/.init-<random>/vault`;
 * 3. rename that to `H/vault` as the last step;
 * 4. unlink the marker and `rmdir` the then-empty staging folder (best effort: a notice if it stays), then print the
 *    recovery key.
 * On a failure before the rename, only this run's marker and empty folder are removed (`removeOwnStaging`); if the
 * folder holds anything else (for example the partly built vault), it stays and the error line names it.
 * Every file-system call here gives fixed text on failure (`files.ts`): no path, no Node message, also for `--debug`.
 */
async function init(ctx: Context): Promise<void> {
  const passphrase = requireNewPassphrase(ctx);
  const { createVault } = await import('vault');
  const { randomBytes } = await import('node:crypto');
  const fs = await import('node:fs');
  const name = `${INIT_PREFIX}${randomBytes(8).toString('hex')}`;
  const staging = join(ctx.request.home, name);
  const marker = join(staging, INIT_MARKER);
  const temporary = join(staging, 'vault');
  let folderCreated = false;
  let markerCreated = false;
  let identity: ReturnType<typeof createVault>;
  try {
    withFixedFileErrors(() => {
      fs.mkdirSync(staging, { mode: 0o700 });
      folderCreated = true;
      const fd = fs.openSync(marker, 'wx', 0o600);
      markerCreated = true;
      try {
        if (ctx.hooks.failInitMarkerWrite) throw markerWriteHookError(marker);
        fs.writeSync(fd, initMarkerContent(name));
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    });
    stall(ctx.hooks);
    identity = withHomeSystemErrors(() => createVault(temporary, { passphrase }));
    if (ctx.hooks.failBeforeInitRename) throw new Error('test hook: init stopped before the rename');
    withFixedFileErrors(() => fs.renameSync(temporary, ctx.paths.vault));
  } catch (error) {
    if (folderCreated && !removeOwnStaging(staging, markerCreated, fs)) ctx.initLeftover = name;
    throw error;
  }
  if (!removeOwnStaging(staging, true, fs)) {
    // The vault exists now, so the recovery key must still be shown; say which empty folder stays.
    ctx.io.err(`foundry: notice: the staging folder "${name}" stays in the Foundry folder; delete it\n`);
  }
  // Fixed text: never echo the home path (a secret may have been pasted into --vault or FOUNDRY_HOME).
  ctx.out('Created a new Foundry vault.\n\n'
    + 'RECOVERY KEY. Write this down now and keep it somewhere safe. It is shown only this once:\n\n'
    + `    ${identity.recoveryKey}\n\n`
    + 'You need the recovery key to set a new passphrase if you forget the current one.\n');
}

async function verify(ctx: Context): Promise<void> {
  const { verifyVault } = await import('vault');
  stall(ctx.hooks);
  const result = verifyVault(ctx.paths.vault);
  const summary = {
    ok: true, sealedSegments: result.position.segment, lastSealedEvent: result.position.lastEventSequence,
    openFiles: result.open.files, openBytes: result.open.bytes, lastEvent: result.open.lastEventSequence,
  };
  if (ctx.request.json) ctx.out(summary);
  else {
    ctx.out(`Vault OK: ${summary.sealedSegments} sealed segment(s), ${summary.openFiles} open file(s), `
      + `last event ${summary.lastEvent}.\n`);
  }
}

async function rebuild(ctx: Context): Promise<void> {
  await keyed(ctx, async session => {
    const options = await indexOptions(ctx, session);
    const { rebuildIndex } = await import('foundry-index');
    stall(ctx.hooks);
    const result = rebuildIndex(options);
    if (ctx.request.json) ctx.out({ ok: true, lastEvent: result.lastEventSeq, skippedRecords: result.skipped });
    else ctx.out(`Index rebuilt: last event ${result.lastEventSeq}, ${result.skipped} record(s) skipped.\n`);
  });
}

async function search(ctx: Context): Promise<void> {
  const query = ctx.request.query ?? '';
  await keyed(ctx, async session => {
    const options = await indexOptions(ctx, session);
    const { searchIndex, updateIndex } = await import('foundry-index');
    stall(ctx.hooks);
    let hits;
    try {
      hits = searchIndex(options, query, ctx.request.filters);
    } catch (error) {
      // A stale index is a PROJECTION error: bring it up to date in the same session, then search once more.
      if (!(error instanceof Error && (error as { code?: string }).code === 'PROJECTION')) throw error;
      updateIndex(options);
      hits = searchIndex(options, query, ctx.request.filters);
    }
    const results = hits.map(hit => ({
      date: hit.imported_at, source: hit.source, snippet: hit.snippet.replace(/\s+/gu, ' ').trim(),
      itemId: hit.item_id, eventSeq: hit.event_seq, score: hit.score,
    }));
    if (ctx.request.json) ctx.out({ results });
    else if (results.length === 0) ctx.out('No results.\n');
    else ctx.out(results.map(r => `${r.date}  ${r.source}  ${r.snippet}\n`).join(''));
  });
}

async function resetPassphraseCommand(ctx: Context): Promise<void> {
  const passphrase = requireNewPassphrase(ctx);
  const recovery = text(ctx.request.secrets.recoveryKey, 'recovery key');
  const id = await vaultId(ctx);
  const { resetPassphrase } = await import('vault');
  stall(ctx.hooks);
  try {
    resetPassphrase(ctx.paths.keyring, id, recovery, { passphrase });
  } catch (error) {
    const code = (error as { code?: string }).code;
    const typed = error instanceof Error && error.name === 'VaultFormatError'
      && (code === 'AUTH' || code === 'KEY' || code === 'MAC' || code === 'KDF');
    if (!typed && !isRecoveryFormatError(error)) ctx.resetMayBeDone = true;
    throw error;
  }
  ctx.out('The passphrase is changed. The master key and the recovery key were NOT rotated: '
    + 'your recovery key stays valid.\n');
}

/** Split collection names into slices of at most `size` (design 4a.3: at most 4,096 names per call). */
export function nameSlices(names: readonly string[], size = MAX_NAMES_PER_CALL): string[][] {
  const slices: string[][] = [];
  for (let start = 0; start < names.length; start += size) slices.push(names.slice(start, start + size));
  return slices;
}

export interface ImportSummary {
  itemsAdded: number;
  itemsAlreadyPresent: number;
  itemsSkipped: number;
  skippedByReason: Record<string, number>;
  partsCount: number;
  parts: string[];
  unrecognisedEntries: number;
  collectionsCreated: number;
  runs: 1 | 2;
}

/** Design 4a.3 step 5: every archive item counted once. Skips, parts and entries come from the LAST run. */
export function summarise(runA: ImportResult, runB: ImportResult | undefined, collectionsCreated: number): ImportSummary {
  const last = runB ?? runA;
  const skippedByReason: Record<string, number> = {};
  for (const error of last.itemErrors) skippedByReason[error.code] = (skippedByReason[error.code] ?? 0) + 1;
  return {
    itemsAdded: runA.totalItemsImported + (runB?.totalItemsImported ?? 0),
    itemsAlreadyPresent: runA.totalItemsSkipped - runA.totalItemsErrored,
    itemsSkipped: last.totalItemsErrored,
    skippedByReason,
    partsCount: last.partsCount,
    parts: last.parts,
    unrecognisedEntries: last.unrecognisedEntries.length,
    collectionsCreated,
    runs: runB ? 2 : 1,
  };
}

/**
 * The archive parts an import reads, resolved from the path the user gave:
 * - `file`: one zip (also the first part of a "set" whose other parts are absent);
 * - `set`: the first part of a multi-part export; ONLY the parts of that export (same name prefix, part numbering) are
 *   read, not every zip in its folder;
 * - `folder`: a folder; the importers' `openArchive` reads every `.zip` file in it (the same filter is used here).
 */
export interface ArchiveParts {
  kind: 'file' | 'set' | 'folder';
  path: string;
  /** Absolute paths of the parts, in order. */
  files: string[];
}

export async function resolveArchiveParts(path: string): Promise<ArchiveParts> {
  const { comparePartNames, parsePartName } = await import('importers');
  const { readdirSync, statSync } = await import('node:fs');
  const { basename, dirname } = await import('node:path');
  const info = statSync(path);
  if (info.isDirectory()) {
    const names = readdirSync(path, { withFileTypes: true })
      .filter(entry => entry.isFile() && entry.name.toLowerCase().endsWith('.zip'))
      .map(entry => entry.name)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return { kind: 'folder', path, files: names.map(name => join(path, name)) };
  }
  const part = info.isFile() ? parsePartName(basename(path)) : undefined;
  if (part && part.ordinal === 1) {
    const folder = dirname(path);
    const names = readdirSync(folder, { withFileTypes: true })
      .filter(entry => entry.isFile() && parsePartName(entry.name)?.prefix === part.prefix)
      .map(entry => entry.name)
      .sort(comparePartNames);
    if (names.length > 1) return { kind: 'set', path, files: names.map(name => join(folder, name)) };
  }
  return { kind: 'file', path, files: [path] };
}

/** Size and modification time (nanoseconds) of every part, taken before Run A and checked before Run B (4a.3). */
export interface PartStamp {
  file: string;
  size: bigint;
  mtimeNs: bigint;
}

export async function stampParts(parts: ArchiveParts): Promise<PartStamp[]> {
  const { statSync } = await import('node:fs');
  return parts.files.map(file => {
    const info = statSync(file, { bigint: true });
    return { file, size: info.size, mtimeNs: info.mtimeNs };
  });
}

export function sameStamps(before: readonly PartStamp[], after: readonly PartStamp[]): boolean {
  return before.length === after.length && before.every((stamp, i) => {
    const other = after[i]!;
    return other.file === stamp.file && other.size === stamp.size && other.mtimeNs === stamp.mtimeNs;
  });
}

/** Design 4a.3: before Run B, the parts must be exactly the ones Run A read (no change, no part added or removed). */
async function checkArchiveUnchanged(path: string, before: readonly PartStamp[]): Promise<void> {
  let after: PartStamp[] | undefined;
  try {
    after = await stampParts(await resolveArchiveParts(path));
  } catch {
    after = undefined; // a part (or the path) is gone or unreadable
  }
  if (!after || !sameStamps(before, after)) {
    throw new CliError('ARCHIVE_CHANGED', 'the archive changed during the import (a part was changed, added or removed)');
  }
}

/**
 * Open the resolved parts as one archive. A `set` is combined here from its parts only (the importers' `openArchive`
 * opens every zip of a folder), with the same rules as `openArchive` for a folder: one prefix, part numbers 1..N
 * without a gap or a duplicate, entries sorted by path, no entry path in two parts. (The importers compare raw entry
 * name bytes for that last rule; their helper is not exported, so this compares the decoded path, which is stricter.)
 */
async function openParts(parts: ArchiveParts) {
  const { ArchiveError, openArchive, openZipFile, parsePartName } = await import('importers');
  if (parts.kind !== 'set') return openArchive(parts.path);
  const { basename } = await import('node:path');
  const names = parts.files.map(file => basename(file));
  names.forEach((name, i) => {
    if (parsePartName(name)?.ordinal !== i + 1) {
      throw new ArchiveError('INVALID_MULTIPART', `Archive parts are not numbered 1 to ${names.length} (${name}).`);
    }
  });
  const opened: Awaited<ReturnType<typeof openZipFile>>[] = [];
  const entries: (typeof opened)[number]['entries'][number][] = [];
  const seen = new Set<string>();
  try {
    for (const file of parts.files) {
      const part = await openZipFile(file, { partName: basename(file) });
      opened.push(part);
      for (const entry of part.entries) {
        if (seen.has(entry.path)) throw new ArchiveError('DUPLICATE_ENTRY', `Duplicate entry path across parts: ${entry.path}.`);
        seen.add(entry.path);
        entries.push(entry);
      }
    }
  } catch (error) {
    await Promise.allSettled(opened.map(part => part.close()));
    throw error;
  }
  entries.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return {
    entries, parts: names,
    async close() {
      const results = await Promise.allSettled(opened.map(part => part.close()));
      const rejected = results.find((r): r is PromiseRejectedResult => r.status === 'rejected');
      if (rejected) throw rejected.reason;
    },
  };
}

/** The keyring file's bytes (a home-folder read: fixed text on failure). */
function readKeyring(ctx: Context): Buffer {
  return withFixedFileErrors(() => readFileSync(ctx.paths.keyring));
}

/** Let the vault writer recover an interrupted append or seal (for example a pending HEAD), then release it. */
async function recoverVaultWriter(ctx: Context, session: UnlockSession, id: string): Promise<void> {
  const vault = await import('vault');
  const unlocked = vault.decodeKeyring(readKeyring(ctx), { session }, id);
  try {
    vault.VaultWriter.open(ctx.paths.vault, unlocked).release();
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

let gcFn: (() => void) | null | undefined;

/** Best-effort V8 GC between heavy import batches and before index update (v7-design section 5; no-ops if refused). */
function maybeCollectGarbage(): void {
  if (gcFn === undefined) {
    try {
      setFlagsFromString('--expose-gc');
      const fn = runInNewContext('gc') as unknown;
      gcFn = typeof fn === 'function' ? (fn as () => void) : null;
    } catch {
      gcFn = null;
    }
  }
  gcFn?.();
}

const IMPORT_BATCH_MAX_BYTES = 1024 * 1024;
const IMPORT_BATCH_MAX_ITEMS = 8;
const IMPORT_GC_EVERY_BATCHES = 32;

async function importRun(
  ctx: Context,
  session: UnlockSession,
  id: string,
  options: IndexStoreOptions,
  parts: ArchiveParts,
  profile: ProfileId,
  explicitCollection: string | undefined,
  sensitivityRules: readonly UserSensitivityRule[],
) {
  const vault = await import('vault');
  const importers = await import('importers');
  const profiles = await import('foundry-profiles');
  const { openItemKeyLookup } = await import('foundry-index');
  const { classifyImportItem } = await import('./classify.ts');
  const { itemTextOfPlaintext, loadParsers } = await import('./derive.ts');
  const parsers = await loadParsers();
  const deriveText = (mime: string | null, plaintext: Uint8Array) => itemTextOfPlaintext(parsers, mime, plaintext);
  const unlocked = vault.decodeKeyring(readKeyring(ctx), { session }, id);
  let writer: ReturnType<typeof vault.VaultWriter.open> | undefined;
  let lookup: ReturnType<typeof openItemKeyLookup> | undefined;
  let archive: Awaited<ReturnType<typeof openParts>> | undefined;
  let batches = 0;
  try {
    archive = await openParts(parts);
    const opened = writer = vault.VaultWriter.open(ctx.paths.vault, unlocked);
    // Counts the events this command durably stored: a batch counts once `appendBatch` has returned.
    const counting = {
      appendBatch(items: Parameters<typeof opened.appendBatch>[0]) {
        const results = opened.appendBatch(items);
        ctx.storedEvents += results.filter(result => result.type === 'event').length;
        if (++batches % IMPORT_GC_EVERY_BATCHES === 0) maybeCollectGarbage();
        return results;
      },
      closeSegment: () => opened.closeSegment(),
    };
    lookup = openItemKeyLookup(options);
    stall(ctx.hooks);
    return await importers.importArchive({
      archive,
      writer: counting,
      importers: importers.DEFAULT_IMPORTERS,
      profile,
      // P-1 fix round 1 (B1): every name, explicit or default, must be `<profile>/...`.
      resolveCollection: ({ profile: itemProfile, source, sourceTs }) =>
        profiles.assertCollectionForProfile(
          itemProfile,
          explicitCollection ?? profiles.defaultCollectionForItem(itemProfile as ProfileId, source, sourceTs),
        ),
      resolveCollectionKeyId: name => vault.collectionKeyId(unlocked, profile, name),
      // P-1 fix round 1 (items 6 and B0): the raw bytes AND the search text the index stores are classified.
      resolveSensitivity: (source, itemPath, item) => {
        const input = {
          profile,
          collection:
            item?.collection ??
            explicitCollection ??
            profiles.defaultCollectionForItem(profile, source, item?.sourceTs),
          source,
          path: itemPath,
          userRules: sensitivityRules,
        };
        if (item === undefined) return profiles.classifySensitivity(input).sensitivity;
        return classifyImportItem(profiles.classifySensitivity, deriveText, input, item).sensitivity;
      },
      vaultDir: ctx.paths.vault,
      unlocked,
      itemKeys: lookup,
      batchMaxBytes: IMPORT_BATCH_MAX_BYTES,
      batchMaxItems: IMPORT_BATCH_MAX_ITEMS,
      // Not called while `itemKeys` is given; bound to this run's unlocked keyring for type safety.
      readVaultRecord: (directory, location) => vault.readVaultRecord(directory, location, unlocked),
    });
  } finally {
    // The lookup holds the index writer lock: close it before any index update.
    try {
      lookup?.close();
    } finally {
      try {
        writer?.release();
      } finally {
        try {
          await archive?.close();
        } finally {
          unlocked.masterKey.fill(0);
          for (const key of unlocked.keys.values()) key.fill(0);
        }
      }
    }
  }
}

async function importCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  const profile: ProfileId =
    ctx.request.importProfile === undefined
      ? PROFILE
      : profiles.assertProfileId(ctx.request.importProfile);
  // P-1 fix round 1 (B1): a custom collection must be `<profile>/...` (checked before any key derivation).
  const explicitCollection =
    ctx.request.importCollection === undefined
      ? undefined
      : profiles.assertCollectionForProfile(profile, ctx.request.importCollection);

  await keyed(ctx, async (session, id) => {
    // An earlier command may have stopped inside a segment seal (a pending HEAD). The read-only replay of the index
    // update or profile state refuses that state; only the vault writer recovers it. So: writer first. (It completes
    // or rolls back an EARLIER command's seal and stores no imported item.)
    await recoverVaultWriter(ctx, session, id);
    // One replay for both checks, before any write of this import.
    const profileState = profiles.loadVaultProfileState(ctx.paths.vault, { session });
    profiles.assertProfileVault(profileState); // B5: PRE_PROFILE_VAULT
    profiles.assertImportConsent(profileState, profile);

    const options = await indexOptions(ctx, session);
    const { updateIndex } = await import('foundry-index');
    const { ensureCollectionKeys } = await import('vault');
    updateIndex(options); // catch-up after an earlier crash: the item-key lookup needs a current index
    const path = ctx.request.path!;
    const parts = await resolveArchiveParts(path);
    const stamps = await stampParts(parts);
    ctx.importStage = 'runA';
    const runA = await importRun(
      ctx,
      session,
      id,
      options,
      parts,
      profile,
      explicitCollection,
      profileState.sensitivityRules,
    );
    let runB: ImportResult | undefined;
    let collectionsCreated = 0;
    if (runA.missingCollections.length > 0) {
      ctx.importStage = 'between';
      // B3 (A-41 limits 1 and 5): record each new name's owner profile durably BEFORE its key exists. Event first,
      // key second: a crash between them leaves an event without a key (harmless; the next import creates the key
      // with the same derived ID).
      const bindings = profiles.recordCollectionBindings(ctx.paths.vault, { session }, profile, runA.missingCollections);
      // The first binding of a vault creates `me`'s `system` key: it is a new collection key too.
      if (bindings.createdSystemKey) collectionsCreated++;
      if (ctx.hooks.failAfterCollectionBinding) {
        throw hookError('after the collection binding', secretTexts(ctx.request.secrets));
      }
      for (const slice of nameSlices(runA.missingCollections)) {
        collectionsCreated += ensureCollectionKeys(ctx.paths.keyring, id, { session }, profile, slice).created;
      }
      if (ctx.hooks.failBetweenRunsUpdate) throw hookError('index update between runs', secretTexts(ctx.request.secrets));
      updateIndex(options);
      ctx.hooks.betweenRuns?.(path);
      await checkArchiveUnchanged(path, stamps); // before Run B opens or stores anything
      ctx.importStage = 'runB';
      if (ctx.hooks.failRunB) throw hookError('run B', secretTexts(ctx.request.secrets));
      runB = await importRun(
        ctx,
        session,
        id,
        options,
        parts,
        profile,
        explicitCollection,
        profileState.sensitivityRules,
      );
      if (runB.missingCollections.length > 0) {
        throw new CliError('INTERNAL', 'internal error: the second import run still found collections without a key');
      }
    }
    const summary = summarise(runA, runB, collectionsCreated);
    // A failure here keeps its own code; `executeCommand` adds the "index is behind" guidance to the same line and
    // prints `--debug` text through the same redacting handler as every other error.
    ctx.importStage = 'final';
    if (ctx.hooks.failFinalIndexUpdate) throw hookError('final index update', secretTexts(ctx.request.secrets));
    maybeCollectGarbage();
    updateIndex(options);
    ctx.importStage = 'done';
    if (ctx.request.json) {
      ctx.out(summary);
      return;
    }
    const reasons = Object.entries(summary.skippedByReason).map(([code, count]) => `${code} ${count}`).join(', ');
    ctx.out(`Imported ${summary.itemsAdded} new item(s); ${summary.itemsAlreadyPresent} item(s) were already stored.\n`
      + `Skipped: ${summary.itemsSkipped}${reasons ? ` (${reasons})` : ''}.\n`
      + `Parts seen: ${summary.partsCount}. Unrecognised entries: ${summary.unrecognisedEntries}.\n`
      + (summary.collectionsCreated > 0 ? `New collection keys: ${summary.collectionsCreated}.\n` : ''));
  });
}

async function profileAddCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  const profile = profiles.assertProfileId(ctx.request.targetProfile);
  const displayName =
    ctx.request.displayName === undefined
      ? undefined
      : profiles.assertDisplayName(ctx.request.displayName);

  await keyed(ctx, async (session, id) => {
    await recoverVaultWriter(ctx, session, id);
    stall(ctx.hooks);
    const result = profiles.addProfile(ctx.paths.vault, { session }, { profile, displayName });
    // B7: a mutation command never prints decrypted user text (and takes no --reveal).
    if (ctx.request.json) {
      ctx.out({
        ok: true,
        profile: result.profile,
        displayNameSet: result.displayName !== undefined,
        ts: result.ts,
        eventSeq: result.eventSeq,
      });
    } else {
      ctx.out(`Profile "${result.profile}" saved (event ${result.eventSeq}).\n`);
    }
  });
}

/** The matcher fields of a sensitivity rule; their values are user-written text. */
const RULE_MATCHER_FIELDS = ['sourcePrefix', 'pathContains', 'tag', 'keyword'] as const;

/**
 * C1: a sensitivity rule without its user-written text: its position (`rule 1`, `rule 2`, in replay order), `tier`,
 * scope (`profile`, when set) and the names of the matcher fields that are set. Round 2 (G2): the rule `id` is free
 * text too, so it is printed only with --reveal.
 */
function redactRule(rule: UserSensitivityRule, index: number): {
  rule: string;
  tier: UserSensitivityRule['tier'];
  profile?: ProfileId;
  matchers: string[];
} {
  return {
    rule: `rule ${index + 1}`,
    tier: rule.tier,
    ...(rule.profile !== undefined ? { profile: rule.profile } : {}),
    matchers: RULE_MATCHER_FIELDS.filter(field => rule[field] !== undefined),
  };
}

async function profileListCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  await keyed(ctx, async (session, id) => {
    await recoverVaultWriter(ctx, session, id);
    stall(ctx.hooks);
    const { profiles: items, destroyedProfileCount } = profiles.listProfiles(ctx.paths.vault, { session });
    // B7: the display name is decrypted user text; it is printed only with --reveal.
    // C1: so is the matcher text of a sensitivity rule (keyword, pathContains, tag, sourcePrefix); round 2 (G2): and
    // its `id`.
    const reveal = ctx.request.reveal === true;
    if (ctx.request.json) {
      const shown = items.map(({ displayName, sensitivityRules, ...rest }) => ({
        ...rest,
        displayNameSet: displayName !== undefined,
        ...(reveal && displayName !== undefined ? { displayName } : {}),
        sensitivityRules: reveal ? sensitivityRules : sensitivityRules.map(redactRule),
      }));
      ctx.out({ profiles: shown, erasedProfileKeys: destroyedProfileCount });
      return;
    }
    if (items.length === 0) {
      ctx.out('No profiles recorded.\n');
      return;
    }
    const lines = items.map(p => {
      const label = p.displayName === undefined ? '' : reveal ? ` (${p.displayName})` : ' (name set)';
      const consent =
        p.profile === 'me'
          ? 'owner'
          : p.consentRecorded
            ? `consent:${p.consentBasis ?? 'recorded'}`
            : 'consent:missing';
      return `${p.profile}${label}  [${consent}]\n`;
    });
    ctx.out(lines.join(''));
  });
}

async function consentRecordCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  const profile = profiles.assertConsentSubjectProfile(ctx.request.targetProfile);
  const basis = profiles.assertConsentBasis(ctx.request.basis);
  // Item 13: basis `other` needs a nonempty --note (checked before any key derivation).
  const note = profiles.assertConsentNoteForBasis(basis, ctx.request.note);

  await keyed(ctx, async (session, id) => {
    await recoverVaultWriter(ctx, session, id);
    stall(ctx.hooks);
    const result = profiles.recordConsent(ctx.paths.vault, { session }, { profile, basis, note });
    // B7: a mutation command never prints the note.
    if (ctx.request.json) {
      ctx.out({
        ok: true,
        profile: result.profile,
        basis: result.basis,
        noteSet: result.note !== undefined,
        ts: result.ts,
        eventSeq: result.eventSeq,
      });
    } else {
      ctx.out(`Recorded consent for profile "${result.profile}" (${result.basis}, event ${result.eventSeq}).\n`);
    }
  });
}

async function consentListCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  await keyed(ctx, async (session, id) => {
    await recoverVaultWriter(ctx, session, id);
    stall(ctx.hooks);
    const result = profiles.listConsents(ctx.paths.vault, { session });
    // B7: the note is decrypted user text; it is printed only with --reveal.
    const reveal = ctx.request.reveal === true;
    const shown = (records: readonly ConsentRecord[]) =>
      records.map(({ note, ...rest }) => ({
        ...rest,
        noteSet: note !== undefined,
        ...(reveal && note !== undefined ? { note } : {}),
      }));
    if (ctx.request.json) {
      ctx.out({ consents: shown(result.consents), history: shown(result.history) });
      return;
    }
    if (result.consents.length === 0) {
      ctx.out('No consent records.\n');
      return;
    }
    const noteText = (note: string | undefined) => (note === undefined ? '' : reveal ? `  ${note}` : '  (note set)');
    const lines = result.consents.map(c =>
      `${c.ts}  ${c.profile}  ${c.basis}${noteText(c.note)}  (event ${c.eventSeq})\n`,
    );
    ctx.out(lines.join(''));
  });
}

async function collectionPromptPolicyCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  // B1: only a name with a valid profile prefix; that prefix is the policy's owner profile.
  const { collection } = profiles.assertProfileCollectionName(ctx.request.targetCollection);
  const allowChildModelPrompts = Boolean(ctx.request.childPrompts);

  await keyed(ctx, async (session, id) => {
    await recoverVaultWriter(ctx, session, id);
    stall(ctx.hooks);
    const result = profiles.setCollectionPromptPolicy(ctx.paths.vault, { session }, {
      collection,
      allowChildModelPrompts,
    });
    // Fix round 3 (blocker 6): a custom collection name is user text; the output never echoes it. A default name
    // (`<profile>/<shipped source>/<year|undated>`) is generic and is echoed.
    const isDefault = profiles.isDefaultCollectionName(result.collection);
    const onOff = result.allowChildModelPrompts ? 'on' : 'off';
    if (ctx.request.json) {
      ctx.out({
        ok: true,
        ...(isDefault ? { collection: result.collection } : { customCollection: true }),
        allowChildModelPrompts: result.allowChildModelPrompts,
        kind: result.kind,
        ts: result.ts,
        eventSeq: result.eventSeq,
      });
    } else if (isDefault) {
      ctx.out(`Collection "${result.collection}" child model prompts: ${onOff} (event ${result.eventSeq}).\n`);
    } else {
      ctx.out(`Collection (custom) child model prompts: ${onOff} (event ${result.eventSeq}).\n`);
    }
  });
}

async function collectionListCommand(ctx: Context): Promise<void> {
  const profiles = await import('foundry-profiles');
  await keyed(ctx, async (session, id) => {
    await recoverVaultWriter(ctx, session, id);
    stall(ctx.hooks);
    const { collections } = profiles.listCollections(ctx.paths.vault, { session });
    // Fix round 3 (blocker 6, rule R14): a custom collection name is user text, printed only with --reveal.
    // Without it, a custom name is `custom collection N` (N = its 1-based position in the listed order); a
    // default name (`<profile>/<shipped source>/<year|undated>`) is generic and prints as before.
    const reveal = ctx.request.reveal === true;
    const hidden = (name: string) => !reveal && !profiles.isDefaultCollectionName(name);
    if (ctx.request.json) {
      ctx.out({
        collections: collections.map(({ collection, ...rest }, index) =>
          hidden(collection) ? { customCollection: index + 1, ...rest } : { collection, ...rest },
        ),
      });
      return;
    }
    if (collections.length === 0) {
      ctx.out('No collections.\n');
      return;
    }
    const lines = collections.map((c, index) =>
      `${hidden(c.collection) ? `custom collection ${index + 1}` : c.collection}  profile=${c.profile ?? 'unknown'}  items=${c.itemCount}  child-prompts=${c.allowChildModelPrompts ? 'on' : 'off'}\n`,
    );
    ctx.out(lines.join(''));
  });
}

// ---------------------------------------------------------------------------------------------------------------
// P-3: Mode B second copy, write-once export and reminders (Architecture 8.1, A-44).
// Output never echoes the drive path or the home path (either could hold a pasted secret).

/** The working-device register of second copies, in the Foundry home next to `vault/` and `index/`. */
export const REGISTER_NAME = 'second-copies.json';

function registerPath(ctx: Context): string {
  return join(ctx.request.home, REGISTER_NAME);
}

function nowOf(ctx: Context): Date {
  return ctx.hooks.now === undefined ? new Date() : new Date(ctx.hooks.now);
}

function targetOptions(ctx: Context): { probe?: FileSystemProbe } {
  return ctx.hooks.secondCopyProbe ? { probe: ctx.hooks.secondCopyProbe } : {};
}

function keyringVersionOf(ctx: Context): number | undefined {
  try {
    const value = (JSON.parse(readKeyring(ctx).toString('utf8')) as { version?: unknown }).version;
    return typeof value === 'number' && Number.isSafeInteger(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function fileSystemNotice(ctx: Context, report: { type?: string }): void {
  if (report.type === undefined) {
    ctx.io.err('foundry: notice: the file system of the drive could not be detected; FAT32 drives cannot hold a second copy\n');
  }
}

/** Architecture 8.1: a second copy on the same disk does not survive that disk. */
function diskWarning(ctx: Context, relation: string): void {
  if (relation === 'same-volume' || relation === 'same-disk') {
    ctx.io.err('foundry: warning: the second copy is on the same disk as this vault, so one disk failure loses both; '
      + 'use an external drive\n');
  } else if (relation === 'unknown') {
    ctx.io.err('foundry: notice: Foundry cannot tell whether the second copy is on another physical disk; '
      + 'make sure it is an external drive\n');
  }
}

type VaultModule = typeof import('vault/second-copy');
type CopyRegisterValue = ReturnType<VaultModule['readCopyRegister']>;

/**
 * Keyed commands: the register, rebuilt from a read-only replay of the `copy.*` events when it is missing, damaged
 * or flagged (R18-2). Nothing is written here; the caller writes the register after its event.
 */
async function keyedRegister(ctx: Context, session: UnlockSession, id: string): Promise<CopyRegisterValue> {
  const vault = await import('vault/second-copy');
  const state = vault.loadCopyRegister(registerPath(ctx), id);
  if (!state.rebuild) return state.register;
  try {
    return vault.replayCopyRegister(ctx.paths.vault, { session }, state.readable ? state.register : undefined);
  } catch (error) {
    if (error instanceof Error && error.name === 'VaultFormatError') {
      throw new CliError('REGISTER', 'the second-copy register must be rebuilt from the vault, and the vault could not be '
        + 'read (an unfinished write is finished by `foundry profile list`); then repeat this command');
    }
    throw error;
  }
}

/** Append one `copy.*` event under `me`'s `system` key (counts, ids and hashes only). */
async function appendCopyEvent(
  ctx: Context, session: UnlockSession, id: string, keyId: string, kind: string, ts: string, body: Record<string, unknown>,
): Promise<void> {
  const vault = await import('vault/second-copy');
  const unlocked = vault.decodeKeyring(readKeyring(ctx), { session }, id);
  try {
    const writer = vault.VaultWriter.open(ctx.paths.vault, unlocked);
    try {
      writer.appendBatch([{ type: 'event', keyId, event: { ts, kind, profile: PROFILE, collection: 'system', sensitivity: 'personal', body } }]);
    } finally {
      writer.release();
    }
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

/** `me`'s `system` collection key (created on first use), for the `copy.*` events. */
async function systemKeyId(ctx: Context, session: UnlockSession, id: string): Promise<string> {
  const vault = await import('vault/second-copy');
  const keyId = vault.ensureCollectionKeys(ctx.paths.keyring, id, { session }, PROFILE, ['system']).keyIds.get('system');
  if (keyId === undefined) throw new CliError('INTERNAL', 'internal error: the system collection key is missing');
  return keyId;
}

async function copyInitCommand(ctx: Context): Promise<void> {
  const vault = await import('vault/second-copy');
  const target = ctx.request.target!;
  const label = ctx.request.label;
  await keyed(ctx, async (session, id) => {
    // `copy init` compares no chain head, so the working vault may finish an earlier interrupted write first.
    await recoverVaultWriter(ctx, session, id);
    const path = registerPath(ctx);
    let register = await keyedRegister(ctx, session, id);
    // Keyless and read-only: placement, file system, and what the folder holds.
    const inspected = vault.inspectCopyTarget(ctx.paths.vault, target, targetOptions(ctx));
    let copy: CopyRegisterValue['copies'][number];
    let adoptedFrom: string | null | undefined;
    let registered = false;
    const known = inspected.copyId === undefined ? undefined : register.copies.find(entry => entry.copy_id === inspected.copyId);
    if (known) {
      // This record's own folder (complete, or an interrupted init): finish it, no new record.
      if (label !== undefined && vault.assertCopyLabel(label) !== known.label) throw new vault.SecondCopyError('COPY_MISMATCH', 'label');
      copy = known;
    } else if (inspected.state === 'copy') {
      if (!ctx.request.adopt) throw new vault.SecondCopyError('COPY_MISMATCH', 'adopt-required');
      adoptedFrom = inspected.copyId ?? null;
      ({ register, copy } = vault.addCopyRecord(register, label, nowOf(ctx)));
      registered = true;
    } else if (inspected.state === 'interrupted') {
      // Another record's (or device's) unfinished init: not this device's to finish.
      throw new vault.SecondCopyError('COPY_MISMATCH', 'interrupted-init');
    } else {
      const unsealed = label === undefined ? undefined : register.copies.find(entry => entry.label === label && entry.head === null);
      if (unsealed) {
        // The record exists (its event and register write happened) but its folder was never finished.
        copy = unsealed;
      } else {
        ({ register, copy } = vault.addCopyRecord(register, label, nowOf(ctx)));
        registered = true;
      }
    }
    stall(ctx.hooks);
    if (registered) {
      // Events first, register second (R18-2): flag the register, append `copy.registered`, then write it.
      const keyId = await systemKeyId(ctx, session, id);
      const previous = { ...register, copies: register.copies.filter(entry => entry.copy_id !== copy.copy_id) };
      vault.writeCopyRegister(path, { ...previous, needs_replay: true });
      await appendCopyEvent(ctx, session, id, keyId, vault.COPY_REGISTERED, copy.created_at,
        vault.copyRegisteredBody(copy, register.cadence, adoptedFrom));
    }
    vault.writeCopyRegister(path, { ...register, needs_replay: false });
    const result = vault.initSecondCopy(ctx.paths.vault, target, {
      ...targetOptions(ctx), copyId: copy.copy_id, adopt: adoptedFrom !== undefined,
    });
    fileSystemNotice(ctx, result.fileSystem);
    diskWarning(ctx, result.disk);
    const summary = {
      ok: true, label: copy.label, copyId: copy.copy_id, created: result.created, resumed: result.resumed,
      adoptedFrom: adoptedFrom ?? null, adopted: adoptedFrom !== undefined,
      fileSystem: result.fileSystem.type ?? null, disk: result.disk,
    };
    if (ctx.request.json) {
      ctx.out(summary);
      return;
    }
    const state = adoptedFrom !== undefined
      ? `adopted: the folder's copy id ${adoptedFrom ?? '(none)'} is replaced by ${copy.copy_id}`
      : result.created ? 'ready' : 'ready (an earlier copy init of this record was finished)';
    ctx.out(`Second copy "${summary.label}" is ${state}.\n`
      + `Next: run \`foundry vault seal <folder>\` to copy the vault to it.\n`);
  });
}

/** The record a session acts on: `--copy`, else the one whose id the drive's `COPY.json` names, else the only one. */
function selectSessionCopy(vault: VaultModule, register: CopyRegisterValue, ctx: Context, id: string) {
  if (ctx.request.copyLabel !== undefined) return vault.selectCopy(register, ctx.request.copyLabel);
  let driveId: string | undefined;
  try {
    driveId = vault.readCopyIdentity(ctx.request.target!, id);
  } catch {
    driveId = undefined; // The session's own phase 1 reports what is wrong with the drive.
  }
  return register.copies.find(entry => entry.copy_id === driveId) ?? vault.selectCopy(register);
}

/**
 * Check a new output file before any work (findings 17 and 18): not inside the working vault or the copy (strict
 * verification would reject the extra entry), not existing, and its parent an existing folder. Fixed texts only.
 */
async function checkNewOutput(path: string, inside: readonly string[]): Promise<void> {
  const vault = await import('vault/second-copy');
  const { lstatSync } = await import('node:fs');
  const { dirname, resolve } = await import('node:path');
  const absolute = resolve(path);
  if (inside.some(folder => vault.pathInside(folder, absolute))) throw new vault.SecondCopyError('OUTPUT_UNSUITABLE');
  const [existing, parent] = withFixedFileErrors(() => [
    lstatSync(absolute, { throwIfNoEntry: false }), lstatSync(dirname(absolute), { throwIfNoEntry: false }),
  ] as const);
  if (existing !== undefined) throw new vault.SecondCopyError('OUTPUT_EXISTS');
  if (parent === undefined || !parent.isDirectory()) {
    throw new CliError('IO', 'the folder for the output file does not exist or is not a folder');
  }
}

async function sealCommand(ctx: Context): Promise<void> {
  const vault = await import('vault/second-copy');
  const target = ctx.request.target!;
  // The SVG destination is checked before the seal: a seal is committed once it is written (finding 18).
  if (ctx.request.anchorSvg !== undefined) await checkNewOutput(ctx.request.anchorSvg, [ctx.paths.vault, target]);
  await keyed(ctx, async (session, id) => {
    const path = registerPath(ctx);
    // Read-only so far: the register (or its replay) and the selected record.
    let register = await keyedRegister(ctx, session, id);
    const copy = selectSessionCopy(vault, register, ctx, id);
    const recorded = copy.head === null ? null : { segment: copy.head.segment, hash: copy.head.manifest_sha256 };
    // Steps 1 to 3 (keyless, read-only), then the drive's lock and its recovery (R18-2).
    const copySession = vault.openSecondCopySession(ctx.paths.vault, target, {
      recorded, copyId: copy.copy_id, ...targetOptions(ctx),
      ...(ctx.hooks.copyCheckpoint ? { checkpoint: ctx.hooks.copyCheckpoint } : {}),
    });
    let result: ReturnType<typeof copySession.seal>;
    let keyId: string;
    try {
      fileSystemNotice(ctx, copySession.report.fileSystem);
      diskWarning(ctx, copySession.report.disk);
      // Working-device writes start only now, after the drive passed steps 1 to 3: an earlier command may have
      // stopped inside a segment seal, and the writer completes or rolls it back.
      await recoverVaultWriter(ctx, session, id);
      // Before the keyring copy (step 7): `me`'s `system` key for the `copy.sealed` event exists, so the keyring on
      // the drive already holds it.
      keyId = await systemKeyId(ctx, session, id);
      const unlocked = vault.decodeKeyring(readKeyring(ctx), { session }, id);
      try {
        stall(ctx.hooks);
        result = copySession.seal(unlocked);
      } finally {
        unlocked.masterKey.fill(0);
        for (const key of unlocked.keys.values()) key.fill(0);
      }
    } finally {
      copySession.release();
    }
    // Step 8, events first and register second (R18-2): a crash between them leaves the register flagged, and the
    // next keyed second-copy command rebuilds it from the events.
    vault.writeCopyRegister(path, { ...register, needs_replay: true });
    await appendCopyEvent(ctx, session, id, keyId, vault.COPY_SEALED, result.sealedAt, vault.copySealedBody(copy, register.cadence, result));
    register = vault.recordSeal(register, copy.copy_id, result);
    vault.writeCopyRegister(path, { ...register, needs_replay: false });
    // The seal is committed. An optional SVG that cannot be written is a warning: the anchor text and step 9 below are
    // still printed (finding 18).
    let anchorSvgWritten = false;
    if (ctx.request.anchorSvg !== undefined) {
      const svg = ctx.request.anchorSvg;
      const fs = await import('node:fs');
      try {
        if (ctx.hooks.failAnchorSvgWrite) throw Object.assign(new Error('TEST ONLY write failed'), { code: 'EIO', syscall: 'open' });
        const fd = fs.openSync(svg, 'wx', 0o644);
        try {
          fs.writeSync(fd, vault.anchorQrSvg(result.anchor));
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
        anchorSvgWritten = true;
      } catch {
        ctx.io.err('foundry: warning: the seal is complete, but the anchor SVG file could not be written; '
          + 'copy the anchor text below instead\n');
      }
    }
    const report = copySession.report;
    if (ctx.request.json) {
      ctx.out({
        ok: true, label: copy.label, copyId: copy.copy_id, previousSegment: result.previous.segment,
        segment: result.head.segment, manifestSha256: result.head.hash, sealedAt: result.sealedAt,
        segmentsCopied: result.segmentsCopied, filesCopied: result.filesCopied, bytesCopied: result.bytesCopied,
        keyringVersion: result.keyringVersion, removedPartialSegment: report.removedPartialSegment ?? null,
        completedHead: report.completedHead, protectedSegments: report.protectedSegments,
        anchor: vault.anchorPayload(result.anchor), anchorSvgWritten,
        nextSteps: [AFTER_SEAL],
      });
      return;
    }
    const notes = [
      report.removedPartialSegment === undefined ? '' : `An unfinished segment ${report.removedPartialSegment} from an interrupted session was removed first.\n`,
      report.completedHead ? 'An interrupted session\'s head update was completed first.\n' : '',
    ].join('');
    ctx.out(`${notes}Second copy "${copy.label}" sealed: segment ${result.previous.segment} -> ${result.head.segment}, `
      + `${result.segmentsCopied} segment(s), ${result.filesCopied} file(s), ${result.bytesCopied} byte(s) copied; `
      + `keyring version ${result.keyringVersion}.\n\n`
      + `${vault.anchorText(result.anchor)}\n`
      + `${vault.anchorQrText(result.anchor, { invert: ctx.request.qrInvert === true })}\n`
      + 'Write the anchor down or print it, and keep it away from the drive. It makes a swapped or rolled-back copy\n'
      + 'tamper-evident: `foundry vault verify-copy <folder> --anchor <compact anchor>` checks a copy against it.\n\n'
      + `${AFTER_SEAL}\n`);
  });
}

const AFTER_SEAL = 'Now switch on the drive\'s write-protect (if it has one) and disconnect the drive.';
const FINALISE_DISC = 'Burn it as a single, finalised (closed) session, so nothing can be appended to the disc later.';

/**
 * `foundry vault verify-copy <folder> [--anchor <text>] [--copy <label>]` (finding 32). Keyless. The folder must pass
 * the full keyless check as a second copy of this vault. With `--anchor`, its chain must hold the anchored segment
 * with the anchored hash (an older copy fails). Without it, the chain head is compared with the seal recorded on
 * this device: older is a rollback STOP, the same segment with another hash is a tamper STOP.
 */
async function verifyCopyCommand(ctx: Context): Promise<void> {
  const vault = await import('vault/second-copy');
  const id = await vaultId(ctx);
  const target = ctx.request.target!;
  const anchor = ctx.request.anchor === undefined ? undefined : vault.parseAnchor(ctx.request.anchor);
  stall(ctx.hooks);
  const verified = withHomeSystemErrors(() => vault.verifyVault(target, { secondCopy: true, ...(anchor ? { anchor } : {}) }));
  if (verified.vault.vault_id !== id) throw new vault.SecondCopyError('VAULT_MISMATCH');
  const position = verified.position;
  let recorded: 'match' | 'newer' | 'none' = 'none';
  if (anchor === undefined) {
    const { register } = vault.loadCopyRegister(registerPath(ctx), id);
    let driveId: string | undefined;
    try {
      driveId = vault.readCopyIdentity(target, id);
    } catch {
      driveId = undefined;
    }
    const copy = ctx.request.copyLabel !== undefined
      ? vault.selectCopy(register, ctx.request.copyLabel)
      : register.copies.find(entry => entry.copy_id === driveId);
    if (copy !== undefined && driveId !== undefined && copy.copy_id !== driveId) throw new vault.SecondCopyError('COPY_MISMATCH', 'different');
    if (copy?.head) {
      if (position.segment < copy.head.segment) throw new vault.SecondCopyError('ROLLBACK_DETECTED', 'drive-older-than-recorded');
      if (position.segment === copy.head.segment && position.hash !== copy.head.manifest_sha256) {
        throw new vault.SecondCopyError('TAMPER_DETECTED', 'recorded-segment-differs');
      }
      recorded = position.segment === copy.head.segment ? 'match' : 'newer';
    }
  }
  if (ctx.request.json) {
    ctx.out({ ok: true, segment: position.segment, manifestSha256: position.hash, anchorChecked: anchor !== undefined, recorded });
    return;
  }
  const against = anchor !== undefined ? 'it holds the anchored segment with the anchored hash'
    : recorded === 'match' ? 'its head is the seal recorded on this device'
      : recorded === 'newer' ? 'its head is newer than the seal recorded on this device'
        : 'no seal is recorded for it on this device and no anchor was given, so its age is not checked';
  ctx.out(`Second copy OK: segment ${position.segment}; ${against}.\n`);
}

async function statusCommand(ctx: Context): Promise<void> {
  const vault = await import('vault/second-copy');
  const id = await vaultId(ctx);
  stall(ctx.hooks);
  // Keyless: a missing or damaged register cannot be replayed here, so it is reported as "rebuild needed" (R18-2).
  const { register } = vault.loadCopyRegister(registerPath(ctx), id);
  const status = vault.copyRegisterStatus(register, nowOf(ctx), keyringVersionOf(ctx));
  if (ctx.request.json) {
    ctx.out({ ...status, lastCheck: register.last_check });
    return;
  }
  const lines = status.copies.map(copy => {
    const sealed = copy.head === null ? 'never sealed' : `segment ${copy.head.segment}, sealed ${copy.head.sealed_at}`;
    const keyring = copy.keyringCurrent === false ? '  keyring copy is OLDER (seal again)' : '';
    return `${copy.label}  ${sealed}  ${copy.daysUnsealed} day(s) ago${copy.overdue ? '  OVERDUE' : copy.due ? '  due' : ''}${keyring}\n`;
  });
  const check = register.last_check === null ? '' : `Last reminder check: ${register.last_check.checked_at} (keyless check: ${register.last_check.verify}).\n`;
  ctx.out(`Cadence: ${status.cadence}.\n${lines.join('')}${check}${status.banner ? `${status.banner}\n` : ''}`);
}

async function reminderCommand(ctx: Context): Promise<void> {
  const { notifyDesktop, runReminder } = await import('vault/second-copy');
  stall(ctx.hooks);
  const result = runReminder(ctx.paths.vault, registerPath(ctx), { verify: ctx.request.verifyChain === true, now: nowOf(ctx) });
  const message = result.status.banner ?? (result.status.due ? 'A second-copy session is due.' : 'The second copy is up to date.');
  const check = result.verify === 'skipped' ? '' : `Keyless vault check: ${result.verify}${result.verifyError ? ` (${result.verifyError})` : ''}.`;
  // Linux: a desktop notification when a session bus is reachable (R18-4). The printed line always goes out too:
  // the systemd user service writes it to the journal, and the Windows task shows it in its console window.
  const platform = ctx.hooks.schedulerPlatform ?? process.platform;
  const delivered = platform === 'linux'
    ? notifyDesktop(check === '' ? message : `${message} ${check}`, {
      env: process.env, ...(ctx.hooks.schedulerRunner ? { run: ctx.hooks.schedulerRunner } : {}),
      ...(ctx.hooks.reminderBusExists ? { exists: ctx.hooks.reminderBusExists } : {}),
      ...(ctx.hooks.reminderEnv ? { env: ctx.hooks.reminderEnv } : {}),
    })
    : 'none';
  if (ctx.request.json) ctx.out({ ...result.status, verify: result.verify, verifyError: result.verifyError ?? null, delivered });
  else ctx.out(`${message}\n${check === '' ? '' : `${check}\n`}`);
  if (result.verify === 'failed') {
    throw new CliError('VERIFY_FAILED', 'the keyless vault check failed; run `foundry vault verify`');
  }
}

async function exportIsoCommand(ctx: Context): Promise<void> {
  const vault = await import('vault/second-copy');
  const includeKeyring = ctx.request.includeKeyring === true;
  if (includeKeyring) {
    ctx.io.err('foundry: warning: --include-keyring-irreversible puts the keyring on the image. A key on a write-once disc '
      + 'can never be destroyed: erasing a person or collection later cannot reach that disc.\n');
  }
  await checkNewOutput(ctx.request.output!, [ctx.paths.vault]);
  stall(ctx.hooks);
  const result = vault.exportVaultIso(ctx.paths.vault, ctx.request.output!, { includeKeyring });
  if (ctx.request.json) {
    ctx.out({
      ok: true, segment: result.head.segment, manifestSha256: result.head.hash, segments: result.segments, files: result.files,
      imageBytes: result.imageBytes, keyringIncluded: result.keyringIncluded, openFilesNotExported: result.openFiles,
      anchor: vault.anchorPayload(result.anchor),
      // The single-session finalisation instruction is part of the machine-readable result too (finding 33).
      nextSteps: [FINALISE_DISC],
    });
    return;
  }
  ctx.out(`Image written: ${result.segments} sealed segment(s), ${result.files} file(s), ${result.imageBytes} byte(s); `
    + `keyring ${result.keyringIncluded ? 'INCLUDED' : 'not included'}.\n`
    + (result.openFiles > 0 ? `${result.openFiles} file(s) of the open segment are not on the image; run \`foundry vault seal\` first to include them.\n` : '')
    + `${FINALISE_DISC}\n\n`
    + `${vault.anchorText(result.anchor)}\n`);
}

function schedulerEnvironment(ctx: Context, env: Readonly<Record<string, string | undefined>>, home: () => string) {
  const xdg = env.XDG_CONFIG_HOME;
  return {
    platform: ctx.hooks.schedulerPlatform ?? process.platform,
    ...(ctx.hooks.schedulerRunner ? { run: ctx.hooks.schedulerRunner } : {}),
    configHome: ctx.hooks.schedulerConfigHome ?? (xdg && xdg.startsWith('/') ? xdg : join(home(), '.config')),
    scratch: ctx.request.home,
    now: nowOf(ctx),
  };
}

async function scheduleCommand(ctx: Context): Promise<void> {
  const vault = await import('vault/second-copy');
  const { homedir } = await import('node:os');
  const { fileURLToPath } = await import('node:url');
  const env = schedulerEnvironment(ctx, process.env, homedir);
  const command = ctx.request.command;
  stall(ctx.hooks);
  if (command === 'vault schedule status') {
    const id = await vaultId(ctx);
    const status = vault.reminderStatus(ctx.request.home, env);
    const cadence = vault.readCopyRegister(registerPath(ctx), id).cadence;
    if (ctx.request.json) ctx.out({ ...status, cadence });
    else ctx.out(`Cadence: ${cadence}. Reminder job: ${status.installed.length === 0 ? 'none' : status.installed.join(', ')}.\n`);
    return;
  }
  if (command === 'vault schedule remove') {
    const removed = vault.removeReminder(ctx.request.home, env);
    if (ctx.request.json) ctx.out({ ok: true, name: removed.name, removed: removed.removed });
    else ctx.out(removed.removed.length === 0 ? 'No reminder job was installed.\n' : `Reminder removed (${removed.removed.join(', ')}).\n`);
    return;
  }
  const id = await vaultId(ctx);
  const cadence = vault.assertCadence(ctx.request.cadence);
  const path = registerPath(ctx);
  const register = vault.readCopyRegister(path, id);
  // The register is written first and restored if the scheduler change fails, so the two never disagree (finding 28).
  vault.writeCopyRegister(path, { ...register, cadence });
  let method: string;
  try {
    if (cadence === 'manual') {
      method = vault.removeReminder(ctx.request.home, env).removed.length > 0 ? 'removed' : 'none';
    } else {
      const installed = vault.installReminder({
        home: ctx.request.home, node: process.execPath, cli: fileURLToPath(new URL('../bin/foundry.mjs', import.meta.url)),
        cadence, verify: ctx.request.verifyChain === true,
      }, env);
      method = installed.method;
    }
  } catch (error) {
    vault.writeCopyRegister(path, register);
    throw error;
  }
  if (ctx.request.json) ctx.out({ ok: true, cadence, method });
  else if (cadence === 'manual') {
    ctx.out('Cadence: manual. No reminder job is installed; `foundry vault status` still shows the overdue banner after 14 days.\n');
  } else {
    ctx.out(`Reminder installed (${method}, ${cadence}). It never reads a key: it checks the seal age`
      + `${ctx.request.verifyChain ? ' and runs the keyless vault check' : ''} and records the result for \`foundry vault status\`.\n`);
  }
}

const BODIES: Readonly<Record<CommandName, (ctx: Context) => Promise<void>>> = {
  'vault copy init': copyInitCommand,
  'vault seal': sealCommand,
  'vault session': sealCommand,
  'vault status': statusCommand,
  'vault reminder': reminderCommand,
  'vault export-iso': exportIsoCommand,
  'vault verify-copy': verifyCopyCommand,
  'vault schedule set': scheduleCommand,
  'vault schedule status': scheduleCommand,
  'vault schedule remove': scheduleCommand,
  'init': init,
  'import': importCommand,
  'search': search,
  'vault verify': verify,
  'index rebuild': rebuild,
  'vault reset-passphrase': resetPassphraseCommand,
  'profile add': profileAddCommand,
  'profile list': profileListCommand,
  'consent record': consentRecordCommand,
  'consent list': consentListCommand,
  'collection prompt-policy': collectionPromptPolicyCommand,
  'collection list': collectionListCommand,
};

/** The P-3 path operands as typed and as resolved, for removal from `--debug` text (finding 16). */
function operandTexts(request: CommandRequest): string[] {
  const out: string[] = [];
  for (const value of [request.target, request.output, request.anchorSvg]) {
    if (value === undefined || value.length === 0) continue;
    out.push(value);
    try {
      out.push(resolvePath(value));
    } catch {
      // The typed form is enough.
    }
  }
  return out;
}

function secretTexts(secrets: CommandSecrets): string[] {
  return [secrets.passphrase, secrets.recoveryKey, secrets.newPassphrase]
    .map(bytes => asBuffer(bytes)?.toString('utf8') ?? '')
    .filter(value => value.length > 0);
}

/**
 * Guidance added to the ONE failure line (design 4.6), after the message and before the code, in this order:
 * - `import`, "the index is behind": a failure in the final index update, or any failure after this command stored
 *   at least one item and before the final index update finished (this includes the update between the runs);
 * - `import`, "items stored so far stay stored": only when this command durably stored at least one item;
 * - `import`, "repeating the import is safe": every failure after Run A started;
 * - `vault reset-passphrase`, failure that may follow the keyring replacement (design 4.4; same line, not an extra one).
 */
function failureGuidance(ctx: Context): string[] {
  const guidance: string[] = [];
  if (ctx.request.command === 'import') {
    const stage = ctx.importStage;
    if (stage === 'final' || (ctx.storedEvents > 0 && stage !== 'done')) {
      guidance.push('the index is behind; run `foundry index rebuild`');
    }
    if (ctx.storedEvents > 0) guidance.push('items stored so far stay stored');
    if (stage !== 'before') guidance.push('repeating the import is safe');
  }
  if (ctx.resetMayBeDone) guidance.push('the passphrase may already be changed; try the new passphrase before you repeat the reset');
  if (ctx.initLeftover !== undefined) {
    guidance.push(`the unfinished staging folder "${ctx.initLeftover}" stays in the Foundry folder; `
      + 'delete it before you run `foundry init` again');
  }
  return guidance;
}

/** Run one command body. Writes its own output and error line; returns the exit code. Zeroes every secret. */
export async function executeCommand(request: CommandRequest, io: CommandIo, hooks: TestHooks = {}): Promise<number> {
  const ctx = new Context(request, io, hooks);
  try {
    if (hooks.leakHandle) setInterval(() => {}, 1000);
    if (hooks.throwWithSecret) throw new Error(`test hook: ${secretTexts(request.secrets).join(' | ')}`);
    await BODIES[request.command](ctx);
    return 0;
  } catch (thrown) {
    // Last line of defence: a Node system error about the home folder (from a library call) becomes fixed text, so
    // neither the line nor the `--debug` text can quote the path.
    // P-3 commands take new path operands (a drive folder, an SVG or ISO file): any Node system error there becomes
    // fixed text too, and the operands are removed from the `--debug` text (finding 16).
    const p3 = SECOND_COPY_COMMANDS.includes(request.command);
    const error = homeSystemError(thrown, request.home) ?? (p3 && isSystemError(thrown) ? fixedFileError(thrown) : thrown);
    const mapped = mapError(error, { erasedInImport: request.command === 'import' });
    if (request.debug) {
      const operands = p3 ? operandTexts(request) : [];
      io.err(debugText(error, [...secretTexts(request.secrets), ...operands]));
    }
    io.err(errorLine(mapped, failureGuidance(ctx)));
    return mapped.exit;
  } finally {
    for (const bytes of [request.secrets.passphrase, request.secrets.recoveryKey, request.secrets.newPassphrase]) {
      if (bytes && bytes.byteLength > 0) bytes.fill(0);
    }
  }
}

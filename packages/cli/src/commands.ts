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
import { join, resolve } from 'node:path';
import type { IndexStoreOptions } from 'foundry-index';
import type { ImportResult } from 'importers';
import type { UnlockSession } from 'vault';
import type { CommandName, SearchFilters } from './args.ts';
import { CliError, debugText, errorLine, isRecoveryFormatError, mapError } from './errors.ts';

export const PROFILE = 'me';
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
  filters: SearchFilters;
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
  /** `import`: the final index update throws an errno-style error whose message quotes every secret. */
  failFinalIndexUpdate?: boolean;
  /** `import`: Run B throws an errno-style error at its start (after any archive check, before it stores). */
  failRunB?: boolean;
  /**
   * `import`: called with the archive path after Run A has closed the archive, before Run B (it may change a part).
   * A function: it cannot cross into the worker thread, so only the inline path (`runCli` with `inline`) can use it.
   */
  betweenRuns?: (archivePath: string) => void;
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

class Context {
  readonly paths: ReturnType<typeof homePaths>;
  /** Events this command durably appended (counted when the vault writer's `appendBatch` returns). */
  storedEvents = 0;
  /** True while the final index update of `import` runs. */
  finalIndexUpdate = false;
  /** `vault reset-passphrase` failed in a way that may follow the atomic keyring replacement. */
  resetMayBeDone = false;

  constructor(readonly request: CommandRequest, readonly io: CommandIo, readonly hooks: TestHooks) {
    this.paths = homePaths(request.home);
  }

  out(value: string | object): void {
    this.io.out(typeof value === 'string' ? value : JSON.stringify(value) + '\n');
  }
}

async function vaultId(ctx: Context): Promise<string> {
  const { decodeVaultMetadata } = await import('vault');
  return decodeVaultMetadata(readFileSync(join(ctx.paths.vault, 'VAULT.json'))).vault_id;
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
  return {
    directory: ctx.paths.index, vaultDirectory: ctx.paths.vault, credential: { session },
    projection: await loadProjection(),
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

/** Temporary folders of `init` inside H: `.init-` and 16 lowercase hex digits. Nothing else matches. */
const INIT_FOLDER = /^\.init-[0-9a-f]{16}$/u;

export function isInitLeftover(name: string): boolean {
  return INIT_FOLDER.test(name);
}

/**
 * `init` builds the vault in `H/.init-<random>` and renames it to `H/vault` as the last step, then prints the
 * recovery key. An interrupted init leaves at most such a folder; the next `init` (under the lock) removes only
 * folders that match the pattern, and the NOT_EMPTY check ignores them.
 */
async function init(ctx: Context): Promise<void> {
  const passphrase = requireNewPassphrase(ctx);
  const { createVault } = await import('vault');
  const { randomBytes } = await import('node:crypto');
  const { readdirSync, renameSync, rmSync } = await import('node:fs');
  for (const name of readdirSync(ctx.request.home)) {
    if (isInitLeftover(name)) rmSync(join(ctx.request.home, name), { recursive: true, force: true });
  }
  const temporary = join(ctx.request.home, `.init-${randomBytes(8).toString('hex')}`);
  stall(ctx.hooks);
  const identity = createVault(temporary, { passphrase });
  if (ctx.hooks.failBeforeInitRename) throw new Error('test hook: init stopped before the rename');
  renameSync(temporary, ctx.paths.vault);
  ctx.out(`Created a new Foundry vault in ${resolve(ctx.request.home)}.\n\n`
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

/** Let the vault writer recover an interrupted append or seal (for example a pending HEAD), then release it. */
async function recoverVaultWriter(ctx: Context, session: UnlockSession, id: string): Promise<void> {
  const vault = await import('vault');
  const unlocked = vault.decodeKeyring(readFileSync(ctx.paths.keyring), { session }, id);
  try {
    vault.VaultWriter.open(ctx.paths.vault, unlocked).release();
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

async function importRun(ctx: Context, session: UnlockSession, id: string, options: IndexStoreOptions, parts: ArchiveParts) {
  const vault = await import('vault');
  const importers = await import('importers');
  const { openItemKeyLookup } = await import('foundry-index');
  const unlocked = vault.decodeKeyring(readFileSync(ctx.paths.keyring), { session }, id);
  let writer: ReturnType<typeof vault.VaultWriter.open> | undefined;
  let lookup: ReturnType<typeof openItemKeyLookup> | undefined;
  let archive: Awaited<ReturnType<typeof openParts>> | undefined;
  try {
    archive = await openParts(parts);
    const opened = writer = vault.VaultWriter.open(ctx.paths.vault, unlocked);
    // Counts the events this command durably stored: a batch counts once `appendBatch` has returned.
    const counting = {
      appendBatch(items: Parameters<typeof opened.appendBatch>[0]) {
        const results = opened.appendBatch(items);
        ctx.storedEvents += results.filter(result => result.type === 'event').length;
        return results;
      },
      closeSegment: () => opened.closeSegment(),
    };
    lookup = openItemKeyLookup(options);
    stall(ctx.hooks);
    return await importers.importArchive({
      archive, writer: counting, importers: importers.DEFAULT_IMPORTERS, profile: PROFILE,
      resolveCollectionKeyId: name => vault.collectionKeyId(unlocked, PROFILE, name),
      vaultDir: ctx.paths.vault, unlocked, itemKeys: lookup,
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
  await keyed(ctx, async (session, id) => {
    const options = await indexOptions(ctx, session);
    const { updateIndex } = await import('foundry-index');
    const { ensureCollectionKeys } = await import('vault');
    // An earlier command may have stopped inside a segment seal (a pending HEAD). The read-only replay of the index
    // update refuses that state; only the vault writer recovers it. So: writer first, then the catch-up update.
    await recoverVaultWriter(ctx, session, id);
    updateIndex(options); // catch-up after an earlier crash: the item-key lookup needs a current index
    const path = ctx.request.path!;
    const parts = await resolveArchiveParts(path);
    const stamps = await stampParts(parts);
    const runA = await importRun(ctx, session, id, options, parts);
    let runB: ImportResult | undefined;
    let collectionsCreated = 0;
    if (runA.missingCollections.length > 0) {
      for (const slice of nameSlices(runA.missingCollections)) {
        collectionsCreated += ensureCollectionKeys(ctx.paths.keyring, id, { session }, PROFILE, slice).created;
      }
      updateIndex(options);
      ctx.hooks.betweenRuns?.(path);
      await checkArchiveUnchanged(path, stamps); // before Run B opens or stores anything
      if (ctx.hooks.failRunB) throw hookError('run B', secretTexts(ctx.request.secrets));
      runB = await importRun(ctx, session, id, options, parts);
      if (runB.missingCollections.length > 0) {
        throw new CliError('INTERNAL', 'internal error: the second import run still found collections without a key');
      }
    }
    const summary = summarise(runA, runB, collectionsCreated);
    // A failure here keeps its own code; `executeCommand` adds the "index is behind" guidance to the same line and
    // prints `--debug` text through the same redacting handler as every other error.
    ctx.finalIndexUpdate = true;
    if (ctx.hooks.failFinalIndexUpdate) throw hookError('final index update', secretTexts(ctx.request.secrets));
    updateIndex(options);
    ctx.finalIndexUpdate = false;
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

const BODIES: Readonly<Record<CommandName, (ctx: Context) => Promise<void>>> = {
  'init': init,
  'import': importCommand,
  'search': search,
  'vault verify': verify,
  'index rebuild': rebuild,
  'vault reset-passphrase': resetPassphraseCommand,
};

function secretTexts(secrets: CommandSecrets): string[] {
  return [secrets.passphrase, secrets.recoveryKey, secrets.newPassphrase]
    .map(bytes => asBuffer(bytes)?.toString('utf8') ?? '')
    .filter(value => value.length > 0);
}

/**
 * Guidance added to the ONE failure line (design 4.6), after the message and before the code:
 * - `import`, failure in the final index update: the index is behind;
 * - `import`, only when this command durably stored at least one item: stored items stay, repeating is safe;
 * - `vault reset-passphrase`, failure that may follow the keyring replacement (design 4.4; same line, not an extra one).
 */
function failureGuidance(ctx: Context): string[] {
  const guidance: string[] = [];
  if (ctx.request.command === 'import') {
    if (ctx.finalIndexUpdate) guidance.push('the index is behind; run `foundry index rebuild`');
    if (ctx.storedEvents > 0) guidance.push('items stored so far stay stored; repeating the import is safe');
  }
  if (ctx.resetMayBeDone) guidance.push('the passphrase may already be changed; try the new passphrase before you repeat the reset');
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
  } catch (error) {
    const mapped = mapError(error, { erasedInImport: request.command === 'import' });
    if (request.debug) io.err(debugText(error, secretTexts(request.secrets)));
    io.err(errorLine(mapped, failureGuidance(ctx)));
    return mapped.exit;
  } finally {
    for (const bytes of [request.secrets.passphrase, request.secrets.recoveryKey, request.secrets.newPassphrase]) {
      if (bytes && bytes.byteLength > 0) bytes.fill(0);
    }
  }
}

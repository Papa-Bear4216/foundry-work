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
  phase: 'start' | 'stored' = 'start';

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

async function init(ctx: Context): Promise<void> {
  const passphrase = requireNewPassphrase(ctx);
  const { createVault } = await import('vault');
  stall(ctx.hooks);
  const identity = createVault(ctx.paths.vault, { passphrase });
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
    if (!typed && !isRecoveryFormatError(error)) {
      throw Object.assign(error as object, { afterRenameNotice: true });
    }
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

/** A zip, the first part of a multi-part set (its folder is opened), or a folder of parts. */
async function openImportArchive(path: string) {
  const { openArchive, parsePartName } = await import('importers');
  const { readdirSync, statSync } = await import('node:fs');
  const { basename, dirname } = await import('node:path');
  const info = statSync(path);
  if (info.isFile()) {
    const part = parsePartName(basename(path));
    const folder = dirname(path);
    if (part && part.ordinal === 1) {
      const siblings = readdirSync(folder).filter(name => {
        const other = parsePartName(name);
        return other !== undefined && other.prefix === part.prefix && other.ordinal !== 1;
      });
      if (siblings.length > 0) return openArchive(folder);
    }
  }
  return openArchive(path);
}

async function importRun(ctx: Context, session: UnlockSession, id: string, options: IndexStoreOptions) {
  const vault = await import('vault');
  const importers = await import('importers');
  const { openItemKeyLookup } = await import('foundry-index');
  const unlocked = vault.decodeKeyring(readFileSync(ctx.paths.keyring), { session }, id);
  let writer: ReturnType<typeof vault.VaultWriter.open> | undefined;
  let lookup: ReturnType<typeof openItemKeyLookup> | undefined;
  let archive: Awaited<ReturnType<typeof openImportArchive>> | undefined;
  try {
    archive = await openImportArchive(ctx.request.path!);
    writer = vault.VaultWriter.open(ctx.paths.vault, unlocked);
    lookup = openItemKeyLookup(options);
    stall(ctx.hooks);
    return await importers.importArchive({
      archive, writer, importers: importers.DEFAULT_IMPORTERS, profile: PROFILE,
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
    updateIndex(options); // catch-up after an earlier crash: the item-key lookup needs a current index
    ctx.phase = 'stored'; // from here on a failure may follow stored batches; re-running is safe
    const runA = await importRun(ctx, session, id, options);
    let runB: ImportResult | undefined;
    let collectionsCreated = 0;
    if (runA.missingCollections.length > 0) {
      for (const slice of nameSlices(runA.missingCollections)) {
        collectionsCreated += ensureCollectionKeys(ctx.paths.keyring, id, { session }, PROFILE, slice).created;
      }
      updateIndex(options);
      runB = await importRun(ctx, session, id, options);
      if (runB.missingCollections.length > 0) {
        throw new CliError('INTERNAL', 'internal error: the second import run still found collections without a key');
      }
    }
    const summary = summarise(runA, runB, collectionsCreated);
    try {
      updateIndex(options);
    } catch (error) {
      if (ctx.request.debug) ctx.io.err(debugText(error, []));
      throw new CliError('INDEX_BEHIND', 'items are stored; the index is behind; run `foundry index rebuild`');
    }
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
    io.err(errorLine(mapped));
    if (request.command === 'import' && ctx.phase === 'stored' && mapped.code !== 'INDEX_BEHIND') {
      io.err('foundry: items stored so far stay stored; running the same import again is safe (it adds nothing twice)\n');
    } else if (request.command === 'import' && mapped.code === 'INDEX_BEHIND') {
      io.err('foundry: running the same import again is safe (it adds nothing twice)\n');
    }
    if ((error as { afterRenameNotice?: boolean } | null)?.afterRenameNotice) {
      io.err('foundry: the passphrase may already be changed; try the new passphrase before you repeat the reset\n');
    }
    return mapped.exit;
  } finally {
    for (const bytes of [request.secrets.passphrase, request.secrets.recoveryKey, request.secrets.newPassphrase]) {
      if (bytes && bytes.byteLength > 0) bytes.fill(0);
    }
  }
}

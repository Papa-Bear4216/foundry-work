import type { Buffer } from 'node:buffer';
import { createHash, hkdfSync, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { platform } from 'node:process';
import { DatabaseSync } from 'node:sqlite';
import { decodeKeyring, decodeVaultMetadata, openVaultReplay, retireIndexKey, stageIndexKey } from '../../vault/codec/dist/index.js';
import type { Unlock, VerifyOptions } from '../../vault/codec/dist/index.js';
import { assertIndexPolicy, IndexError, openSqlDriver, transaction } from './driver.ts';
import type { IndexPolicy, SqlDriver } from './driver.ts';
import { applyIncremental, applyRebuild, assertSchema, initializeSchema, validateVersion } from './projection.ts';
import type { ProjectionOptions, ProjectionResult } from './projection.ts';
import { search } from './search.ts';
import type { SearchOptions } from './search.ts';

export interface IndexStoreOptions {
  directory: string;
  vaultDirectory: string;
  credential: Unlock;
  verify?: VerifyOptions;
  policy?: IndexPolicy;
  projection?: ProjectionOptions;
  /** Test hook called after publication and before retirement. */
  afterPublish?: () => void;
}

interface Catalog {
  vault_id: string;
  adapter: 'sqlcipher' | 'plain';
  active: string | null;
  snapshot: string | null;
  staged: string | null;
  staged_snapshot: string | null;
  staged_version: number | null;
  retiring: string | null;
  last_seq: number;
  keyring_floor: number;
}

interface Context {
  directory: string;
  vault: string;
  vaultId: string;
  keyring: string;
  policy: IndexPolicy;
  catalog: SqlDriver;
  options: IndexStoreOptions;
}

const hash = (value: string | Uint8Array): string => createHash('sha256').update(value).digest('hex');
const nested = (parent: string, child: string): boolean => {
  const path = relative(parent, child);
  return !isAbsolute(path) && path !== '..' && !path.startsWith(`..${sep}`);
};
const requiresRebuild = new Error('Projection requires a new generation.');

function readCatalog(db: SqlDriver): Catalog {
  const state = db.prepare('SELECT * FROM catalog WHERE singleton=1').get() as unknown as Catalog;
  for (const id of [state.active, state.staged, state.retiring]) {
    if (id !== null && !/^[0-9a-f]{32}$/u.test(id)) {
      throw new IndexError('FORMAT', 'The index generation catalog contains an invalid key ID.');
    }
  }
  return state;
}

function withCatalog<T>(opts: IndexStoreOptions, work: (ctx: Context) => T): T {
  const directory = resolve(opts.directory);
  const vault = resolve(opts.vaultDirectory);
  if (nested(vault, directory) || nested(directory, vault)) {
    throw new IndexError('CONFIG', 'The index and vault must use separate directory trees.');
  }
  const policy = opts.policy ?? {};
  assertIndexPolicy(directory, policy);
  const { vault_id: vaultId } = decodeVaultMetadata(readFileSync(join(vault, 'VAULT.json')));
  const created = mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (created) syncDirectory(dirname(created));

  // The serialization lock lives in a separate file. Catalog transactions must
  // commit independently while the lock stays held across stage, publish and retire.
  const lock = new DatabaseSync(join(directory, 'writer-lock.sqlite'), { timeout: 5000 });
  try {
    return transaction(lock, () => {
      const catalog = new DatabaseSync(join(directory, 'generations.sqlite'), { timeout: 5000 });
      try {
        catalog.exec(`
          PRAGMA synchronous = FULL;
          CREATE TABLE IF NOT EXISTS catalog (
            singleton INTEGER PRIMARY KEY CHECK (singleton=1),
            vault_id TEXT NOT NULL, adapter TEXT NOT NULL,
            active TEXT, snapshot TEXT, staged TEXT, staged_snapshot TEXT, staged_version INTEGER,
            retiring TEXT, last_seq INTEGER NOT NULL DEFAULT 0, keyring_floor INTEGER NOT NULL DEFAULT 0
          ) STRICT;
        `);
        const adapter = policy.adapter ?? 'sqlcipher';
        catalog.prepare('INSERT OR IGNORE INTO catalog (singleton, vault_id, adapter) VALUES (1, ?, ?)')
          .run(vaultId, adapter);
        syncDirectory(directory);
        const state = readCatalog(catalog);
        if (state.vault_id !== vaultId || state.adapter !== adapter) {
          throw new IndexError('CONFIG', 'Index directory belongs to a different vault or adapter.');
        }
        return work({ directory, vault, vaultId, keyring: join(vault, 'keyring', 'keyring.json'),
          policy, catalog, options: opts });
      } finally {
        catalog.close();
      }
    });
  } finally {
    lock.close();
  }
}

function indexPath(ctx: Context, id: string): string {
  return join(ctx.directory, `generation-${id}.sqlite`);
}

function removeFile(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as { code?: string }).code !== 'ENOENT') throw error;
  }
}

function syncPath(path: string, mode: 'r' | 'r+'): void {
  const fd = openSync(path, mode);
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function syncDirectory(path: string): void {
  // Node cannot open a directory as an ordinary file descriptor on Windows.
  if (platform !== 'win32') syncPath(path, 'r');
}

function removeGeneration(ctx: Context, id: string): void {
  const path = indexPath(ctx, id);
  for (const suffix of ['-journal', '-wal', '-shm', '']) removeFile(path + suffix);
  syncDirectory(ctx.directory);
}

function retirePending(ctx: Context): void {
  const { retiring } = readCatalog(ctx.catalog);
  if (!retiring) return;
  retireIndexKey(ctx.keyring, ctx.vaultId, ctx.options.credential, retiring);
  removeGeneration(ctx, retiring);
  ctx.catalog.exec('UPDATE catalog SET retiring=NULL WHERE singleton=1');
}

// Catalog stamps bind staged progress to an append-only replay boundary, the
// relevant keyring entries and the deriver. Index-only key updates do not move it.
function policyHash(bytes: Buffer): string {
  const ring = JSON.parse(bytes.toString()) as {
    keys: { kind: string }[]; master: unknown; kdf: unknown;
  };
  return hash(JSON.stringify([ring.kdf, ring.master,
    ring.keys.filter(entry => entry.kind !== 'index')]));
}

function capture(ctx: Context) {
  const raw = readFileSync(ctx.keyring);
  const ring = decodeKeyring(raw, ctx.options.credential, ctx.vaultId);
  let replay: ReturnType<typeof openVaultReplay> | undefined;
  try {
    if (ring.keyring.version < readCatalog(ctx.catalog).keyring_floor) {
      throw new IndexError('PROJECTION', 'The vault keyring predates the index. Restore a current keyring.');
    }
    replay = openVaultReplay(ctx.vault, ctx.options.credential, ctx.options.verify);
    if (hash(raw) !== hash(readFileSync(ctx.keyring))) {
      throw new IndexError('PROJECTION', 'Vault keys changed during replay capture. Retry the index update.');
    }
    const policy = policyHash(raw);
    const stamp = hash(JSON.stringify([replay.boundary, policy]));
    const tombstone = new Uint8Array(hkdfSync('sha256', ring.masterKey,
      Uint8Array.from(ctx.vaultId.match(/../gu)!, byte => Number.parseInt(byte, 16)),
      new TextEncoder().encode('foundry/tombstone/v1'), 32));
    return {
      replay, ring, stamp, tombstone,
      checkKeys() {
        if (policyHash(readFileSync(ctx.keyring)) !== policy) {
          throw new IndexError('PROJECTION', 'Vault erasure or key rotation changed during indexing. Retry.');
        }
      },
      close() {
        tombstone.fill(0);
        replay?.close();
        for (const key of ring.keys.values()) key.fill(0);
      },
    };
  } catch (error) {
    replay?.close();
    for (const key of ring.keys.values()) key.fill(0);
    throw error;
  } finally {
    ring.masterKey.fill(0);
    ring.labels.clear();
  }
}

type Capture = ReturnType<typeof capture>;

function published<T>(ctx: Context, input: Capture, id: string, work: (db: SqlDriver) => T): T {
  const entry = input.ring.keyring.keys.find(key => key.key_id === id);
  if (entry?.kind !== 'index' || entry.state !== 'active') {
    throw new IndexError('KEY', 'The published index generation key is unavailable. Rebuild the working index.');
  }
  const key = ctx.policy.adapter === 'plain' ? undefined : input.ring.keys.get(id);
  const db = openSqlDriver(indexPath(ctx, id), { ...ctx.policy, key });
  try {
    assertSchema(db);
    return work(db);
  } finally {
    db.close();
  }
}

function rebuildLocked(ctx: Context, input: Capture, hiddenChanged = false): ProjectionResult {
  const version = validateVersion(ctx.options.projection ?? {});
  const state = readCatalog(ctx.catalog);
  if (input.replay.boundary.lastEventSequence < state.last_seq) {
    throw new IndexError('PROJECTION', 'The vault is older than the last indexed event.');
  }
  let id = state.staged;
  const stagedKey = input.ring.keyring.keys.find(key => key.key_id === id);
  if (id && (state.staged_snapshot !== input.stamp || state.staged_version !== version ||
      (stagedKey ? stagedKey.state !== 'active' : existsSync(indexPath(ctx, id))))) {
    // If the process stopped before staging a key, no entry exists to retire.
    if (stagedKey) retireIndexKey(ctx.keyring, ctx.vaultId, ctx.options.credential, id);
    ctx.catalog.exec('UPDATE catalog SET staged=NULL, staged_snapshot=NULL, staged_version=NULL WHERE singleton=1');
    removeGeneration(ctx, id);
    id = null;
  }
  if (!id) {
    id = randomBytes(16).toString('hex');
    ctx.catalog.prepare('UPDATE catalog SET staged=?, staged_snapshot=?, staged_version=? WHERE singleton=1')
      .run(id, input.stamp, version);
  }
  const path = indexPath(ctx, id);
  const key = stageIndexKey(ctx.keyring, ctx.vaultId, ctx.options.credential, id);
  let result: ProjectionResult;
  try {
    const stagedFile = lstatSync(path, { throwIfNoEntry: false });
    const empty = stagedFile?.isFile() && stagedFile.size === 0;
    if (empty) removeGeneration(ctx, id);
    const db = openSqlDriver(path, { ...ctx.policy, key: ctx.policy.adapter === 'plain' ? undefined : key,
      create: !stagedFile || empty });
    try {
      initializeSchema(db);
      result = applyRebuild(db, input.replay, ctx.options.projection, input.tombstone);
      const checkpoint = db.prepare('PRAGMA wal_checkpoint(TRUNCATE)').get();
      if (checkpoint?.busy !== 0) throw new IndexError('PROJECTION', 'Could not checkpoint the rebuilt index.');
    } finally {
      db.close();
    }
  } finally {
    key.fill(0);
  }
  syncPath(path, 'r+');
  syncDirectory(ctx.directory);
  input.checkKeys();
  ctx.catalog.prepare(`
    UPDATE catalog SET active=?, snapshot=?, last_seq=?, retiring=active,
      staged=NULL, staged_snapshot=NULL, staged_version=NULL, keyring_floor=? WHERE singleton=1
  `).run(id, input.stamp, result.lastEventSeq, input.ring.keyring.version);
  ctx.options.afterPublish?.();
  retirePending(ctx);
  return { ...result, hiddenChanged };
}

function updateLocked(ctx: Context, input: Capture): ProjectionResult {
  const { active, staged, snapshot, last_seq: last } = readCatalog(ctx.catalog);
  if (input.replay.boundary.lastEventSequence < last) {
    throw new IndexError('PROJECTION', 'The vault is older than the last indexed event.');
  }
  if (staged || !active) return rebuildLocked(ctx, input);

  let hiddenChanged = false;
  try {
    return published(ctx, input, active, db => {
      const version = validateVersion(ctx.options.projection ?? {});
      const current = db.prepare("SELECT deriver_version, last_event_seq FROM projection_state WHERE projection='complete'").get();
      if (current?.deriver_version !== version) throw requiresRebuild;
      if (snapshot === input.stamp && current.last_event_seq === last) {
        input.checkKeys();
        return { lastEventSeq: last, skipped: input.replay.skipped, hiddenChanged: false };
      }
      const result = applyIncremental(db, input.replay, ctx.options.projection, input.tombstone, changed => {
        hiddenChanged = changed;
        if (changed) throw requiresRebuild;
      }, input.checkKeys);
      ctx.catalog.prepare('UPDATE catalog SET snapshot=?, last_seq=?, keyring_floor=? WHERE singleton=1')
        .run(input.stamp, result.lastEventSeq, input.ring.keyring.version);
      return result;
    });
  } catch (error) {
    if (error !== requiresRebuild) throw error;
    return rebuildLocked(ctx, input, hiddenChanged);
  }
}

function withCapture<T>(opts: IndexStoreOptions, work: (ctx: Context, input: Capture) => T): T {
  return withCatalog(opts, ctx => {
    retirePending(ctx);
    const input = capture(ctx);
    try {
      return work(ctx, input);
    } finally {
      input.close();
    }
  });
}

export function updateIndex(options: IndexStoreOptions): ProjectionResult {
  return withCapture(options, updateLocked);
}

export function rebuildIndex(options: IndexStoreOptions): ProjectionResult {
  return withCapture(options, (ctx, input) => rebuildLocked(ctx, input));
}

/** Search only a current generation. Updating or rebuilding has a separate memory budget. */
export function searchIndex(options: IndexStoreOptions, query: string, filters?: SearchOptions) {
  return withCatalog(options, ctx => {
    const { active, snapshot, last_seq: last, staged, retiring } = readCatalog(ctx.catalog);
    const stale = () => new IndexError('PROJECTION', 'Working index is stale. Update or rebuild it before searching.');
    if (!active || staged || retiring) throw stale();
    const input = capture(ctx);
    try {
      if (snapshot !== input.stamp) throw stale();
      return published(ctx, input, active, db => {
        const current = db.prepare("SELECT deriver_version, last_event_seq FROM projection_state WHERE projection='complete'").get();
        if (current?.deriver_version !== validateVersion(options.projection ?? {}) || current.last_event_seq !== last) {
          throw stale();
        }
        const hits = search(db, query, filters);
        input.checkKeys();
        return hits;
      });
    } finally {
      input.close();
    }
  });
}

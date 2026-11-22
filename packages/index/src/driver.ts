import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { DatabaseSync } from 'node:sqlite';

export type SqlValue = null | string | number | bigint | Uint8Array;
export type SqlRow = Record<string, SqlValue>;

export interface SqlStatement {
  run(...values: SqlValue[]): { changes: number | bigint };
  get(...values: SqlValue[]): SqlRow | undefined;
  all(...values: SqlValue[]): SqlRow[];
  iterate(...values: SqlValue[]): IterableIterator<SqlRow>;
}

export interface SqlDriver {
  exec(sql: string): void;
  prepare(sql: string): SqlStatement;
  close(): void;
}

type NativeDriver = SqlDriver & { pragma(sql: string, options: { simple: true }): unknown };
type Addon = new (path: string, options: { fileMustExist: boolean; timeout: number }) => NativeDriver;

export class IndexError extends Error {
  constructor(
    public readonly code: 'ADDON' | 'KEY' | 'FORMAT' | 'CONFIG' | 'EXTENSION' | 'PLAIN_POLICY' | 'PROJECTION',
    message: string,
  ) {
    super(message);
    this.name = 'IndexError';
  }
}

export type IndexPolicy =
  | { adapter?: 'sqlcipher' }
  | { adapter: 'plain'; allowPlain?: boolean; checkDiskEncryption?: (path: string) => boolean };

export type OpenOptions = IndexPolicy & { key?: Uint8Array; create?: boolean };
const require = createRequire(import.meta.url);
const timeout = 5000;

export const SQLCIPHER_PARAMETERS = Object.freeze([
  ['cipher', "'sqlcipher'", 'sqlcipher'],
  ['legacy', 4, 4],
  ['legacy_page_size', 4096, 4096],
  ['kdf_iter', 256000, 256000],
  ['fast_kdf_iter', 2, 2],
  ['hmac_use', 1, 1],
  ['hmac_check', 1, 1],
  ['hmac_pgno', 1, 1],
  ['hmac_salt_mask', 58, 58],
  ['hmac_algorithm', 2, 2],
  ['kdf_algorithm', 2, 2],
  ['plaintext_header_size', 0, 0],
  ['temp_store', 'MEMORY', 2],
  ['secure_delete', 'ON', 1],
] as const);
for (const parameter of SQLCIPHER_PARAMETERS) Object.freeze(parameter);

function openCipher(path: string, key: Uint8Array | undefined, create: boolean): NativeDriver {
  if (key?.byteLength !== 32) throw new IndexError('KEY', 'SQLCipher requires a raw 32-byte index key.');
  let db: NativeDriver;
  try {
    const Database = require('better-sqlite3-multiple-ciphers') as Addon;
    db = new Database(path, { fileMustExist: !create, timeout });
  } catch (error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string' && code.startsWith('SQLITE_')) {
      throw new IndexError('FORMAT', 'SQLCipher could not open the index file.');
    }
    throw new IndexError('ADDON', 'SQLCipher native addon could not load for this Node runtime.');
  }

  try {
    for (const [name, setting] of SQLCIPHER_PARAMETERS) {
      db.pragma(`${name} = ${setting}`, { simple: true });
    }
    const bytes = Buffer.from(key);
    try {
      db.pragma(`key = "x'${bytes.toString('hex')}'"`, { simple: true });
    } finally {
      bytes.fill(0);
    }
    for (const [name, , expected] of SQLCIPHER_PARAMETERS) {
      if (String(db.pragma(name, { simple: true })) !== String(expected)) {
        throw new IndexError('CONFIG', `SQLCipher rejected the pinned ${name} setting.`);
      }
    }
    return db;
  } catch (error) {
    db.close();
    if (error instanceof IndexError) throw error;
    throw new IndexError('CONFIG', 'SQLCipher could not apply the pinned settings.');
  }
}

/** The disk check must affirm encryption for the volume containing this path. */
export function assertIndexPolicy(path: string, policy: IndexPolicy): void {
  if (policy.adapter !== undefined && policy.adapter !== 'sqlcipher' && policy.adapter !== 'plain') {
    throw new IndexError('CONFIG', 'Unknown index adapter.');
  }
  if (policy.adapter === 'plain' &&
      (policy.allowPlain !== true || policy.checkDiskEncryption?.(path) !== true)) {
    throw new IndexError('PLAIN_POLICY', 'Plain SQLite requires explicit opt-in and confirmed disk encryption.');
  }
}

/** Open the actual index file. File creation must be requested explicitly. */
export function openSqlDriver(path: string, options: OpenOptions = {}): SqlDriver {
  assertIndexPolicy(path, options);
  const create = options.create === true;
  let db: SqlDriver;
  if (options.adapter === 'plain') {
    try {
      // readOnly would prevent updating existing indexes. The filesystem check
      // happens before opening; managed generation operations serialize callers.
      if (!create && !existsSync(path)) throw new IndexError('FORMAT', 'Plain SQLite index file is missing.');
      db = new DatabaseSync(path, { timeout, allowExtension: false });
    } catch {
      throw new IndexError('FORMAT', 'Plain SQLite could not open the index file.');
    }
  } else {
    db = openCipher(path, options.key, create);
  }
  try {
    if (options.adapter === 'plain') db.exec('PRAGMA temp_store = MEMORY; PRAGMA secure_delete = ON;');
    const extensions = db.prepare("SELECT sqlite_compileoption_used('ENABLE_FTS5') AS fts, " +
      "sqlite_compileoption_used('ENABLE_RTREE') AS rtree").get();
    if (extensions?.fts !== 1 || extensions.rtree !== 1) {
      throw new IndexError('EXTENSION', 'The SQLite binary must support FTS5 and R-tree.');
    }
    db.prepare('SELECT count(*) FROM sqlite_schema').get();
    if (db.prepare('PRAGMA journal_mode = WAL').get()?.journal_mode !== 'wal') {
      throw new IndexError('CONFIG', 'The working index requires WAL journaling.');
    }
    db.exec('PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON; PRAGMA cache_size = -4096;');
    return db;
  } catch (error) {
    db.close();
    if (error instanceof IndexError) throw error;
    throw new IndexError('FORMAT', 'SQLite rejected the index format or encryption key.');
  }
}

export function transaction<T>(db: SqlDriver, work: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = work();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

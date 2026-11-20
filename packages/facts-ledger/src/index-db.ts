import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  realpathSync,
  statSync,
  unlinkSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { DatabaseSync, type SqlStatementSync } from 'node:sqlite';
import {
  compareBytewise,
  readLogHeaderFromFd,
  readLogHeaderState,
  replaceFileWithRetry,
  scanFdRange,
} from './log.js';
import { normalizeBlockFactsAndRetractions } from './normalize.js';
import {
  type Block,
  type IndexState,
  type IndexSyncResult,
  type ScanReport,
} from './types.js';

export const INDEX_SCHEMA_VERSION = 4;

const REQUIRED_INDEX_TABLES = [
  'blocks',
  'facts',
  'fact_tags',
  'fact_evidence',
  'fact_retractions',
  'fact_supersessions',
  'facts_fts',
  'state',
] as const;

interface DerivedTableCounts {
  readonly blocksCount: number;
  readonly factsCount: number;
  readonly factTagsCount: number;
  readonly factEvidenceCount: number;
  readonly factRetractionsCount: number;
  readonly factSupersessionsCount: number;
}

function canonicalPath(target: string): string {
  if (existsSync(target)) {
    return realpathSync(target);
  }
  const dir = dirname(target);
  if (existsSync(dir)) {
    return join(realpathSync(dir), basename(target));
  }
  return resolve(target);
}

function safeBigIntStat(target: string): { dev: bigint; ino: bigint } | null {
  try {
    const stat = statSync(target, { bigint: true });
    return { dev: stat.dev, ino: stat.ino };
  } catch {
    return null;
  }
}

/** Reject index paths that resolve to the source ledger log or its lock file. */
export function assertDistinctIndexPath(logPath: string, indexPath: string): void {
  const lockPath = `${logPath}.lock.sqlite`;
  const idxResolved = resolve(indexPath);
  if (idxResolved === resolve(logPath) || idxResolved === resolve(lockPath)) {
    throw new Error(`Refusing to use log or lock path as indexPath: ${indexPath}`);
  }

  const idxCanon = canonicalPath(indexPath);
  for (const reserved of [logPath, lockPath]) {
    const reservedCanon = canonicalPath(reserved);
    if (idxCanon === reservedCanon) {
      throw new Error(`Refusing to overwrite log or lock path as indexPath: ${indexPath}`);
    }
    const idxStat = safeBigIntStat(indexPath);
    const resStat = safeBigIntStat(reserved);
    if (
      idxStat &&
      resStat &&
      idxStat.ino !== 0n &&
      idxStat.dev === resStat.dev &&
      idxStat.ino === resStat.ino
    ) {
      throw new Error(`Refusing to overwrite log or lock path sharing inode: ${indexPath}`);
    }
  }
}

function readDerivedTableCounts(db: DatabaseSync): DerivedTableCounts {
  const row = db
    .prepare(
      `SELECT
        (SELECT count(*) FROM blocks) AS b,
        (SELECT count(*) FROM facts) AS f,
        (SELECT count(*) FROM fact_tags) AS t,
        (SELECT count(*) FROM fact_evidence) AS e,
        (SELECT count(*) FROM fact_retractions) AS r,
        (SELECT count(*) FROM fact_supersessions) AS s`,
    )
    .get();
  return {
    blocksCount: Number(row?.['b'] ?? 0),
    factsCount: Number(row?.['f'] ?? 0),
    factTagsCount: Number(row?.['t'] ?? 0),
    factEvidenceCount: Number(row?.['e'] ?? 0),
    factRetractionsCount: Number(row?.['r'] ?? 0),
    factSupersessionsCount: Number(row?.['s'] ?? 0),
  };
}

function verifySchemaAndQuickCheck(db: DatabaseSync): boolean {
  try {
    const rows = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all();
    const present = new Set(rows.map((r) => String(r['name'])));
    for (const table of REQUIRED_INDEX_TABLES) {
      if (!present.has(table)) return false;
    }
    const qc = db.prepare('PRAGMA quick_check').get();
    return Boolean(qc && qc['quick_check'] === 'ok');
  } catch {
    return false;
  }
}

function verifyIndexIntegrity(db: DatabaseSync, saved: IndexState): boolean {
  try {
    const counts = readDerivedTableCounts(db);
    if (
      counts.blocksCount !== saved.blocksCount ||
      counts.factsCount !== saved.factsCount ||
      counts.factTagsCount !== saved.factTagsCount ||
      counts.factEvidenceCount !== saved.factEvidenceCount ||
      counts.factRetractionsCount !== saved.factRetractionsCount ||
      counts.factSupersessionsCount !== saved.factSupersessionsCount
    ) {
      return false;
    }

    const orphanQueries = [
      'SELECT 1 FROM facts f WHERE NOT EXISTS (SELECT 1 FROM blocks b WHERE b.id = f.block_id) LIMIT 1',
      'SELECT 1 FROM fact_tags t WHERE NOT EXISTS (SELECT 1 FROM facts f WHERE f.fact_id = t.fact_id) LIMIT 1',
      'SELECT 1 FROM fact_evidence e WHERE NOT EXISTS (SELECT 1 FROM facts f WHERE f.fact_id = e.fact_id) LIMIT 1',
      'SELECT 1 FROM fact_retractions r WHERE NOT EXISTS (SELECT 1 FROM blocks b WHERE b.id = r.block_id) LIMIT 1',
      'SELECT 1 FROM fact_supersessions s WHERE NOT EXISTS (SELECT 1 FROM blocks b WHERE b.id = s.block_id) LIMIT 1',
    ];
    for (const sql of orphanQueries) {
      if (db.prepare(sql).get()) {
        return false;
      }
    }

    db.exec("INSERT INTO facts_fts(facts_fts, rank) VALUES('integrity-check', 1);");
    return true;
  } catch {
    return false;
  }
}

/** Return the default sidecar index filename (`facts.index.sqlite`) next to `logPath`. */
export function defaultIndexPath(logPath: string): string {
  return join(dirname(logPath), 'facts.index.sqlite');
}

function createSchema(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE blocks (
      id TEXT PRIMARY KEY COLLATE BINARY,
      ts TEXT NOT NULL COLLATE BINARY,
      agent TEXT NOT NULL COLLATE BINARY,
      project TEXT NOT NULL COLLATE BINARY,
      parent TEXT COLLATE BINARY,
      trace_id TEXT COLLATE BINARY,
      status TEXT COLLATE BINARY,
      intent TEXT NOT NULL COLLATE BINARY,
      reasoning TEXT NOT NULL COLLATE BINARY,
      supersedes TEXT COLLATE BINARY,
      schema INTEGER,
      line_number INTEGER NOT NULL
    );

    CREATE TABLE facts (
      fact_id TEXT NOT NULL UNIQUE COLLATE BINARY,
      block_id TEXT NOT NULL COLLATE BINARY,
      project TEXT NOT NULL COLLATE BINARY,
      tier TEXT NOT NULL COLLATE BINARY,
      scope TEXT NOT NULL COLLATE BINARY,
      check_json TEXT COLLATE BINARY,
      claim TEXT NOT NULL COLLATE BINARY,
      note TEXT NOT NULL COLLATE BINARY,
      sensitivity TEXT NOT NULL COLLATE BINARY,
      verified_at TEXT NOT NULL COLLATE BINARY,
      supersedes TEXT COLLATE BINARY
    );

    CREATE INDEX facts_block_idx ON facts (block_id, fact_id);
    CREATE INDEX facts_supersedes_idx ON facts (supersedes, fact_id);
    CREATE INDEX facts_project_idx ON facts (project, fact_id);

    CREATE TABLE fact_tags (
      fact_id TEXT NOT NULL COLLATE BINARY,
      tag TEXT NOT NULL COLLATE BINARY,
      PRIMARY KEY (tag, fact_id)
    );

    CREATE INDEX fact_tags_by_fact_idx ON fact_tags (fact_id, tag);

    CREATE TABLE fact_evidence (
      fact_id TEXT NOT NULL COLLATE BINARY,
      evidence_idx INTEGER NOT NULL,
      type TEXT NOT NULL COLLATE BINARY,
      repo TEXT COLLATE BINARY,
      path TEXT COLLATE BINARY,
      commit_id TEXT COLLATE BINARY,
      blob TEXT COLLATE BINARY,
      body TEXT NOT NULL COLLATE BINARY,
      PRIMARY KEY (fact_id, evidence_idx)
    );

    CREATE INDEX fact_evidence_repo_path_idx ON fact_evidence (repo, path, fact_id);
    CREATE INDEX fact_evidence_path_idx ON fact_evidence (path, fact_id);
    CREATE INDEX fact_evidence_commit_idx ON fact_evidence (commit_id, fact_id);
    CREATE INDEX fact_evidence_repo_idx ON fact_evidence (repo, fact_id);

    CREATE TABLE fact_retractions (
      fact_id TEXT PRIMARY KEY COLLATE BINARY,
      block_id TEXT NOT NULL COLLATE BINARY,
      reason TEXT NOT NULL COLLATE BINARY
    );

    CREATE TABLE fact_supersessions (
      superseded_fact_id TEXT PRIMARY KEY COLLATE BINARY,
      block_id TEXT NOT NULL COLLATE BINARY
    );

    CREATE VIRTUAL TABLE facts_fts USING fts5(
      claim,
      note,
      content='facts',
      content_rowid='rowid'
    );

    CREATE TABLE state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      schema_version INTEGER NOT NULL,
      log_bytes INTEGER NOT NULL,
      head_sha256 TEXT NOT NULL COLLATE BINARY,
      tail_sha256 TEXT NOT NULL COLLATE BINARY,
      log_mtime_ns TEXT NOT NULL COLLATE BINARY,
      log_ctime_ns TEXT NOT NULL COLLATE BINARY,
      log_ino TEXT NOT NULL COLLATE BINARY,
      indexed_offset INTEGER NOT NULL,
      next_line_number INTEGER NOT NULL,
      complete_bad_lines_json TEXT NOT NULL COLLATE BINARY,
      tail_incomplete INTEGER NOT NULL,
      blocks_count INTEGER NOT NULL,
      facts_count INTEGER NOT NULL,
      fact_tags_count INTEGER NOT NULL,
      fact_evidence_count INTEGER NOT NULL,
      fact_retractions_count INTEGER NOT NULL,
      fact_supersessions_count INTEGER NOT NULL
    );
  `);
}

interface PreparedIngest {
  readonly insertBlock: SqlStatementSync;
  readonly insertFact: SqlStatementSync;
  readonly insertTag: SqlStatementSync;
  readonly insertEvidence: SqlStatementSync;
  readonly insertRetraction: SqlStatementSync;
  readonly insertSupersession: SqlStatementSync;
  readonly insertFts: SqlStatementSync;
}

function prepareIngest(db: DatabaseSync): PreparedIngest {
  return {
    insertBlock: db.prepare(
      `INSERT OR IGNORE INTO blocks
        (id, ts, agent, project, parent, trace_id, status, intent, reasoning, supersedes, schema, line_number)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ),
    insertFact: db.prepare(
      `INSERT OR IGNORE INTO facts
        (fact_id, block_id, project, tier, scope, check_json, claim, note, sensitivity, verified_at, supersedes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ),
    insertTag: db.prepare('INSERT OR IGNORE INTO fact_tags (fact_id, tag) VALUES (?, ?)'),
    insertEvidence: db.prepare(
      `INSERT OR IGNORE INTO fact_evidence
        (fact_id, evidence_idx, type, repo, path, commit_id, blob, body)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ),
    insertRetraction: db.prepare(
      'INSERT OR IGNORE INTO fact_retractions (fact_id, block_id, reason) VALUES (?, ?, ?)',
    ),
    insertSupersession: db.prepare(
      'INSERT OR IGNORE INTO fact_supersessions (superseded_fact_id, block_id) VALUES (?, ?)',
    ),
    insertFts: db.prepare('INSERT INTO facts_fts (rowid, claim, note) VALUES (?, ?, ?)'),
  };
}

function ingestBlock(stmts: PreparedIngest, block: Block, lineNumber: number): number {
  const blockRes = stmts.insertBlock.run(
    block.id,
    block.ts,
    block.agent,
    block.project,
    block.parent ?? null,
    block.trace_id ?? null,
    block.status ?? null,
    block.intent,
    block.reasoning,
    block.supersedes ?? null,
    typeof block.schema === 'number' ? block.schema : null,
    lineNumber,
  );
  if (blockRes.changes === 0) {
    return 0;
  }

  let factsAdded = 0;
  const { facts, retractions, supersessions } = normalizeBlockFactsAndRetractions(block);
  for (const sup of supersessions) {
    stmts.insertSupersession.run(sup.superseded_fact_id, block.id);
  }
  for (const fact of facts) {
    const factRes = stmts.insertFact.run(
      fact.fact_id,
      block.id,
      block.project,
      fact.tier,
      fact.scope,
      fact.checkJson,
      fact.claim,
      fact.note,
      fact.sensitivity,
      fact.verified_at,
      fact.supersedes,
    );
    if (factRes.changes === 0) continue;
    factsAdded++;
    stmts.insertFts.run(factRes.lastInsertRowid, fact.claim, fact.note);

    const uniqueTags = [...new Set(fact.tags)].sort(compareBytewise);
    for (const tag of uniqueTags) {
      stmts.insertTag.run(fact.fact_id, tag);
    }

    for (let idx = 0; idx < fact.evidence.length; idx++) {
      const ev = fact.evidence[idx];
      const evRecord = ev as unknown as Record<string, unknown>;
      stmts.insertEvidence.run(
        fact.fact_id,
        idx,
        ev.type,
        typeof evRecord['repo'] === 'string' ? evRecord['repo'] : null,
        typeof evRecord['path'] === 'string' ? evRecord['path'] : null,
        typeof evRecord['commit'] === 'string' ? evRecord['commit'] : null,
        typeof evRecord['blob'] === 'string' ? evRecord['blob'] : null,
        JSON.stringify(ev),
      );
    }
  }

  for (const ret of retractions) {
    stmts.insertRetraction.run(ret.fact_id, block.id, ret.reason);
  }

  return factsAdded;
}

function openReadOnlyIfExists(logPath: string): number | null {
  try {
    return openSync(logPath, 'r');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

function isNonNegativeSafeInt(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function readStateRow(db: DatabaseSync): IndexState | null {
  try {
    const row = db
      .prepare(
        `SELECT schema_version, log_bytes, head_sha256, tail_sha256, log_mtime_ns, log_ctime_ns, log_ino,
                indexed_offset, next_line_number, complete_bad_lines_json, tail_incomplete,
                blocks_count, facts_count, fact_tags_count, fact_evidence_count, fact_retractions_count, fact_supersessions_count
         FROM state WHERE id = 1`,
      )
      .get();
    if (!row) return null;
    if (
      typeof row['schema_version'] !== 'number' ||
      !isNonNegativeSafeInt(row['log_bytes']) ||
      typeof row['head_sha256'] !== 'string' ||
      typeof row['tail_sha256'] !== 'string' ||
      typeof row['log_mtime_ns'] !== 'string' ||
      typeof row['log_ctime_ns'] !== 'string' ||
      typeof row['log_ino'] !== 'string' ||
      !isNonNegativeSafeInt(row['indexed_offset']) ||
      row['indexed_offset'] > row['log_bytes'] ||
      typeof row['next_line_number'] !== 'number' ||
      !Number.isSafeInteger(row['next_line_number']) ||
      row['next_line_number'] < 1 ||
      typeof row['complete_bad_lines_json'] !== 'string' ||
      typeof row['tail_incomplete'] !== 'number' ||
      !isNonNegativeSafeInt(row['blocks_count']) ||
      !isNonNegativeSafeInt(row['facts_count']) ||
      !isNonNegativeSafeInt(row['fact_tags_count']) ||
      !isNonNegativeSafeInt(row['fact_evidence_count']) ||
      !isNonNegativeSafeInt(row['fact_retractions_count']) ||
      !isNonNegativeSafeInt(row['fact_supersessions_count'])
    ) {
      return null;
    }
    const parsedBad = JSON.parse(row['complete_bad_lines_json']) as unknown;
    if (!Array.isArray(parsedBad) || !parsedBad.every((n) => typeof n === 'number')) {
      return null;
    }
    return {
      schemaVersion: row['schema_version'],
      logBytes: row['log_bytes'],
      headSha256: row['head_sha256'],
      tailSha256: row['tail_sha256'],
      logMtimeNs: row['log_mtime_ns'],
      logCtimeNs: row['log_ctime_ns'],
      logIno: row['log_ino'],
      indexedOffset: row['indexed_offset'],
      nextLineNumber: row['next_line_number'],
      completeBadLines: parsedBad,
      tailIncomplete: row['tail_incomplete'] === 1,
      blocksCount: row['blocks_count'],
      factsCount: row['facts_count'],
      factTagsCount: row['fact_tags_count'],
      factEvidenceCount: row['fact_evidence_count'],
      factRetractionsCount: row['fact_retractions_count'],
      factSupersessionsCount: row['fact_supersessions_count'],
    };
  } catch {
    return null;
  }
}

function makeScanReport(completeBadLines: readonly number[], tailIncomplete: boolean, nextLineNumber: number): ScanReport {
  const badLineNumbers = tailIncomplete
    ? [...completeBadLines, nextLineNumber]
    : [...completeBadLines];
  return { badLineCount: badLineNumbers.length, badLineNumbers };
}

function saveState(
  db: DatabaseSync,
  header: {
    readonly size: number;
    readonly headSha256: string;
    readonly tailSha256: string;
    readonly mtimeNs: string;
    readonly ctimeNs: string;
    readonly ino: string;
  },
  counts: DerivedTableCounts,
  indexedOffset: number,
  nextLineNumber: number,
  completeBadLines: readonly number[],
  tailIncomplete: boolean,
): void {
  db.prepare('DELETE FROM state').run();
  db.prepare(
    `INSERT INTO state
      (id, schema_version, log_bytes, head_sha256, tail_sha256, log_mtime_ns, log_ctime_ns, log_ino,
       indexed_offset, next_line_number, complete_bad_lines_json, tail_incomplete,
       blocks_count, facts_count, fact_tags_count, fact_evidence_count, fact_retractions_count, fact_supersessions_count)
     VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    INDEX_SCHEMA_VERSION,
    header.size,
    header.headSha256,
    header.tailSha256,
    header.mtimeNs,
    header.ctimeNs,
    header.ino,
    indexedOffset,
    nextLineNumber,
    JSON.stringify(completeBadLines),
    tailIncomplete ? 1 : 0,
    counts.blocksCount,
    counts.factsCount,
    counts.factTagsCount,
    counts.factEvidenceCount,
    counts.factRetractionsCount,
    counts.factSupersessionsCount,
  );
}

/**
 * Rebuild the SQLite index from scratch in a temporary sibling file and atomically replace `indexPath`.
 * Ledger logs are append-only; run `facts rebuild` after any out-of-band manual edit or repair of historical lines.
 */
export function rebuildIndex(
  logPath: string,
  indexPath: string = defaultIndexPath(logPath),
): IndexSyncResult {
  assertDistinctIndexPath(logPath, indexPath);
  mkdirSync(dirname(indexPath), { recursive: true });
  const header = readLogHeaderState(logPath);
  const tempPath = `${indexPath}.tmp.${process.pid}.${randomUUID().replaceAll('-', '').slice(0, 8)}`;
  const db = new DatabaseSync(tempPath);
  let dbClosed = false;
  let logFd: number | null = null;
  let scanState = {
    completeBadLineNumbers: [] as readonly number[],
    tailIncomplete: false,
    nextLineNumber: 1,
    lastCompleteOffset: 0,
    blocksRead: 0,
  };

  try {
    db.exec('PRAGMA journal_mode = DELETE;');
    createSchema(db);
    const stmts = prepareIngest(db);

    db.exec('BEGIN');
    logFd = openReadOnlyIfExists(logPath);
    if (logFd !== null && header.size > 0) {
      scanState = scanFdRange(
        logFd,
        0,
        1,
        header.size,
        (block, lineNumber) => {
          ingestBlock(stmts, block, lineNumber);
        },
        false,
      );
    }
    if (logFd !== null) {
      closeSync(logFd);
      logFd = null;
    }

    const counts = readDerivedTableCounts(db);
    saveState(
      db,
      header,
      counts,
      scanState.lastCompleteOffset,
      scanState.nextLineNumber,
      scanState.completeBadLineNumbers,
      scanState.tailIncomplete,
    );
    db.exec('COMMIT');
    db.close();
    dbClosed = true;

    replaceFileWithRetry(tempPath, indexPath);

    return {
      indexPath,
      rebuilt: true,
      indexedBlocks: counts.blocksCount,
      indexedFacts: counts.factsCount,
      badLines: makeScanReport(
        scanState.completeBadLineNumbers,
        scanState.tailIncomplete,
        scanState.nextLineNumber,
      ),
    };
  } finally {
    if (logFd !== null) {
      try {
        closeSync(logFd);
      } catch {
        // Ignore cleanup errors on log fd.
      }
    }
    if (!dbClosed) {
      try {
        db.close();
      } catch {
        // Best-effort handle cleanup before removing temp file.
      }
    }
    if (existsSync(tempPath)) {
      try {
        unlinkSync(tempPath);
      } catch {
        // Ignore cleanup errors on temp file.
      }
    }
  }
}

function isWarmStateMatch(
  saved: IndexState,
  header: {
    readonly size: number;
    readonly headSha256: string;
    readonly tailSha256: string;
    readonly mtimeNs: string;
    readonly ctimeNs: string;
    readonly ino: string;
  },
): boolean {
  return (
    saved.schemaVersion === INDEX_SCHEMA_VERSION &&
    header.size === saved.logBytes &&
    header.headSha256 === saved.headSha256 &&
    header.tailSha256 === saved.tailSha256 &&
    header.mtimeNs === saved.logMtimeNs &&
    header.ctimeNs === saved.logCtimeNs &&
    header.ino === saved.logIno
  );
}

/**
 * Incrementally ingest only new appended bytes from `saved.indexedOffset` when the log grew cleanly
 * with matching first-4-KiB head hash and file inode; otherwise rebuild from scratch.
 * Ledger files are append-only — run `facts rebuild` after any manual edit to historical lines.
 */
export function syncIndex(
  logPath: string,
  indexPath: string = defaultIndexPath(logPath),
  options?: { readonly onReadRange?: (offset: number, length: number) => void },
): IndexSyncResult {
  assertDistinctIndexPath(logPath, indexPath);
  if (!existsSync(indexPath)) {
    return rebuildIndex(logPath, indexPath);
  }

  let db: DatabaseSync;
  try {
    db = new DatabaseSync(indexPath, { timeout: 5000 });
  } catch {
    return rebuildIndex(logPath, indexPath);
  }

  let inTxn = false;
  let dbClosed = false;
  let logFd: number | null = null;
  const onReadRange = options?.onReadRange;

  const closeLogFd = (): void => {
    if (logFd !== null) {
      try {
        closeSync(logFd);
      } catch {
        // Ignore cleanup close errors on log fd.
      }
      logFd = null;
    }
  };

  try {
    db.exec('PRAGMA journal_mode = DELETE;');
    db.exec('BEGIN IMMEDIATE');
    inTxn = true;

    if (!verifySchemaAndQuickCheck(db)) {
      db.exec('ROLLBACK');
      inTxn = false;
      db.close();
      dbClosed = true;
      return rebuildIndex(logPath, indexPath);
    }

    const saved = readStateRow(db);
    if (!saved || saved.schemaVersion !== INDEX_SCHEMA_VERSION || !verifyIndexIntegrity(db, saved)) {
      db.exec('ROLLBACK');
      inTxn = false;
      db.close();
      dbClosed = true;
      return rebuildIndex(logPath, indexPath);
    }

    logFd = openReadOnlyIfExists(logPath);
    const header =
      logFd !== null ? readLogHeaderFromFd(logFd, onReadRange) : readLogHeaderState(logPath);

    if (isWarmStateMatch(saved, header)) {
      const badLines = makeScanReport(
        saved.completeBadLines,
        saved.tailIncomplete,
        saved.nextLineNumber,
      );
      closeLogFd();
      db.exec('ROLLBACK');
      inTxn = false;
      return {
        indexPath,
        rebuilt: false,
        indexedBlocks: saved.blocksCount,
        indexedFacts: saved.factsCount,
        badLines,
      };
    }

    const sameFileInode =
      saved.logIno === header.ino || saved.logIno === '0' || header.ino === '0';
    if (
      logFd === null ||
      !header.exists ||
      header.size <= saved.logBytes ||
      header.headSha256 !== saved.headSha256 ||
      !sameFileInode
    ) {
      closeLogFd();
      db.exec('ROLLBACK');
      inTxn = false;
      db.close();
      dbClosed = true;
      return rebuildIndex(logPath, indexPath);
    }

    const stmts = prepareIngest(db);
    const scanState = scanFdRange(
      logFd,
      saved.indexedOffset,
      saved.nextLineNumber,
      header.size,
      (block, lineNumber) => {
        ingestBlock(stmts, block, lineNumber);
      },
      false,
      onReadRange,
    );
    closeLogFd();

    const combinedBadLines = [
      ...saved.completeBadLines,
      ...scanState.completeBadLineNumbers,
    ];
    const counts = readDerivedTableCounts(db);
    saveState(
      db,
      header,
      counts,
      scanState.lastCompleteOffset,
      scanState.nextLineNumber,
      combinedBadLines,
      scanState.tailIncomplete,
    );
    db.exec('COMMIT');
    inTxn = false;

    return {
      indexPath,
      rebuilt: false,
      indexedBlocks: counts.blocksCount,
      indexedFacts: counts.factsCount,
      badLines: makeScanReport(
        combinedBadLines,
        scanState.tailIncomplete,
        scanState.nextLineNumber,
      ),
    };
  } catch {
    closeLogFd();
    if (inTxn) {
      try {
        db.exec('ROLLBACK');
      } catch {
        // Ignore rollback failure on corrupt db before rebuild.
      }
      inTxn = false;
    }
    if (!dbClosed) {
      try {
        db.close();
        dbClosed = true;
      } catch {
        // Fall back to clean rebuild on any corrupt or schema-mismatched index.
      }
    }
    return rebuildIndex(logPath, indexPath);
  } finally {
    closeLogFd();
    if (inTxn) {
      try {
        db.exec('ROLLBACK');
      } catch {
        // Ignore cleanup rollback errors.
      }
    }
    if (!dbClosed) {
      try {
        db.close();
      } catch {
        // Ignore cleanup close errors.
      }
    }
  }
}

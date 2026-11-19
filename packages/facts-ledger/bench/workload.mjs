import { createHash } from 'node:crypto';
import {
  closeSync, fstatSync, fsyncSync, openSync, readSync, renameSync, writeFileSync, writeSync,
} from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { block, blockCount, line, project } from './fixture.mjs';

// Measurement prototype for the generated fixture. Later packages own the ledger implementation.
const [operation, directory] = process.argv.slice(2);
const log = `${directory}/ledger.jsonl`;
const index = `${directory}/facts.index.sqlite`;
const started = process.hrtime.bigint();

function state() {
  const fd = openSync(log, 'r');
  try {
    const bytes = Buffer.alloc(4096);
    const length = readSync(fd, bytes, 0, bytes.length, 0);
    return {
      bytes: fstatSync(fd).size,
      head: createHash('sha256').update(bytes.subarray(0, length)).digest('hex'),
    };
  } finally {
    closeSync(fd);
  }
}

function createSchema(db) {
  db.exec(`
    CREATE TABLE blocks (id TEXT PRIMARY KEY, ts TEXT, project TEXT, status TEXT, intent TEXT);
    CREATE TABLE facts (id TEXT NOT NULL UNIQUE, tier TEXT, claim TEXT, note TEXT, verified_at TEXT);
    CREATE TABLE fact_tags (fact_id TEXT, tag TEXT, PRIMARY KEY (tag, fact_id));
    CREATE TABLE fact_evidence (fact_id TEXT, repo TEXT, path TEXT, commit_id TEXT, body TEXT);
    CREATE INDEX evidence_path ON fact_evidence (repo, path, fact_id);
    CREATE INDEX evidence_commit ON fact_evidence (commit_id, fact_id);
    CREATE VIRTUAL TABLE facts_fts USING fts5(claim, note, content='facts', content_rowid='rowid');
    CREATE TABLE state (bytes INTEGER, head TEXT);
  `);
}

function ingest(db, offset, current) {
  const insertBlock = db.prepare('INSERT INTO blocks VALUES (?, ?, ?, ?, ?)');
  const insertFact = db.prepare('INSERT INTO facts VALUES (?, ?, ?, ?, ?)');
  const insertTag = db.prepare('INSERT INTO fact_tags VALUES (?, ?)');
  const insertEvidence = db.prepare('INSERT INTO fact_evidence VALUES (?, ?, ?, ?, ?)');
  const insertSearch = db.prepare('INSERT INTO facts_fts (rowid, claim, note) VALUES (?, ?, ?)');
  const fd = openSync(log, 'r');
  try {
    const buffer = Buffer.alloc(64 * 1024);
    const decoder = new TextDecoder();
    let pending = '';
    db.exec('BEGIN');
    while (offset < current.bytes) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, current.bytes - offset), offset);
      if (!count) throw new Error('Fixture ended during ingestion');
      offset += count;
      pending += decoder.decode(buffer.subarray(0, count), { stream: true });
      let start = 0;
      for (let end = pending.indexOf('\n'); end !== -1; end = pending.indexOf('\n', start)) {
        const record = JSON.parse(pending.slice(start, end));
        start = end + 1;
        insertBlock.run(record.id, record.ts, record.project, record.status, record.intent);
        for (const fact of record.facts) {
          const row = insertFact.run(fact.fact_id, fact.tier, fact.claim, fact.note, fact.verified_at);
          insertSearch.run(row.lastInsertRowid, fact.claim, fact.note);
          for (const tag of fact.tags) insertTag.run(fact.fact_id, tag);
          for (const evidence of fact.evidence) {
            insertEvidence.run(fact.fact_id, evidence.repo, evidence.path, evidence.commit, JSON.stringify(evidence));
          }
        }
      }
      pending = pending.slice(start);
    }
    if (pending + decoder.decode()) throw new Error('Incomplete fixture line');
    db.exec('DELETE FROM state');
    db.prepare('INSERT INTO state VALUES (?, ?)').run(current.bytes, current.head);
    db.exec('COMMIT');
  } finally {
    closeSync(fd);
  }
}

function digest(db) {
  const target = `${directory}/digest.${project}.md`;
  const { count } = db.prepare('SELECT count(*) AS count FROM facts').get();
  const { date } = db.prepare('SELECT substr(max(ts), 1, 10) AS date FROM blocks').get();
  let output = `# ${project}\n\n${date} | ${count} asserted facts\n`;
  let included = 0;
  const sections = [
    db.prepare("SELECT 'A ' || claim AS line, 1 AS fact FROM facts JOIN fact_tags ON fact_id = id WHERE tag = 'pinned' ORDER BY tier, id"),
    db.prepare("SELECT '- ' || intent AS line, 0 AS fact FROM blocks WHERE status = 'proposed' ORDER BY ts DESC, id"),
    db.prepare("SELECT '- ' || intent AS line, 0 AS fact FROM blocks WHERE status = 'done' ORDER BY ts DESC, id"),
    db.prepare("SELECT 'A ' || claim AS line, 1 AS fact FROM facts WHERE id NOT IN (SELECT fact_id FROM fact_tags WHERE tag = 'pinned') ORDER BY verified_at DESC, id"),
  ];
  const footer = (remaining) => `\n${remaining} facts omitted. Run facts query --repo ${project}.\n`;
  fill: for (const section of sections) {
    for (const row of section.iterate()) {
      if (Buffer.byteLength(output + row.line + '\n' + footer(count - included - row.fact)) > 6000) break fill;
      output += row.line + '\n';
      included += row.fact;
    }
  }
  output += footer(count - included);
  writeFileSync(`${target}.new`, output);
  renameSync(`${target}.new`, target);
  return Buffer.byteLength(output);
}

function append(db) {
  const lock = new DatabaseSync(`${log}.lock.sqlite`, { timeout: 5000 });
  try {
    lock.exec('BEGIN IMMEDIATE');
    const before = state();
    const parent = db.prepare('SELECT id FROM blocks ORDER BY id DESC LIMIT 1').get().id;
    const fd = openSync(log, 'a+');
    try {
      const lastByte = Buffer.alloc(1);
      if (readSync(fd, lastByte, 0, 1, before.bytes - 1) !== 1 || lastByte[0] !== 10) {
        throw new Error('Expected a complete fixture line before append');
      }
      const bytes = Buffer.from(line(block(blockCount + 1, parent)));
      if (writeSync(fd, bytes) !== bytes.length) throw new Error('Short fixture append');
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    ingest(db, before.bytes, state());
    lock.exec('COMMIT');
  } finally {
    lock.close();
  }
  return digest(db);
}

function run() {
  if (operation === 'fts5') {
    const db = new DatabaseSync(':memory:');
    try {
      db.exec("CREATE VIRTUAL TABLE probe USING fts5(body); INSERT INTO probe VALUES ('calibration sample');");
      return db.prepare("SELECT sqlite_version() AS sqlite, count(*) AS matches FROM probe WHERE probe MATCH 'calibration'").get();
    } finally {
      db.close();
    }
  }

  const db = new DatabaseSync(index);
  try {
    const current = state();
    if (['seed', 'rebuild', 'query-cold'].includes(operation)) {
      createSchema(db);
      ingest(db, 0, current);
    } else {
      const saved = db.prepare('SELECT bytes, head FROM state').get();
      if (saved.bytes !== current.bytes || saved.head !== current.head) throw new Error('Fixture index is stale');
    }
    switch (operation) {
      case 'cold-start':
        return { logBytes: current.bytes };
      case 'seed':
      case 'rebuild':
        return db.prepare('SELECT count(*) AS blocks FROM blocks').get();
      case 'append': {
        const digestBytes = append(db);
        return { ...db.prepare('SELECT count(*) AS blocks FROM blocks').get(), digestBytes };
      }
      case 'query-warm':
      case 'query-cold': {
        const rows = db.prepare(`
          SELECT facts.id, facts.claim, facts.note FROM facts_fts
          JOIN facts ON facts.rowid = facts_fts.rowid
          WHERE facts_fts MATCH 'calibration AND sample' ORDER BY rank, facts.id LIMIT 20
        `).all();
        return { matches: rows.length, resultBytes: Buffer.byteLength(JSON.stringify(rows)) };
      }
      case 'digest':
        return { digestBytes: digest(db) };
      default:
        throw new Error('Unknown benchmark operation');
    }
  } finally {
    db.close();
  }
}

const result = run();
if (operation !== 'seed') {
  const innerMs = Number(process.hrtime.bigint() - started) / 1e6;
  const innerKiB = process.resourceUsage().maxRSS;
  writeSync(1, JSON.stringify({ operation, innerMs, innerKiB, ...result }) + '\n');
  // Hold the process for the parent to read the OS high-water counter. EOF also releases it.
  readSync(0, Buffer.alloc(1));
}

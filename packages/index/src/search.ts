import { IndexError } from './driver.ts';
import type { SqlDriver, SqlValue } from './driver.ts';

export interface SearchOptions {
  from?: string;
  until?: string;
  source?: string;
  profile?: string;
  collection?: string;
  tier?: string;
  limit?: number;
}

export interface SearchHit {
  item_id: string;
  event_seq: number;
  source: string;
  imported_at: string;
  snippet: string;
  score: number;
}

/** Match an FTS5 expression. Dates filter the import time, with an exclusive upper bound. */
export function search(db: SqlDriver, query: string, options: SearchOptions = {}): SearchHit[] {
  const limit = options.limit ?? 20;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
    throw new IndexError('PROJECTION', 'Search limit must be between 1 and 1000.');
  }
  if (!query.trim()) return [];
  const filters = ['chunks_fts MATCH ?'];
  const values: SqlValue[] = [query];
  const columns = [
    ['i.imported_at >=', options.from === undefined ? undefined : importDate(options.from)],
    ['i.imported_at <', options.until === undefined ? undefined : importDate(options.until)],
    ['i.source =', options.source],
    ['i.profile =', options.profile],
    ['i.collection =', options.collection],
    ['i.tier =', options.tier],
  ] as const;
  for (const [column, value] of columns) {
    if (value !== undefined) {
      filters.push(`${column} ?`);
      values.push(value);
    }
  }

  // Stream matches from FTS5's own cursor. The ranking buffer holds at most
  // one chunk per result, even when the query matches the entire corpus.
  type Candidate = SearchHit & { chunk_id: string };
  const best = new Map<string, Candidate>();
  const compare = (a: Candidate, b: Candidate) => a.score - b.score ||
    (a.item_id < b.item_id ? -1 : Number(a.item_id > b.item_id));
  let worst: Candidate | undefined;
  const rows = db.prepare(`
    SELECT i.item_id, i.event_seq, i.source, i.imported_at, CAST(c.chunk_id AS TEXT) AS chunk_id,
      snippet(chunks_fts, 0, '', '', ' ... ', 16) AS snippet, bm25(chunks_fts) AS score
    FROM chunks_fts JOIN chunks c ON c.chunk_id=chunks_fts.rowid
    JOIN items i USING (item_id) WHERE ${filters.join(' AND ')}
  `).iterate(...values) as IterableIterator<unknown>;
  for (const row of rows) {
    const candidate = row as Candidate;
    const previous = best.get(candidate.item_id);
    if (previous) {
      if (candidate.score > previous.score || (candidate.score === previous.score &&
          BigInt(candidate.chunk_id) >= BigInt(previous.chunk_id))) continue;
    } else if (worst && best.size === limit) {
      if (compare(candidate, worst) >= 0) continue;
      best.delete(worst.item_id);
    }
    best.set(candidate.item_id, candidate);
    worst = undefined;
    for (const hit of best.values()) {
      if (!worst || compare(hit, worst) > 0) worst = hit;
    }
  }
  return [...best.values()].sort(compare).map(({ chunk_id: _chunk, ...hit }) => hit);
}

export function importDate(value: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) throw new IndexError('PROJECTION', 'Invalid index timestamp.');
  return date.toISOString();
}

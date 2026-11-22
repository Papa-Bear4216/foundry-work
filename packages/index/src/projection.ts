import { createHmac } from 'node:crypto';
import type { openVaultReplay, VaultReplayItem } from '../../vault/codec/dist/index.js';
import { IndexError, transaction } from './driver.ts';
import type { SqlDriver } from './driver.ts';
import { integer, object, optionalString, string } from './event.ts';
import { isGraphEvent, projectGraph } from './graph.ts';
import { SCHEMA_SQL, SCHEMA_VERSION } from './schema.ts';
import { importDate } from './search.ts';
import { chunkText, MAX_CHUNKS } from './text.ts';

type Replay = ReturnType<typeof openVaultReplay>;
type Event = Extract<VaultReplayItem, { type: 'event' }>;
type Blob = Extract<VaultReplayItem, { type: 'blob' }>;
const withdrawalKinds = new Set(['consent.withdrawn', 'redaction.applied', 'key.destroyed']);
const batchSize = 128;

export interface DeriveItem {
  itemId: string;
  eventSeq: number;
  mime: string | null;
  source: string;
}

export interface ProjectionOptions {
  version?: number;
  derive?: (item: DeriveItem, frames: Iterable<Uint8Array>) => Iterable<string>;
  /** Test hook called after a rebuild batch is durably committed. */
  checkpoint?: (phase: 'hidden' | 'events' | 'blobs', position: number) => void;
}

export interface ProjectionResult {
  lastEventSeq: number;
  skipped: number;
  hiddenChanged: boolean;
}

export function initializeSchema(db: SqlDriver): void {
  transaction(db, () => {
    const version = db.prepare('PRAGMA user_version').get()?.user_version;
    if (version === SCHEMA_VERSION) return;
    if (version !== 0 || db.prepare('SELECT name FROM sqlite_schema LIMIT 1').get()) {
      throw new IndexError('FORMAT', 'The file is not a supported Foundry index.');
    }
    db.exec(SCHEMA_SQL);
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
  });
}

export function assertSchema(db: SqlDriver): void {
  if (db.prepare('PRAGMA user_version').get()?.user_version !== SCHEMA_VERSION ||
      !db.prepare("SELECT name FROM sqlite_schema WHERE name='projection_state' AND type='table'").get()) {
    throw new IndexError('FORMAT', 'The file is not a supported Foundry index.');
  }
}

export function validateVersion(options: ProjectionOptions): number {
  const version = integer(options.version ?? 1, 'deriver version');
  if (version < 1) throw new IndexError('PROJECTION', 'Deriver version must be positive.');
  return version;
}

function progress(db: SqlDriver, phase: string, version: number): number {
  const row = db.prepare('SELECT deriver_version, last_event_seq FROM projection_state WHERE projection = ?').get(phase);
  if (!row) return 0;
  if (row.deriver_version !== version) {
    throw new IndexError('PROJECTION', 'Deriver version changed. Rebuild the working index.');
  }
  return row.last_event_seq as number;
}

function saveProgress(db: SqlDriver, phase: string, version: number, position: number): void {
  db.prepare(`
    INSERT INTO projection_state VALUES (?, ?, ?)
    ON CONFLICT (projection) DO UPDATE SET deriver_version=excluded.deriver_version,
      last_event_seq=excluded.last_event_seq
  `).run(phase, version, position);
}

function recordHidden(db: SqlDriver, entry: VaultReplayItem): void {
  const insert = db.prepare('INSERT OR IGNORE INTO hidden VALUES (?, ?)');
  if (entry.type === 'skipped') {
    insert.run('key', entry.keyId);
    return;
  }
  if (entry.type !== 'event') return;
  const { kind, profile, collection } = entry.event;
  const body = object(entry.event.body, 'withdrawal body');
  let targets = 0;
  for (const [scope, field] of [['item', 'item_id'], ['collection', 'collection'], ['profile', 'profile'],
    ['key', 'key_id'], ['tombstone', 'tombstone']] as const) {
    if (body[field] === undefined) continue;
    const target = string(body[field], field);
    if (scope === 'tombstone' && !/^[0-9a-f]{64}$/u.test(target)) {
      throw new IndexError('PROJECTION', 'Expected a lowercase hexadecimal tombstone HMAC.');
    }
    insert.run(scope, target);
    targets++;
  }
  const reference = body.target_ref ?? body.event_seq;
  if (reference !== undefined) {
    if (typeof reference === 'number') insert.run('event', String(integer(reference, 'target event')));
    else insert.run('item', string(reference, 'target item'));
    targets++;
  }
  if (targets === 0 && kind === 'consent.withdrawn') {
    if (typeof collection === 'string' && collection !== 'system') insert.run('collection', collection);
    else if (typeof profile === 'string' && profile !== 'system') insert.run('profile', profile);
    else throw new IndexError('PROJECTION', 'Consent withdrawal has no projection target.');
  } else if (targets === 0) {
    throw new IndexError('PROJECTION', 'Erasure event has no projection target.');
  }
}

function purge(db: SqlDriver): void {
  db.exec(`
    DELETE FROM event_origin AS o WHERE EXISTS (
      SELECT 1 FROM hidden h WHERE (h.scope, h.target) IN (
        ('event', CAST(o.event_seq AS TEXT)), ('key', o.key_id), ('profile', o.profile), ('collection', o.collection)
      )
    ) OR EXISTS (
      SELECT 1 FROM items i JOIN hidden h ON h.scope='item' AND h.target=i.item_id WHERE i.event_seq=o.event_seq
    );
    DELETE FROM blob_locator AS b WHERE NOT EXISTS (
      SELECT 1 FROM items i WHERE i.collection=b.collection AND i.blob_id=b.blob_id
    );
  `);
}

function projectEvent(db: SqlDriver, { event, seq, keyId }: Event): void {
  const { kind } = event;
  if (typeof kind !== 'string' || withdrawalKinds.has(kind)) return;
  const graph = isGraphEvent(kind);
  const body = kind === 'item.imported' || graph ? object(event.body, kind) : undefined;
  const profile = optionalString(event.profile, 'profile');
  const collection = optionalString(event.collection, 'collection');
  const itemId = kind === 'item.imported' ? optionalString(body?.item_id, 'item_id') ?? String(seq) : null;
  if (db.prepare(`
    SELECT 1 FROM hidden WHERE (scope, target) IN (
      ('item', ?), ('event', ?), ('key', ?), ('profile', ?), ('collection', ?)
    )
  `).get(itemId, String(seq), keyId, profile, collection)) return;

  db.prepare('INSERT INTO event_origin VALUES (?, ?, ?, ?)').run(seq, keyId, profile, collection);
  if (graph) {
    db.prepare('INSERT INTO graph_events VALUES (?, ?, ?)').run(seq, kind, JSON.stringify(body));
  } else if (itemId !== null && body) {
    const blob = string(body.blob, 'blob id');
    if (!/^[0-9a-f]{64}$/u.test(blob)) throw new IndexError('PROJECTION', 'Invalid blob id.');
    const sourceAt = optionalString(body.source_ts, 'source timestamp');
    db.prepare(`
      INSERT INTO items (item_id, event_seq, source, profile, collection, tier, sensitivity,
        title, path, mime, size, source_at, imported_at, blob_id, key_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(itemId, seq, string(event.source, 'source'), string(profile, 'profile'), string(collection, 'collection'),
      optionalString(event.tier ?? body.tier, 'tier') ?? 'public', optionalString(event.sensitivity, 'sensitivity'),
      optionalString(body.title, 'title'), optionalString(body.path, 'path'), optionalString(body.mime, 'mime'),
      body.size === undefined ? null : integer(body.size, 'size'), sourceAt === null ? null : importDate(sourceAt),
      importDate(string(event.ts, 'timestamp')), blob, keyId);
    if (body.place !== undefined) {
      const place = object(body.place, 'place');
      db.prepare('INSERT INTO places VALUES (?, ?, ?, ?, ?, ?)').run(
        seq, itemId, integer(place.ts, 'place timestamp'), integer(place.lat_e7, 'latitude'),
        integer(place.lng_e7, 'longitude'), place.accuracy_m == null ? null : integer(place.accuracy_m, 'accuracy'),
      );
    }
  }
}

function projectBlob(
  db: SqlDriver, replay: Replay, entry: Blob, tombstoneKey: Uint8Array | undefined,
  derive: ProjectionOptions['derive'],
): void {
  const { keyId, blobId, location } = entry;
  const items = db.prepare(`
    SELECT item_id, event_seq, mime, source, collection FROM items
    WHERE key_id=? AND blob_id=? AND derived=0 AND event_seq>? ORDER BY event_seq LIMIT ${batchSize}
  `);
  if (tombstoneKey && db.prepare('SELECT 1 FROM items WHERE key_id=? AND blob_id=? LIMIT 1').get(keyId, blobId)) {
    const digest = createHmac('sha256', tombstoneKey);
    for (const frame of replay.streamBlob(location)) digest.update(frame);
    if (db.prepare("SELECT 1 FROM hidden WHERE scope='tombstone' AND target=?").get(digest.digest('hex'))) {
      db.prepare('DELETE FROM event_origin WHERE event_seq IN (SELECT event_seq FROM items WHERE key_id=? AND blob_id=?)')
        .run(keyId, blobId);
      return;
    }
  }

  const insertChunk = db.prepare('INSERT INTO chunks VALUES (?, ?, ?, ?)');
  const insertLocation = db.prepare(`
    INSERT OR IGNORE INTO blob_locator VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const done = db.prepare('UPDATE items SET derived=1 WHERE event_seq=?');
  let after = 0;
  for (;;) {
    const batch = items.all(keyId, blobId, after);
    if (!batch.length) break;
    for (const row of batch) {
      const itemId = row.item_id as string;
      const eventSeq = row.event_seq as number;
      const mime = row.mime as string | null;
      const frames = replay.streamBlob(location);
      let ord = 0;
      try {
        const chunks = derive?.({ itemId, eventSeq, mime, source: row.source as string }, frames) ??
          (mime?.split(';', 1)[0].trim().toLowerCase() === 'text/plain' ? chunkText(frames) : []);
        for (const chunk of chunks) {
          if (ord >= MAX_CHUNKS) throw new IndexError('PROJECTION', 'Deriver exceeded the chunk limit.');
          const chunkId = BigInt(eventSeq) * BigInt(MAX_CHUNKS) + BigInt(ord);
          insertChunk.run(chunkId, itemId, ord++, chunk);
        }
      } finally {
        frames.return();
      }
      insertLocation.run(blobId, row.collection, location.segment, location.stream, location.offset,
        location.encodedLength, location.headerSha256);
      done.run(eventSeq);
      after = eventSeq;
    }
  }
}

function finish(db: SqlDriver, version: number, lastEventSeq: number, skipped: number): void {
  if (db.prepare('SELECT 1 FROM items WHERE derived=0 LIMIT 1').get()) {
    throw new IndexError('PROJECTION', 'An unhidden item refers to a missing blob under its collection key.');
  }
  purge(db);
  projectGraph(db);
  for (const phase of ['hidden', 'events', 'blobs', 'complete']) saveProgress(db, phase, version, lastEventSeq);
  db.prepare("INSERT OR REPLACE INTO meta VALUES ('skipped_records', ?)").run(String(skipped));
  db.prepare("DELETE FROM meta WHERE key IN ('rebuild_hidden_done', 'rebuild_blob_cursor')").run();
  // Merge residual FTS segments and remove obsolete terms from the searchable snapshot.
  db.exec("INSERT INTO chunks_fts(chunks_fts) VALUES ('optimize')");
}

function keyForTombstones(db: SqlDriver, key: Uint8Array | undefined): Uint8Array | undefined {
  if (!db.prepare("SELECT 1 FROM hidden WHERE scope='tombstone' LIMIT 1").get()) return;
  if (!key) throw new IndexError('KEY', 'A tombstone key is required to verify redacted originals.');
  return key;
}

function requireForward(last: number, replay: Replay): number {
  const seq = replay.boundary.lastEventSequence;
  if (last > seq) throw new IndexError('PROJECTION', 'The vault is older than the last indexed event.');
  return seq;
}

/** Apply new events atomically while removing records made invisible since the last update. */
export function applyIncremental(
  db: SqlDriver, replay: Replay, options: ProjectionOptions = {}, tombstoneKey?: Uint8Array,
  beforeApply?: (hiddenChanged: boolean) => void, beforeCommit?: () => void,
): ProjectionResult {
  const version = validateVersion(options);
  return transaction(db, () => {
    const last = progress(db, 'complete', version);
    const lastEventSeq = requireForward(last, replay);
    const hiddenBefore = db.prepare('SELECT count(*) AS n FROM hidden').get()?.n;
    for (const entry of replay.replay({ withdrawalsOnly: true })) recordHidden(db, entry);
    const hiddenChanged = hiddenBefore !== db.prepare('SELECT count(*) AS n FROM hidden').get()?.n;
    beforeApply?.(hiddenChanged);
    purge(db);
    const key = keyForTombstones(db, tombstoneKey);
    for (const entry of replay.replay()) {
      if (entry.type === 'event' && entry.seq > last) projectEvent(db, entry);
      if (entry.type === 'blob') projectBlob(db, replay, entry, key, options.derive);
    }
    finish(db, version, lastEventSeq, replay.skipped);
    beforeCommit?.();
    return { lastEventSeq, skipped: replay.skipped, hiddenChanged };
  });
}

function replayBatches(
  db: SqlDriver, entries: Iterable<VaultReplayItem>, visit: (entry: VaultReplayItem) => void,
  checkpoint: () => void, afterCommit?: () => void,
): void {
  // Consume the iterator before committing its last batch, so the replay's final
  // integrity checks run before the phase is marked complete.
  const iterator = entries[Symbol.iterator]();
  let complete = false;
  try {
    while (!complete) {
      transaction(db, () => {
        for (let i = 0; i < batchSize; i++) {
          const entry = iterator.next();
          if (entry.done) {
            complete = true;
            break;
          }
          visit(entry.value);
        }
        checkpoint();
      });
      afterCommit?.();
    }
  } finally {
    iterator.return?.();
  }
}

/** Resume only with the same authenticated replay boundary and deriver version. */
export function applyRebuild(
  db: SqlDriver, replay: Replay, options: ProjectionOptions = {}, tombstoneKey?: Uint8Array,
): ProjectionResult {
  const version = validateVersion(options);
  const lastEventSeq = requireForward(progress(db, 'complete', version), replay);
  const result = { lastEventSeq, skipped: replay.skipped, hiddenChanged: false };
  if (db.prepare("SELECT 1 FROM projection_state WHERE projection='complete'").get()) return result;
  if (!db.prepare("SELECT 1 FROM meta WHERE key='rebuild_hidden_done'").get()) {
    let cursor = progress(db, 'hidden', version);
    const write = (entry: VaultReplayItem) => {
      if (entry.type === 'blob') return;
      if ('seq' in entry) {
        if (entry.seq <= cursor) return;
        cursor = entry.seq;
      }
      recordHidden(db, entry);
    };
    replayBatches(db, replay.replay({ withdrawalsOnly: true }), write,
      () => saveProgress(db, 'hidden', version, cursor), () => options.checkpoint?.('hidden', cursor));
    db.prepare("INSERT INTO meta VALUES ('rebuild_hidden_done', '1')").run();
  }

  let seq = progress(db, 'events', version);
  const savedBlob = Number(db.prepare("SELECT value FROM meta WHERE key='rebuild_blob_cursor'").get()?.value ?? 0);
  let blob = 0;
  const key = keyForTombstones(db, tombstoneKey);
  replayBatches(db, replay.replay(), entry => {
    if (entry.type === 'event' && entry.seq > seq) {
      projectEvent(db, entry);
      seq = entry.seq;
    } else if (entry.type === 'blob' && ++blob > savedBlob) {
      projectBlob(db, replay, entry, key, options.derive);
    }
  }, () => {
    saveProgress(db, 'events', version, seq);
    if (blob > savedBlob) {
      db.prepare("INSERT OR REPLACE INTO meta VALUES ('rebuild_blob_cursor', ?)").run(String(blob));
    }
  }, () => {
    if (blob) options.checkpoint?.('blobs', blob);
    else options.checkpoint?.('events', seq);
  });
  transaction(db, () => finish(db, version, lastEventSeq, replay.skipped));
  return result;
}

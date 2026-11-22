/**
 * @file pipeline.ts
 * Stage-1 archive import orchestrator: streams entries through matching Importers,
 * stores original bytes first as vault blobs (V-3 blob dedup), appends idempotent
 * `item.imported` events with profile/collection/sensitivity metadata, and supports
 * crash resumption and unrecognised-entry reporting.
 */

import { Buffer } from 'node:buffer';
import type { Readable } from 'node:stream';
import type {
  Archive,
  ImportCheckpointInfo,
  ImportCrashPoint,
  Importer,
  ImportResult,
  SensitivityTier,
  SourceImportCounts,
  UnlockedKeyringLike,
  VaultAppend,
  VaultWriterLike,
} from './types.js';
import {
  computeItemKey,
  DEFAULT_PROFILE,
  defaultCollectionName,
  defaultSensitivityForSource,
  formatUtcTimestamp,
} from './defaults.js';
import { computeBlobId, deriveCollectionIdKey, loadExistingItemKeys } from './vault-state.js';
import type { ReadVaultRecordFn } from './vault-state.js';

const DEFAULT_BATCH_MAX_ITEMS = 16;
const DEFAULT_BATCH_MAX_BYTES = 4 * 1024 * 1024;

export interface ImportArchiveOptions {
  archive: Archive;
  writer: VaultWriterLike;
  importers: readonly Importer[];
  /**
   * Maps a logical collection name (e.g. `google-takeout/mail/2024`) to an active
   * 32-hex collection key ID in the vault keyring.
   */
  resolveCollectionKeyId: (collection: string) => string;
  /** Profile name stamped on imported events (defaults to `me`, per A-36). */
  profile?: string;
  /** Override sensitivity resolution per source/item (defaults to A-36 fixed table). */
  resolveSensitivity?: (source: string, path: string) => SensitivityTier;
  /** Optional clock override for deterministic tests. */
  now?: () => Date;
  /**
   * Pre-loaded set of already-imported `item_key` strings for idempotent re-import.
   * When omitted and `vaultDir` + `unlocked` + `readVaultRecord` are provided, keys are
   * scanned automatically from the vault's `events-*.fvr` streams.
   */
  existingItemKeys?: Set<string>;
  vaultDir?: string;
  unlocked?: UnlockedKeyringLike;
  readVaultRecord?: ReadVaultRecordFn;
  /** Maximum items buffered per `VaultWriter.appendBatch` call. Default: 16. */
  batchMaxItems?: number;
  /** Maximum plaintext bytes buffered per `VaultWriter.appendBatch` call. Default: 4 MiB. */
  batchMaxBytes?: number;
  /** Close the open segment after importing finishes. Default: false. */
  closeSegmentOnFinish?: boolean;
  /** Called for every archive entry no importer recognised (Risk R-5). */
  onUnrecognisedEntry?: (entryPath: string) => void;
  /** Injectable synchronous crash/test checkpoint. */
  checkpoint?: (point: ImportCrashPoint, info: ImportCheckpointInfo) => void;
}

async function readItemBytes(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks);
}

interface PendingItem {
  keyId: string;
  source: string;
  entryPath: string;
  itemPath: string;
  itemIndex: number;
  plaintext: Buffer;
  size: number;
  blobId?: string;
  itemKey?: string;
  profile: string;
  collection: string;
  sensitivity: SensitivityTier;
  mime: string;
  sourceTs?: string;
  tags: string[];
  meta?: Readonly<Record<string, unknown>>;
}

/**
 * Runs a streaming, crash-safe, idempotent Stage-1 import from an Archive into a VaultWriter.
 * Never writes to the index and never calls any network service or model.
 */
export async function importArchive(options: ImportArchiveOptions): Promise<ImportResult> {
  const profile = options.profile ?? DEFAULT_PROFILE;
  const resolveSensitivity = options.resolveSensitivity ?? (source => defaultSensitivityForSource(source));
  const now = options.now ?? (() => new Date());
  const batchMaxItems = Math.max(1, options.batchMaxItems ?? DEFAULT_BATCH_MAX_ITEMS);
  const batchMaxBytes = Math.max(1024, options.batchMaxBytes ?? DEFAULT_BATCH_MAX_BYTES);

  const existingItemKeys =
    options.existingItemKeys ??
    (options.vaultDir && options.unlocked && options.readVaultRecord
      ? loadExistingItemKeys(options.vaultDir, options.unlocked, options.readVaultRecord)
      : new Set<string>());

  // Cache derived collection ID keys for fast local blobId pre-checking on re-import, zeroed in finally.
  const idKeyCache = new Map<string, Buffer>();
  const getIdKey = (keyId: string): Buffer | undefined => {
    if (!options.unlocked) return undefined;
    let cached = idKeyCache.get(keyId);
    if (!cached) {
      const ck = options.unlocked.keys.get(keyId);
      if (!ck) return undefined;
      cached = deriveCollectionIdKey(ck, options.unlocked.keyring.vault_id);
      idKeyCache.set(keyId, cached);
    }
    return cached;
  };

  const countsBySource: Record<string, SourceImportCounts> = {};
  const unrecognisedEntries: string[] = [];
  let totalItemsImported = 0;
  let totalItemsSkipped = 0;
  let totalBlobsWritten = 0;
  let totalBlobsDeduplicated = 0;
  let totalEventsWritten = 0;
  let totalBytesStored = 0;

  const ensureSourceCounts = (source: string): SourceImportCounts => {
    let entry = countsBySource[source];
    if (!entry) {
      entry = { itemsImported: 0, itemsSkipped: 0, blobsWritten: 0, blobsDeduplicated: 0, bytesStored: 0 };
      countsBySource[source] = entry;
    }
    return entry;
  };

  let pending: PendingItem[] = [];
  let pendingBytes = 0;
  let globalItemIndex = 0;

  const buildEvent = (item: PendingItem, blobId: string, itemKey: string): Record<string, unknown> => {
    const body: Record<string, unknown> = {
      blob: blobId,
      path: item.itemPath,
      mime: item.mime,
      size: item.size,
      item_key: itemKey,
    };
    if (item.sourceTs !== undefined) body.source_ts = item.sourceTs;
    if (item.meta) {
      for (const [k, v] of Object.entries(item.meta)) {
        if (v !== undefined && !(k in body)) body[k] = v;
      }
    }
    return {
      ts: formatUtcTimestamp(now()),
      kind: 'item.imported',
      profile: item.profile,
      collection: item.collection,
      sensitivity: item.sensitivity,
      source: item.source,
      tags: item.tags,
      body,
    };
  };

  const flushBatch = (): void => {
    if (pending.length === 0) return;
    const batch = pending;
    pending = [];
    pendingBytes = 0;

    // Product 6.3 rule 1: Store original bytes first (blobs), then append item events.
    if (options.checkpoint) {
      // When crash checkpoints are active, flush blobs first so `after-blob-before-event` can be tested deterministically.
      for (const item of batch) {
        const counts = ensureSourceCounts(item.source);
        const [blobRes] = options.writer.appendBatch([{ type: 'blob', keyId: item.keyId, plaintext: item.plaintext }]);
        item.plaintext.fill(0);
        if (!blobRes || blobRes.type !== 'blob') throw new Error('Expected blob result from VaultWriter.');
        if (blobRes.duplicate) {
          counts.blobsDeduplicated++;
          totalBlobsDeduplicated++;
        } else {
          counts.blobsWritten++;
          totalBlobsWritten++;
          counts.bytesStored += item.size;
          totalBytesStored += item.size;
        }
        const itemKey = item.itemKey ?? computeItemKey(item.profile, item.collection, item.source, item.itemPath, blobRes.id);
        if (existingItemKeys.has(itemKey)) {
          counts.itemsSkipped++;
          totalItemsSkipped++;
          continue;
        }
        options.checkpoint('after-blob-before-event', {
          itemIndex: item.itemIndex,
          entryPath: item.entryPath,
          itemPath: item.itemPath,
          source: item.source,
        });
        options.writer.appendBatch([
          { type: 'event', keyId: item.keyId, event: buildEvent(item, blobRes.id, itemKey) },
        ]);
        existingItemKeys.add(itemKey);
        counts.itemsImported++;
        totalItemsImported++;
        totalEventsWritten++;
      }
      const last = batch[batch.length - 1]!;
      options.checkpoint('after-batch', {
        itemIndex: last.itemIndex,
        entryPath: last.entryPath,
        itemPath: last.itemPath,
        source: last.source,
      });
      return;
    }

    // Fast path without checkpoints: if blobId was precomputed, submit [blob, event, ...] in ONE appendBatch (one fsync!).
    const allPrecomputed = batch.every(i => i.blobId !== undefined && i.itemKey !== undefined);
    if (allPrecomputed) {
      const ops: VaultAppend[] = [];
      for (const item of batch) {
        ops.push({ type: 'blob', keyId: item.keyId, plaintext: item.plaintext });
        ops.push({
          type: 'event',
          keyId: item.keyId,
          event: buildEvent(item, item.blobId!, item.itemKey!),
        });
      }
      const results = options.writer.appendBatch(ops);
      for (let idx = 0; idx < batch.length; idx++) {
        const item = batch[idx]!;
        item.plaintext.fill(0);
        const blobRes = results[idx * 2];
        const counts = ensureSourceCounts(item.source);
        if (blobRes && blobRes.type === 'blob') {
          if (blobRes.duplicate) {
            counts.blobsDeduplicated++;
            totalBlobsDeduplicated++;
          } else {
            counts.blobsWritten++;
            totalBlobsWritten++;
            counts.bytesStored += item.size;
            totalBytesStored += item.size;
          }
        }
        existingItemKeys.add(item.itemKey!);
        counts.itemsImported++;
        totalItemsImported++;
        totalEventsWritten++;
      }
      return;
    }

    // Fallback path (no unlocked keyring passed): write blobs first to obtain IDs, then events for non-skipped items.
    const blobOps: VaultAppend[] = batch.map(item => ({ type: 'blob', keyId: item.keyId, plaintext: item.plaintext }));
    const blobResults = options.writer.appendBatch(blobOps);
    const eventOps: VaultAppend[] = [];
    const newKeys: Array<{ key: string; source: string }> = [];

    for (let idx = 0; idx < batch.length; idx++) {
      const item = batch[idx]!;
      item.plaintext.fill(0);
      const blobRes = blobResults[idx];
      if (!blobRes || blobRes.type !== 'blob') throw new Error('Expected blob result from VaultWriter.');
      const counts = ensureSourceCounts(item.source);
      if (blobRes.duplicate) {
        counts.blobsDeduplicated++;
        totalBlobsDeduplicated++;
      } else {
        counts.blobsWritten++;
        totalBlobsWritten++;
        counts.bytesStored += item.size;
        totalBytesStored += item.size;
      }
      const itemKey = computeItemKey(item.profile, item.collection, item.source, item.itemPath, blobRes.id);
      if (existingItemKeys.has(itemKey)) {
        counts.itemsSkipped++;
        totalItemsSkipped++;
        continue;
      }
      eventOps.push({ type: 'event', keyId: item.keyId, event: buildEvent(item, blobRes.id, itemKey) });
      newKeys.push({ key: itemKey, source: item.source });
    }

    if (eventOps.length > 0) {
      options.writer.appendBatch(eventOps);
      for (const nk of newKeys) {
        existingItemKeys.add(nk.key);
        const counts = ensureSourceCounts(nk.source);
        counts.itemsImported++;
        totalItemsImported++;
        totalEventsWritten++;
      }
    }
  };

  try {
    for (const entry of options.archive.entries) {
      const importer = options.importers.find(imp => imp.matches(entry));
      if (!importer) {
        unrecognisedEntries.push(entry.path);
        options.onUnrecognisedEntry?.(entry.path);
        continue;
      }

      const counts = ensureSourceCounts(importer.id);

      for await (const rawItem of importer.split(entry)) {
        globalItemIndex++;
        const plaintext = await readItemBytes(rawItem.bytes);
        const collection = defaultCollectionName(importer.id, rawItem.sourceTs);
        const keyId = options.resolveCollectionKeyId(collection);
        const sensitivity = resolveSensitivity(importer.id, rawItem.path);

        let precomputedBlobId: string | undefined;
        let precomputedItemKey: string | undefined;
        const idKey = getIdKey(keyId);
        if (idKey) {
          precomputedBlobId = computeBlobId(idKey, plaintext);
          precomputedItemKey = computeItemKey(profile, collection, importer.id, rawItem.path, precomputedBlobId);
          if (existingItemKeys.has(precomputedItemKey)) {
            plaintext.fill(0);
            counts.itemsSkipped++;
            totalItemsSkipped++;
            continue;
          }
        }

        pending.push({
          keyId,
          source: importer.id,
          entryPath: entry.path,
          itemPath: rawItem.path,
          itemIndex: globalItemIndex,
          plaintext,
          size: plaintext.length,
          blobId: precomputedBlobId,
          itemKey: precomputedItemKey,
          profile,
          collection,
          sensitivity,
          mime: rawItem.mime,
          sourceTs: rawItem.sourceTs,
          tags: rawItem.tags,
          meta: rawItem.meta,
        });
        pendingBytes += plaintext.length;

        if (pending.length >= batchMaxItems || pendingBytes >= batchMaxBytes) {
          flushBatch();
        }
      }

      flushBatch();
      options.checkpoint?.('after-entry', {
        itemIndex: globalItemIndex,
        entryPath: entry.path,
        itemPath: entry.path,
        source: importer.id,
      });
    }

    flushBatch();
    if (options.closeSegmentOnFinish) {
      options.writer.closeSegment();
    }
  } finally {
    for (const item of pending) item.plaintext.fill(0);
    for (const key of idKeyCache.values()) key.fill(0);
    idKeyCache.clear();
  }

  return {
    countsBySource,
    unrecognisedEntries,
    totalItemsImported,
    totalItemsSkipped,
    totalBlobsWritten,
    totalBlobsDeduplicated,
    totalEventsWritten,
    totalBytesStored,
  };
}

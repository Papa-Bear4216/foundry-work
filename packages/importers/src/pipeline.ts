/**
 * @file pipeline.ts
 * Stage-1 archive import orchestrator: pre-validates archive integrity for all matched
 * entries before the first vault write, streams entries through matching Importers with
 * a strict 64 MiB per-item cap, stores original bytes first as vault blobs (V-3 blob dedup),
 * derives identity state directly from the vault, deduplicates within each batch, re-derives
 * state after any append failure, and reports unrecognised entries and per-item errors.
 */

import { Buffer } from 'node:buffer';
import type { Readable } from 'node:stream';
import type {
  Archive,
  ArchiveEntry,
  ImportCheckpointInfo,
  ImportCrashPoint,
  Importer,
  ImportResult,
  ItemErrorInfo,
  SensitivityTier,
  SourceImportCounts,
  UnlockedKeyringLike,
  VaultAppend,
  VaultWriterLike,
} from './types.js';
import {
  computeItemKey,
  DEFAULT_MAX_ITEM_BYTES,
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
  /** Vault directory used to derive durable item identity state from persisted events. */
  vaultDir: string;
  /** Unlocked vault keyring used to compute collection-keyed blob IDs and read persisted events. */
  unlocked: UnlockedKeyringLike;
  /** V-3 `readVaultRecord` function used to scan persisted `events-*.fvr` streams. */
  readVaultRecord: ReadVaultRecordFn;
  /** Profile name stamped on imported events (defaults to `me`, per A-36). */
  profile?: string;
  /** Override sensitivity resolution per source/item (defaults to A-36 fixed table). */
  resolveSensitivity?: (source: string, path: string) => SensitivityTier;
  /** Optional clock override for deterministic tests. */
  now?: () => Date;
  /** Maximum plaintext byte size per individual item before skipping. Default: 64 MiB. */
  maxItemBytes?: number;
  /** Maximum items buffered per `VaultWriter.appendBatch` call. Default: 16. */
  batchMaxItems?: number;
  /** Maximum plaintext bytes buffered per `VaultWriter.appendBatch` call. Default: 4 MiB. */
  batchMaxBytes?: number;
  /** Close the open segment after importing finishes. Default: false. */
  closeSegmentOnFinish?: boolean;
  /** Called for every archive entry no importer recognised (Risk R-5). */
  onUnrecognisedEntry?: (entryPath: string) => void;
  /** Called for every typed per-item error/skip (over-limit item, nested/unfinished vCard). */
  onItemError?: (error: ItemErrorInfo) => void;
  /** Injectable synchronous crash/test checkpoint. */
  checkpoint?: (point: ImportCrashPoint, info: ImportCheckpointInfo) => void;
}

async function readItemBytesBounded(
  stream: Readable,
  maxBytes: number,
): Promise<{ buffer: Buffer; exceeded: false } | { exceeded: true; observedBytes: number }> {
  const chunks: Buffer[] = [];
  let total = 0;
  let exceeded = false;

  for await (const rawChunk of stream) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk as Uint8Array);
    total += chunk.length;
    if (exceeded) continue;
    if (total > maxBytes) {
      // Drop accumulated references immediately and drain the remainder without buffering.
      chunks.length = 0;
      exceeded = true;
      continue;
    }
    chunks.push(chunk);
  }

  if (exceeded) return { exceeded: true, observedBytes: total };
  return { buffer: chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks), exceeded: false };
}

async function drainEntryStream(entry: ArchiveEntry): Promise<void> {
  const stream = entry.open();
  for await (const _chunk of stream) {
    // Intentionally empty: stream-validates CRC-32, sizes, deflate consumption, and bomb limits in O(1) memory.
  }
}

interface PendingItem {
  keyId: string;
  source: string;
  entryPath: string;
  itemPath: string;
  itemIndex: number;
  plaintext: Buffer;
  size: number;
  blobId: string;
  itemKey: string;
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
 * Pre-validates every matched archive entry before the first vault write, derives durable
 * item identity state from the vault, enforces a 64 MiB per-item cap, never writes to the
 * index, and never calls any network service or model.
 */
export async function importArchive(options: ImportArchiveOptions): Promise<ImportResult> {
  if (!options.vaultDir || typeof options.vaultDir !== 'string') {
    throw new TypeError('importArchive requires vaultDir to derive durable item identity state.');
  }
  if (!options.unlocked || typeof options.unlocked !== 'object') {
    throw new TypeError('importArchive requires unlocked keyring to derive durable item identity state.');
  }
  if (typeof options.readVaultRecord !== 'function') {
    throw new TypeError('importArchive requires readVaultRecord to derive durable item identity state.');
  }

  const profile = options.profile ?? DEFAULT_PROFILE;
  const resolveSensitivity = options.resolveSensitivity ?? (source => defaultSensitivityForSource(source));
  const now = options.now ?? (() => new Date());
  const maxItemBytes = Math.max(1, options.maxItemBytes ?? DEFAULT_MAX_ITEM_BYTES);
  const batchMaxItems = Math.max(1, options.batchMaxItems ?? DEFAULT_BATCH_MAX_ITEMS);
  const batchMaxBytes = Math.max(1024, options.batchMaxBytes ?? DEFAULT_BATCH_MAX_BYTES);

  // Phase 0 (Ruling 1): Match entries and stream-validate EVERY entry that will be imported
  // across all parts BEFORE the first vault write. Unrecognised entries need not be read.
  const matchedPlan: Array<{ entry: ArchiveEntry; importer: Importer }> = [];
  const unrecognisedEntries: string[] = [];

  for (const entry of options.archive.entries) {
    const importer = options.importers.find(imp => imp.matches(entry));
    if (!importer) {
      unrecognisedEntries.push(entry.path);
    } else {
      matchedPlan.push({ entry, importer });
    }
  }

  for (const { entry } of matchedPlan) {
    await drainEntryStream(entry);
  }

  for (const path of unrecognisedEntries) {
    options.onUnrecognisedEntry?.(path);
  }

  // Phase 1 (Ruling 9): Always build durable identity state from the vault.
  let existingItemKeys = loadExistingItemKeys(options.vaultDir, options.unlocked, options.readVaultRecord);

  // Cache derived collection ID keys for blobId pre-checking, zeroed in finally.
  const idKeyCache = new Map<string, Buffer>();
  const getIdKey = (keyId: string): Buffer => {
    let cached = idKeyCache.get(keyId);
    if (!cached) {
      const ck = options.unlocked.keys.get(keyId);
      if (!ck) {
        throw new Error(`Collection key ${keyId} is not present in the unlocked keyring.`);
      }
      cached = deriveCollectionIdKey(ck, options.unlocked.keyring.vault_id);
      idKeyCache.set(keyId, cached);
    }
    return cached;
  };

  const countsBySource: Record<string, SourceImportCounts> = {};
  const itemErrors: ItemErrorInfo[] = [];
  let totalItemsImported = 0;
  let totalItemsSkipped = 0;
  let totalItemsErrored = 0;
  let totalBlobsWritten = 0;
  let totalBlobsDeduplicated = 0;
  let totalEventsWritten = 0;
  let totalBytesStored = 0;

  const ensureSourceCounts = (source: string): SourceImportCounts => {
    let entry = countsBySource[source];
    if (!entry) {
      entry = {
        itemsImported: 0,
        itemsSkipped: 0,
        itemsErrored: 0,
        blobsWritten: 0,
        blobsDeduplicated: 0,
        bytesStored: 0,
      };
      countsBySource[source] = entry;
    }
    return entry;
  };

  const recordItemError = (err: ItemErrorInfo): void => {
    const counts = ensureSourceCounts(err.source);
    counts.itemsSkipped++;
    counts.itemsErrored++;
    totalItemsSkipped++;
    totalItemsErrored++;
    itemErrors.push(err);
    options.onItemError?.(err);
  };

  let pending: PendingItem[] = [];
  const pendingKeys = new Set<string>();
  let pendingBytes = 0;
  let globalItemIndex = 0;

  const buildEvent = (item: PendingItem): Record<string, unknown> => {
    const body: Record<string, unknown> = {
      blob: item.blobId,
      path: item.itemPath,
      mime: item.mime,
      size: item.size,
      item_key: item.itemKey,
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

  const rederiveIdentityFromVault = (): void => {
    existingItemKeys = loadExistingItemKeys(options.vaultDir, options.unlocked, options.readVaultRecord);
  };

  const flushBatch = (): void => {
    if (pending.length === 0) return;
    const batch = pending;
    pending = [];
    pendingKeys.clear();
    pendingBytes = 0;

    try {
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
          if (existingItemKeys.has(item.itemKey)) {
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
            { type: 'event', keyId: item.keyId, event: buildEvent(item) },
          ]);
          existingItemKeys.add(item.itemKey);
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

      // Standard path: submit [blob, event, ...] in ONE appendBatch (one fsync per batch).
      const ops: VaultAppend[] = [];
      for (const item of batch) {
        ops.push({ type: 'blob', keyId: item.keyId, plaintext: item.plaintext });
        ops.push({
          type: 'event',
          keyId: item.keyId,
          event: buildEvent(item),
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
        existingItemKeys.add(item.itemKey);
        counts.itemsImported++;
        totalItemsImported++;
        totalEventsWritten++;
      }
    } catch (error) {
      for (const item of batch) item.plaintext.fill(0);
      // Ruling 9: After any append throws, re-derive identity state from the vault before any further write.
      try {
        rederiveIdentityFromVault();
      } catch {
        existingItemKeys.clear();
      }
      throw error;
    }
  };

  try {
    for (const { entry, importer } of matchedPlan) {
      const counts = ensureSourceCounts(importer.id);

      for await (const rawItem of importer.split(entry, { maxItemBytes, onItemError: recordItemError })) {
        globalItemIndex++;
        const read = await readItemBytesBounded(rawItem.bytes, maxItemBytes);
        if (read.exceeded) {
          recordItemError({
            code: 'ITEM_TOO_LARGE',
            source: importer.id,
            entryPath: entry.path,
            itemPath: rawItem.path,
            message: `Item ${rawItem.path} (${read.observedBytes} bytes) exceeds per-item limit (${maxItemBytes} bytes).`,
            limitBytes: maxItemBytes,
            observedBytes: read.observedBytes,
          });
          continue;
        }

        const plaintext = read.buffer;
        const collection = defaultCollectionName(importer.id, rawItem.sourceTs);
        const keyId = options.resolveCollectionKeyId(collection);
        const sensitivity = resolveSensitivity(importer.id, rawItem.path);
        const idKey = getIdKey(keyId);
        const blobId = computeBlobId(idKey, plaintext);
        const itemKey = computeItemKey(profile, collection, importer.id, rawItem.path, blobId);

        // Deduplicate against BOTH persisted vault state AND in-flight batch keys.
        if (existingItemKeys.has(itemKey) || pendingKeys.has(itemKey)) {
          plaintext.fill(0);
          counts.itemsSkipped++;
          totalItemsSkipped++;
          continue;
        }

        pendingKeys.add(itemKey);
        pending.push({
          keyId,
          source: importer.id,
          entryPath: entry.path,
          itemPath: rawItem.path,
          itemIndex: globalItemIndex,
          plaintext,
          size: plaintext.length,
          blobId,
          itemKey,
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
    pendingKeys.clear();
    for (const key of idKeyCache.values()) key.fill(0);
    idKeyCache.clear();
  }

  return {
    partsCount: options.archive.parts.length,
    parts: [...options.archive.parts],
    countsBySource,
    unrecognisedEntries,
    itemErrors,
    totalItemsImported,
    totalItemsSkipped,
    totalItemsErrored,
    totalBlobsWritten,
    totalBlobsDeduplicated,
    totalEventsWritten,
    totalBytesStored,
  };
}

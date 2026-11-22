import type { Buffer } from 'node:buffer';
import type { Readable } from 'node:stream';

/** Sensitivity tiers defined by Product Spec section 9. */
export type SensitivityTier = 'public' | 'personal' | 'private' | 'secret' | 'clinical' | 'child';

/** Typed per-item skip / validation error codes reported without aborting valid items. */
export type ItemErrorCode =
  | 'ITEM_TOO_LARGE'
  | 'VCARD_NESTED_BEGIN'
  | 'VCARD_UNFINISHED';

/** Structured record of a single skipped or malformed item encountered during import. */
export interface ItemErrorInfo {
  readonly code: ItemErrorCode;
  readonly source: string;
  readonly entryPath: string;
  readonly itemPath: string;
  readonly message: string;
  readonly limitBytes?: number;
  readonly observedBytes?: number;
}

/** Optional controls passed to an Importer's split stage. */
export interface SplitOptions {
  /** Maximum per-item plaintext byte cap enforced before buffering past it. Default: 64 MiB. */
  maxItemBytes?: number;
  /** Callback invoked for typed per-item errors so the caller can count, report, and continue. */
  onItemError?: (error: ItemErrorInfo) => void;
}

/** Single readable entry inside a zip or multi-part archive tree (Architecture 7). */
export interface ArchiveEntry {
  readonly path: string;
  readonly size: number;
  readonly compressedSize: number;
  readonly part?: string;
  readonly mtime?: Date;
  open(): Readable;
}

/** Opened single-zip or multi-part archive tree. Never unpacks to disk. */
export interface Archive {
  readonly entries: readonly ArchiveEntry[];
  readonly parts: readonly string[];
  close(): Promise<void>;
}

/** Lossless original item produced by an Importer's split stage (Architecture 7). */
export interface RawItem {
  bytes: Readable;
  path: string;
  mime: string;
  sourceTs?: string;
  tags: string[];
  meta?: Readonly<Record<string, unknown>>;
}

/** Stage-1 importer contract (Architecture 7): splits archive entries into lossless RawItems. */
export interface Importer {
  readonly id: string;
  matches(entry: ArchiveEntry): boolean;
  split(entry: ArchiveEntry, options?: SplitOptions): AsyncIterable<RawItem>;
}

/** Metadata of a stored vault item passed into a Deriver (Architecture 7). */
export interface StoredItem {
  eventSeq?: number;
  source: string;
  path: string;
  mime: string;
  size: number;
  blobId: string;
  profile: string;
  collection: string;
  sensitivity: SensitivityTier;
  sourceTs?: string;
  tags: string[];
  meta?: Readonly<Record<string, unknown>>;
}

/** Output union emitted by a Deriver for downstream index projections (Architecture 7). */
export type Derived =
  | {
      kind: 'text';
      title?: string;
      text: string;
      structured: Readonly<Record<string, unknown>>;
      sourceTs?: string;
      tags?: string[];
    }
  | {
      kind: 'place';
      latE7: number;
      lngE7: number;
      ts?: string;
      accuracyM?: number;
      label?: string;
    }
  | {
      kind: 'graph_evidence';
      nodes: ReadonlyArray<{ kind: string; canonicalKey: string; label: string }>;
      edges: ReadonlyArray<{
        srcKind: string;
        srcKey: string;
        dstKind: string;
        dstKey: string;
        kind: string;
      }>;
    };

/** Stage-2 deriver contract (Architecture 7): derives text/places/graph evidence without vault writes. */
export interface Deriver {
  readonly id: string;
  readonly version: number;
  derive(item: StoredItem, bytes: Readable): AsyncIterable<Derived>;
}

/** Structural mirror of V-3 VaultRecordLocation (keeps packages/importers decoupled from vault build order). */
export interface VaultRecordLocation {
  segment: number;
  stream: string;
  offset: number;
}

/** Structural mirror of V-3 VaultAppend. */
export type VaultAppend =
  | { type: 'event'; keyId: string; event: Readonly<Record<string, unknown>> }
  | { type: 'blob'; keyId: string; plaintext: Buffer };

/** Structural mirror of V-3 VaultAppendResult. */
export type VaultAppendResult =
  | { type: 'event'; sequence: number; location: VaultRecordLocation }
  | { type: 'blob'; id: string; duplicate: boolean; location: VaultRecordLocation };

/** Structural supertype of V-3 VaultWriter. */
export interface VaultWriterLike {
  appendBatch(items: Iterable<VaultAppend>): VaultAppendResult[];
  closeSegment(): { segment: number; hash: string; lastEventSequence: number };
}

/** Structural mirror of V-2/V-3 UnlockedKeyring subset needed for blob-id computation and event scanning. */
export interface UnlockedKeyringLike {
  readonly keyring: {
    readonly vault_id: string;
    readonly keys: ReadonlyArray<{
      readonly key_id: string;
      readonly kind: string;
      readonly state: string;
    }>;
  };
  readonly keys: ReadonlyMap<string, Buffer>;
}

/**
 * Durable lookup of item keys already stored in the vault (for example backed by the working index).
 * `importArchive` calls `add` only after the batch holding that item is durably appended to the vault.
 */
export interface ItemKeyLookup {
  has(itemKey: string): boolean;
  add(itemKey: string): void;
}

/** Injectable crash checkpoints for resumability tests. */
export type ImportCrashPoint =
  | 'after-blob-before-event'
  | 'after-batch'
  | 'after-entry';

export interface ImportCheckpointInfo {
  itemIndex: number;
  entryPath: string;
  itemPath: string;
  source: string;
}

export interface SourceImportCounts {
  itemsImported: number;
  itemsSkipped: number;
  itemsErrored: number;
  blobsWritten: number;
  blobsDeduplicated: number;
  bytesStored: number;
}

export interface ImportResult {
  partsCount: number;
  parts: string[];
  countsBySource: Record<string, SourceImportCounts>;
  unrecognisedEntries: string[];
  itemErrors: ItemErrorInfo[];
  totalItemsImported: number;
  totalItemsSkipped: number;
  totalItemsErrored: number;
  totalBlobsWritten: number;
  totalBlobsDeduplicated: number;
  totalEventsWritten: number;
  totalBytesStored: number;
}

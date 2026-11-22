import { Buffer } from 'node:buffer';
import { createHmac } from 'node:crypto';
import {
  closeSync, fsyncSync, ftruncateSync, mkdirSync, openSync, readdirSync, unlinkSync, writeSync,
} from 'node:fs';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import { canonical, check, integer, sha256 } from './bytes.ts';
import { acquireWriterLock, renameWithRetry, syncDirectory } from './keyring-file.ts';
import { blobId, collectionIdKey } from './keyring.ts';
import { create } from './keys.ts';
import { decodeVaultMetadata, encodeManifest, signingPublicKey, streamOrdinal } from './manifest.ts';
import type { ChainPosition, Manifest } from './manifest.ts';
import { StreamScanner, streamFile } from './record-file.ts';
import type { UnlockedKeyring } from './record-file.ts';
import { encodeRecord, recordLength } from './record.ts';
import type { VaultRecordLocation } from './vault-reader.ts';
import {
  GENESIS, HEAD, HEAD_PENDING, headBytes, headMatches, makeReadOnly, MANIFEST, MANIFEST_PENDING, metadata, OPEN_ARTIFACTS,
  publishHead, readHead, removePending, replaceHead, scanOpen, scanSealed, segmentName, SIGNATURE, SIGNATURE_PENDING,
  statIfPresent, streamNames, streamType, VAULT_METADATA, writePending,
} from './vault-directory.ts';

const FILE_CAP = 64 * 1024 * 1024;
const SEGMENT_CAP = 512 * 1024 * 1024;
const LOCK = '.writer.lock.sqlite';

type VaultIdentity = Pick<ReturnType<typeof create>, 'vaultId' | 'createdAt' | 'signingPublicKey'>;

function prepareEmptyLayout(directory: string): void {
  const segments = join(directory, 'segments');
  mkdirSync(segments, { recursive: true, mode: 0o700 });
  check(statIfPresent(segments)?.isDirectory() && readdirSync(segments, { withFileTypes: true }).length === 0
    && !statIfPresent(join(directory, 'open')), 'INVENTORY');
  if (statIfPresent(join(directory, HEAD))) check(headMatches(readHead(directory), GENESIS), 'HEAD');
}

function initialize(directory: string, identity: VaultIdentity): void {
  const destination = join(directory, VAULT_METADATA);
  const pending = destination + '.pending';
  const bytes = Buffer.from(canonical({
    format: 'foundry-vault/1', vault_id: identity.vaultId, created_at: identity.createdAt,
    signing_public_key: identity.signingPublicKey.toString('base64'),
  }));
  const wanted = decodeVaultMetadata(bytes);
  if (statIfPresent(destination)) {
    const actual = metadata(directory);
    check(actual.vault_id === wanted.vault_id && actual.created_at === wanted.created_at
      && actual.signing_public_key === wanted.signing_public_key, 'KEY');
    return;
  }
  prepareEmptyLayout(directory);
  removePending(join(directory, HEAD_PENDING));
  if (!statIfPresent(join(directory, HEAD))) publishHead(directory, GENESIS);
  removePending(pending);
  writePending(pending, bytes);
  renameWithRetry(pending, destination);
  syncDirectory(directory);
}

/** Initialize the directory with an identity returned by V-2 key creation. */
export function initializeVault(directory: string, identity: VaultIdentity): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const lock = acquireWriterLock(join(directory, LOCK));
  try {
    initialize(directory, identity);
  } finally {
    lock.close();
  }
}

/** Create the V-2 keyring and vault metadata. The returned recovery key is shown once by the caller. */
export function createVault(directory: string, options: Parameters<typeof create>[1]) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const lock = acquireWriterLock(join(directory, LOCK));
  try {
    check(!statIfPresent(join(directory, VAULT_METADATA)), 'INVENTORY');
    prepareEmptyLayout(directory);
    const keyring = join(directory, 'keyring');
    mkdirSync(keyring, { recursive: true, mode: 0o700 });
    check(statIfPresent(keyring)?.isDirectory(), 'INVENTORY');
    const identity = create(join(keyring, 'keyring.json'), options);
    initialize(directory, identity);
    return identity;
  } finally {
    lock.close();
  }
}

export type VaultAppend =
  | { type: 'event'; keyId: string; event: Readonly<Record<string, unknown>> }
  | { type: 'blob'; keyId: string; plaintext: Buffer };

export type VaultAppendResult =
  | { type: 'event'; sequence: number; location: VaultRecordLocation }
  | { type: 'blob'; id: string; duplicate: boolean; location: VaultRecordLocation };

export type VaultCrashPoint =
  | 'before-write' | 'after-write'
  | 'before-batch-fsync' | 'after-batch-fsync' | 'before-close-fsync' | 'after-close-fsync'
  | 'before-manifest-fsync' | 'after-manifest-fsync'
  | 'before-signature-fsync' | 'after-signature-fsync'
  | 'before-signature-rename' | 'after-signature-rename' | 'before-manifest-rename' | 'after-manifest-rename'
  | 'before-head-fsync' | 'after-head-fsync'
  | 'before-segment-rename' | 'after-segment-rename' | 'before-head-update' | 'after-head-update';

export interface VaultWriterOptions {
  writer?: string;
  /** Synchronous process-kill checkpoints used by the crash suite. */
  checkpoint?: (point: VaultCrashPoint) => void;
}

interface OpenStream {
  name: string;
  bytes: number;
}

export class VaultWriter {
  readonly #directory: string;
  readonly #open: string;
  readonly #unlocked: UnlockedKeyring;
  readonly #options: VaultWriterOptions;
  readonly #lock: DatabaseSync;
  readonly #signingSeed: Buffer;
  readonly #scanner = new StreamScanner();
  readonly #streams = new Map<1 | 2, OpenStream>();
  readonly #dirty = new Set<string>();
  #position: ChainPosition = GENESIS;
  #last = 0;
  #totalBytes = 0;
  #state: 'ready' | 'running' | 'failed' | 'released' = 'ready';
  readonly repairs: { stream: string; offset: number; removedBytes: number }[] = [];
  readonly repairedHead: boolean;

  private constructor(directory: string, unlocked: UnlockedKeyring, options: VaultWriterOptions, lock: DatabaseSync) {
    this.#directory = directory;
    this.#open = join(directory, 'open');
    this.#unlocked = unlocked;
    this.#options = options;
    this.#lock = lock;
    const vault = metadata(directory);
    const signingEntry = unlocked.keyring.keys.find(entry => entry.kind === 'signing' && entry.state === 'active');
    const seed = signingEntry && unlocked.keys.get(signingEntry.key_id);
    check(unlocked.keyring.vault_id === vault.vault_id && seed
      && signingPublicKey(seed).toString('base64') === vault.signing_public_key, 'KEY');
    check(options.writer === undefined || (typeof options.writer === 'string' && options.writer.length > 0));
    this.#signingSeed = seed;
    const { position, previous } = scanSealed(directory, vault, this.#scanner);
    this.#position = position;
    const head = readHead(directory);
    this.repairedHead = !headMatches(head, position);
    check(!this.repairedHead || (position.segment > 0 && headMatches(head, previous)
      && headMatches(readHead(directory, HEAD_PENDING), position)), 'HEAD');
    const recovered = scanOpen(this.#open, position.lastEventSequence, this.#scanner, unlocked, true);
    for (const tail of recovered.incomplete) {
      const path = join(this.#open, tail.name);
      if (tail.bytes === 0) {
        unlinkSync(path);
      } else {
        const fd = openSync(path, 'r+');
        try {
          ftruncateSync(fd, tail.bytes);
          fsyncSync(fd);
        } finally {
          closeSync(fd);
        }
      }
      this.repairs.push({ stream: tail.name, offset: tail.bytes, removedBytes: tail.removedBytes });
    }
    if (statIfPresent(this.#open)) {
      for (const name of OPEN_ARTIFACTS) removePending(join(this.#open, name));
      syncDirectory(this.#open);
    }
    if (this.repairedHead) {
      syncDirectory(join(directory, 'segments'));
      replaceHead(directory);
    } else {
      removePending(join(directory, HEAD_PENDING));
    }
    if (position.segment > 0) makeReadOnly(this.#segmentPath(position.segment));
    for (const file of recovered.files.sort((a, b) => streamOrdinal(a.name) - streamOrdinal(b.name))) {
      this.#streams.set(streamType(file.name), file);
    }
    this.#last = recovered.last;
    this.#totalBytes = recovered.totalBytes;
    if (this.#totalBytes >= SEGMENT_CAP) this.#seal();
  }

  static open(directory: string, unlocked: UnlockedKeyring, options: VaultWriterOptions = {}): VaultWriter {
    const lock = acquireWriterLock(join(directory, LOCK));
    try {
      return new VaultWriter(directory, unlocked, options, lock);
    } catch (error) {
      lock.close();
      throw error;
    }
  }

  /** Durably append one batch. A batch can span segments and a crash can retain a prefix. */
  appendBatch(items: Iterable<VaultAppend>): VaultAppendResult[] {
    return this.#run(() => {
      const results: VaultAppendResult[] = [];
      for (const item of items) {
        if (item.type === 'blob') {
          results.push(this.#appendBlob(item));
        } else {
          check(item.type === 'event');
          const sequence = this.#last + 1;
          integer(sequence, 1);
          const plaintext = Buffer.from(JSON.stringify({ ...item.event, seq: sequence }));
          try {
            const result = this.#append(1, item.keyId, sequence, plaintext);
            results.push({ type: 'event', sequence, location: result });
          } finally {
            plaintext.fill(0);
          }
        }
      }
      this.#syncDirty();
      return results;
    });
  }

  /** Seal a nonempty open segment and return its chain position. */
  closeSegment(): ChainPosition {
    return this.#run(() => {
      this.#seal();
      return { ...this.#position };
    });
  }

  /** Release the OS-held lock, leaving any successfully appended open records in place. */
  release(): void {
    if (this.#state === 'released') return;
    check(this.#state !== 'running');
    this.#lock.close();
    this.#state = 'released';
  }

  #run<T>(work: () => T): T {
    if (this.#state !== 'ready') throw new Error('Vault writer must be reopened.');
    this.#state = 'running';
    try {
      const result = work();
      this.#state = 'ready';
      return result;
    } catch (error) {
      this.#state = 'failed';
      throw error;
    }
  }

  #segmentPath(segment: number): string {
    return join(this.#directory, 'segments', segmentName(segment));
  }

  #point(point: VaultCrashPoint): void {
    this.#options.checkpoint?.(point);
  }

  #appendBlob(item: Extract<VaultAppend, { type: 'blob' }>): VaultAppendResult {
    const encryptionKey = this.#unlocked.collectionEncryptionKey(item.keyId);
    const identityKey = collectionIdKey(this.#unlocked.keys.get(item.keyId)!, this.#unlocked.keyring.vault_id);
    try {
      const id = blobId(identityKey, item.plaintext);
      const duplicate = this.#findBlob(item.keyId, id, recordLength(item.plaintext.length), identityKey, encryptionKey);
      const location = duplicate ?? this.#append(2, item.keyId, 0, item.plaintext);
      return { type: 'blob', id, duplicate: duplicate !== undefined, location };
    } finally {
      encryptionKey.fill(0);
      identityKey.fill(0);
    }
  }

  #findBlob(keyId: string, id: string, length: number, identityKey: Buffer, key: Buffer): VaultRecordLocation | undefined {
    for (let number = this.#position.segment + 1; number >= 1; number--) {
      const segment = number > this.#position.segment ? null : number;
      const directory = segment === null ? this.#open : this.#segmentPath(segment);
      if (!statIfPresent(directory)) continue;
      for (const stream of streamNames(directory, segment === null ? [] : [MANIFEST, SIGNATURE])) {
        if (streamType(stream) !== 2) continue;
        const found = streamFile(join(directory, stream), (fd, size) => {
          let offset: number | undefined;
          const result = this.#scanner.walk(fd, size, record => {
            if (record.keyId !== keyId || record.end - record.offset !== length) return;
            const hash = createHmac('sha256', identityKey);
            this.#scanner.frames(fd, record, undefined, {
              vaultId: this.#unlocked.keyring.vault_id, key, consume: bytes => { hash.update(bytes); },
            });
            if (hash.digest('hex') === id) {
              offset = record.offset;
              return false;
            }
          });
          check(result.shortAt === undefined, 'LENGTH');
          return offset;
        });
        if (found !== undefined) return { segment: number, stream, offset: found };
      }
    }
    return undefined;
  }

  #append(type: 1 | 2, keyId: string, sequence: number, plaintext: Buffer): VaultRecordLocation {
    const length = recordLength(plaintext.length);
    const key = this.#unlocked.collectionEncryptionKey(keyId);
    let encoded: Buffer;
    try {
      if (this.#totalBytes > 0 && this.#totalBytes + length > SEGMENT_CAP) this.#seal();
      encoded = encodeRecord({ type, keyId, context: BigInt(sequence) }, plaintext, this.#unlocked.keyring.vault_id, key);
    } finally {
      key.fill(0);
    }
    const segment = this.#position.segment + 1;
    const existing = this.#streams.get(type);
    const newFile = !existing || existing.bytes + length > FILE_CAP;
    const ordinal = existing ? streamOrdinal(existing.name) + 1 : 1;
    if (newFile) integer(ordinal, 1);
    const stream = newFile
      ? { name: (type === 1 ? 'events-' : 'pack-') + String(ordinal).padStart(4, '0') + '.fvr', bytes: 0 }
      : existing;
    mkdirSync(this.#open, { recursive: true, mode: 0o700 });
    const path = join(this.#open, stream.name);
    const fd = newFile ? openSync(path, 'wx', 0o600) : openSync(path, 'r+');
    const offset = stream.bytes;
    try {
      this.#point('before-write');
      check(writeSync(fd, encoded, 0, length, offset) === length, 'LENGTH');
      this.#point('after-write');
    } finally {
      closeSync(fd);
    }
    stream.bytes += length;
    this.#streams.set(type, stream);
    this.#dirty.add(path);
    this.#totalBytes += length;
    if (type === 1) this.#last = sequence;
    if (this.#totalBytes >= SEGMENT_CAP) this.#seal();
    return { segment, stream: stream.name, offset };
  }

  #syncDirty(): void {
    if (!this.#dirty.size) return;
    this.#point('before-batch-fsync');
    for (const path of this.#dirty) this.#syncFile(path);
    syncDirectory(this.#open);
    syncDirectory(this.#directory);
    this.#dirty.clear();
    this.#point('after-batch-fsync');
  }

  #syncFile(path: string): void {
    const fd = openSync(path, 'r+');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  #seal(): void {
    if (!this.#totalBytes) return;
    const names = streamNames(this.#open, []);
    this.#point('before-close-fsync');
    for (const name of names) this.#syncFile(join(this.#open, name));
    syncDirectory(this.#open);
    // Make the old directory entry durable before publishing the rename.
    syncDirectory(this.#directory);
    this.#point('after-close-fsync');
    const scanned = scanOpen(this.#open, this.#position.lastEventSequence, this.#scanner, this.#unlocked);
    check('first' in scanned && scanned.totalBytes === this.#totalBytes && scanned.last === this.#last, 'LENGTH');
    const manifest: Manifest = {
      format: 'foundry-segment/1', vault_id: this.#unlocked.keyring.vault_id, epoch: 1,
      segment: this.#position.segment + 1, prev_manifest_sha256: this.#position.hash,
      first_event_seq: scanned.first, last_event_seq: scanned.first === null ? null : scanned.last,
      files: scanned.files, key_ids: [...scanned.keyIds].sort(),
      closed_at: new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z'), writer: this.#options.writer ?? 'foundry 0.1.0',
    };
    const { bytes, signature } = encodeManifest(manifest, this.#signingSeed);
    writePending(join(this.#open, MANIFEST_PENDING), bytes, () => this.#point('before-manifest-fsync'));
    this.#point('after-manifest-fsync');
    writePending(join(this.#open, SIGNATURE_PENDING), signature, () => this.#point('before-signature-fsync'));
    this.#point('after-signature-fsync');
    this.#point('before-signature-rename');
    renameWithRetry(join(this.#open, SIGNATURE_PENDING), join(this.#open, SIGNATURE));
    this.#point('after-signature-rename');
    this.#point('before-manifest-rename');
    renameWithRetry(join(this.#open, MANIFEST_PENDING), join(this.#open, MANIFEST));
    this.#point('after-manifest-rename');
    syncDirectory(this.#open);
    const position = { segment: manifest.segment, hash: sha256(bytes), lastEventSequence: scanned.last };
    writePending(join(this.#directory, HEAD_PENDING), headBytes(position), () => this.#point('before-head-fsync'));
    syncDirectory(this.#directory);
    this.#point('after-head-fsync');
    const target = this.#segmentPath(manifest.segment);
    check(!statIfPresent(target), 'CHAIN');
    this.#point('before-segment-rename');
    renameWithRetry(this.#open, target);
    this.#point('after-segment-rename');
    syncDirectory(join(this.#directory, 'segments'));
    syncDirectory(this.#directory);
    this.#point('before-head-update');
    replaceHead(this.#directory);
    this.#point('after-head-update');
    makeReadOnly(target);
    this.#position = position;
    this.#totalBytes = 0;
    this.#streams.clear();
    this.#dirty.clear();
  }
}

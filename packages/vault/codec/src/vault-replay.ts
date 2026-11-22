import { Buffer } from 'node:buffer';
import { createHash, createHmac } from 'node:crypto';
import { closeSync, fstatSync, openSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { check, integer, sha256 } from './bytes.ts';
import { collectionIdKey, decodeKeyring } from './keyring.ts';
import type { Unlock } from './keyring.ts';
import { streamOrdinal } from './manifest.ts';
import type { ManifestFile } from './manifest.ts';
import { diskRecord, StreamScanner } from './record-file.ts';
import type { UnlockedKeyring } from './record-file.ts';
import { FRAME_OVERHEAD, HEADER_BYTES } from './record.ts';
import {
  checkRootInventory, checkVerifiedHead, metadata, OPEN_ARTIFACTS, readHead, scanOpen, scanSealed, segmentName,
  statIfPresent, streamNames, streamType,
} from './vault-directory.ts';
import type { VerifyOptions } from './vault-directory.ts';
import type { VaultRecordLocation } from './vault-reader.ts';

export interface ReplayLocation extends VaultRecordLocation {
  encodedLength: number;
  /** Binds a located read to the record header observed during replay. */
  headerSha256: string;
}

interface ReplayRecord {
  location: ReplayLocation;
  keyId: string;
}

export type VaultReplayItem = ReplayRecord & (
  | { type: 'event'; seq: number; event: Record<string, unknown> }
  | { type: 'blob'; blobId: string }
  | { type: 'skipped'; recordType: 'event'; seq: number }
  | { type: 'skipped'; recordType: 'blob' }
);

export interface ReplayOptions {
  /** Yields only restore-rule events and explicit destroyed-key skips. */
  withdrawalsOnly?: boolean;
}

interface CapturedStream extends ManifestFile {
  segment: number;
  type: 1 | 2;
}

const withdrawalKinds = new Set<unknown>(['consent.withdrawn', 'redaction.applied', 'key.destroyed']);

const activeIterators = new WeakMap<object, ReadonlySet<unknown>>();

/** TEST ONLY: the number of started, unfinished iterators a replay source tracks for close(). */
export function activeReplayIteratorCountForTest(source: object): number {
  return activeIterators.get(source)?.size ?? 0;
}

function openCapturedStream(directory: string, stream: CapturedStream, openSegment: number): number {
  const sealed = join(directory, 'segments', segmentName(stream.segment));
  const openPath = join(directory, 'open', stream.name);
  if (stream.segment === openSegment && !statIfPresent(sealed)) {
    try {
      if (statIfPresent(openPath)?.isFile()) {
        const fd = openSync(openPath, 'r');
        let useOpen = false;
        try {
          useOpen = !statIfPresent(sealed);
          if (useOpen) return fd;
        } finally {
          if (!useOpen) closeSync(fd);
        }
      }
    } catch (error) {
      if ((error as { code?: string }).code !== 'ENOENT') throw error;
    }
  }
  const path = join(sealed, stream.name);
  check(statIfPresent(sealed)?.isDirectory() && statIfPresent(path)?.isFile(), 'INVENTORY');
  return openSync(path, 'r');
}

function openStreamLengths(directory: string): Map<string, number> {
  const lengths = new Map<string, number>();
  if (statIfPresent(directory)) {
    for (const name of streamNames(directory, OPEN_ARTIFACTS)) {
      const stat = statIfPresent(join(directory, name));
      check(stat && stat.isFile() && Number.isSafeInteger(stat.size), 'INVENTORY');
      lengths.set(name, stat.size);
    }
  }
  return lengths;
}

function clearKeys(unlocked: UnlockedKeyring): void {
  unlocked.masterKey.fill(0);
  for (const key of unlocked.keys.values()) key.fill(0);
  unlocked.labels.clear();
}

/** Capture and verify the append-only prefix before opening either rebuild pass. */
export function openVaultReplay(directory: string, credential: Unlock, { anchor }: VerifyOptions = {}) {
  directory = resolve(directory);
  const vault = metadata(directory);
  checkRootInventory(directory);
  const head = readHead(directory);
  const next = join(directory, 'segments', segmentName(head.segment + 1));
  const sealedAtStart = head.segment + Number(statIfPresent(next)?.isDirectory() ?? false);
  const openSegment = sealedAtStart + 1;
  const openPath = join(directory, 'open');
  const limits = openStreamLengths(openPath);
  const confirm = openStreamLengths(openPath);
  check(limits.size === confirm.size && [...limits].every(([name, bytes]) => confirm.get(name) === bytes), 'FILE_SIZE');
  const keyringPath = join(directory, 'keyring', 'keyring.json');
  check(statIfPresent(join(directory, 'keyring'))?.isDirectory() && statIfPresent(keyringPath)?.isFile(), 'INVENTORY');
  const unlocked = decodeKeyring(readFileSync(keyringPath), credential, vault.vault_id);
  const streams: Record<1 | 2, CapturedStream[]> = { 1: [], 2: [] };
  const scanner = new StreamScanner();
  const captureFiles = (segment: number, files: ManifestFile[]) => {
    for (const file of [...files].sort((a, b) => streamOrdinal(a.name) - streamOrdinal(b.name))) {
      const type = streamType(file.name);
      streams[type].push({ ...file, segment, type });
    }
  };
  try {
    const { position, previous, erased } = scanSealed(directory, vault, scanner, unlocked, anchor, undefined, captureFiles);
    check(position.segment === sealedAtStart, 'HEAD');
    checkVerifiedHead(directory, position, previous);
    const open = scanOpen(openPath, position.lastEventSequence, scanner, unlocked, true, undefined, limits);
    check(!statIfPresent(join(directory, 'segments', segmentName(openSegment))), 'HEAD');
    checkVerifiedHead(directory, position, previous);
    captureFiles(openSegment, open.files);
    const destroyed = new Set(unlocked.keyring.keys.filter(entry => entry.kind === 'collection'
      && entry.state === 'destroyed').map(entry => entry.key_id));
    const packBySegment = new Map(streams[2].map(stream => [`${stream.segment}/${stream.name}`, stream]));
    const skipped = erased + open.erased;
    let closed = false;
    const active = new Set<() => void>();

    function track<T, R>(generator: Generator<T, R, undefined>): Generator<T, R, undefined> {
      // Registered in `active` on the first next()/throw(), so dropped unstarted iterators hold no reference.
      let started = false;
      let finished = false;
      let endedByClose = false;
      // True while this generator's body runs; close() must not call .return() on a running generator.
      let running = false;
      const closeIterator = () => {
        endedByClose = true;
        active.delete(closeIterator);
        // A running read fails KEY at its next checkpoint (or when its step returns) instead.
        if (!running) generator.return(undefined as R);
      };
      const step = (resume: () => IteratorResult<T, R>): IteratorResult<T, R> => {
        // A reentrant call on this running generator: the engine throws its own TypeError and no flag changes.
        if (running) return resume();
        if (!started) {
          started = true;
          if (closed) {
            endedByClose = true;
            generator.return(undefined as R);
          } else {
            active.add(closeIterator);
          }
        }
        if (endedByClose || (closed && !finished)) check(false, 'KEY');
        let result: IteratorResult<T, R>;
        running = true;
        try {
          result = resume();
        } catch (error) {
          finished = true;
          active.delete(closeIterator);
          // close() ran during this step: the read fails KEY, whatever error ended the step.
          if (endedByClose) check(false, 'KEY');
          throw error;
        } finally {
          running = false;
        }
        if (result.done) {
          finished = true;
          active.delete(closeIterator);
        }
        if (endedByClose) {
          // close() ran during this step: end the generator now so its finally blocks wipe keys, then fail KEY.
          if (!result.done) generator.return(undefined as R);
          finished = true;
          check(false, 'KEY');
        }
        return result;
      };
      const iterator = Object.create(
        Object.getPrototypeOf(Object.getPrototypeOf(generator)),
      ) as Generator<T, R, undefined>;
      iterator.next = () => step(() => generator.next());
      iterator.return = (value: R) => {
        // On a running generator this call throws "already running" before any flag below changes; keep that order.
        const result = generator.return(value);
        // Only a never-started iterator returned after close() is marked, so its later next() fails KEY. A started one
        // was already marked by close() itself if it was still active; an ended one stays done. Never joins `active`.
        if (closed && !started) endedByClose = true;
        started = true;
        finished = true;
        active.delete(closeIterator);
        return result;
      };
      iterator.throw = (error: unknown) => step(() => generator.throw(error));
      iterator[Symbol.iterator] = () => iterator;
      return iterator;
    }

    function* replay({ withdrawalsOnly = false }: ReplayOptions = {}): Generator<VaultReplayItem, { skipped: number }, undefined> {
      check(!closed, 'KEY');
      const scanner = new StreamScanner();
      const header = Buffer.alloc(HEADER_BYTES);
      for (const group of [streams[1], streams[2]]) {
        for (const stream of group) {
          check(!closed, 'KEY');
          const fd = openCapturedStream(directory, stream, openSegment);
          try {
            const size = fstatSync(fd).size;
            check(stream.segment === openSegment ? size >= stream.bytes : size === stream.bytes, 'FILE_SIZE');
            const verified = scanner.scan(fd, stream.bytes, stream.type, () => {});
            check(verified.shortAt === undefined, 'LENGTH');
            if (verified.sha256 !== stream.sha256) {
              // Classify the damaged record before falling back to the snapshot hash error.
              scanner.scan(fd, stream.bytes, stream.type, () => {}, unlocked);
              check(false, 'FILE_HASH');
            }
            const hash = createHash('sha256');
            let offset = 0;
            while (offset < stream.bytes) {
              check(!closed, 'KEY');
              const record = diskRecord(fd, offset, stream.bytes, header);
              check(record, 'LENGTH');
              check(record.type === stream.type);
              const keyId = record.keyId;
              const location = { segment: stream.segment, stream: stream.name, offset,
                encodedLength: record.end - offset, headerSha256: sha256(header) };
              offset = record.end;
              if (destroyed.has(keyId)) {
                scanner.frames(fd, record, hash);
                yield record.type === 1
                  ? { type: 'skipped', recordType: 'event', seq: Number(record.context), keyId, location }
                  : { type: 'skipped', recordType: 'blob', keyId, location };
              } else if (record.type === 1) {
                const bytes = scanner.authenticate(fd, record, unlocked, hash, true)!;
                let event: Record<string, unknown>;
                try {
                  event = JSON.parse(bytes.toString()) as Record<string, unknown>;
                } finally {
                  bytes.fill(0);
                }
                if (!withdrawalsOnly || withdrawalKinds.has(event.kind)) {
                  yield { type: 'event', seq: Number(record.context), event, keyId, location };
                }
              } else if (withdrawalsOnly) {
                scanner.frames(fd, record, hash);
              } else {
                const key = unlocked.collectionEncryptionKey(keyId);
                const idKey = collectionIdKey(unlocked.keys.get(keyId)!, vault.vault_id);
                let blobId: string;
                try {
                  const identity = createHmac('sha256', idKey);
                  scanner.frames(fd, record, hash, { vaultId: vault.vault_id, key, consume: chunk => { identity.update(chunk); } });
                  blobId = identity.digest('hex');
                } finally {
                  idKey.fill(0);
                  key.fill(0);
                }
                yield { type: 'blob', blobId, keyId, location };
              }
            }
            if (hash.digest('hex') !== stream.sha256) {
              // Preserve V-3's KEY/AUTH distinction even in a framing-only filtered pack.
              if (withdrawalsOnly && stream.type === 2) scanner.scan(fd, stream.bytes, stream.type, () => {}, unlocked);
              check(false, 'FILE_HASH');
            }
          } finally {
            closeSync(fd);
          }
        }
      }
      return { skipped };
    }

    function* streamBlob(location: ReplayLocation): Generator<Buffer, void, undefined> {
      check(!closed, 'KEY');
      const { segment, stream: name, offset, encodedLength, headerSha256 } = location;
      // Location getters run here and may call close().
      check(!closed, 'KEY');
      integer(offset);
      integer(encodedLength, HEADER_BYTES + FRAME_OVERHEAD);
      const stream = packBySegment.get(`${segment}/${name}`);
      check(stream, 'INVENTORY');
      check(encodedLength <= stream.bytes - offset, 'LENGTH');
      const fd = openCapturedStream(directory, stream, openSegment);
      try {
        const record = diskRecord(fd, offset, offset + encodedLength, Buffer.alloc(HEADER_BYTES));
        check(record && record.end === offset + encodedLength, 'LENGTH');
        check(record.type === 2);
        check(sha256(record.header) === headerSha256, 'FILE_HASH');
        check(!closed, 'KEY');
        const key = unlocked.collectionEncryptionKey(record.keyId);
        try {
          const frames = new StreamScanner().frameChunks(fd, record, undefined, { vaultId: vault.vault_id, key });
          for (const chunk of frames) {
            check(!closed, 'KEY');
            yield chunk;
            check(!closed, 'KEY');
          }
        } finally {
          key.fill(0);
        }
      } finally {
        closeSync(fd);
      }
    }

    const source = {
      boundary: {
        sealed: position,
        openSegment,
        openStreams: [...limits].map(([name, bytes]) => ({ name, bytes })),
        repairs: open.incomplete,
        lastEventSequence: open.last,
      },
      skipped,
      replay(options?: ReplayOptions) {
        return track(replay(options));
      },
      streamBlob(location: ReplayLocation) {
        return track(streamBlob(location));
      },
      close() {
        closed = true;
        try {
          let firstError: unknown;
          for (const closeIterator of [...active]) {
            try {
              closeIterator();
            } catch (error) {
              firstError ??= error;
            }
          }
          active.clear();
          if (firstError !== undefined) throw firstError;
        } finally {
          clearKeys(unlocked);
        }
      },
    };
    activeIterators.set(source, active);
    return source;
  } catch (error) {
    clearKeys(unlocked);
    throw error;
  }
}

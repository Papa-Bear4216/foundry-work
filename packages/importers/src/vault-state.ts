/**
 * @file vault-state.ts
 * Helpers for computing collection-keyed blob IDs (Architecture 4.4) and scanning
 * existing `item.imported` events from a V-3 vault directory via V-3's public
 * `readVaultRecord` API for idempotent re-import and crash resumption.
 */

import { Buffer } from 'node:buffer';
import { createHmac, hkdfSync } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readdirSync, readSync } from 'node:fs';
import { join } from 'node:path';
import type { UnlockedKeyringLike, VaultRecordLocation } from './types.js';
import { computeItemKey } from './defaults.js';

const FVR1_MAGIC = Buffer.from('FVR1', 'ascii');
const FVR1_HEADER_BYTES = 69;

/** Derives the 32-byte collection ID key per Architecture 5.1 (`foundry/collection-id/v1`). */
export function deriveCollectionIdKey(collectionKey: Buffer, vaultId: string): Buffer {
  const salt = Buffer.from(vaultId, 'hex');
  const info = Buffer.from('foundry/collection-id/v1', 'ascii');
  return Buffer.from(hkdfSync('sha256', collectionKey, salt, info, 32));
}

/** Computes the collection-keyed blob ID per Architecture 4.4 (`HMAC-SHA256(idKey, plaintext)`). */
export function computeBlobId(collectionIdKey: Buffer, plaintext: Buffer): string {
  return createHmac('sha256', collectionIdKey).update(plaintext).digest('hex');
}

export type ReadVaultRecordFn = (
  directory: string,
  location: VaultRecordLocation,
  unlocked: UnlockedKeyringLike,
) => { type: number; context: bigint; keyId: string; plaintext: Buffer };

function listEventStreams(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const names: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isFile() && /^events-\d{4,16}\.fvr$/u.test(entry.name)) {
      names.push(entry.name);
    }
  }
  return names.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function* iterateRecordOffsets(filePath: string): Iterable<{ offset: number; type: number; keyId: string }> {
  const fd = openSync(filePath, 'r');
  try {
    const size = fstatSync(fd).size;
    const header = Buffer.alloc(FVR1_HEADER_BYTES);
    let offset = 0;
    while (offset + FVR1_HEADER_BYTES <= size) {
      const read = readSync(fd, header, 0, FVR1_HEADER_BYTES, offset);
      if (read < FVR1_HEADER_BYTES) break;
      if (!header.subarray(0, 4).equals(FVR1_MAGIC)) break;
      const type = header[4]!;
      const keyId = header.subarray(5, 21).toString('hex');
      const bodyLen = header.readBigUInt64BE(61);
      const next = offset + FVR1_HEADER_BYTES + Number(bodyLen);
      if (!Number.isSafeInteger(next) || next > size) break;
      yield { offset, type, keyId };
      offset = next;
    }
  } finally {
    closeSync(fd);
  }
}

/**
 * Loads existing idempotent `item_key` values from every `events-*.fvr` stream in
 * sealed `segments/` and `open/` using V-3's `readVaultRecord`.
 * Skips records encrypted under destroyed collection keys.
 */
export function loadExistingItemKeys(
  vaultDir: string,
  unlocked: UnlockedKeyringLike,
  readVaultRecord: ReadVaultRecordFn,
): Set<string> {
  const existing = new Set<string>();
  const destroyed = new Set(
    unlocked.keyring.keys
      .filter(k => k.kind === 'collection' && k.state === 'destroyed')
      .map(k => k.key_id),
  );

  const scanStreamDir = (dir: string, segment: number) => {
    for (const stream of listEventStreams(dir)) {
      const filePath = join(dir, stream);
      for (const rec of iterateRecordOffsets(filePath)) {
        if (rec.type !== 1 || destroyed.has(rec.keyId)) continue;
        const record = readVaultRecord(vaultDir, { segment, stream, offset: rec.offset }, unlocked);
        try {
          const parsed = JSON.parse(record.plaintext.toString('utf8')) as Record<string, unknown>;
          if (parsed.kind !== 'item.imported') continue;
          const body = parsed.body as Record<string, unknown> | undefined;
          if (!body || typeof body !== 'object') continue;
          if (typeof body.item_key === 'string' && body.item_key.length === 64) {
            existing.add(body.item_key);
          } else if (
            typeof parsed.profile === 'string' &&
            typeof parsed.collection === 'string' &&
            typeof parsed.source === 'string' &&
            typeof body.path === 'string' &&
            typeof body.blob === 'string'
          ) {
            existing.add(computeItemKey(parsed.profile, parsed.collection, parsed.source, body.path, body.blob));
          }
        } finally {
          record.plaintext.fill(0);
        }
      }
    }
  };

  let maxSealedSegment = 0;
  const segmentsDir = join(vaultDir, 'segments');
  if (existsSync(segmentsDir)) {
    const segNums = readdirSync(segmentsDir, { withFileTypes: true })
      .filter(d => d.isDirectory() && /^\d+$/.test(d.name))
      .map(d => ({ name: d.name, num: Number.parseInt(d.name, 10) }))
      .sort((a, b) => a.num - b.num);
    for (const seg of segNums) {
      maxSealedSegment = seg.num;
      scanStreamDir(join(segmentsDir, seg.name), seg.num);
    }
  }

  const openDir = join(vaultDir, 'open');
  if (existsSync(openDir)) {
    scanStreamDir(openDir, maxSealedSegment + 1);
  }

  return existing;
}

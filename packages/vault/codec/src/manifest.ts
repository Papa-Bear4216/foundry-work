import { Buffer } from 'node:buffer';
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import {
  base64, canonical, check, hex, integer, object, parseCanonical, sha256, timestamp,
} from './bytes.ts';
import type { Json } from './bytes.ts';
import { scanRecords } from './record.ts';

export const GENESIS_HASH = '0'.repeat(64);
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

export function decodeVaultMetadata(raw: Buffer) {
  const data = parseCanonical(raw);
  check(data !== null && typeof data === 'object' && Object.hasOwn(data, 'format'));
  check((data as { format: unknown }).format === 'foundry-vault/1', 'VERSION');
  object(data, 'format vault_id created_at signing_public_key');
  const { vault_id, created_at, signing_public_key } = data;
  hex(vault_id, 16);
  timestamp(created_at);
  base64(signing_public_key, 32);
  return { format: 'foundry-vault/1' as const, vault_id, created_at, signing_public_key };
}

export interface ManifestFile {
  name: string;
  bytes: number;
  sha256: string;
}

export interface Manifest {
  format: 'foundry-segment/1';
  vault_id: string;
  epoch: 1;
  segment: number;
  prev_manifest_sha256: string;
  first_event_seq: number | null;
  last_event_seq: number | null;
  files: ManifestFile[];
  key_ids: string[];
  closed_at: string;
  writer: string;
}

function signingKey(seed: Buffer) {
  check(seed.length === 32, 'KEY');
  return createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([PKCS8_PREFIX, seed]) });
}

export function signingPublicKey(seed: Buffer): Buffer {
  return createPublicKey(signingKey(seed)).export({ format: 'der', type: 'spki' }).subarray(SPKI_PREFIX.length);
}

function validateManifest(value: unknown): asserts value is Manifest {
  check(value !== null && typeof value === 'object' && Object.hasOwn(value, 'format'));
  check((value as { format: unknown }).format === 'foundry-segment/1', 'VERSION');
  object(value, 'format vault_id epoch segment prev_manifest_sha256 first_event_seq last_event_seq files key_ids closed_at writer');
  hex(value.vault_id, 16);
  check(value.epoch === 1);
  integer(value.segment, 1);
  hex(value.prev_manifest_sha256, 32);
  if (value.first_event_seq === null) {
    check(value.last_event_seq === null);
  } else {
    integer(value.first_event_seq, 1);
    integer(value.last_event_seq, value.first_event_seq);
  }
  timestamp(value.closed_at);
  check(typeof value.writer === 'string' && value.writer.length > 0);
  check(Array.isArray(value.files) && value.files.length > 0
    && Array.isArray(value.key_ids) && value.key_ids.length > 0);
  let previous = '';
  for (const file of value.files) {
    object(file, 'name bytes sha256');
    check(typeof file.name === 'string' && /^(?:events|pack)-[0-9]{4,}\.fvr$/u.test(file.name)
      && file.name.endsWith('.fvr') && file.name > previous);
    const number = file.name.slice(file.name.indexOf('-') + 1, -4);
    check(Number.isSafeInteger(Number(number)) && Number(number) >= 1
      && number === String(Number(number)).padStart(4, '0'));
    integer(file.bytes, 89);
    hex(file.sha256, 32);
    previous = file.name;
  }
  previous = '';
  for (const id of value.key_ids) {
    hex(id, 16);
    check(id > previous);
    previous = id;
  }
}

export function encodeManifest(manifest: Manifest, seed: Buffer): { bytes: Buffer; signature: Buffer } {
  validateManifest(manifest);
  const bytes = Buffer.from(canonical(manifest as unknown as Json));
  return { bytes, signature: sign(null, bytes, signingKey(seed)) };
}

export function decodeManifest(bytes: Buffer, signature: Buffer, publicKey: Buffer): Manifest {
  const data = parseCanonical(bytes);
  validateManifest(data);
  check(publicKey.length === 32, 'KEY');
  const key = createPublicKey({ format: 'der', type: 'spki', key: Buffer.concat([SPKI_PREFIX, publicKey]) });
  check(signature.length === 64 && verify(null, bytes, key, signature), 'SIGNATURE');
  return data;
}

export interface ChainPosition {
  segment: number;
  hash: string;
  lastEventSequence: number;
}

export function verifySegment(
  bytes: Buffer, signature: Buffer, publicKey: Buffer, vaultId: string,
  files: ReadonlyMap<string, Buffer>, previous?: ChainPosition,
) {
  const manifest = decodeManifest(bytes, signature, publicKey);
  const lastEvent = previous?.lastEventSequence ?? 0;
  check(manifest.vault_id === vaultId && manifest.segment === (previous?.segment ?? 0) + 1
    && manifest.prev_manifest_sha256 === (previous?.hash ?? GENESIS_HASH)
    && (manifest.first_event_seq === null || manifest.first_event_seq === lastEvent + 1), 'CHAIN');
  check(files.size === manifest.files.length, 'FILE');

  let eventSequence = lastEvent;
  const keyIds = new Set<string>();
  // Event stream filenames are traversed by numeric ordinal, including ordinals above 9999.
  const ordered = [...manifest.files].sort((a, b) => {
    const aNumber = Number(a.name.slice(a.name.indexOf('-') + 1, -4));
    const bNumber = Number(b.name.slice(b.name.indexOf('-') + 1, -4));
    return aNumber - bNumber;
  });
  for (const file of ordered) {
    const stream = files.get(file.name);
    check(stream && stream.length === file.bytes && sha256(stream) === file.sha256, 'FILE');
    const type = file.name.startsWith('events-') ? 1 : 2;
    for (const record of scanRecords(stream)) {
      check(record.type === type, 'SCHEMA');
      keyIds.add(record.keyId);
      if (record.type === 1) check(record.context === BigInt(++eventSequence), 'SEQUENCE');
    }
  }
  check(eventSequence === (manifest.last_event_seq ?? lastEvent), 'SEQUENCE');
  check(manifest.key_ids.join() === [...keyIds].sort().join(), 'KEY');
  const position: ChainPosition = {
    segment: manifest.segment, hash: sha256(bytes), lastEventSequence: eventSequence,
  };
  return { manifest, position };
}

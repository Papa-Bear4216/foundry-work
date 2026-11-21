import { Buffer, isUtf8 } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { check, derive, hex, open, seal, VaultFormatError } from './bytes.ts';

export const FRAME_BYTES = 1024 * 1024;
const HEADER_BYTES = 69;
const OVERHEAD = 20;
const MAX_U64 = (1n << 64n) - 1n;

export interface RecordFields {
  type: 1 | 2;
  keyId: string;
  context: bigint;
}

function checkFields(type: number, context: bigint): asserts type is 1 | 2 {
  check(type === 1 ? context > 0n && context <= MAX_U64 : type === 2 && context === 0n);
}

function frameParameters(header: Buffer, vaultId: string, index: bigint, final: boolean) {
  hex(vaultId, 16);
  const nonce = Buffer.alloc(12);
  nonce.writeBigUInt64BE(index, 4);
  const aad = Buffer.concat([header, Buffer.from(vaultId, 'hex'), nonce.subarray(4), Buffer.from([Number(final)])]);
  return { nonce, aad };
}

/** The optional salt is for reproducible vectors. Never reuse a salt with a production key. */
export function encodeRecord(
  fields: RecordFields, plaintext: Buffer, vaultId: string, encryptionKey: Buffer, salt = randomBytes(32),
): Buffer {
  checkFields(fields.type, fields.context);
  hex(fields.keyId, 16);
  check(salt.length === 32);
  check(fields.type === 2 || BigInt(eventSequence(plaintext)) === fields.context, 'SEQUENCE');
  const count = Math.max(1, Math.ceil(plaintext.length / FRAME_BYTES));
  const header = Buffer.alloc(HEADER_BYTES);
  header.set(Buffer.from('FVR1'));
  header[4] = fields.type;
  header.set(Buffer.from(fields.keyId, 'hex'), 5);
  header.set(salt, 21);
  header.writeBigUInt64BE(fields.context, 53);
  header.writeBigUInt64BE(BigInt(plaintext.length + count * OVERHEAD), 61);

  const key = derive(encryptionKey, 'record-key', salt);
  const chunks = [header];
  for (let i = 0; i < count; i++) {
    const frame = plaintext.subarray(i * FRAME_BYTES, (i + 1) * FRAME_BYTES);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(frame.length, 0);
    const { nonce, aad } = frameParameters(header, vaultId, BigInt(i), i === count - 1);
    chunks.push(length, seal(key, nonce, aad, frame));
  }
  return Buffer.concat(chunks);
}

interface ScannedRecord extends RecordFields {
  header: Buffer;
  frames: Buffer[];
}

export function* scanRecords(stream: Buffer): Generator<ScannedRecord, void, undefined> {
  let start = 0;
  while (start < stream.length) {
    check(stream.length - start >= HEADER_BYTES, 'LENGTH');
    const header = stream.subarray(start, start + HEADER_BYTES);
    check(header.subarray(0, 4).equals(Buffer.from('FVR1')), 'VERSION');
    const type = header[4];
    const context = header.readBigUInt64BE(53);
    checkFields(type, context);
    const bodyLength = header.readBigUInt64BE(61);
    let offset = start + HEADER_BYTES;
    check(bodyLength >= BigInt(OVERHEAD) && bodyLength <= BigInt(stream.length - offset), 'LENGTH');
    const end = offset + Number(bodyLength);
    const frames: Buffer[] = [];
    while (offset < end) {
      check(end - offset >= OVERHEAD, 'LENGTH');
      const size = stream.readUInt32BE(offset);
      const next = offset + OVERHEAD + size;
      const final = next === end;
      check(next <= end && size <= FRAME_BYTES && (final || size === FRAME_BYTES)
        && (size > 0 || (type === 2 && frames.length === 0)), 'LENGTH');
      frames.push(stream.subarray(offset + 4, next));
      offset = next;
    }
    yield { header, frames, type, context, keyId: header.subarray(5, 21).toString('hex') };
    start = end;
  }
}

export function eventSequence(bytes: Buffer): number {
  check(isUtf8(bytes));
  let event: unknown;
  try {
    // The source token preserves the integer spelling before JSON numbers are rounded.
    const parse = JSON.parse as (text: string, reviver: (key: string, value: unknown,
      context: { source?: string }) => unknown) => unknown;
    event = parse(bytes.toString(), (key, value, { source }) => {
      if (key !== 'seq') return value;
      return source && /^[1-9][0-9]*$/u.test(source) ? value : null;
    });
  } catch {
    throw new VaultFormatError('SCHEMA');
  }
  check(event !== null && typeof event === 'object' && Object.hasOwn(event, 'seq'));
  const seq = (event as { seq: unknown }).seq;
  check(typeof seq === 'number' && Number.isSafeInteger(seq) && seq > 0, 'SEQUENCE');
  return seq;
}

export function decryptRecord(
  record: ScannedRecord,
  vaultId: string, encryptionKey: Buffer,
): Buffer {
  const { header, frames } = record;
  const key = derive(encryptionKey, 'record-key', header.subarray(21, 53));
  const plaintext = Buffer.concat(frames.map((frame, index) => {
    const { nonce, aad } = frameParameters(header, vaultId, BigInt(index), index === frames.length - 1);
    return open(key, nonce, aad, frame);
  }));
  check(record.type === 2 || BigInt(eventSequence(plaintext)) === record.context, 'SEQUENCE');
  return plaintext;
}

export function decodeRecord(bytes: Buffer, vaultId: string, encryptionKey: Buffer): RecordFields & { plaintext: Buffer } {
  const records = scanRecords(bytes);
  const first = records.next();
  check(!first.done && records.next().done, 'LENGTH');
  const { type, keyId, context } = first.value;
  return { type, keyId, context, plaintext: decryptRecord(first.value, vaultId, encryptionKey) };
}

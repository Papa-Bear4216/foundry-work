import { Buffer, isUtf8 } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { check, derive, hex, open, sealInto, VaultFormatError } from './bytes.ts';

export const FRAME_BYTES = 1024 * 1024;
export const HEADER_BYTES = 69;
export const FRAME_OVERHEAD = 20;
const MAX_EVENT_CONTEXT = BigInt(Number.MAX_SAFE_INTEGER);
const MAGIC = Buffer.from('FVR1');

export interface RecordFields {
  type: 1 | 2;
  keyId: string;
  context: bigint;
}

export function recordLength(plaintextBytes: number): number {
  return HEADER_BYTES + plaintextBytes + Math.max(1, Math.ceil(plaintextBytes / FRAME_BYTES)) * FRAME_OVERHEAD;
}

export function decodeRecordHeader(header: Buffer) {
  check(header.length === HEADER_BYTES, 'LENGTH');
  check(header.subarray(0, 4).equals(MAGIC), 'VERSION');
  const type = header[4];
  const context = header.readBigUInt64BE(53);
  checkFields(type, context);
  const bodyLength = header.readBigUInt64BE(61);
  check(bodyLength >= BigInt(FRAME_OVERHEAD), 'LENGTH');
  return { type, context, keyId: header.subarray(5, 21).toString('hex'), bodyLength };
}

export function checkFrameSize(size: number, remaining: number, type: number, first: boolean): void {
  const length = FRAME_OVERHEAD + size;
  check(length <= remaining && size <= FRAME_BYTES && (length === remaining || size === FRAME_BYTES)
    && (size > 0 || (type === 2 && first)), 'LENGTH');
}

function checkFields(type: number, context: bigint): asserts type is 1 | 2 {
  check(type === 1 ? context > 0n && context <= MAX_EVENT_CONTEXT : type === 2 && context === 0n);
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
  const output = Buffer.allocUnsafe(recordLength(plaintext.length));
  const header = output.subarray(0, HEADER_BYTES);
  header.set(MAGIC);
  header[4] = fields.type;
  header.set(Buffer.from(fields.keyId, 'hex'), 5);
  header.set(salt, 21);
  header.writeBigUInt64BE(fields.context, 53);
  header.writeBigUInt64BE(BigInt(output.length - HEADER_BYTES), 61);

  const key = derive(encryptionKey, 'record-key', salt);
  try {
    let offset = HEADER_BYTES;
    for (let i = 0; i < count; i++) {
      const frame = plaintext.subarray(i * FRAME_BYTES, (i + 1) * FRAME_BYTES);
      output.writeUInt32BE(frame.length, offset);
      const { nonce, aad } = frameParameters(header, vaultId, BigInt(i), i === count - 1);
      sealInto(key, nonce, aad, frame, output, offset + 4);
      offset += FRAME_OVERHEAD + frame.length;
    }
    return output;
  } finally {
    key.fill(0);
  }
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
    const { type, context, keyId, bodyLength } = decodeRecordHeader(header);
    let offset = start + HEADER_BYTES;
    check(bodyLength <= BigInt(stream.length - offset), 'LENGTH');
    const end = offset + Number(bodyLength);
    const frames: Buffer[] = [];
    while (offset < end) {
      check(end - offset >= FRAME_OVERHEAD, 'LENGTH');
      const size = stream.readUInt32BE(offset);
      checkFrameSize(size, end - offset, type, frames.length === 0);
      const next = offset + FRAME_OVERHEAD + size;
      frames.push(stream.subarray(offset + 4, next));
      offset = next;
    }
    yield { header, frames, type, context, keyId };
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

export function recordKey(header: Buffer, encryptionKey: Buffer): Buffer {
  return derive(encryptionKey, 'record-key', header.subarray(21, 53));
}

export function decryptFrame(
  header: Buffer, vaultId: string, key: Buffer, frame: Buffer, index: number, final: boolean,
): Buffer {
  const { nonce, aad } = frameParameters(header, vaultId, BigInt(index), final);
  return open(key, nonce, aad, frame);
}

export function decryptRecord(
  record: ScannedRecord,
  vaultId: string, encryptionKey: Buffer,
): Buffer {
  const { header, frames } = record;
  const key = recordKey(header, encryptionKey);
  const chunks: Buffer[] = [];
  try {
    for (const [index, frame] of frames.entries()) {
      chunks.push(decryptFrame(header, vaultId, key, frame, index, index === frames.length - 1));
    }
    const plaintext = Buffer.concat(chunks);
    check(record.type === 2 || BigInt(eventSequence(plaintext)) === record.context, 'SEQUENCE');
    return plaintext;
  } finally {
    key.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

export function decodeRecord(bytes: Buffer, vaultId: string, encryptionKey: Buffer): RecordFields & { plaintext: Buffer } {
  const records = scanRecords(bytes);
  const first = records.next();
  check(!first.done && records.next().done, 'LENGTH');
  const { type, keyId, context } = first.value;
  return { type, keyId, context, plaintext: decryptRecord(first.value, vaultId, encryptionKey) };
}

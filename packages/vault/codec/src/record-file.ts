import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { check } from './bytes.ts';
import {
  checkFrameSize, decodeRecordHeader, decryptFrame, eventSequence, FRAME_BYTES, FRAME_OVERHEAD, HEADER_BYTES, recordKey,
} from './record.ts';
import type { RecordFields } from './record.ts';
import type { decodeKeyring } from './keyring.ts';

export type UnlockedKeyring = ReturnType<typeof decodeKeyring>;

export interface DiskRecord extends RecordFields {
  offset: number;
  end: number;
  header: Buffer;
}

export function readExactly(fd: number, target: Buffer, position: number): void {
  let read = 0;
  while (read < target.length) {
    const count = readSync(fd, target, read, target.length - read, position + read);
    check(count > 0, 'LENGTH');
    read += count;
  }
}

export function streamFile<T>(path: string, callback: (fd: number, size: number) => T): T {
  const fd = openSync(path, 'r');
  try {
    const stat = fstatSync(fd);
    check(stat.isFile() && Number.isSafeInteger(stat.size), 'INVENTORY');
    return callback(fd, stat.size);
  } finally {
    closeSync(fd);
  }
}

/** Undefined means a physically incomplete record. Complete malformed framing throws. */
export function diskRecord(fd: number, offset: number, size: number, header: Buffer): DiskRecord | undefined {
  if (size - offset < HEADER_BYTES) {
    const prefix = header.subarray(0, Math.min(4, size - offset));
    readExactly(fd, prefix, offset);
    check(prefix.equals(Buffer.from('FVR1').subarray(0, prefix.length)), 'VERSION');
    return undefined;
  }
  readExactly(fd, header, offset);
  const { bodyLength, ...fields } = decodeRecordHeader(header);
  if (bodyLength > BigInt(size - offset - HEADER_BYTES)) return undefined;
  return { ...fields, header, offset, end: offset + HEADER_BYTES + Number(bodyLength) };
}

export class StreamScanner {
  readonly #header = Buffer.alloc(HEADER_BYTES);
  readonly #frame = Buffer.allocUnsafe(FRAME_BYTES + FRAME_OVERHEAD);

  frames(
    fd: number, record: DiskRecord, hash?: ReturnType<typeof createHash>,
    plaintext?: { vaultId: string; key: Buffer; consume: (chunk: Buffer) => void },
  ): void {
    let offset = record.offset + HEADER_BYTES;
    let index = 0;
    hash?.update(record.header);
    const key = plaintext && recordKey(record.header, plaintext.key);
    try {
      while (offset < record.end) {
        const remaining = record.end - offset;
        check(remaining >= FRAME_OVERHEAD, 'LENGTH');
        readExactly(fd, this.#frame.subarray(0, 4), offset);
        const size = this.#frame.readUInt32BE(0);
        checkFrameSize(size, remaining, record.type, index === 0);
        const frameLength = size + FRAME_OVERHEAD;
        offset += frameLength;
        if (hash || key) readExactly(fd, this.#frame.subarray(4, frameLength), offset - frameLength + 4);
        hash?.update(this.#frame.subarray(0, frameLength));
        if (plaintext && key) {
          const chunk = decryptFrame(record.header, plaintext.vaultId, key,
            this.#frame.subarray(4, frameLength), index, offset === record.end);
          try {
            plaintext.consume(chunk);
          } finally {
            chunk.fill(0);
          }
        }
        index++;
      }
    } finally {
      key?.fill(0);
    }
  }

  walk(
    fd: number, size: number, visit: (record: DiskRecord) => boolean | void,
  ): { shortAt?: number } {
    let offset = 0;
    while (offset < size) {
      const record = diskRecord(fd, offset, size, this.#header);
      if (!record) return { shortAt: offset };
      if (visit(record) === false) break;
      offset = record.end;
    }
    return {};
  }

  scan(
    fd: number, size: number, type: RecordFields['type'],
    inspect: (record: DiskRecord) => void, unlocked?: UnlockedKeyring,
  ) {
    const hash = createHash('sha256');
    let erased = 0;
    const { shortAt } = this.walk(fd, size, record => {
      check(record.type === type, 'SCHEMA');
      inspect(record);
      if (unlocked && !unlocked.erased.has(record.keyId)) {
        this.authenticate(fd, record, unlocked, hash);
      } else {
        this.frames(fd, record, hash);
        if (unlocked) erased++;
      }
    });
    return { bytes: shortAt ?? size, sha256: hash.digest('hex'), shortAt, erased };
  }

  authenticate(
    fd: number, record: DiskRecord, unlocked: UnlockedKeyring,
    hash?: ReturnType<typeof createHash>, returnPlaintext = false,
  ): Buffer | undefined {
    const key = unlocked.collectionEncryptionKey(record.keyId);
    let output: Buffer | undefined;
    try {
      if (record.type === 1 || returnPlaintext) {
        const bodyLength = record.end - record.offset - HEADER_BYTES;
        const frameCount = Math.ceil(bodyLength / (FRAME_BYTES + FRAME_OVERHEAD));
        output = Buffer.allocUnsafe(bodyLength - frameCount * FRAME_OVERHEAD);
      }
      let written = 0;
      this.frames(fd, record, hash, {
        vaultId: unlocked.keyring.vault_id, key,
        consume: chunk => {
          output?.set(chunk, written);
          written += chunk.length;
        },
      });
      check(!output || output.length === written, 'LENGTH');
      if (record.type === 1) check(BigInt(eventSequence(output!)) === record.context, 'SEQUENCE');
      return returnPlaintext ? output : undefined;
    } catch (error) {
      output?.fill(0);
      throw error;
    } finally {
      if (!returnPlaintext) output?.fill(0);
      key.fill(0);
    }
  }
}

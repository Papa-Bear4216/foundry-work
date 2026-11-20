import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { TextDecoder, TextEncoder } from 'node:util';
import {
  BLOCK_STATUSES,
  type Block,
  type BlockInput,
  type ScanReport,
} from './types.js';

export const MAX_LINE_BYTES = 64 * 1024;
export const LOG_HEAD_HASH_BYTES = 4096;

const LF = 10;
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();
const retryableRenameErrors = new Set(['EPERM', 'EACCES', 'EBUSY']);
const waitCell = new Int32Array(new SharedArrayBuffer(4));

/** Compare two strings by exact UTF-8 byte order (matching SQLite COLLATE BINARY). */
export function compareBytewise(a: string, b: string): number {
  if (a === b) return 0;
  const bytesA = encoder.encode(a);
  const bytesB = encoder.encode(b);
  const limit = Math.min(bytesA.length, bytesB.length);
  for (let i = 0; i < limit; i++) {
    if (bytesA[i] !== bytesB[i]) {
      return bytesA[i] < bytesB[i] ? -1 : 1;
    }
  }
  if (bytesA.length !== bytesB.length) {
    return bytesA.length < bytesB.length ? -1 : 1;
  }
  return 0;
}

function parseBlock(bytes: Uint8Array): Block | undefined {
  try {
    const value = JSON.parse(decoder.decode(bytes)) as Record<string, unknown> | null;
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      !['id', 'ts', 'agent', 'project', 'intent', 'reasoning'].every(
        (field) => typeof value[field] === 'string',
      ) ||
      (value['status'] != null &&
        !(BLOCK_STATUSES as readonly unknown[]).includes(value['status'])) ||
      (value['parent'] != null && typeof value['parent'] !== 'string') ||
      (value['trace_id'] != null && typeof value['trace_id'] !== 'string') ||
      (value['supersedes'] != null && typeof value['supersedes'] !== 'string') ||
      (value['schema'] != null &&
        (typeof value['schema'] !== 'number' || !Number.isSafeInteger(value['schema'])))
    ) {
      return undefined;
    }
    return value as unknown as Block;
  } catch {
    return undefined;
  }
}

export interface StreamScanState {
  readonly completeBadLineNumbers: readonly number[];
  readonly tailIncomplete: boolean;
  readonly nextLineNumber: number;
  readonly lastCompleteOffset: number;
  readonly blocksRead: number;
}

/** Stream complete blocks from `startOffset` up to `maxPosition` using a fixed-size buffer. */
export function scanFdRange(
  fd: number,
  startOffset: number,
  startLineNumber: number,
  maxPosition: number,
  onBlock: (block: Block, lineNumber: number, endOffset: number) => void,
  recoverTail: boolean,
): StreamScanState {
  const chunk = new Uint8Array(MAX_LINE_BYTES);
  const line = new Uint8Array(MAX_LINE_BYTES - 1);
  const completeBadLineNumbers: number[] = [];
  let lineNumber = startLineNumber;
  let length = 0;
  let overflow = false;
  let position = startOffset;
  let lastCompleteOffset = startOffset;
  let nextLineNumber = startLineNumber;
  let blocksRead = 0;

  function finishLine(complete: boolean, endOffset: number | null): void {
    const block = complete && !overflow ? parseBlock(line.subarray(0, length)) : undefined;
    if (block) {
      onBlock(block, lineNumber, endOffset ?? position);
      blocksRead++;
    } else if (endOffset !== null) {
      completeBadLineNumbers.push(lineNumber);
    }
    length = 0;
    overflow = false;
    lineNumber++;
    if (endOffset !== null) {
      lastCompleteOffset = endOffset;
      nextLineNumber = lineNumber;
    }
  }

  while (position < maxPosition) {
    const count = readSync(fd, chunk, 0, Math.min(chunk.length, maxPosition - position), position);
    if (count === 0) break;
    const chunkBase = position;
    position += count;
    let start = 0;
    while (start < count) {
      const newline = chunk.subarray(start, count).indexOf(LF);
      const end = newline < 0 ? count : start + newline;
      if (!overflow && length + end - start <= line.length) {
        line.set(chunk.subarray(start, end), length);
        length += end - start;
      } else {
        overflow = true;
      }
      if (newline >= 0) {
        finishLine(true, chunkBase + end + 1);
      }
      start = end + 1;
    }
  }

  const tailIncomplete = length > 0 || overflow;
  if (tailIncomplete && recoverTail) {
    finishLine(true, null);
  }

  return {
    completeBadLineNumbers,
    tailIncomplete,
    nextLineNumber,
    lastCompleteOffset,
    blocksRead,
  };
}

/** Visit complete blocks in file order and report one-based numbers of skipped lines. */
export function scanLog(logPath: string, onBlock: (block: Block) => void): ScanReport {
  let fd: number;
  try {
    fd = openSync(logPath, 'r');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      return { badLineCount: 0, badLineNumbers: [] };
    }
    throw error;
  }
  try {
    const size = fstatSync(fd).size;
    const state = scanFdRange(fd, 0, 1, size, (block) => onBlock(block), false);
    const badLineNumbers = state.tailIncomplete
      ? [...state.completeBadLineNumbers, state.nextLineNumber]
      : [...state.completeBadLineNumbers];
    return { badLineCount: badLineNumbers.length, badLineNumbers };
  } finally {
    closeSync(fd);
  }
}

/** Stream `[startOffset, endOffset)` from an open fd into a SHA-256 hasher using a fixed buffer. */
export function updateSha256FromFdRange(
  fd: number,
  hasher: { update(data: Uint8Array): unknown },
  startOffset: number,
  endOffset: number,
): void {
  if (endOffset <= startOffset) return;
  const chunk = new Uint8Array(MAX_LINE_BYTES);
  let pos = startOffset;
  while (pos < endOffset) {
    const toRead = Math.min(chunk.length, endOffset - pos);
    const n = readSync(fd, chunk, 0, toRead, pos);
    if (n === 0) break;
    hasher.update(n === chunk.length ? chunk : chunk.subarray(0, n));
    pos += n;
  }
}

/** Read size, stat metadata, and head/tail 4 KiB SHA-256 digests from an already-open log fd. */
export function readLogHeaderFromFd(fd: number): {
  exists: true;
  size: number;
  headSha256: string;
  tailSha256: string;
  mtimeNs: string;
  ctimeNs: string;
  ino: string;
} {
  const stat = fstatSync(fd, { bigint: true });
  const size = Number(stat.size);
  const headLen = Math.min(LOG_HEAD_HASH_BYTES, size);
  const headBuf = new Uint8Array(headLen);
  let totalHead = 0;
  while (totalHead < headLen) {
    const n = readSync(fd, headBuf, totalHead, headLen - totalHead, totalHead);
    if (n === 0) break;
    totalHead += n;
  }
  const headSha256 = createHash('sha256').update(headBuf.subarray(0, totalHead)).digest('hex');

  const tailOffset = Math.max(0, size - LOG_HEAD_HASH_BYTES);
  const tailLen = size - tailOffset;
  const tailBuf = new Uint8Array(tailLen);
  let totalTail = 0;
  while (totalTail < tailLen) {
    const n = readSync(fd, tailBuf, totalTail, tailLen - totalTail, tailOffset + totalTail);
    if (n === 0) break;
    totalTail += n;
  }
  const tailSha256 = createHash('sha256').update(tailBuf.subarray(0, totalTail)).digest('hex');

  return {
    exists: true,
    size,
    headSha256,
    tailSha256,
    mtimeNs: stat.mtimeNs.toString(),
    ctimeNs: stat.ctimeNs.toString(),
    ino: stat.ino.toString(),
  };
}

/** Compute the file size, stat metadata, and head/tail 4 KiB SHA-256 digests for incremental validation. */
export function readLogHeaderState(logPath: string): {
  exists: boolean;
  size: number;
  headSha256: string;
  tailSha256: string;
  mtimeNs: string;
  ctimeNs: string;
  ino: string;
} {
  let fd: number;
  try {
    fd = openSync(logPath, 'r');
  } catch (error) {
    if ((error as { code?: string }).code === 'ENOENT') {
      const emptySha = createHash('sha256').update('').digest('hex');
      return {
        exists: false,
        size: 0,
        headSha256: emptySha,
        tailSha256: emptySha,
        mtimeNs: '0',
        ctimeNs: '0',
        ino: '0',
      };
    }
    throw error;
  }
  try {
    return readLogHeaderFromFd(fd);
  } finally {
    closeSync(fd);
  }
}

/** Atomically replace `targetPath` from `tempPath` with retry + backoff for Windows file locks. */
export function replaceFileWithRetry(
  tempPath: string,
  targetPath: string,
  options?: { maxAttempts?: number; baseDelayMs?: number },
): void {
  const maxAttempts = options?.maxAttempts ?? 8;
  const baseDelayMs = options?.baseDelayMs ?? 15;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      renameSync(tempPath, targetPath);
      return;
    } catch (error) {
      const code = (error as { code?: string }).code;
      if (attempt < maxAttempts && code && retryableRenameErrors.has(code)) {
        Atomics.wait(waitCell, 0, 0, baseDelayMs * attempt);
        continue;
      }
      try {
        unlinkSync(tempPath);
      } catch {
        // Best-effort cleanup of temp file after failed rename.
      }
      throw error;
    }
  }
}

function shortId(): string {
  return randomUUID().replaceAll('-', '').slice(0, 12);
}

/** Append and flush one block while holding the shared SQLite writer lock. */
export function appendBlock(logPath: string, input: BlockInput): Block {
  mkdirSync(dirname(logPath), { recursive: true });
  const lock = new DatabaseSync(`${logPath}.lock.sqlite`, { timeout: 5000 });
  try {
    lock.exec('BEGIN IMMEDIATE');
    const fd = openSync(logPath, 'a+', 0o600);
    try {
      const size = fstatSync(fd).size;
      const lastByte = new Uint8Array(1);
      if (size > 0 && readSync(fd, lastByte, 0, 1, size - 1) !== 1) {
        throw new Error('Could not read the last byte of the ledger');
      }
      const needsSeparator = size > 0 && lastByte[0] !== LF;
      const supersedes = input.supersedes ?? null;
      if (supersedes === '') {
        throw new Error('Unknown block: empty supersedes reference');
      }
      let parent: string | null = null;
      let target: Block | undefined;
      let resolved = false;
      scanFdRange(
        fd,
        0,
        1,
        size,
        (block) => {
          if (block.project === input.project) parent = block.id;
          if (supersedes !== null) {
            if (block.id === supersedes) target = block;
            if (block.supersedes === supersedes) resolved = true;
          }
        },
        needsSeparator,
      );

      if (supersedes !== null) {
        if (!target) throw new Error(`Unknown block: ${supersedes}`);
        if (resolved || (target.status != null && target.status !== 'proposed')) {
          throw new Error(`Block is already resolved: ${supersedes}`);
        }
      }

      const block: Block = {
        ...input,
        actions: input.actions ?? [],
        verification: input.verification ?? null,
        touches: input.touches ?? [],
        supersedes,
        status: input.status ?? 'proposed',
        trace_id: input.trace_id ?? target?.trace_id ?? shortId(),
        id: shortId(),
        ts: new Date().toISOString().replace(/\.\d{3}Z$/, '+00:00'),
        parent,
      };
      const line = encoder.encode(JSON.stringify(block) + '\n');
      if (line.length > MAX_LINE_BYTES) throw new Error('Ledger block exceeds 64 KiB');
      if (!parseBlock(line)) throw new Error('Invalid ledger block');
      const bytes = needsSeparator ? new Uint8Array(line.length + 1) : line;
      if (needsSeparator) {
        bytes[0] = LF;
        bytes.set(line, 1);
      }
      if (writeSync(fd, bytes) !== bytes.length) throw new Error('Incomplete ledger write');
      fsyncSync(fd);
      lock.exec('COMMIT');
      return block;
    } finally {
      closeSync(fd);
    }
  } finally {
    // Closing also rolls back any transaction left open by an exception.
    lock.close();
  }
}

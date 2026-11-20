import { randomUUID } from 'node:crypto';
import { closeSync, fstatSync, fsyncSync, mkdirSync, openSync, readSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { TextDecoder, TextEncoder } from 'node:util';

export const MAX_LINE_BYTES = 64 * 1024;
const LF = 10;
const decoder = new TextDecoder('utf-8', { fatal: true });
const encoder = new TextEncoder();
const statuses = ['proposed', 'done', 'failed', 'abandoned'] as const;
export type BlockStatus = typeof statuses[number];

export interface BlockInput {
  agent: string;
  project: string;
  intent: string;
  reasoning: string;
  trace_id?: string;
  status?: BlockStatus;
  actions?: readonly Record<string, unknown>[];
  verification?: string | null;
  touches?: readonly string[];
  supersedes?: string | null;
  schema?: 2;
  facts?: readonly unknown[];
  retracted_facts?: readonly { fact_id: string; reason: string }[];
  token_usage?: { model: string; task: string; input: number; output: number; measured: boolean };
}

export interface Block extends Omit<BlockInput, 'status'> {
  id: string;
  ts: string;
  parent?: string | null;
  status?: BlockStatus | null;
}

export interface ScanReport {
  badLineCount: number;
  badLineNumbers: readonly number[];
}

function parseBlock(bytes: Uint8Array): Block | undefined {
  try {
    const value = JSON.parse(decoder.decode(bytes));
    if (!value || typeof value !== 'object' ||
        !['id', 'ts', 'agent', 'project', 'intent', 'reasoning'].every(
          (field) => typeof value[field] === 'string',
        ) || (value.status != null && !statuses.includes(value.status))) {
      return undefined;
    }
    return value;
  } catch {
    return undefined;
  }
}

// The writer includes a recoverable tail because its separator will complete that line.
function scan(fd: number, onBlock: (block: Block) => void, recoverTail: boolean): ScanReport {
  const chunk = new Uint8Array(MAX_LINE_BYTES);
  const line = new Uint8Array(MAX_LINE_BYTES - 1);
  const badLineNumbers: number[] = [];
  let lineNumber = 1;
  let length = 0;
  let overflow = false;
  let position = 0;
  // Read a fixed prefix so an append during a scan cannot extend it indefinitely.
  const size = fstatSync(fd).size;

  function finish(complete: boolean): void {
    const block = complete && !overflow ? parseBlock(line.subarray(0, length)) : undefined;
    if (block) onBlock(block);
    else badLineNumbers.push(lineNumber);
    length = 0;
    overflow = false;
    lineNumber++;
  }

  while (position < size) {
    const count = readSync(fd, chunk, 0, Math.min(chunk.length, size - position), position);
    if (count === 0) break;
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
      if (newline >= 0) finish(true);
      start = end + 1;
    }
  }
  if (length || overflow) finish(recoverTail);
  return { badLineCount: badLineNumbers.length, badLineNumbers };
}

/** Visit complete blocks in file order and report the one-based numbers of skipped lines. */
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
    return scan(fd, onBlock, false);
  } finally {
    closeSync(fd);
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
      let parent: string | null = null;
      let target: Block | undefined;
      let resolved = false;
      scan(fd, (block) => {
        if (block.project === input.project) parent = block.id;
        if (block.id === input.supersedes) target = block;
        if (input.supersedes && block.supersedes === input.supersedes) resolved = true;
      }, needsSeparator);

      if (input.supersedes) {
        if (!target) throw new Error(`Unknown block: ${input.supersedes}`);
        if (resolved || (target.status != null && target.status !== 'proposed')) {
          throw new Error(`Block is already resolved: ${input.supersedes}`);
        }
      }

      const block: Block = {
        actions: [],
        verification: null,
        touches: [],
        supersedes: null,
        ...input,
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

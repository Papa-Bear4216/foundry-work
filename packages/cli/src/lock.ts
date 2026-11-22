/**
 * One heavy job at a time (Architecture 9, design 4.7): `H/foundry.lock`, created exclusively.
 *
 * Content: JSON with `pid`, `command`, `started` (ISO time) and `host`. A lock whose holder runs on this host and
 * whose pid is not alive is stale: it is replaced with a notice. Any other lock fails fast with `BUSY`. Limits (for
 * A-39): a reused pid looks alive, so such a stale lock needs manual removal; a lock written by another host on a
 * shared folder is never treated as stale.
 */
import { closeSync, fsyncSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from 'node:fs';
import { hostname } from 'node:os';
import process from 'node:process';
import { CliError } from './errors.ts';

export const LOCK_NAME = 'foundry.lock';
/** An unreadable lock younger than this may still be being written by its holder. */
const UNREADABLE_GRACE_MS = 10_000;

export interface LockInfo {
  pid: number;
  command: string;
  started: string;
  host: string;
}

export interface HeldLock {
  readonly path: string;
  readonly info: LockInfo;
  release(): void;
}

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as { code?: string }).code === 'EPERM';
  }
}

function readLock(path: string): LockInfo | undefined {
  try {
    const value = JSON.parse(readFileSync(path).toString('utf8')) as Partial<LockInfo>;
    if (Number.isSafeInteger(value.pid) && typeof value.command === 'string' && typeof value.started === 'string'
      && typeof value.host === 'string') {
      return value as LockInfo;
    }
  } catch {
    // Unreadable or half-written; handled by the caller.
  }
  return undefined;
}

function tryCreate(path: string, info: LockInfo): boolean {
  let fd: number;
  try {
    fd = openSync(path, 'wx', 0o600);
  } catch (error) {
    if ((error as { code?: string }).code === 'EEXIST') return false;
    throw error;
  }
  try {
    writeSync(fd, JSON.stringify(info) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  return true;
}

function removeIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as { code?: string }).code !== 'ENOENT') throw error;
  }
}

/** Take the lock or throw `BUSY`. `notice` receives one line when a stale lock is recovered. */
export function acquireLock(path: string, command: string, notice: (line: string) => void): HeldLock {
  const info: LockInfo = { pid: process.pid, command, started: new Date().toISOString(), host: hostname() };
  for (let attempt = 0; attempt < 2; attempt++) {
    if (tryCreate(path, info)) {
      let released = false;
      return {
        path,
        info,
        release() {
          if (released) return;
          released = true;
          const current = readLock(path);
          if (current && current.pid === info.pid && current.started === info.started) removeIfPresent(path);
        },
      };
    }
    const holder = readLock(path);
    if (holder === undefined) {
      const age = Date.now() - (statSync(path, { throwIfNoEntry: false })?.mtimeMs ?? 0);
      if (age < UNREADABLE_GRACE_MS) throw new CliError('BUSY', 'another foundry command is starting; try again shortly');
      removeIfPresent(path);
      notice('foundry: notice: replaced an unreadable lock file left by an earlier command\n');
      continue;
    }
    if (holder.host === info.host && !isProcessAlive(holder.pid)) {
      removeIfPresent(path);
      notice(`foundry: notice: recovered a stale lock from process ${holder.pid} (${holder.command}, started ${holder.started})\n`);
      continue;
    }
    throw new CliError('BUSY',
      `another foundry command is running (process ${holder.pid}, ${holder.command}, started ${holder.started}`
      + `${holder.host === info.host ? '' : ', on another computer'})`);
  }
  throw new CliError('BUSY', 'another foundry command took the lock first');
}

/**
 * One heavy job at a time (Architecture 9, design 4.7): `H/foundry.lock`, created exclusively.
 *
 * Content: JSON with `pid`, `command`, `started` (ISO time) and `host`. A lock whose holder runs on this host and
 * whose pid is not alive is stale. Any other lock fails fast with `BUSY`.
 *
 * Stale recovery is serialized by a second exclusive file, `H/foundry.lock.recover`. Only its creator may remove a
 * lock that is not its own, and only after it re-reads the lock under that file and finds the SAME dead holder (pid,
 * start time, host). A new lock can only be created while no lock file exists, so a live holder's lock is never
 * removed. The recovery file is held for a few file operations; if it exists, the command fails with `BUSY`.
 *
 * Nothing is removed by age: an unreadable lock file (or a recovery file left by a crash) gives `BUSY` with a message
 * that names the file and says to delete it if no Foundry command runs. The message names the file inside the
 * Foundry folder, never the full path (the folder may come from `--vault`).
 *
 * If writing or syncing a new lock's metadata fails, the file this command just created is removed.
 *
 * File type (review item 22): before any open of the lock or the recovery file, the path is `lstat`-ed. A path that
 * exists and is not a regular file (FIFO, folder, symbolic link, device) gives `BUSY` with the fixed file-error
 * message, without any open. An existing lock is read only through `readSmallRegularFile` (`O_NONBLOCK` and
 * `O_NOFOLLOW` where the platform has them, then `fstat`).
 *
 * Fixed text (review item 14): any other file-system error of the lock or the recovery file becomes exit 2 `IO` with
 * a fixed message naming only the error code, never the path (`files.ts`). Releasing the lock is best effort.
 *
 * Limits (for A-39): a reused pid looks alive, so such a stale lock needs manual removal; a lock written by another
 * host on a shared folder is never treated as stale.
 */
import { closeSync, fsyncSync, lstatSync, openSync, unlinkSync, writeSync } from 'node:fs';
import { hostname } from 'node:os';
import process from 'node:process';
import { CliError } from './errors.ts';
import { errnoCode, fileErrorMessage, fixedFileError, NOT_REGULAR, readSmallRegularFile } from './files.ts';

export const LOCK_NAME = 'foundry.lock';
export const RECOVERY_NAME = `${LOCK_NAME}.recover`;

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

/** Test hooks, reachable only by calling `acquireLock` directly (never argv or environment). */
export interface LockHooks {
  /** Runs right after the current holder was read, before any recovery decision. */
  afterHolderRead?: () => void;
  /** Replaces the metadata write (to inject a failure). */
  writeMetadata?: (fd: number, text: string) => void;
}

export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as { code?: string }).code === 'EPERM';
  }
}

type ReadResult = LockInfo | 'missing' | 'unreadable' | 'not-regular';

/** A lock file is a few hundred bytes; anything longer is damaged. */
const MAX_LOCK_BYTES = 4096;

/** The `BUSY` error for a lock or recovery path that exists and is not a regular file (fixed text, no path). */
function notRegularError(): CliError {
  return new CliError('BUSY', fileErrorMessage(NOT_REGULAR));
}

/** Throw `BUSY` if something other than a regular file is at `path` (checked with `lstat`, before any open). */
function requireRegularOrAbsent(path: string): void {
  const info = lstatSync(path, { throwIfNoEntry: false });
  if (info !== undefined && !info.isFile()) throw notRegularError();
}

function readLock(path: string): ReadResult {
  let bytes;
  try {
    const read = readSmallRegularFile(path, MAX_LOCK_BYTES);
    if (read === 'missing' || read === 'not-regular') return read;
    if (read.length > MAX_LOCK_BYTES) return 'unreadable';
    bytes = read;
  } catch (error) {
    return errnoCode(error) === 'ENOENT' ? 'missing' : 'unreadable';
  }
  try {
    const value = JSON.parse(bytes.toString('utf8')) as Partial<LockInfo>;
    if (Number.isSafeInteger(value.pid) && typeof value.command === 'string' && typeof value.started === 'string'
      && typeof value.host === 'string') {
      return value as LockInfo;
    }
  } catch {
    // Half-written or damaged: unreadable.
  }
  return 'unreadable';
}

function removeIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as { code?: string }).code !== 'ENOENT') throw error;
  }
}

/** Create `path` exclusively with `info`. False if it exists. On a write or sync failure the new file is removed. */
function tryCreate(path: string, info: LockInfo, hooks: LockHooks): boolean {
  let fd: number;
  try {
    fd = openSync(path, 'wx', 0o600);
  } catch (error) {
    if ((error as { code?: string }).code === 'EEXIST') return false;
    throw error;
  }
  let complete = false;
  try {
    const text = JSON.stringify(info) + '\n';
    if (hooks.writeMetadata) hooks.writeMetadata(fd, text);
    else writeSync(fd, text);
    fsyncSync(fd);
    closeSync(fd);
    complete = true;
  } finally {
    if (!complete) {
      try {
        closeSync(fd);
      } catch {
        // Already closed, or the close itself failed: the file is removed below either way.
      }
      removeIfPresent(path);
    }
  }
  return true;
}

function sameHolder(a: LockInfo, b: LockInfo): boolean {
  return a.pid === b.pid && a.started === b.started && a.host === b.host && a.command === b.command;
}

/** Remove the lock of a dead holder, serialized by the recovery file. Returns true if this call removed it. */
function recoverStale(path: string, holder: LockInfo, info: LockInfo, hooks: LockHooks): boolean {
  const guard = `${path}.recover`; // `H/foundry.lock.recover` (RECOVERY_NAME)
  requireRegularOrAbsent(guard);
  if (!tryCreate(guard, info, hooks)) {
    throw new CliError('BUSY', `another foundry command is recovering the lock; try again shortly. If no foundry command is `
      + `running, delete the file ${RECOVERY_NAME} in the Foundry folder`);
  }
  try {
    const again = readLock(path);
    if (typeof again === 'object' && sameHolder(again, holder) && !isProcessAlive(again.pid)) {
      unlinkSync(path);
      return true;
    }
    return false;
  } finally {
    removeIfPresent(guard);
  }
}

/**
 * Take the lock or throw `BUSY`. `notice` receives one line when a stale lock is recovered. Every file-system error
 * becomes the fixed-text `IO` error (no path); a `CliError` passes unchanged.
 */
export function acquireLock(path: string, command: string, notice: (line: string) => void, hooks: LockHooks = {}): HeldLock {
  try {
    return takeLock(path, command, notice, hooks);
  } catch (error) {
    throw fixedFileError(error);
  }
}

function takeLock(path: string, command: string, notice: (line: string) => void, hooks: LockHooks): HeldLock {
  const info: LockInfo = { pid: process.pid, command, started: new Date().toISOString(), host: hostname() };
  for (let attempt = 0; attempt < 3; attempt++) {
    requireRegularOrAbsent(path);
    if (tryCreate(path, info, hooks)) {
      let released = false;
      return {
        path,
        info,
        release() {
          if (released) return;
          released = true;
          try {
            const current = readLock(path);
            if (typeof current === 'object' && sameHolder(current, info)) removeIfPresent(path);
          } catch {
            // Best effort: a lock left behind holds this process's pid, so it becomes stale and is recovered later.
          }
        },
      };
    }
    const holder = readLock(path);
    hooks.afterHolderRead?.();
    if (holder === 'missing') continue; // released in between: try again
    if (holder === 'not-regular') throw notRegularError();
    if (holder === 'unreadable') {
      throw new CliError('BUSY', `the lock file ${LOCK_NAME} in the Foundry folder cannot be read; another foundry command `
        + `may be starting. If no foundry command is running, delete that file and try again`);
    }
    if (holder.host === info.host && !isProcessAlive(holder.pid)) {
      if (recoverStale(path, holder, info, hooks)) {
        notice(`foundry: notice: recovered a stale lock from process ${holder.pid} (${holder.command}, started ${holder.started})\n`);
      }
      continue;
    }
    throw new CliError('BUSY',
      `another foundry command is running (process ${holder.pid}, ${holder.command}, started ${holder.started}`
      + `${holder.host === info.host ? '' : ', on another computer'})`);
  }
  throw new CliError('BUSY', 'another foundry command took the lock first');
}

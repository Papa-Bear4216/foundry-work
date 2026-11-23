/**
 * Small file helpers for the Foundry home folder, its lock and recovery files, and init's ownership marker.
 *
 * Fixed text: the home folder comes from `--vault` or `FOUNDRY_HOME`, where a secret could have been pasted by
 * mistake. A Node file-system error carries that path in its message and its stack, so such an error is replaced by
 * a `CliError` with a fixed message that names only the error code (also for `--debug`, which prints the replacement).
 * This covers the main thread (preflight, lock) and the worker (init's staging folder, marker and rename, the vault
 * metadata and keyring reads); `homeSystemError` is the last line of defence for library calls on the home folder.
 *
 * No blocking open: a path is `lstat`-ed before it is opened; only a regular file is opened, read-only, with
 * `O_NONBLOCK` and `O_NOFOLLOW` where the platform has them (not on Windows), and checked again with `fstat`. A FIFO,
 * folder, symbolic link or device is never opened.
 */
import { Buffer } from 'node:buffer';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import process from 'node:process';
import { CliError } from './errors.ts';

/** The fixed message for a file-system failure of the home folder, the lock or the recovery file. */
export function fileErrorMessage(code: string): string {
  return `a file operation on the Foundry folder or its lock file failed (${code})`;
}

/** The fixed reason for a lock, recovery or marker path that exists but is not a regular file. */
export const NOT_REGULAR = 'not a regular file';

/** The errno code of a Node file-system error, or undefined. */
export function errnoCode(error: unknown): string | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^E[A-Z0-9]+$/u.test(code) ? code : undefined;
}

/**
 * Replace a Node file-system error by a fixed-text `CliError` (exit 2 `IO`). A `CliError` passes unchanged. Any other
 * value becomes a fixed `IO` error too: its message is never kept, because it could quote the path.
 */
export function fixedFileError(error: unknown): CliError {
  if (error instanceof CliError) return error;
  return new CliError('IO', fileErrorMessage(errnoCode(error) ?? 'unknown error'));
}

/** Run `work`; a file-system error it throws becomes the fixed-text error. */
export function withFixedFileErrors<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    throw fixedFileError(error);
  }
}

/** A Node system error (errno code and `syscall`): its message, stack, `path` and `dest` can quote a path. */
export function isSystemError(error: unknown): boolean {
  return error instanceof Error && errnoCode(error) !== undefined
    && typeof (error as { syscall?: unknown }).syscall === 'string';
}

/** Run a library call on the home folder (for example `createVault`): a Node system error becomes the fixed text. */
export function withHomeSystemErrors<T>(work: () => T): T {
  try {
    return work();
  } catch (error) {
    throw isSystemError(error) ? fixedFileError(error) : error;
  }
}

function inside(path: string, home: string): boolean {
  const fold = (value: string) => (process.platform === 'win32' ? value.toLowerCase() : value);
  const p = fold(resolve(path));
  const h = fold(resolve(home));
  return p === h || p.startsWith(h.endsWith(sep) ? h : h + sep);
}

/**
 * The fixed-text replacement for a Node system error about the home folder or anything below it (its `path` or
 * `dest` is inside `home`, or its message quotes `home`), else undefined. The command bodies use it as a last line of
 * defence for library calls (vault, index) on the home folder, before the error line and the `--debug` text.
 */
export function homeSystemError(error: unknown, home: string): CliError | undefined {
  if (!isSystemError(error)) return undefined;
  const { path, dest, message } = error as { path?: unknown; dest?: unknown; message: string };
  const quotes = [path, dest].some(value => typeof value === 'string' && inside(value, home)) || message.includes(home);
  return quotes ? fixedFileError(error) : undefined;
}

export type SmallFile = Buffer | 'missing' | 'not-regular';

/**
 * Read at most `limit` bytes of a regular file without a blocking open. `missing` if nothing is at `path`;
 * `not-regular` if something other than a regular file is there; otherwise the bytes (`limit + 1` bytes are read, so
 * a longer file shows as longer than `limit`). Other errors are thrown (the caller decides).
 */
export function readSmallRegularFile(path: string, limit: number): SmallFile {
  const info = lstatSync(path, { throwIfNoEntry: false });
  if (info === undefined) return 'missing';
  if (!info.isFile()) return 'not-regular';
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0));
  } catch (error) {
    const code = errnoCode(error);
    if (code === 'ENOENT') return 'missing';
    if (code === 'ELOOP' || code === 'EISDIR') return 'not-regular'; // replaced after the lstat
    throw error;
  }
  try {
    if (!fstatSync(fd).isFile()) return 'not-regular';
    const bytes = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = readSync(fd, bytes, length, bytes.length - length, null);
      if (read === 0) break;
      length += read;
    }
    return bytes.subarray(0, length);
  } finally {
    closeSync(fd);
  }
}

import type { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { closeSync, fsyncSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { platform } from 'node:process';
import { DatabaseSync } from 'node:sqlite';

function errorCode(error: unknown): string | undefined {
  return (error as { code?: string } | null)?.code;
}

function renameWithRetry(source: string, target: string): void {
  const wait = new Int32Array(new SharedArrayBuffer(4));
  for (let attempt = 0; ; attempt++) {
    try {
      renameSync(source, target);
      return;
    } catch (error) {
      if (platform !== 'win32' || attempt === 9
        || !['EACCES', 'EBUSY', 'EPERM'].includes(errorCode(error) ?? '')) throw error;
      Atomics.wait(wait, 0, 0, Math.min(10 * 2 ** attempt, 400));
    }
  }
}

function readExisting(path: string): Buffer | undefined {
  try {
    return readFileSync(path);
  } catch (error) {
    if (errorCode(error) !== 'ENOENT') throw error;
    return undefined;
  }
}

export function publishKeyring(path: string, next: Buffer, previous?: Buffer, beforeRename?: () => void): void {
  const directory = dirname(path);
  const prefix = basename(path) + '.pending-';
  const lock = new DatabaseSync(path + '.lock.sqlite', { timeout: 5000 });
  try {
    lock.exec('BEGIN IMMEDIATE');
    for (const name of readdirSync(directory, { withFileTypes: true })) {
      if (name.isFile() && name.name.startsWith(prefix) && /^[0-9a-f]{32}$/u.test(name.name.slice(prefix.length))) {
        unlinkSync(join(directory, name.name));
      }
    }
    const existing = readExisting(path);
    if (previous ? !existing?.equals(previous) : existing !== undefined) {
      throw new Error(previous ? 'Keyring changed during rewrite.' : 'Keyring already exists.');
    }
    const pending = join(directory, prefix + randomBytes(16).toString('hex'));
    const fd = openSync(pending, 'wx', 0o600);
    try {
      try {
        writeFileSync(fd, next);
        fsyncSync(fd);
      } catch (error) {
        try { closeSync(fd); } catch { /* Preserve the original failure. */ }
        throw error;
      }
      closeSync(fd);
      beforeRename?.();
      renameWithRetry(pending, path);
    } catch (error) {
      try { unlinkSync(pending); } catch { /* Preserve the original failure. */ }
      throw error;
    }
    if (platform !== 'win32') {
      const dirFd = openSync(directory, 'r');
      try {
        fsyncSync(dirFd);
      } finally {
        closeSync(dirFd);
      }
    }
  } finally {
    lock.close();
  }
}

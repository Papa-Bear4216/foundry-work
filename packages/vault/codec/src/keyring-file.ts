import type { Buffer } from 'node:buffer';
import { closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { platform } from 'node:process';

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
      if (platform !== 'win32' || attempt === 5
        || !['EACCES', 'EBUSY', 'EPERM'].includes(errorCode(error) ?? '')) throw error;
      Atomics.wait(wait, 0, 0, 10 * 2 ** attempt);
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

export function publishKeyring(path: string, next: Buffer, previous?: Buffer): void {
  // Exclusive creation serializes cooperating writers. Rename releases the slot.
  const pending = path + '.pending';
  let fd: number;
  try {
    fd = openSync(pending, 'wx', 0o600);
  } catch (error) {
    if (errorCode(error) === 'EEXIST') throw new Error('A keyring rewrite is in progress or was interrupted.', { cause: error });
    throw error;
  }
  let published = false;
  try {
    try {
      const existing = readExisting(path);
      if (previous ? !existing?.equals(previous) : existing !== undefined) {
        throw new Error(previous ? 'Keyring changed during rewrite.' : 'Keyring already exists.');
      }
      writeFileSync(fd, next);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameWithRetry(pending, path);
    published = true;
  } finally {
    if (!published) unlinkSync(pending);
  }
}

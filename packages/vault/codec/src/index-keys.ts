import type { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { publishKeyring, syncDirectory } from './keyring-file.ts';
import { updateIndexEntry } from './keyring.ts';
import type { Unlock } from './keyring.ts';

/** Stage a generation under a caller-selected 16-byte hex ID. Retrying returns the same active key. */
export function stageIndexKey(path: string, vaultId: string, credential: Unlock, indexKeyId: string): Buffer {
  const previous = readFileSync(path);
  const { next, key } = updateIndexEntry(previous, vaultId, credential, indexKeyId, 'stage');
  try {
    if (next) publishKeyring(path, next, previous);
    else syncDirectory(dirname(path));
    return key!;
  } catch (error) {
    key?.fill(0);
    throw error;
  }
}

/** Retire the old generation after publishing its replacement. A retired ID remains reserved. */
export function retireIndexKey(path: string, vaultId: string, credential: Unlock, indexKeyId: string): void {
  const previous = readFileSync(path);
  const { next } = updateIndexEntry(previous, vaultId, credential, indexKeyId, 'retire');
  if (next) publishKeyring(path, next, previous);
  else syncDirectory(dirname(path));
}

import { Buffer } from 'node:buffer';
import { join } from 'node:path';
import { check, integer } from './bytes.ts';
import { diskRecord, StreamScanner, streamFile } from './record-file.ts';
import type { UnlockedKeyring } from './record-file.ts';
import { HEADER_BYTES } from './record.ts';
import {
  headMatches, metadata, readHead, scanOpen, scanSealed, segmentName, statIfPresent, streamType,
} from './vault-directory.ts';
import type { VerifyOptions } from './vault-directory.ts';

export interface VaultRecordLocation {
  /** Stable segment number, including the next segment while it is open. */
  segment: number;
  stream: string;
  offset: number;
}

function verify(directory: string, { anchor }: VerifyOptions, unlocked?: UnlockedKeyring) {
  const vault = metadata(directory);
  if (unlocked) check(unlocked.keyring.vault_id === vault.vault_id, 'KEY');
  const scanner = new StreamScanner();
  const { position } = scanSealed(directory, vault, scanner, unlocked, anchor);
  check(headMatches(readHead(directory), position), 'HEAD');
  const open = scanOpen(join(directory, 'open'), position.lastEventSequence, scanner, unlocked);
  return {
    vault, position,
    open: { files: open.files.length, bytes: open.totalBytes, lastEventSequence: open.last },
  };
}

/** Checks the sealed chain and unsigned open framing. Reads no keyring or credential. */
export function verifyVault(directory: string, options: VerifyOptions = {}) {
  return verify(directory, options);
}

/** Authenticates every frame and checks every event sequence. Erased records raise ERASED. */
export function verifyVaultDeep(directory: string, unlocked: UnlockedKeyring, options: VerifyOptions = {}) {
  return verify(directory, options, unlocked);
}

/** Opens a located record with its collection key. Use verifyVault to verify sealed placement. */
export function readVaultRecord(directory: string, location: VaultRecordLocation, unlocked: UnlockedKeyring) {
  const { segment, stream, offset } = location;
  integer(offset);
  const type = streamType(stream);
  const vault = metadata(directory);
  check(unlocked.keyring.vault_id === vault.vault_id, 'KEY');
  const segments = join(directory, 'segments');
  check(statIfPresent(segments)?.isDirectory(), 'INVENTORY');
  const sealed = join(segments, segmentName(segment));
  const parent = !statIfPresent(sealed) && segment === readHead(directory).segment + 1
    ? join(directory, 'open') : sealed;
  const path = join(parent, stream);
  check(statIfPresent(parent)?.isDirectory() && statIfPresent(path)?.isFile(), 'INVENTORY');
  return streamFile(path, (fd, size) => {
    check(offset < size, 'LENGTH');
    const record = diskRecord(fd, offset, size, Buffer.alloc(HEADER_BYTES));
    check(record, 'LENGTH');
    check(record.type === type);
    return {
      type: record.type, context: record.context, keyId: record.keyId,
      plaintext: new StreamScanner().authenticate(fd, record, unlocked, undefined, true)!,
    };
  });
}

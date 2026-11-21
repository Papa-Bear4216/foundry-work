import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { check } from './bytes.ts';
import {
  changeKeyringPassphrase, decodeKeyring, encodeKeyring, nextKeyringVersion, readKeyring, replacementParallelism,
  unlockKeyring, validateParallelism,
} from './keyring.ts';
import type { KdfParallelism } from './keyring.ts';
import { publishKeyring } from './keyring-file.ts';
import { signingPublicKey } from './manifest.ts';
import { decodeRecoveryKey, formatRecoveryKey } from './recovery.ts';

interface PassphraseOptions {
  passphrase: string;
  parallelism?: KdfParallelism;
}

type Credential = { passphrase: string } | { recoveryKey: string };

function now(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z');
}

/** Create version 1. The recovery key is available only in this result. */
export function create(path: string, { passphrase, parallelism = 1 }: PassphraseOptions) {
  validateParallelism(parallelism);
  const vaultId = randomBytes(16).toString('hex');
  const masterKey = randomBytes(32);
  const seed = randomBytes(32);
  const recovery = randomBytes(32);
  const createdAt = now();
  try {
    const entry = {
      key_id: randomBytes(16).toString('hex'), kind: 'signing', parent: 'master',
      state: 'active', created_at: createdAt, key: seed,
    } as const;
    const bytes = encodeKeyring({ vaultId, version: 1, masterKey, entries: [entry], parallelism }, passphrase, recovery);
    const result = { vaultId, createdAt, signingPublicKey: signingPublicKey(seed), recoveryKey: formatRecoveryKey(recovery) };
    publishKeyring(path, bytes);
    return result;
  } finally {
    masterKey.fill(0);
    seed.fill(0);
    recovery.fill(0);
  }
}

export function unlockByPassphrase(path: string, vaultId: string, passphrase: string): ReturnType<typeof decodeKeyring> {
  return decodeKeyring(readFileSync(path), { passphrase }, vaultId);
}

export function unlockByRecovery(path: string, vaultId: string, recoveryKey: string): ReturnType<typeof decodeKeyring> {
  const recovery = decodeRecoveryKey(recoveryKey);
  try {
    return decodeKeyring(readFileSync(path), { recoveryKey: recovery }, vaultId);
  } finally {
    recovery.fill(0);
  }
}

export function changePassphrase(
  path: string, vaultId: string, currentPassphrase: string, replacement: PassphraseOptions,
): void {
  const previous = readFileSync(path);
  const next = changeKeyringPassphrase(previous, vaultId, currentPassphrase, replacement.passphrase, replacement.parallelism);
  publishKeyring(path, next, previous);
}

interface RekeyOptions extends PassphraseOptions {
  /** The writer's complete set of current collection IDs, excluding historical and destroyed IDs. */
  currentCollectionIds: readonly string[];
}

/** Rotate keys for future writes. The result contains a new, one-time recovery key and the writer's new collection IDs. */
export function rekeyAll(path: string, vaultId: string, credential: Credential, options: RekeyOptions) {
  if (options.parallelism !== undefined) validateParallelism(options.parallelism);
  const previous = readFileSync(path);
  const ring = readKeyring(previous, vaultId);
  const version = nextKeyringVersion(ring.version);
  const parallelism = replacementParallelism(ring.kdf.p, options.parallelism);
  const activeCollections = new Set(ring.keys.filter(entry => entry.kind === 'collection' && entry.state === 'active')
    .map(entry => entry.key_id));
  const currentIds = new Set(options.currentCollectionIds);
  check(currentIds.size === options.currentCollectionIds.length
    && [...currentIds].every(id => activeCollections.has(id))
    && (activeCollections.size === 0 || currentIds.size > 0), 'KEY');
  const oldRecovery = 'recoveryKey' in credential ? decodeRecoveryKey(credential.recoveryKey) : undefined;
  try {
    const unlocked = unlockKeyring(ring, 'passphrase' in credential ? credential : { recoveryKey: oldRecovery! });
    const masterKey = randomBytes(32);
    const recovery = randomBytes(32);
    const generated = [masterKey, recovery];
    try {
      const created_at = now();
      const ids = new Set(ring.keys.map(entry => entry.key_id));
      const collectionIds = new Map<string, string>();
      const entries = ring.keys.flatMap<Parameters<typeof encodeKeyring>[0]['entries'][number]>(entry => {
        if (entry.state === 'destroyed') return [entry];
        const { key_id, kind, parent, state } = entry;
        const identity = { key_id, kind, parent, state };
        const oldKey = unlocked.keys.get(key_id)!;
        if (kind === 'signing') return [{ ...identity, created_at: entry.created_at, key: oldKey }];
        if (kind === 'collection' && !currentIds.has(key_id)) {
          return [{ ...identity, created_at: entry.created_at, key: oldKey }];
        }
        const key = randomBytes(32);
        generated.push(key);
        if (kind === 'collection') {
          let nextId: string;
          do nextId = randomBytes(16).toString('hex'); while (ids.has(nextId));
          ids.add(nextId);
          collectionIds.set(key_id, nextId);
          return [
            { ...identity, created_at: entry.created_at, key: oldKey },
            { ...identity, key_id: nextId, created_at, key },
          ];
        }
        return [{ ...identity, created_at, key, label: unlocked.labels.get(key_id) }];
      });
      const next = encodeKeyring({ vaultId, version, masterKey, entries, parallelism }, options.passphrase, recovery);
      const result = { recoveryKey: formatRecoveryKey(recovery), collectionIds };
      publishKeyring(path, next, previous);
      return result;
    } finally {
      for (const key of generated) key.fill(0);
      for (const key of unlocked.keys.values()) key.fill(0);
      unlocked.masterKey.fill(0);
    }
  } finally {
    oldRecovery?.fill(0);
  }
}

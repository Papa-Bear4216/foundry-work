import type { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { check } from './bytes.ts';
import {
  changeKeyringPassphrase, createUnlockSession, decodeKeyring, encodeKeyring, nextKeyringVersion, readKeyring,
  replacementParallelism, resetKeyringPassphrase, snapshotCredential, unlockKeyring, validateParallelism, vaultKey,
} from './keyring.ts';
import type { KdfParallelism, UnlockSession, VaultCredential } from './keyring.ts';
import { publishKeyring } from './keyring-file.ts';
import { signingPublicKey } from './manifest.ts';
import { decodeRecoveryKey, formatRecoveryKey } from './recovery.ts';

interface PassphraseOptions {
  passphrase: string;
  parallelism?: KdfParallelism;
}

type Credential = { passphrase: string } | { recoveryKey: string } | { session: UnlockSession };

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

/** Run the KDF (or recovery unwrap) once and hold the unwrapped master key until dispose(). */
export function unlockVault(
  keyringPath: string, vaultId: string, input: VaultCredential,
): UnlockSession {
  const credential = snapshotCredential(input, false) as VaultCredential;
  return createUnlockSession(readFileSync(keyringPath), vaultId, credential);
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

/**
 * Forgotten passphrase: unlock with the printed recovery key and publish the same keyring with a new passphrase wrap of
 * the SAME master key (new KDF salt). Rotates nothing; use rekeyAll when a credential may be known to someone else.
 * On any failure before the atomic rename this call leaves the keyring file untouched (if another writer published in
 * the meantime, the previous-bytes check fails this call and that writer's complete keyring stays in place); as for
 * changePassphrase, a failure
 * after the rename (directory sync or writer-lock release) throws although the complete new keyring is already in
 * place, so a caller that gets an error tries the new passphrase before it repeats the reset.
 */
export function resetPassphrase(
  path: string, vaultId: string, recoveryKey: string, replacement: PassphraseOptions,
): void {
  const recovery = decodeRecoveryKey(recoveryKey);
  try {
    const previous = readFileSync(path);
    const next = resetKeyringPassphrase(previous, vaultId, recovery, replacement.passphrase, replacement.parallelism);
    publishKeyring(path, next, previous);
  } finally {
    recovery.fill(0);
  }
}

interface RekeyOptions extends PassphraseOptions {
  /** Together these lists must partition all active collection IDs. */
  currentCollectionIds: readonly string[];
  historicalCollectionIds: readonly string[];
  /** Called synchronously under the writer lock. The tombstone buffers are borrowed for the call. */
  beforePublish?: (handoff: RekeyHandoff) => undefined;
}

export interface RekeyHandoff {
  oldTombstoneKey: Buffer;
  newTombstoneKey: Buffer;
  collectionIds: ReadonlyMap<string, string>;
  indexKeyId: string;
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
  check(Array.isArray(options.currentCollectionIds) && Array.isArray(options.historicalCollectionIds), 'KEY');
  const currentIds = new Set(options.currentCollectionIds);
  const historicalIds = new Set(options.historicalCollectionIds);
  check(currentIds.size === options.currentCollectionIds.length
    && historicalIds.size === options.historicalCollectionIds.length
    && currentIds.size + historicalIds.size === activeCollections.size
    && [...currentIds].every(id => activeCollections.has(id))
    && [...historicalIds].every(id => activeCollections.has(id) && !currentIds.has(id)), 'KEY');
  const snapshot = snapshotCredential(credential, true);
  const hasPassphrase = 'passphrase' in snapshot;
  const hasRecovery = 'recoveryKey' in snapshot;
  const oldRecovery = hasRecovery ? decodeRecoveryKey((snapshot as { recoveryKey: string }).recoveryKey) : undefined;
  try {
    const unlocked = unlockKeyring(
      ring,
      hasRecovery ? { recoveryKey: oldRecovery! }
        : hasPassphrase ? { passphrase: (snapshot as { passphrase: string }).passphrase }
          : { session: (snapshot as { session: UnlockSession }).session },
    );
    const generated: Buffer[] = [];
    try {
      const newKey = () => {
        const key = randomBytes(32);
        generated.push(key);
        return key;
      };
      const masterKey = newKey();
      const recovery = newKey();
      const created_at = now();
      const ids = new Set(ring.keys.map(entry => entry.key_id));
      const newId = () => {
        let id: string;
        do id = randomBytes(16).toString('hex'); while (ids.has(id));
        ids.add(id);
        return id;
      };
      const collectionIds = new Map<string, string>();
      const entries = ring.keys.flatMap<Parameters<typeof encodeKeyring>[0]['entries'][number]>(entry => {
        if (entry.state === 'destroyed') return [entry];
        const { key_id, kind, parent, state } = entry;
        if (kind === 'index') return [{ key_id, kind, parent, state: 'destroyed', destroyed_at: created_at }];
        const identity = { key_id, kind, parent, state };
        const oldKey = unlocked.keys.get(key_id)!;
        const retained = { ...identity, created_at: entry.created_at, key: oldKey };
        if (kind === 'collection') {
          if (!currentIds.has(key_id)) return [retained];
          const nextId = newId();
          collectionIds.set(key_id, nextId);
          return [retained, { ...identity, key_id: nextId, created_at, key: newKey() }];
        }
        if (kind === 'signing') return [retained];
        return [{ ...identity, created_at, key: newKey(), label: unlocked.labels.get(key_id) }];
      });
      const indexKeyId = newId();
      entries.push({ key_id: indexKeyId, kind: 'index', parent: 'master', state: 'active', created_at, key: newKey() });
      const next = encodeKeyring({ vaultId, version, masterKey, entries, parallelism }, options.passphrase, recovery);
      const verified = decodeKeyring(next, { recoveryKey: recovery }, vaultId);
      verified.masterKey.fill(0);
      for (const key of verified.keys.values()) key.fill(0);

      const result = { recoveryKey: formatRecoveryKey(recovery), collectionIds, indexKeyId };
      const beforePublish = options.beforePublish;
      publishKeyring(path, next, previous, beforePublish && (() => {
        const oldTombstoneKey = vaultKey(unlocked.masterKey, vaultId, 'tombstone');
        try {
          const newTombstoneKey = vaultKey(masterKey, vaultId, 'tombstone');
          try {
            check(beforePublish({
              oldTombstoneKey, newTombstoneKey, collectionIds: new Map(collectionIds), indexKeyId,
            }) === undefined, 'KEY');
          } finally {
            newTombstoneKey.fill(0);
          }
        } finally {
          oldTombstoneKey.fill(0);
        }
      }));
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

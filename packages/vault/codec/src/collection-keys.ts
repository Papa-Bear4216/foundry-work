import { Buffer } from 'node:buffer';
import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { check } from './bytes.ts';
import { publishKeyring, syncDirectory } from './keyring-file.ts';
import { appendKeyringEntries, readKeyring, unlockKeyring, vaultKey } from './keyring.ts';
import type { KeyringAddition, Unlock } from './keyring.ts';
import type { UnlockedKeyring } from './record-file.ts';

/*
 * A-41: collection keys on demand. The key ID of the collection key for name N in the profile with key ID P is the
 * first 16 bytes (32 lowercase hex characters) of HMAC-SHA256(NK, UTF-8(P + "\n" + N)), where
 * NK = HKDF-SHA256(ikm = raw master key, salt = 16 raw vault ID bytes, info = "foundry/collection-key-id/v1"), which is
 * exactly vaultKey(masterKey, vaultId, 'collection-key-id'). No case folding, normalisation or trimming. This rule can
 * never change once real vaults exist.
 */
const ID_LABEL = 'collection-key-id';
const RESERVED_PREFIX = 'foundry:';
const RULE_MARKER = 'foundry:collection-key-id-rule/v1';
const MAX_TEXT_BYTES = 512;
const MAX_NAMES = 4096;

type Entries = UnlockedKeyring['keyring']['keys'];

export interface EnsureCollectionKeysResult {
  profileKeyId: string;
  /** Requested name -> collection key ID, for every distinct requested name. */
  keyIds: Map<string, string>;
  /** New collection entries for requested names (not the profile, not the rule marker). */
  created: number;
}

function validText(value: unknown): asserts value is string {
  check(typeof value === 'string' && value.isWellFormed(), 'KEY');
  const size = value.length > MAX_TEXT_BYTES ? MAX_TEXT_BYTES + 1 : Buffer.from(value, 'utf8').length;
  check(size >= 1 && size <= MAX_TEXT_BYTES, 'KEY');
}

function validName(value: unknown): asserts value is string {
  validText(value);
  check(!value.startsWith(RESERVED_PREFIX), 'KEY');
}

/** Validates before any file read. Returns the distinct names in first-seen order. */
function validateRequest(profileLabel: unknown, names: unknown): string[] {
  validText(profileLabel);
  check(Array.isArray(names), 'KEY');
  const copy: unknown[] = Array.prototype.slice.call(names);
  const distinct = new Set<string>();
  for (const name of copy) {
    validName(name);
    distinct.add(name);
    check(distinct.size <= MAX_NAMES, 'KEY');
  }
  check(distinct.size > 0, 'KEY');
  return [...distinct];
}

function deriveId(nk: Buffer, profileKeyId: string, name: string): string {
  return createHmac('sha256', nk).update(Buffer.from(profileKeyId + '\n' + name, 'utf8')).digest()
    .subarray(0, 16).toString('hex');
}

/**
 * The active profile labelled `profileLabel`. More than one: KEY. None while any destroyed profile entry exists: ERASED
 * (a destroyed profile has no label, so it might be this one). None otherwise: undefined.
 */
function findProfile(entries: Entries, labels: ReadonlyMap<string, string>, profileLabel: string): string | undefined {
  const matches = entries.filter(entry => entry.kind === 'profile' && entry.state === 'active'
    && labels.get(entry.key_id) === profileLabel);
  check(matches.length <= 1, 'KEY');
  if (matches.length === 1) return matches[0]!.key_id;
  check(!entries.some(entry => entry.kind === 'profile' && entry.state === 'destroyed'), 'ERASED');
  return undefined;
}

/**
 * Shared checks after the profile is known, in this order: marker rule (KEY), distinct derived IDs including the
 * marker (KEY), then per name in order: destroyed (ERASED), another kind or parent (KEY). Zeroes NK.
 */
function resolveNames(
  entries: Entries, masterKey: Buffer, vaultId: string, profileKeyId: string, names: readonly string[],
): { ids: Map<string, string>; markerId: string; hasCollections: boolean; absent: string[] } {
  const nk = vaultKey(masterKey, vaultId, ID_LABEL);
  let markerId: string;
  const ids = new Map<string, string>();
  try {
    markerId = deriveId(nk, profileKeyId, RULE_MARKER);
    for (const name of names) ids.set(name, deriveId(nk, profileKeyId, name));
  } finally {
    nk.fill(0);
  }
  const byId = new Map(entries.map(entry => [entry.key_id, entry]));
  const hasCollections = entries.some(entry => entry.kind === 'collection' && entry.parent === profileKeyId);
  if (hasCollections) {
    const marker = byId.get(markerId);
    check(marker?.kind === 'collection' && marker.parent === profileKeyId && marker.state === 'active', 'KEY');
  }
  const seen = new Set([markerId]);
  for (const id of ids.values()) {
    check(!seen.has(id), 'KEY');
    seen.add(id);
  }
  const absent: string[] = [];
  for (const [name, id] of ids) {
    const entry = byId.get(id);
    if (!entry) {
      absent.push(name);
      continue;
    }
    check(entry.state !== 'destroyed', 'ERASED');
    check(entry.kind === 'collection' && entry.parent === profileKeyId, 'KEY');
  }
  return { ids, markerId, hasCollections, absent };
}

/**
 * A-41: make sure the profile labelled `profileLabel` and one collection key per name exist, creating what is missing in
 * ONE atomic keyring publish (one version step). Nothing missing: no write. Returns IDs only, never key bytes. The
 * caller holds the vault's command lock; a concurrent writer makes publishKeyring fail and nothing is retried.
 */
export function ensureCollectionKeys(
  keyringPath: string, vaultId: string, credential: Unlock, profileLabel: string, names: readonly string[],
): EnsureCollectionKeysResult {
  const requested = validateRequest(profileLabel, names);
  const previous = readFileSync(keyringPath);
  const ring = readKeyring(previous, vaultId);
  const unlocked = unlockKeyring(ring, credential);
  const generated: Buffer[] = [];
  const fresh = (): Buffer => {
    const key = randomBytes(32);
    generated.push(key);
    return key;
  };
  try {
    const entries = ring.keys;
    let profileKeyId = findProfile(entries, unlocked.labels, profileLabel);
    const additions: KeyringAddition[] = [];
    if (profileKeyId === undefined) {
      const ids = new Set(entries.map(entry => entry.key_id));
      do profileKeyId = randomBytes(16).toString('hex'); while (ids.has(profileKeyId));
      additions.push({ key_id: profileKeyId, kind: 'profile', parent: 'master', key: fresh(), label: profileLabel });
    }
    const { ids, markerId, hasCollections, absent } = resolveNames(entries, unlocked.masterKey, vaultId, profileKeyId,
      requested);
    if (absent.length === 0) {
      syncDirectory(dirname(keyringPath));
    } else {
      if (!hasCollections) {
        check(!entries.some(entry => entry.key_id === markerId), 'KEY');
        additions.push({ key_id: markerId, kind: 'collection', parent: profileKeyId, key: fresh() });
      }
      for (const name of absent) {
        additions.push({ key_id: ids.get(name)!, kind: 'collection', parent: profileKeyId, key: fresh() });
      }
      publishKeyring(keyringPath, appendKeyringEntries(ring, unlocked.masterKey, unlocked.keys, additions), previous);
    }
    return { profileKeyId, keyIds: ids, created: absent.length };
  } finally {
    for (const key of generated) key.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
    unlocked.masterKey.fill(0);
  }
}

/**
 * A-41: the ID of the active collection key for `name` in the profile labelled `profileLabel`, or undefined when the
 * profile or the key does not exist yet. Pure: reads no file and does not zero the caller's keys. Destroyed key or
 * erased-profile rule: ERASED. Ambiguous label or broken rule marker: KEY.
 */
export function collectionKeyId(unlocked: UnlockedKeyring, profileLabel: string, name: string): string | undefined {
  validText(profileLabel);
  validName(name);
  const { keyring, labels, masterKey } = unlocked;
  const profileKeyId = findProfile(keyring.keys, labels, profileLabel);
  if (profileKeyId === undefined) return undefined;
  const { ids, absent } = resolveNames(keyring.keys, masterKey, keyring.vault_id, profileKeyId, [name]);
  return absent.length === 0 ? ids.get(name) : undefined;
}

import { Buffer, isUtf8 } from 'node:buffer';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import {
  base64, canonical, check, derive, hex, integer, object, open, parseCanonical, seal, timestamp,
} from './bytes.ts';
import type { Json } from './bytes.ts';

const FORMAT = 'foundry-keyring/1';
const MAX_MEMORY = 256 * 1024 * 1024;

interface Kdf {
  name: 'scrypt';
  N: 131072;
  r: 8;
  p: 1 | 2;
  salt: string;
}

type Kind = 'profile' | 'collection' | 'index' | 'signing';
interface EntryIdentity {
  key_id: string;
  kind: Kind;
  parent: string;
}
type Entry = EntryIdentity & (
  | { state: 'active'; created_at: string; wrapped: string; label_enc?: string }
  | { state: 'destroyed'; destroyed_at: string; wrapped: null }
);
type EntryInput = EntryIdentity & (
  | { state: 'active'; created_at: string; key: Buffer; label?: string }
  | { state: 'destroyed'; destroyed_at: string }
);
interface Keyring {
  format: typeof FORMAT;
  vault_id: string;
  version: number;
  kdf: Kdf;
  master: { by_passphrase: string; by_recovery: string };
  keys: Entry[];
  mac: string;
}
interface KeyringInput {
  vaultId: string;
  version: number;
  masterKey: Buffer;
  entries: readonly EntryInput[];
  parallelism?: Kdf['p'];
}
export type VaultCredential = { passphrase: string } | { recoveryKey: Buffer };
export type Unlock = VaultCredential | { session: UnlockSession };
export type KdfParallelism = Kdf['p'];

const SESSION_TOKEN = Symbol('foundry.vault.unlock-session');
const sessionState = new WeakMap<UnlockSession, { vaultId: string; masterKey: Buffer; disposed: boolean }>();
let kdfCalls = 0;

/** @internal Test-only hook for counting scrypt KDF invocations. */
export function getKdfCallCountForTest(): number {
  return kdfCalls;
}

/** @internal Test-only hook for resetting the scrypt KDF counter. */
export function resetKdfCallCountForTest(): void {
  kdfCalls = 0;
}

/** @internal Test-only hook verifying that dispose() zeroed the owned master-key bytes. */
export function isSessionMasterKeyZeroedForTest(session: UnlockSession): boolean {
  const state = sessionState.get(session);
  return state !== undefined && state.masterKey.every(byte => byte === 0);
}

/** Holds an unwrapped vault master key for one command so the KDF runs at most once. */
export class UnlockSession {
  readonly vaultId: string;

  /** @internal Construct via unlockVault(). */
  constructor(vaultId: string, masterKey: Buffer, token: symbol) {
    check(token === SESSION_TOKEN && masterKey.length === 32, 'KEY');
    hex(vaultId, 16);
    this.vaultId = vaultId;
    sessionState.set(this, { vaultId, masterKey, disposed: false });
  }

  get disposed(): boolean {
    return sessionState.get(this)?.disposed ?? true;
  }

  dispose(): void {
    const state = sessionState.get(this);
    if (!state || state.disposed) return;
    state.masterKey.fill(0);
    state.disposed = true;
  }
}

export function validateParallelism(value: unknown): asserts value is KdfParallelism {
  check(value === 1 || value === 2, 'KDF');
}

function validateKdf(value: unknown): asserts value is Kdf {
  object(value, 'name N r p salt');
  check(value.name === 'scrypt' && value.N === 131072 && value.r === 8, 'KDF');
  validateParallelism(value.p);
  base64(value.salt, 32);
}

function validateKeyring(value: unknown): asserts value is Keyring {
  check(value !== null && typeof value === 'object' && Object.hasOwn(value, 'format'));
  check((value as { format: unknown }).format === FORMAT, 'VERSION');
  object(value, 'format vault_id version kdf master keys mac');
  hex(value.vault_id, 16);
  integer(value.version, 1);
  validateKdf(value.kdf);
  object(value.master, 'by_passphrase by_recovery');
  base64(value.master.by_passphrase, 60);
  base64(value.master.by_recovery, 60);
  base64(value.mac, 32);
  check(Array.isArray(value.keys));
  const byId = new Map<string, Entry>();
  let previous = '';
  for (const entry of value.keys) {
    check(entry !== null && typeof entry === 'object' && !Array.isArray(entry));
    const { key_id, kind, parent, state } = entry;
    hex(key_id, 16);
    check(key_id > previous);
    check(kind === 'profile' || kind === 'collection' || kind === 'index' || kind === 'signing');
    if (kind === 'collection') hex(parent, 16);
    else check(parent === 'master');

    const fields = 'key_id kind parent state wrapped ';
    if (state === 'active') {
      object(entry, fields + (kind === 'profile' ? 'created_at label_enc' : 'created_at'));
      timestamp(entry.created_at);
      base64(entry.wrapped, 60);
      if (kind === 'profile') check(base64(entry.label_enc).length >= 29);
    } else {
      check(state === 'destroyed');
      object(entry, fields + 'destroyed_at');
      timestamp(entry.destroyed_at);
      check(entry.wrapped === null);
    }
    byId.set(key_id, entry as unknown as Entry);
    previous = key_id;
  }
  for (const entry of byId.values()) {
    if (entry.kind !== 'collection') continue;
    const parent = byId.get(entry.parent);
    check(parent?.kind === 'profile' && (entry.state === 'destroyed' || parent.state === 'active'), 'KEY');
  }
}

function passphraseKey(passphrase: string, kdf: Kdf): Buffer {
  check(typeof passphrase === 'string' && passphrase.isWellFormed(), 'KEY');
  const { N, r, p, salt } = kdf;
  const secret = Buffer.from(passphrase);
  try {
    kdfCalls++;
    return scryptSync(secret, base64(salt, 32), 32, { N, r, p, maxmem: MAX_MEMORY });
  } finally {
    secret.fill(0);
  }
}

export function vaultKey(key: Buffer, vaultId: string, label: string): Buffer {
  return derive(key, label, Buffer.from(vaultId, 'hex'));
}

export function collectionIdKey(collectionKey: Buffer, vaultId: string): Buffer {
  hex(vaultId, 16);
  return vaultKey(collectionKey, vaultId, 'collection-id');
}

export function blobId(idKey: Buffer, plaintext: Buffer): string {
  check(idKey.length === 32, 'KEY');
  return createHmac('sha256', idKey).update(plaintext).digest('hex');
}

function aad(vaultId: string, keyId: string, kind: string, parent: string, kdf?: Kdf): Buffer {
  return Buffer.from(canonical([FORMAT, vaultId, keyId, kind, parent, (kdf as unknown as Json) ?? null]));
}

function wrap(key: Buffer, nonce: Buffer, data: Buffer, plaintext: Buffer): string {
  check(key.length === 32 && nonce.length === 12, 'KEY');
  return Buffer.concat([nonce, seal(key, nonce, data, plaintext)]).toString('base64');
}

function unwrap(key: Buffer, data: Buffer, wrapped: string): Buffer {
  const bytes = base64(wrapped);
  return open(key, bytes.subarray(0, 12), data, bytes.subarray(12));
}

function mac(body: Omit<Keyring, 'mac'>, master: Buffer): Buffer {
  const key = vaultKey(master, body.vault_id, 'keyring-mac');
  try {
    return createHmac('sha256', key).update(Buffer.from(canonical(body as unknown as Json))).digest();
  } finally {
    key.fill(0);
  }
}

function encodeBody(body: Omit<Keyring, 'mac'>, masterKey: Buffer): Buffer {
  const data = { ...body, mac: mac(body, masterKey).toString('base64') };
  validateKeyring(data);
  return Buffer.from(canonical(data as unknown as Json));
}

function newKdf(p: KdfParallelism, entropy: typeof randomBytes): Kdf {
  const kdf: Kdf = { name: 'scrypt', N: 131072, r: 8, p, salt: entropy(32).toString('base64') };
  validateKdf(kdf);
  return kdf;
}

function passphraseWrap(
  passphrase: string, kdf: Kdf, vaultId: string, masterKey: Buffer, entropy: typeof randomBytes,
): string {
  const key = passphraseKey(passphrase, kdf);
  try {
    return wrap(key, entropy(12), aad(vaultId, 'master', 'master', 'passphrase', kdf), masterKey);
  } finally {
    key.fill(0);
  }
}

export function replacementParallelism(
  current: KdfParallelism, requested = current,
): KdfParallelism {
  check(requested >= current, 'KDF');
  return requested;
}

export function nextKeyringVersion(version: number): number {
  integer(version + 1, 2);
  return version + 1;
}

export function updateIndexEntry(
  bytes: Buffer, vaultId: string, credential: Unlock, keyId: string, operation: 'stage' | 'retire',
): { next?: Buffer; key?: Buffer } {
  hex(keyId, 16);
  const ring = readKeyring(bytes, vaultId);
  const { mac: _mac, ...body } = ring;
  const master = unlockMaster(ring, credential);
  try {
    const existing = body.keys.find(entry => entry.key_id === keyId);
    const slot = aad(vaultId, keyId, 'index', 'master');
    if (operation === 'stage' && existing) {
      check(existing.kind === 'index' && existing.state === 'active', 'KEY');
      return { key: unwrap(master, slot, existing.wrapped) };
    }
    const date = new Date().toISOString().replace(/\.\d{3}Z$/u, 'Z');
    if (operation === 'retire') {
      check(existing?.kind === 'index', 'KEY');
      if (existing.state === 'destroyed') return {};
      const retired: Entry = { key_id: keyId, kind: 'index', parent: 'master', state: 'destroyed',
        destroyed_at: date, wrapped: null };
      const keys = body.keys.map(entry => entry === existing ? retired : entry);
      return { next: encodeBody({ ...body, version: nextKeyringVersion(body.version), keys }, master) };
    }
    const key = randomBytes(32);
    try {
      const staged: Entry = { key_id: keyId, kind: 'index', parent: 'master', state: 'active',
        created_at: date, wrapped: wrap(master, randomBytes(12), slot, key) };
      const keys = [...body.keys, staged].sort((a, b) => a.key_id < b.key_id ? -1 : 1);
      return { next: encodeBody({ ...body, version: nextKeyringVersion(body.version), keys }, master), key };
    } catch (error) {
      key.fill(0);
      throw error;
    }
  } finally {
    master.fill(0);
  }
}

export function changeKeyringPassphrase(
  bytes: Buffer, vaultId: string, current: string, replacement: string, parallelism?: KdfParallelism,
): Buffer {
  if (parallelism !== undefined) validateParallelism(parallelism);
  const keyring = readKeyring(bytes, vaultId);
  const version = nextKeyringVersion(keyring.version);
  const kdf = newKdf(replacementParallelism(keyring.kdf.p, parallelism), randomBytes);
  const masterKey = unlockMaster(keyring, { passphrase: current });
  try {
    return encodeBody({
      format: FORMAT, vault_id: vaultId, version, kdf, keys: keyring.keys,
      master: {
        by_passphrase: passphraseWrap(replacement, kdf, vaultId, masterKey, randomBytes),
        by_recovery: keyring.master.by_recovery,
      },
    }, masterKey);
  } finally {
    masterKey.fill(0);
  }
}

/** The optional entropy source is for synthetic vectors and must never be reused in production. */
export function encodeKeyring(
  input: KeyringInput, passphrase: string, recoveryKey: Buffer, entropy = randomBytes,
): Buffer {
  const { vaultId, version, masterKey, entries, parallelism = 1 } = input;
  hex(vaultId, 16);
  check(masterKey.length === 32, 'KEY');
  const kdf = newKdf(parallelism, entropy);
  const recovery = vaultKey(recoveryKey, vaultId, 'recovery-wrap');
  let master: Keyring['master'];
  try {
    master = {
      by_passphrase: passphraseWrap(passphrase, kdf, vaultId, masterKey, entropy),
      by_recovery: wrap(recovery, entropy(12), aad(vaultId, 'master', 'master', 'recovery'), masterKey),
    };
  } finally {
    recovery.fill(0);
  }
  const keysById = new Map(entries.flatMap(entry => entry.state === 'active' ? [[entry.key_id, entry.key]] : []));
  const keys: Entry[] = [...entries].sort((a, b) => a.key_id < b.key_id ? -1 : Number(a.key_id > b.key_id))
    .map(({ key_id, kind, parent, ...entry }) => {
      const identity = { key_id, kind, parent };
      if (entry.state === 'destroyed') return { ...identity, ...entry, wrapped: null };
      const wrappingKey = parent === 'master' ? masterKey : keysById.get(parent);
      check(wrappingKey && entry.key.length === 32, 'KEY');
      const wrapped = wrap(wrappingKey, entropy(12), aad(vaultId, key_id, kind, parent), entry.key);
      const serialized: Entry = { ...identity, state: entry.state, created_at: entry.created_at, wrapped };
      if (kind === 'profile') {
        check(entry.label && entry.label.isWellFormed());
        const key = vaultKey(masterKey, vaultId, 'profile-label');
        let label: Buffer | undefined;
        try {
          label = Buffer.from(entry.label);
          serialized.label_enc = wrap(key, entropy(12), aad(vaultId, key_id, 'profile-label', parent), label);
        } finally {
          key.fill(0);
          label?.fill(0);
        }
      } else {
        check(entry.label === undefined);
      }
      return serialized;
    });
  return encodeBody({ format: FORMAT, vault_id: vaultId, version, kdf, master, keys }, masterKey);
}

export function readKeyring(bytes: Buffer, expectedVaultId: string): Keyring {
  const keyring: unknown = parseCanonical(bytes);
  validateKeyring(keyring);
  check(keyring.vault_id === expectedVaultId, 'KEY');
  return keyring;
}

function unlockMaster(keyring: Keyring, credential: Unlock): Buffer {
  const { mac: storedMac, ...body } = keyring;
  const { vault_id: vaultId, kdf, master } = body;
  check(credential !== null && typeof credential === 'object', 'KEY');
  const passphrase = 'passphrase' in credential;
  const recovery = 'recoveryKey' in credential;
  const session = 'session' in credential && credential.session !== undefined;
  check(Number(passphrase) + Number(recovery) + Number(session) === 1, 'KEY');

  if (session) {
    const state = sessionState.get((credential as { session: UnlockSession }).session);
    check(state && !state.disposed && state.vaultId === vaultId, 'KEY');
    const masterKey = Buffer.from(state.masterKey);
    try {
      check(timingSafeEqual(base64(storedMac, 32), mac(body, masterKey)), 'KEY');
      return masterKey;
    } catch (error) {
      masterKey.fill(0);
      throw error;
    }
  }

  const slot = passphrase ? 'passphrase' : 'recovery';
  const wrappingKey = passphrase ? passphraseKey((credential as { passphrase: string }).passphrase, kdf)
    : vaultKey((credential as { recoveryKey: Buffer }).recoveryKey, vaultId, 'recovery-wrap');
  let masterKey: Buffer;
  try {
    masterKey = unwrap(wrappingKey, aad(vaultId, 'master', 'master', slot, passphrase ? kdf : undefined),
      passphrase ? master.by_passphrase : master.by_recovery);
  } finally {
    wrappingKey.fill(0);
  }
  try {
    check(timingSafeEqual(base64(storedMac, 32), mac(body, masterKey)), 'MAC');
    return masterKey;
  } catch (error) {
    masterKey.fill(0);
    throw error;
  }
}

export function createUnlockSession(bytes: Buffer, vaultId: string, credential: VaultCredential): UnlockSession {
  check(credential !== null && typeof credential === 'object'
    && (!('session' in credential) || (credential as { session?: unknown }).session === undefined), 'KEY');
  const ring = readKeyring(bytes, vaultId);
  const masterKey = unlockMaster(ring, credential);
  try {
    return new UnlockSession(vaultId, masterKey, SESSION_TOKEN);
  } catch (error) {
    masterKey.fill(0);
    throw error;
  }
}

export function decodeKeyring(bytes: Buffer, credential: Unlock, expectedVaultId: string) {
  return unlockKeyring(readKeyring(bytes, expectedVaultId), credential);
}

export function unlockKeyring(keyring: Keyring, credential: Unlock) {
  const { vault_id: vaultId, keys } = keyring;
  const masterKey = unlockMaster(keyring, credential);
  const unwrapped = new Map<string, Buffer>();
  const labels = new Map<string, string>();
  const erased = new Map<string, string>();
  try {
    for (const entry of [...keys.filter(key => key.kind !== 'collection'), ...keys.filter(key => key.kind === 'collection')]) {
      const { key_id, kind, parent } = entry;
      if (entry.state === 'destroyed') {
        erased.set(key_id, entry.destroyed_at);
        continue;
      }
      const wrappingKey = parent === 'master' ? masterKey : unwrapped.get(parent);
      check(wrappingKey, 'KEY');
      unwrapped.set(key_id, unwrap(wrappingKey, aad(vaultId, key_id, kind, parent), entry.wrapped));
      if (kind === 'profile') {
        const key = vaultKey(masterKey, vaultId, 'profile-label');
        let label: Buffer | undefined;
        try {
          label = unwrap(key, aad(vaultId, key_id, 'profile-label', parent), entry.label_enc!);
          check(isUtf8(label));
          labels.set(key_id, label.toString());
        } finally {
          key.fill(0);
          label?.fill(0);
        }
      }
    }
  } catch (error) {
    masterKey.fill(0);
    for (const key of unwrapped.values()) key.fill(0);
    throw error;
  }
  return {
    keyring, masterKey, keys: unwrapped, labels, erased,
    collectionEncryptionKey(keyId: string): Buffer {
      const entry = keys.find(entry => entry.key_id === keyId && entry.kind === 'collection');
      check(entry, 'KEY');
      check(entry.state === 'active', 'ERASED');
      const key = unwrapped.get(keyId);
      check(key, 'KEY');
      return vaultKey(key, vaultId, 'collection-encryption');
    },
  };
}

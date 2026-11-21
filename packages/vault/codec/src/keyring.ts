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
export type Unlock = { passphrase: string } | { recoveryKey: Buffer };

function validateKdf(value: unknown): asserts value is Kdf {
  object(value, 'name N r p salt');
  check(value.name === 'scrypt' && value.N === 131072 && value.r === 8
    && (value.p === 1 || value.p === 2), 'KDF');
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
  check(passphrase.isWellFormed(), 'KEY');
  const { N, r, p, salt } = kdf;
  return scryptSync(Buffer.from(passphrase), base64(salt, 32), 32, { N, r, p, maxmem: MAX_MEMORY });
}

function vaultKey(key: Buffer, vaultId: string, label: string): Buffer {
  return derive(key, label, Buffer.from(vaultId, 'hex'));
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
  return createHmac('sha256', vaultKey(master, body.vault_id, 'keyring-mac'))
    .update(Buffer.from(canonical(body as unknown as Json))).digest();
}

/** The optional entropy source is for synthetic vectors and must never be reused in production. */
export function encodeKeyring(
  input: KeyringInput, passphrase: string, recoveryKey: Buffer, entropy = randomBytes,
): Buffer {
  const { vaultId, version, masterKey, entries, parallelism = 1 } = input;
  hex(vaultId, 16);
  check(masterKey.length === 32, 'KEY');
  const kdf: Kdf = { name: 'scrypt', N: 131072, r: 8, p: parallelism, salt: entropy(32).toString('base64') };
  validateKdf(kdf);
  const passKey = passphraseKey(passphrase, kdf);
  const recovery = vaultKey(recoveryKey, vaultId, 'recovery-wrap');
  const master = {
    by_passphrase: wrap(passKey, entropy(12), aad(vaultId, 'master', 'master', 'passphrase', kdf), masterKey),
    by_recovery: wrap(recovery, entropy(12), aad(vaultId, 'master', 'master', 'recovery', kdf), masterKey),
  };
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
        serialized.label_enc = wrap(vaultKey(masterKey, vaultId, 'profile-label'), entropy(12),
          aad(vaultId, key_id, 'profile-label', parent), Buffer.from(entry.label));
      } else {
        check(entry.label === undefined);
      }
      return serialized;
    });
  const body = { format: FORMAT, vault_id: vaultId, version, kdf, master, keys } as const;
  const data = { ...body, mac: mac(body, masterKey).toString('base64') };
  validateKeyring(data);
  return Buffer.from(canonical(data as unknown as Json));
}

export function decodeKeyring(bytes: Buffer, credential: Unlock, expectedVaultId: string) {
  const keyring: unknown = parseCanonical(bytes);
  validateKeyring(keyring);
  const { mac: storedMac, ...body } = keyring;
  const { vault_id: vaultId, kdf, master, keys } = body;
  check(vaultId === expectedVaultId, 'KEY');
  const masterKey = 'passphrase' in credential
    ? unwrap(passphraseKey(credential.passphrase, kdf),
      aad(vaultId, 'master', 'master', 'passphrase', kdf), master.by_passphrase)
    : unwrap(vaultKey(credential.recoveryKey, vaultId, 'recovery-wrap'),
      aad(vaultId, 'master', 'master', 'recovery', kdf), master.by_recovery);
  check(timingSafeEqual(base64(storedMac, 32), mac(body, masterKey)), 'MAC');

  const unwrapped = new Map<string, Buffer>();
  const labels = new Map<string, string>();
  const erased = new Map<string, string>();
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
      const label = unwrap(vaultKey(masterKey, vaultId, 'profile-label'),
        aad(vaultId, key_id, 'profile-label', parent), entry.label_enc!);
      check(isUtf8(label));
      labels.set(key_id, label.toString());
    }
  }
  return {
    keyring, masterKey, keys: unwrapped, labels, erased,
    collectionEncryptionKey(keyId: string): Buffer {
      check(!erased.has(keyId), 'ERASED');
      const key = unwrapped.get(keyId);
      check(key && keys.some(entry => entry.key_id === keyId && entry.kind === 'collection'), 'KEY');
      return vaultKey(key, vaultId, 'collection-encryption');
    },
  };
}

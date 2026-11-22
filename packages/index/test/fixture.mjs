import { createHmac, hkdfSync } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { blobId, collectionIdKey, decodeKeyring, encodeKeyring, initializeVault, signingPublicKey, VaultWriter } from '../../vault/codec/dist/index.js';

const vaultId = 'f1'.repeat(16);
const date = '2026-01-01T00:00:00Z';
const passphrase = 'TEST ONLY working-index synthetic fixture';
const key = value => Buffer.alloc(32, value);
export const ids = { profile: '11'.repeat(16), live: '22'.repeat(16), erase: '33'.repeat(16), system: '44'.repeat(16) };
const active = (key_id, kind, parent, value, extra = {}) =>
  ({ key_id, kind, parent, key: key(value), state: 'active', created_at: date, ...extra });

export function syntheticVault(directory, create = true) {
  const credential = { recoveryKey: key(175) };
  const keyring = join(directory, 'keyring', 'keyring.json');
  if (create) {
    mkdirSync(join(directory, 'keyring'), { recursive: true });
    const signing = active('55'.repeat(16), 'signing', 'master', 5);
    const entries = [active(ids.profile, 'profile', 'master', 1, { label: 'TEST ONLY profile' }),
      active(ids.live, 'collection', ids.profile, 2), active(ids.erase, 'collection', ids.profile, 3),
      active(ids.system, 'collection', ids.profile, 4), signing];
    writeFileSync(keyring, encodeKeyring({ vaultId, version: 1, masterKey: key(6), entries }, passphrase, credential.recoveryKey));
    initializeVault(directory, { vaultId, createdAt: date, signingPublicKey: signingPublicKey(signing.key) });
  }

  const unlock = () => decodeKeyring(readFileSync(keyring), credential, vaultId);
  return {
    directory, vaultId, keyring, credential, unlock,
    write(work) {
      const unlocked = unlock();
      const writer = VaultWriter.open(directory, unlocked);
      try {
        return work(writer);
      } finally {
        writer.release();
        unlocked.masterKey.fill(0);
        for (const bytes of unlocked.keys.values()) bytes.fill(0);
      }
    },
    destroyCollection() {
      const unlocked = unlock();
      const entries = unlocked.keyring.keys.map(entry => entry.key_id === ids.erase
        ? { key_id: ids.erase, kind: 'collection', parent: ids.profile, state: 'destroyed', destroyed_at: date }
        : entry.state === 'destroyed'
          ? { key_id: entry.key_id, kind: entry.kind, parent: entry.parent, state: entry.state, destroyed_at: entry.destroyed_at }
          : { key_id: entry.key_id, kind: entry.kind, parent: entry.parent, state: entry.state,
            created_at: entry.created_at, key: unlocked.keys.get(entry.key_id), label: unlocked.labels.get(entry.key_id) });
      writeFileSync(keyring, encodeKeyring({
        vaultId, version: unlocked.keyring.version + 1, masterKey: unlocked.masterKey, entries,
      }, passphrase, credential.recoveryKey));
    },
    tombstoneKey() {
      const unlocked = unlock();
      const result = Buffer.from(hkdfSync('sha256', unlocked.masterKey, Buffer.from(vaultId, 'hex'),
        Buffer.from('foundry/tombstone/v1'), 32));
      unlocked.masterKey.fill(0);
      for (const bytes of unlocked.keys.values()) bytes.fill(0);
      return result;
    },
    writable() {
      for (const entry of readdirSync(join(directory, 'segments'), { withFileTypes: true })) {
        const segment = join(directory, 'segments', entry.name);
        if (!entry.isDirectory()) continue;
        chmodSync(segment, 0o700);
        for (const name of readdirSync(segment)) chmodSync(join(segment, name), 0o600);
      }
    },
  };
}

export function note(writer, id, text, options = {}) {
  const plaintext = Buffer.from(text);
  const keyId = options.keyId ?? ids.live;
  const [{ id: blob }] = writer.appendBatch([{ type: 'blob', keyId, plaintext }]);
  const [record] = writer.appendBatch([{ type: 'event', keyId, event: {
    kind: 'item.imported', ts: options.ts ?? date, source: options.source ?? 'test/notes',
    profile: options.profile ?? 'me', collection: options.collection ?? 'test-live',
    tier: options.tier ?? 'public', sensitivity: 'personal', body: {
      blob, item_id: id, mime: 'text/plain', size: plaintext.length, ...(options.body ?? {}),
    },
  } }]);
  return record.sequence;
}

export const systemEvent = (kind, body) => ({ type: 'event', keyId: ids.system, event: { kind, body, collection: 'system' } });

export function tombstone(vault, bytes) {
  const raw = vault.tombstoneKey();
  try {
    return createHmac('sha256', raw).update(bytes).digest('hex');
  } finally {
    raw.fill(0);
  }
}

export function appendCorpus(vault, start, count) {
  const raw = collectionIdKey(key(2), vault.vaultId);
  let bytes = 0;
  try {
    vault.write(writer => writer.appendBatch((function* () {
      for (let i = start; i < start + count; i++) {
        const line = `TEST ONLY synthetic note ${i}. Amber crystals appear in the demonstration corpus. `;
        const size = 3500 + i;
        const plaintext = Buffer.from(line.repeat(Math.ceil(size / line.length)).slice(0, size));
        bytes += plaintext.length;
        yield { type: 'blob', keyId: ids.live, plaintext };
        yield { type: 'event', keyId: ids.live, event: {
          kind: 'item.imported', ts: date, profile: 'me', collection: 'test-bench', source: 'test/corpus',
          sensitivity: 'personal', body: { item_id: `synthetic-${i}`, blob: blobId(raw, plaintext), mime: 'text/plain' },
        } };
      }
    })()));
    return bytes;
  } finally {
    raw.fill(0);
  }
}
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  FRAME_BYTES, decodeKeyring, decodeRecord, decryptRecord, scanRecords,
  sha256, signingPublicKey, VaultFormatError, verifySegment,
} from '../src/index.ts';
import type { ChainPosition } from '../src/index.ts';

function asset(name: string): Buffer {
  const stored = readFileSync(new URL('./vectors/' + name, import.meta.url));
  return name.endsWith('.b64') ? Buffer.from(stored.toString('ascii'), 'base64') : stored;
}
const suite = JSON.parse(asset('cases.json').toString());
const metadata = JSON.parse(asset('VAULT.json').toString());
assert.deepEqual(metadata, suite.metadata);
const vaultId = metadata.vault_id;
const publicKey = Buffer.from(metadata.signing_public_key, 'base64');
const unlocked = decodeKeyring(asset(suite.keyring), { passphrase: suite.passphrase }, vaultId);
const initialKey = unlocked.collectionEncryptionKey(suite.ids.collection);
const expect = <T>(operation: () => T, error?: string): T | undefined => {
  if (error === undefined) return operation();
  assert.throws(operation, (value: unknown) => value instanceof VaultFormatError && value.code === error);
};

for (const vector of suite.record_cases) {
  test('record: ' + vector.name, () => {
    let bytes = asset(vector.asset);
    if (vector.prefix) bytes = Buffer.concat([asset(vector.prefix), bytes.subarray(...vector.slice)]);
    if (vector.swap_frames) {
      const split = 69 + FRAME_BYTES + 20;
      bytes = Buffer.concat([bytes.subarray(0, 69), bytes.subarray(split), bytes.subarray(69, split)]);
    }
    const result = expect(() => {
      const records = [...scanRecords(bytes)];
      if (records.length !== 1) throw new VaultFormatError('LENGTH');
      const key = vector.wrong_key ? Buffer.alloc(32) : unlocked.collectionEncryptionKey(records[0].keyId);
      return decodeRecord(bytes, vector.vault_id ?? vaultId, key);
    }, vector.error);
    if (result) {
      assert.equal(result.type, vector.type);
      assert.equal(result.context, BigInt(vector.sequence));
      assert.equal(result.plaintext.length, vector.length);
      assert.equal(sha256(result.plaintext), vector.sha256);
    }
  });
}

const positions = new Map<string, ChainPosition>();
for (const vector of suite.manifest_cases) {
  test('manifest: ' + vector.name, () => {
    const files = new Map(Object.entries<string>(vector.files).map(([name, filename]) => [name, asset(filename)]));
    const previous = vector.prior ? positions.get(vector.prior) : undefined;
    if (vector.prior) assert.ok(previous);
    const result = expect(() => verifySegment(asset(vector.asset), asset(vector.signature), publicKey, vaultId,
      files, previous), vector.error);
    if (result) {
      positions.set(vector.name, result.position);
      const digests = [...files.values()].flatMap(stream => [...scanRecords(stream)].map(record =>
        sha256(decryptRecord(record, vaultId, unlocked.collectionEncryptionKey(record.keyId)))));
      assert.deepEqual(digests, vector.plaintext_sha256);
    }
  });
}

for (const vector of suite.keyring_cases) {
  test('keyring: ' + vector.name, () => {
    const credential = vector.recovery ? { recoveryKey: Buffer.from(suite.recovery_key, 'hex') }
      : { passphrase: vector.wrong_passphrase ? 'TEST ONLY wrong' : suite.passphrase };
    const result = expect(() => decodeKeyring(asset(vector.asset), credential, vector.vault_id ?? vaultId),
      vector.error);
    if (result) {
      assert.deepEqual(result.collectionEncryptionKey(suite.ids.collection), initialKey);
      assert.deepEqual(signingPublicKey(result.keys.get(suite.ids.signing)!), publicKey);
      assert.equal(result.labels.get(suite.ids.profile), 'fixture \u{1f512}');
      assert.equal(result.erased.get(suite.ids.erased), metadata.created_at);
      assert.equal(result.keys.has(suite.ids.erased), false);
    }
  });
}

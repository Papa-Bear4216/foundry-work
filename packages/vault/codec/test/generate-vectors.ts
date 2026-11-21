import assert from 'node:assert/strict';
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHmac, createPrivateKey, scryptSync, sign } from 'node:crypto';
import {
  FRAME_BYTES, GENESIS_HASH, blobId, collectionIdKey, encodeKeyring, encodeManifest, encodeRecord, sha256, signingPublicKey,
} from '../src/index.ts';
import { canonical, derive, seal } from '../src/bytes.ts';
import type { Json } from '../src/bytes.ts';
import type { Manifest } from '../src/index.ts';

// TEST ONLY. Fixed credentials, key bytes, salts and nonces are synthetic and public.
const passphrase = 'TEST ONLY cafe\u0301 \u{1f512}';
const changedPassphrase = 'TEST ONLY changed \u{1f512}';
const vaultId = '10'.repeat(16);
const wrongVault = '11'.repeat(16);
const ids = { collection: '01'.repeat(16), profile: '02'.repeat(16), index: '03'.repeat(16),
  signing: '04'.repeat(16), erased: '05'.repeat(16) };
const master = Buffer.alloc(32, 0x30);
const profile = Buffer.alloc(32, 0x31);
const collection = Buffer.alloc(32, 0x32);
const signing = Buffer.alloc(32, 0x33);
const recoveryKey = Buffer.alloc(32, 0x34);
const indexKey = Buffer.alloc(32, 0x35);
const salt = Buffer.from(vaultId, 'hex');
const encryption = derive(collection, 'collection-encryption', salt);
const identity = collectionIdKey(collection, vaultId);
const date = '2026-01-02T03:04:05Z';
let nonceByte = 0x40;
const live = { state: 'active', created_at: date } as const;
const ringInput = {
  vaultId, version: Number.MAX_SAFE_INTEGER - 1, masterKey: master, entries: [
    { key_id: ids.profile, kind: 'profile', parent: 'master', key: profile, label: 'fixture \u{1f512}', ...live },
    { key_id: ids.collection, kind: 'collection', parent: ids.profile, key: collection, ...live },
    { key_id: ids.index, kind: 'index', parent: 'master', key: indexKey, ...live },
    { key_id: ids.signing, kind: 'signing', parent: 'master', key: signing, ...live },
    { key_id: ids.erased, kind: 'collection', parent: ids.profile, state: 'destroyed', destroyed_at: date },
  ],
} as const satisfies Parameters<typeof encodeKeyring>[0];
const testEntropy = (size: number) => Buffer.alloc(size, nonceByte++);
const keyring = encodeKeyring(ringInput, passphrase, recoveryKey, testEntropy);
const strongerRing = encodeKeyring({ ...ringInput, parallelism: 2 }, passphrase, recoveryKey, testEntropy);

function withKeyringMac(body: Record<string, Json>): Buffer {
  const mac = createHmac('sha256', derive(master, 'keyring-mac', salt)).update(canonical(body)).digest('base64');
  return Buffer.from(canonical({ ...body, mac }));
}

// Simulate a V-2 rewrite using the known MK and the new passphrase as the only secrets.
const { mac: _, ...previousRing } = JSON.parse(keyring.toString());
const changedSalt = testEntropy(32);
const changedKdf = { ...previousRing.kdf, p: 2, salt: changedSalt.toString('base64') };
const changedKey = scryptSync(Buffer.from(changedPassphrase), changedSalt, 32,
  { N: changedKdf.N, r: changedKdf.r, p: changedKdf.p, maxmem: 256 * 1024 * 1024 });
const changedNonce = testEntropy(12);
const changedAad = Buffer.from(canonical([
  previousRing.format, previousRing.vault_id, 'master', 'master', 'passphrase', changedKdf,
]));
const changedRing = withKeyringMac({
  ...previousRing,
  version: previousRing.version + 1,
  kdf: changedKdf,
  master: {
    ...previousRing.master,
    by_passphrase: Buffer.concat([changedNonce, seal(changedKey, changedNonce, changedAad, master)]).toString('base64'),
  },
});
const metadata = { format: 'foundry-vault/1', vault_id: vaultId, created_at: date,
  signing_public_key: signingPublicKey(signing).toString('base64') };
const testSigningKey = createPrivateKey({
  format: 'jwk',
  key: {
    kty: 'OKP', crv: 'Ed25519',
    x: Buffer.from(metadata.signing_public_key, 'base64').toString('base64url'),
    d: signing.toString('base64url'),
  },
});
const dir = new URL('./vectors/', import.meta.url);
const checkOnly = process.argv.includes('--check');
if (!checkOnly) mkdirSync(dir, { recursive: true });
const assets = new Map<string, Buffer>();
function save(name: string, bytes: Buffer): string {
  // Armor large ciphertext so the repository's text scanner sees only ASCII.
  const stored = bytes.length >= FRAME_BYTES ? Buffer.from(bytes.toString('base64')) : bytes;
  if (stored !== bytes) name += '.b64';
  assets.set(name, bytes);
  const path = new URL(name, dir);
  if (checkOnly) assert.deepEqual(readFileSync(path), stored, name);
  else writeFileSync(path, stored);
  return name;
}
function flip(bytes: Buffer, offset: number): Buffer {
  const edited = Buffer.from(bytes);
  edited[offset] ^= 1;
  return edited;
}

const recordCases: object[] = [];
const plaintextDigests = new Map<string, string>();
function record(name: string, type: 1 | 2, sequence: number, plaintext: Buffer, saltByte: number, keyId = ids.collection) {
  const bytes = encodeRecord({ type, keyId, context: BigInt(sequence) }, plaintext, vaultId,
    encryption, Buffer.alloc(32, saltByte));
  const asset = save(name + '.fvr', bytes);
  const digest = sha256(plaintext);
  plaintextDigests.set(asset, digest);
  recordCases.push({ name, asset, type, sequence, length: plaintext.length, sha256: digest,
    ...(type === 2 ? { blob_id: blobId(identity, plaintext) } : {}) });
  return asset;
}
const event = record('event', 1, 1, Buffer.from('{"seq":1,"kind":"vault.created"}'), 0x50);
const event2 = record('event-next', 1, 2, Buffer.from('{"seq":2,"kind":"profile.created"}'), 0x51);
const maxEvent = record('event-max-seq', 1, Number.MAX_SAFE_INTEGER, Buffer.from('{"seq":9007199254740991}'), 0x52);
const empty = record('empty', 2, 0, Buffer.alloc(0), 0x53);
const tiny = record('one-byte', 2, 0, Buffer.from([0xa5]), 0x54);
record('full-frame', 2, 0, Buffer.alloc(FRAME_BYTES, 0x5a), 0x57);
const blobBytes = Buffer.alloc(FRAME_BYTES + 1, 0x5a);
// One wire fixture carries the full nonfinal frame plus a one-byte final frame.
const multi = record('multiple-frames', 2, 0, blobBytes, 0x55);
const read = (name: string) => assets.get(name)!;
const recordError = (name: string, asset: string, error: string, options = {}) =>
  recordCases.push({ name, asset, error, ...options });
recordError('wrong-key', event, 'AUTH', { wrong_key: true });
recordError('wrong-vault', event, 'AUTH', { vault_id: wrongVault });
recordError('invalid-vault-id', event, 'SCHEMA', { vault_id: vaultId + ' ' });
recordError('tag-bit', save('tag-bit.fvr', flip(read(tiny), read(tiny).length - 1)), 'AUTH');
recordError('record-version', save('record-version.fvr', flip(read(event), 3)), 'VERSION');
recordError('record-type', save('record-type.fvr', flip(read(event), 4)), 'SCHEMA');
recordError('changed-context', save('changed-context.fvr', flip(read(event), 59)), 'AUTH');
recordError('changed-salt', save('changed-salt.fvr', flip(read(event), 52)), 'AUTH');
recordError('unknown-key', save('unknown-key.fvr', flip(read(event), 20)), 'KEY');
const erased = Buffer.from(read(empty));
erased.set(Buffer.from(ids.erased, 'hex'), 5);
recordError('erased-key', save('erased-key.fvr', erased), 'ERASED');
const offsets = { magic: 4, type: 5, key_id: 21, salt: 53, context: 61,
  body_length: 69, frame_length: 73, ciphertext: 74, tag: 90 };
for (const [field, end] of Object.entries(offsets)) {
  recordError('cut-' + field, save('cut-' + field + '.fvr', read(tiny).subarray(0, end - 1)), 'LENGTH');
}
const unsafeContext = Buffer.from(read(maxEvent));
unsafeContext.writeBigUInt64BE(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 53);
recordError('event-context-above-max', save('event-context-above-max.fvr', unsafeContext), 'SCHEMA', { scan_only: true });
for (const [name, json, saltByte, error] of [
  ['event-seq-mismatch', '{"seq":2}', 0x58, 'SEQUENCE'],
  ['event-seq-fraction', '{"seq":1.0}', 0x59, 'SEQUENCE'],
  ['empty-event', '', 0x5a, 'LENGTH'],
] as const) {
  // Seal deliberately invalid plaintexts that the production encoder refuses.
  const payload = Buffer.from(json);
  const eventHeader = Buffer.from(read(event).subarray(0, 69));
  eventHeader.fill(saltByte, 21, 53);
  eventHeader.writeBigUInt64BE(BigInt(payload.length + 20), 61);
  const aad = Buffer.concat([eventHeader, salt, Buffer.alloc(8), Buffer.from([1])]);
  const key = derive(encryption, 'record-key', eventHeader.subarray(21, 53));
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length);
  const bytes = Buffer.concat([eventHeader, length, seal(key, Buffer.alloc(12), aad, payload)]);
  recordError(name, save(name + '.fvr', bytes), error, name === 'empty-event' ? { scan_only: true } : {});
}
const unsafeLength = Buffer.from(read(tiny));
unsafeLength.writeBigUInt64BE((1n << 64n) - 1n, 61);
recordError('u64-length', save('u64-length.fvr', unsafeLength), 'LENGTH');
recordError('extra-byte', save('extra-byte.fvr', Buffer.concat([read(tiny), Buffer.alloc(1)])), 'LENGTH');
const header = read(multi).subarray(0, 69);
const firstFrame = read(multi).subarray(69, 69 + FRAME_BYTES + 20);
const oversizedPrefix = Buffer.from(read(multi).subarray(0, 73));
oversizedPrefix.writeBigUInt64BE(BigInt(firstFrame.length + 1), 61);
oversizedPrefix.writeUInt32BE(FRAME_BYTES + 1, 69);
// With an exact final-frame boundary, only the size limit can reject this during scanning.
recordError('oversized-frame', multi, 'LENGTH', {
  prefix: save('oversized-frame-prefix.bin', oversizedPrefix), slice: [73, 70 + firstFrame.length], scan_only: true,
});
const shortenedHeader = Buffer.from(header);
shortenedHeader.writeBigUInt64BE(BigInt(firstFrame.length), 61);
// The recipe stores small bytes separately and references the shared large frame.
recordError('missing-final-frame', multi, 'AUTH', {
  prefix: save('missing-final-header.bin', shortenedHeader), slice: [69, 69 + firstFrame.length],
});
recordError('short-nonfinal-frame', multi, 'LENGTH', { swap_frames: true, scan_only: true });
const double = encodeRecord({ type: 2, keyId: ids.collection, context: 0n },
  Buffer.alloc(2 * FRAME_BYTES, 0x5a), vaultId, encryption, header.subarray(21, 53));
const tagOffset = 73 + FRAME_BYTES;
// With the same synthetic salt and plaintext, the first ciphertext is reusable. Its new
// tag authenticates the new header at index 0. Replaying that complete frame at index 1 fails.
assert.deepEqual(double.subarray(69, tagOffset), read(multi).subarray(69, tagOffset));
recordError('frame-replay', multi, 'AUTH', {
  prefix: save('frame-replay-header.bin', double.subarray(0, 69)),
  slice: [69, tagOffset],
  tag: save('frame-replay-tag.bin', double.subarray(tagOffset, tagOffset + 16)),
  repeat: 2,
});

const eventStream = save('events.fvr', Buffer.concat([read(event), read(event2)]));
const swapped = save('events-swapped.fvr', Buffer.concat([read(event2), read(event)]));
const packStream = save('pack.fvr', Buffer.concat([read(empty), read(tiny)]));
const manifestCases: object[] = [];
function segment(name: string, number: number, files: Record<string, string>, prior?: string,
  range: [number | null, number | null] = [null, null], overrides: Partial<Manifest> = {}) {
  const manifest: Manifest = {
    format: 'foundry-segment/1', vault_id: vaultId, epoch: 1, segment: number,
    prev_manifest_sha256: prior ? sha256(read(prior + '.json')) : GENESIS_HASH,
    first_event_seq: range[0], last_event_seq: range[1],
    files: Object.entries(files).sort(([a], [b]) => a < b ? -1 : 1)
      .map(([name, asset]) => ({ name, bytes: read(asset).length, sha256: sha256(read(asset)) })),
    key_ids: [ids.collection], closed_at: date, writer: 'fixture "\\ \u{1f512}',
    ...overrides,
  };
  const signed = encodeManifest(manifest, signing);
  save(name + '.json', signed.bytes);
  save(name + '.sig', signed.signature);
  return { asset: name + '.json', signature: name + '.sig', files, prior };
}
const genesis = segment('genesis', 1, { 'events-0001.fvr': eventStream, 'pack-0001.fvr': packStream }, undefined, [1, 2]);
const next = segment('next', 2, { 'pack-0001.fvr': multi }, 'genesis');
const end = segment('end', 3, { 'events-0001.fvr': save('event-third.fvr', encodeRecord(
  { type: 1, context: 3n, keyId: ids.collection }, Buffer.from('{"seq":3}'), vaultId, encryption, Buffer.alloc(32, 0x56))) },
'next', [3, 3]);
const boundary = segment('stream-ordinal-boundary', 1,
  { 'events-9999.fvr': event, 'events-10000.fvr': event2 }, undefined, [1, 2]);
const digestFor = (asset: string) => plaintextDigests.get(asset)!;
manifestCases.push(
  { name: 'genesis', ...genesis, plaintext_sha256: [event, event2, empty, tiny].map(digestFor) },
  { name: 'next', ...next, plaintext_sha256: [digestFor(multi)] },
  { name: 'end', ...end, plaintext_sha256: [sha256(Buffer.from('{"seq":3}'))] },
  { name: 'stream-ordinal-boundary', ...boundary, plaintext_sha256: [event, event2].map(digestFor) },
);
manifestCases.push(
  { name: 'reordered-records', ...genesis, error: 'FILE', files: { ...genesis.files, 'events-0001.fvr': swapped } },
  { name: 'signed-reordered-events', ...segment('signed-reorder', 1, { 'events-0001.fvr': swapped }, undefined, [1, 2]),
    error: 'SEQUENCE' },
  { name: 'renamed-record-file', ...genesis, error: 'FILE',
    files: { 'events-0002.fvr': eventStream, 'pack-0001.fvr': packStream } },
  { name: 'missing-file', ...genesis, error: 'FILE', files: { 'events-0001.fvr': eventStream } },
  { name: 'extra-file', ...genesis, error: 'FILE', files: { ...genesis.files, 'pack-0002.fvr': packStream } },
  { name: 'broken-chain', ...segment('broken-chain', 2, next.files, 'genesis', [null, null],
    { prev_manifest_sha256: 'aa'.repeat(32) }), error: 'CHAIN' },
  { name: 'swapped-manifest', ...next, prior: 'next', error: 'CHAIN' },
  { name: 'bad-signature', ...genesis, signature: save('bad-signature.sig', flip(read(genesis.signature), 63)),
    error: 'SIGNATURE' },
  { name: 'manifest-version', ...genesis, asset: save('manifest-version.json',
    Buffer.from(read(genesis.asset).toString().replace('foundry-segment/1', 'foundry-segment/2'))), error: 'VERSION' },
  { name: 'manifest-newline', ...genesis, asset: save('manifest-newline.json',
    Buffer.concat([read(genesis.asset), Buffer.from('\n')])), error: 'CANONICAL' },
);
for (const [name, edit] of [
  ['timestamp-hour-24', (data: Manifest) => { data.closed_at = '2026-01-01T24:00:00Z'; }],
  ['timestamp-leap-second', (data: Manifest) => { data.closed_at = '2026-01-01T23:59:60Z'; }],
  ['stream-leading-zero', (data: Manifest) => { data.files[0].name = 'events-00001.fvr'; }],
  ['empty-key-ids', (data: Manifest) => { data.key_ids = []; }],
] as const) {
  const data = JSON.parse(read(genesis.asset).toString());
  edit(data);
  const bytes = Buffer.from(canonical(data));
  manifestCases.push({ name, ...genesis, asset: save(name + '.json', bytes),
    signature: save(name + '.sig', sign(null, bytes, testSigningKey)), error: 'SCHEMA' });
}
const ring = save('ring.json', keyring);
const changed = save('ring-passphrase-changed.json', changedRing);
const keyringCases: object[] = [{ name: 'passphrase', asset: ring }, { name: 'recovery', asset: ring, recovery: true },
  { name: 'scrypt-at-ceiling', asset: save('ring-p2.json', strongerRing) },
  { name: 'changed-passphrase', asset: changed, changed_passphrase: true },
  { name: 'recovery-after-passphrase-change', asset: changed, recovery: true },
  { name: 'old-passphrase-after-change', asset: changed, error: 'AUTH' },
  { name: 'wrong-passphrase', asset: ring, wrong_passphrase: true, error: 'AUTH' },
  { name: 'keyring-vault', asset: ring, vault_id: wrongVault, error: 'KEY' }];
for (const [name, error, edit, remac] of [
  ['ring-version', 'VERSION', data => { data.format = 'foundry-keyring/2'; }, false],
  ['scrypt-below-floor', 'KDF', data => { data.kdf.N = 65536; }, false],
  ['scrypt-above-ceiling', 'KDF', data => { data.kdf.p = 3; }, false],
  ['kdf-parallelism-tamper', 'AUTH', data => { data.kdf.p = 2; }, false],
  ['ring-mac', 'MAC', data => { data.version--; }, false],
  ['master-slot-swap', 'AUTH', data => {
    [data.master.by_passphrase, data.master.by_recovery] = [data.master.by_recovery, data.master.by_passphrase];
  }, false],
  ['entry-slot-swap', 'AUTH', data => {
    [data.keys[2].wrapped, data.keys[3].wrapped] = [data.keys[3].wrapped, data.keys[2].wrapped];
  }, true],
  ['wrong-parent-kind', 'KEY', data => { data.keys[0].parent = ids.index; }, false],
  ['noncanonical-base64', 'SCHEMA', data => { data.mac = data.mac.replace(/=+$/u, ''); }, false],
] as const) {
  const data = JSON.parse(keyring.toString());
  edit(data);
  if (remac) delete data.mac;
  const bytes = remac ? withKeyringMac(data) : Buffer.from(canonical(data));
  keyringCases.push({ name, asset: save(name + '.json', bytes), error });
}
const tamperedRing = JSON.parse(changedRing.toString());
tamperedRing.kdf.p = 1;
keyringCases.push(
  { name: 'master-slot-swap-recovery', asset: 'master-slot-swap.json', recovery: true, error: 'AUTH' },
  { name: 'recovery-kdf-tamper-after-change', recovery: true, error: 'MAC',
    asset: save('changed-kdf-tamper.json', Buffer.from(canonical(tamperedRing))) },
);
const metadataBytes = Buffer.from(canonical(metadata));
const metadataCases: object[] = [{ name: 'vault-metadata', asset: save('VAULT.json', metadataBytes) }];
for (const [name, bytes, error] of [
  ['vault-newline', Buffer.concat([metadataBytes, Buffer.from('\n')]), 'CANONICAL'],
  ['vault-short-signing-key', Buffer.from(canonical({ ...metadata, signing_public_key: Buffer.alloc(31).toString('base64') })), 'SCHEMA'],
  ['vault-noncanonical-signing-key', Buffer.from(canonical({ ...metadata, signing_public_key: metadata.signing_public_key.slice(0, -1) })), 'SCHEMA'],
  ['vault-invalid-id', Buffer.from(canonical({ ...metadata, vault_id: 'AA'.repeat(16) })), 'SCHEMA'],
  ['vault-invalid-date', Buffer.from(canonical({ ...metadata, created_at: '2026-02-29T00:00:00Z' })), 'SCHEMA'],
  ['json-fraction', Buffer.from('{"a":1.0}'), 'CANONICAL'],
  ['json-nan', Buffer.from('{"a":NaN}'), 'CANONICAL'],
  ['json-surrogate', Buffer.from('{"a":"\\ud800"}'), 'CANONICAL'],
  ['json-unsafe-integer', Buffer.from('{"a":9007199254740992}'), 'CANONICAL'],
] as const) {
  metadataCases.push({ name, asset: save(name + '.json', bytes), error });
}
save('cases.json', Buffer.from(JSON.stringify({
  warning: 'TEST ONLY: all credentials, keys, salts, nonces and content are synthetic.',
  passphrase, changed_passphrase: changedPassphrase, recovery_key: recoveryKey.toString('hex'), metadata, ids,
  keyring: ring, changed_keyring: changed,
  metadata_cases: metadataCases, record_cases: recordCases, manifest_cases: manifestCases, keyring_cases: keyringCases,
}, null, 2) + '\n'));
if (checkOnly) assert.deepEqual(readdirSync(dir).filter(name => name !== '.gitattributes').sort(), [...assets.keys()].sort());

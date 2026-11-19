import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const FRAME_SIZE = 1024 * 1024; // 1 MiB frames per Architecture 4.2
const FRAME_COUNT = 128; // 128 MiB total synthetic payload
const TOTAL_BYTES = FRAME_SIZE * FRAME_COUNT;

const collectionKey = randomBytes(32);
const salt = randomBytes(32);
const keyId = randomBytes(16);
const vaultId = randomBytes(16);
const recordKey = Buffer.from(
  hkdfSync('sha256', collectionKey, salt, Buffer.from('foundry/record-key/v1', 'utf8'), 32),
);

// Build 69-byte FVR1 record header per Architecture 4.2
const header = Buffer.alloc(69);
header.write('FVR1', 0, 'ascii');
header.writeUInt8(2, 4); // blob type
keyId.copy(header, 5);
salt.copy(header, 21);
header.writeBigUInt64BE(0n, 53); // ctx = 0 for blobs
header.writeBigUInt64BE(BigInt(TOTAL_BYTES), 61);

const plainFrame = Buffer.alloc(FRAME_SIZE, 0x5a);
const nonce = Buffer.alloc(12, 0);
const aad = Buffer.alloc(69 + 16 + 8 + 1);
header.copy(aad, 0);
vaultId.copy(aad, 69);

const plainHash = createHash('sha256');
const roundtripHash = createHash('sha256');

let encryptNs = 0n;
let decryptNs = 0n;

const totalStart = performance.now();

for (let i = 0; i < FRAME_COUNT; i++) {
  // Mutate the first 4 bytes per frame so every frame has distinct content.
  plainFrame.writeUInt32BE(i, 0);
  plainHash.update(plainFrame);

  nonce.writeBigUInt64BE(BigInt(i), 4);
  aad.writeBigUInt64BE(BigInt(i), 85);
  aad.writeUInt8(i === FRAME_COUNT - 1 ? 1 : 0, 93);

  const encStart = process.hrtime.bigint();
  const cipher = createCipheriv('aes-256-gcm', recordKey, nonce);
  cipher.setAAD(aad);
  const ct1 = cipher.update(plainFrame);
  const ct2 = cipher.final();
  const tag = cipher.getAuthTag();
  encryptNs += process.hrtime.bigint() - encStart;

  const decStart = process.hrtime.bigint();
  const decipher = createDecipheriv('aes-256-gcm', recordKey, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const pt1 = decipher.update(ct1);
  const pt2 = ct2.length > 0 ? decipher.update(ct2) : Buffer.alloc(0);
  const pt3 = decipher.final();
  decryptNs += process.hrtime.bigint() - decStart;

  roundtripHash.update(pt1);
  if (pt2.length > 0) roundtripHash.update(pt2);
  if (pt3.length > 0) roundtripHash.update(pt3);
}

const totalMs = performance.now() - totalStart;
const expectedDigest = plainHash.digest('hex');
const actualDigest = roundtripHash.digest('hex');
if (expectedDigest !== actualDigest) {
  throw new Error(`Round-trip SHA-256 mismatch: ${expectedDigest} !== ${actualDigest}`);
}

const encryptMs = Number(encryptNs) / 1e6;
const decryptMs = Number(decryptNs) / 1e6;
const totalMiB = TOTAL_BYTES / (1024 * 1024);
const ru = process.resourceUsage();

console.log(JSON.stringify({
  benchmark: 'stream-encrypt-aes-256-gcm',
  payloadMiB: totalMiB,
  frameSizeKiB: FRAME_SIZE / 1024,
  frameCount: FRAME_COUNT,
  roundtripVerified: true,
  encryptMs: Number(encryptMs.toFixed(2)),
  encryptMiBPerSec: Number((totalMiB / (encryptMs / 1000)).toFixed(2)),
  decryptMs: Number(decryptMs.toFixed(2)),
  decryptMiBPerSec: Number((totalMiB / (decryptMs / 1000)).toFixed(2)),
  totalWallMs: Number(totalMs.toFixed(2)),
  internalMaxRssKiB: ru.maxRSS,
  internalMaxRssMiB: Number((ru.maxRSS / 1024).toFixed(2)),
}));

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const FRAME_SIZE = 1024 * 1024; // 1 MiB frames per Architecture 4.2
const CHUNK_SIZE = 64 * 1024; // 64 KiB streaming slices keep V8 external buffer churn flat
const FRAME_COUNT = 128; // 128 MiB total synthetic payload
const TOTAL_PLAINTEXT_BYTES = FRAME_SIZE * FRAME_COUNT;
const FRAME_OVERHEAD = 4 + 16; // u32 BE ciphertext_len + 16-byte GCM tag
const EXPECTED_TOTAL_LEN = BigInt(FRAME_COUNT) * BigInt(FRAME_SIZE + FRAME_OVERHEAD);

const collectionKey = randomBytes(32);
const salt = randomBytes(32);
const keyId = randomBytes(16);
const vaultId = randomBytes(16);
const recordKey = Buffer.from(
  hkdfSync('sha256', collectionKey, salt, Buffer.from('foundry/record-key/v1', 'utf8'), 32),
);

// Build 69-byte FVR1 record header per Architecture 4.2:
// total_len (offset 61..68) is bytes from offset 69 to end of record.
const header = Buffer.alloc(69);
header.write('FVR1', 0, 'ascii');
header.writeUInt8(2, 4); // blob type
keyId.copy(header, 5);
salt.copy(header, 21);
header.writeBigUInt64BE(0n, 53); // ctx = 0 for blobs
header.writeBigUInt64BE(EXPECTED_TOTAL_LEN, 61);

const plainFrame = Buffer.alloc(FRAME_SIZE, 0x5a);
const encodedFrame = Buffer.allocUnsafe(FRAME_SIZE + FRAME_OVERHEAD);
const nonce = Buffer.alloc(12, 0);
const aad = Buffer.alloc(69 + 16 + 8 + 1);
header.copy(aad, 0);
vaultId.copy(aad, 69);

const plainHash = createHash('sha256');
const roundtripHash = createHash('sha256');

let encryptNs = 0n;
let decryptNs = 0n;
let totalEncodedBytes = 0;

const totalStart = performance.now();

for (let i = 0; i < FRAME_COUNT; i++) {
  plainFrame.writeUInt32BE(i, 0);
  plainHash.update(plainFrame);

  nonce.writeBigUInt64BE(BigInt(i), 4);
  aad.writeBigUInt64BE(BigInt(i), 85);
  aad.writeUInt8(i === FRAME_COUNT - 1 ? 1 : 0, 93);

  const encStart = process.hrtime.bigint();
  const cipher = createCipheriv('aes-256-gcm', recordKey, nonce);
  cipher.setAAD(aad);
  let encPos = 4;
  for (let off = 0; off < FRAME_SIZE; off += CHUNK_SIZE) {
    const out = cipher.update(plainFrame.subarray(off, off + CHUNK_SIZE));
    out.copy(encodedFrame, encPos);
    encPos += out.length;
  }
  const ctFinal = cipher.final();
  if (ctFinal.length > 0) {
    ctFinal.copy(encodedFrame, encPos);
    encPos += ctFinal.length;
  }
  const ctLen = encPos - 4;
  encodedFrame.writeUInt32BE(ctLen, 0);
  const tag = cipher.getAuthTag();
  tag.copy(encodedFrame, encPos);
  encryptNs += process.hrtime.bigint() - encStart;

  totalEncodedBytes += 4 + ctLen + tag.length;

  const decStart = process.hrtime.bigint();
  const parsedCtLen = encodedFrame.readUInt32BE(0);
  const parsedTag = encodedFrame.subarray(4 + parsedCtLen, 4 + parsedCtLen + 16);
  const decipher = createDecipheriv('aes-256-gcm', recordKey, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(parsedTag);
  for (let off = 0; off < parsedCtLen; off += CHUNK_SIZE) {
    const pt = decipher.update(encodedFrame.subarray(4 + off, 4 + Math.min(off + CHUNK_SIZE, parsedCtLen)));
    if (pt.length > 0) roundtripHash.update(pt);
  }
  const ptFinal = decipher.final();
  if (ptFinal.length > 0) roundtripHash.update(ptFinal);
  decryptNs += process.hrtime.bigint() - decStart;
}

// Verify 1-bit tamper on the serialized frame fails authentication.
let tamperRejected = false;
const tamperedFrame = Buffer.from(encodedFrame);
tamperedFrame[tamperedFrame.length - 1] ^= 0x01;
const tamperCtLen = tamperedFrame.readUInt32BE(0);
const tamperDecipher = createDecipheriv('aes-256-gcm', recordKey, nonce);
tamperDecipher.setAAD(aad);
tamperDecipher.setAuthTag(tamperedFrame.subarray(4 + tamperCtLen, 4 + tamperCtLen + 16));
try {
  tamperDecipher.update(tamperedFrame.subarray(4, 4 + tamperCtLen));
  tamperDecipher.final();
} catch {
  tamperRejected = true;
}
if (!tamperRejected) {
  throw new Error('Tampered FVR1 frame passed GCM authentication.');
}

const totalMs = performance.now() - totalStart;
const headerTotalLen = header.readBigUInt64BE(61);
if (BigInt(totalEncodedBytes) !== headerTotalLen) {
  throw new Error(`Encoded record length ${totalEncodedBytes} !== header total_len ${headerTotalLen}`);
}

const expectedDigest = plainHash.digest('hex');
const actualDigest = roundtripHash.digest('hex');
if (expectedDigest !== actualDigest) {
  throw new Error(`Round-trip SHA-256 mismatch: ${expectedDigest} !== ${actualDigest}`);
}

const encryptMs = Number(encryptNs) / 1e6;
const decryptMs = Number(decryptNs) / 1e6;
const totalMiB = TOTAL_PLAINTEXT_BYTES / (1024 * 1024);
const ru = process.resourceUsage();

console.log(JSON.stringify({
  benchmark: 'stream-encrypt-aes-256-gcm',
  payloadMiB: totalMiB,
  encodedRecordBodyBytes: totalEncodedBytes,
  headerTotalLen: Number(headerTotalLen),
  frameSizeKiB: FRAME_SIZE / 1024,
  chunkSizeKiB: CHUNK_SIZE / 1024,
  frameCount: FRAME_COUNT,
  roundtripVerified: true,
  tamperRejected,
  encryptMs: Number(encryptMs.toFixed(2)),
  encryptMiBPerSec: Number((totalMiB / (encryptMs / 1000)).toFixed(2)),
  decryptMs: Number(decryptMs.toFixed(2)),
  decryptMiBPerSec: Number((totalMiB / (decryptMs / 1000)).toFixed(2)),
  totalWallMs: Number(totalMs.toFixed(2)),
  internalMaxRssKiB: ru.maxRSS,
  internalMaxRssMiB: Number((ru.maxRSS / 1024).toFixed(2)),
}));

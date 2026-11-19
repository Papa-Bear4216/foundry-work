import { randomBytes, scryptSync } from 'node:crypto';
import { performance } from 'node:perf_hooks';

const N = 131072; // 2^17 per Architecture 5.2
const r = 8;
const p = 1;
const keylen = 32;
const maxmem = 256 * 1024 * 1024;
const iterations = 3;

const passphrase = Buffer.from('foundry-v0-synthetic-passphrase-for-measurement', 'utf8');
const timingsMs = [];
let digestHex = '';

for (let i = 0; i < iterations; i++) {
  const salt = randomBytes(32);
  const t0 = performance.now();
  const key = scryptSync(passphrase, salt, keylen, { N, r, p, maxmem });
  const elapsed = performance.now() - t0;
  timingsMs.push(Number(elapsed.toFixed(2)));
  if (key.length !== keylen) {
    throw new Error(`Unexpected derived key length: ${key.length}`);
  }
  digestHex = key.subarray(0, 4).toString('hex');
}

const sorted = [...timingsMs].sort((a, b) => a - b);
const ru = process.resourceUsage();

console.log(JSON.stringify({
  benchmark: 'kdf-scrypt',
  params: { N, r, p, keylen, maxmem },
  iterations,
  timingsMs,
  minMs: sorted[0],
  medianMs: sorted[Math.floor(sorted.length / 2)],
  maxMs: sorted[sorted.length - 1],
  internalMaxRssKiB: ru.maxRSS,
  internalMaxRssMiB: Number((ru.maxRSS / 1024).toFixed(2)),
  samplePrefix: digestHex,
}));

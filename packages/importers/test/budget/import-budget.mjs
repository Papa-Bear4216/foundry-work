import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import {
  encodeKeyring,
  initializeVault,
  signingPublicKey,
  verifyVault,
} from '../../../vault/codec/dist/index.js';
import { writeSyntheticLargeMboxZip } from '../../dist/index.js';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3', `Expected pinned Node 24.22.3, got ${process.versions.node}`);

const CEILING_MIB = 256;
const TARGET_BYTES = 1024 * 1024 * 1024; // 1 GiB synthetic mbox

function cleanup(dir) {
  const segments = join(dir, 'vault', 'segments');
  if (existsSync(segments)) {
    for (const seg of readdirSync(segments, { withFileTypes: true })) {
      const segPath = join(segments, seg.name);
      if (!seg.isDirectory()) continue;
      chmodSync(segPath, 0o700);
      for (const f of readdirSync(segPath, { withFileTypes: true })) {
        if (f.isFile()) chmodSync(join(segPath, f.name), 0o600);
      }
    }
  }
  rmSync(dir, { recursive: true, force: true });
}

const root = mkdtempSync(join(tmpdir(), 'foundry-v5-1gib-budget-'));
try {
  const zipPath = join(root, 'synthetic-1gib-mail.zip');
  const vaultDir = join(root, 'vault');
  const passphrase = 'TEST ONLY v5 1GiB budget passphrase';

  const genStart = performance.now();
  const generated = await writeSyntheticLargeMboxZip(zipPath, {
    targetBytes: TARGET_BYTES,
    seed: 20261121,
    minMessageBytes: 192 * 1024,
    maxMessageBytes: 320 * 1024,
    compression: 'deflate',
  });
  const genMs = Math.round(performance.now() - genStart);
  assert.ok(generated.uncompressedBytes >= TARGET_BYTES);
  console.log(
    `generated 1 GiB synthetic mbox zip: ${generated.messageCount} messages, ` +
      `${generated.uncompressedBytes} uncompressed bytes, ${generated.compressedBytes} compressed bytes (${genMs} ms)`,
  );

  // Prepare V-2/V-3 vault
  const vaultId = randomBytes(16).toString('hex');
  const createdAt = '2026-11-21T00:00:00Z';
  const masterKey = randomBytes(32);
  const signingSeed = randomBytes(32);
  const recoveryKey = randomBytes(32);
  const profileKeyId = randomBytes(16).toString('hex');
  const profileKey = randomBytes(32);
  const collectionKeyId = randomBytes(16).toString('hex');
  const collectionKey = randomBytes(32);

  const keyringBytes = encodeKeyring(
    {
      vaultId,
      version: 1,
      masterKey,
      entries: [
        { key_id: randomBytes(16).toString('hex'), kind: 'signing', parent: 'master', state: 'active', created_at: createdAt, key: signingSeed },
        { key_id: profileKeyId, kind: 'profile', parent: 'master', state: 'active', created_at: createdAt, key: profileKey, label: 'me' },
        { key_id: collectionKeyId, kind: 'collection', parent: profileKeyId, state: 'active', created_at: createdAt, key: collectionKey },
      ],
    },
    passphrase,
    recoveryKey,
  );
  mkdirSync(join(vaultDir, 'keyring'), { recursive: true });
  writeFileSync(join(vaultDir, 'keyring', 'keyring.json'), keyringBytes);
  initializeVault(vaultDir, { vaultId, createdAt, signingPublicKey: signingPublicKey(signingSeed) });

  const probeScript = fileURLToPath(new URL('./import-probe.mjs', import.meta.url));
  const measured = measurePeakRss(probeScript, [zipPath, vaultDir, vaultId, collectionKeyId], root, passphrase);
  assert.equal(measured.status, 0, measured.stderr);

  const { wallMs, peakRssKiB, summary } = JSON.parse(measured.stdout);
  const externalPeakKiB = Math.round(measured.externalPeakKiB);
  const worstKiB = Math.max(peakRssKiB, externalPeakKiB);
  const worstMiB = (worstKiB / 1024).toFixed(2);

  assert.equal(summary.totalItemsImported, generated.messageCount);
  assert.equal(summary.totalBlobsWritten, generated.messageCount);
  assert.equal(summary.totalBytesStored, generated.uncompressedBytes);

  // Verify the resulting multi-segment sealed vault without secrets
  const verified = verifyVault(vaultDir);
  assert.equal(verified.position.lastEventSequence, generated.messageCount);
  assert.ok(verified.position.segment >= 2, `expected >=2 sealed segments for 1 GiB import, got ${verified.position.segment}`);

  console.log(
    `import 1 GiB synthetic mbox: wall=${wallMs} ms, internalPeak=${peakRssKiB} KiB, ` +
      `externalOsPeak=${externalPeakKiB} KiB, worst=${worstMiB} MiB (ceiling ${CEILING_MIB} MiB), ` +
      `segments=${verified.position.segment}, events=${verified.position.lastEventSequence}`,
  );
  assert.ok(
    worstKiB <= CEILING_MIB * 1024,
    `1 GiB mbox import exceeded ${CEILING_MIB} MiB peak RSS ceiling (worst=${worstMiB} MiB).`,
  );
} finally {
  cleanup(root);
}

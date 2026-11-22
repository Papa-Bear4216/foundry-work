import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { readVaultRecord, unlockByPassphrase, VaultWriter } from '../../../vault/codec/dist/index.js';
import { importArchive, mailImporter, openArchive } from '../../dist/index.js';

const [zipPath, vaultDir, vaultId, collectionKeyId] = process.argv.slice(2);
const passphrase = readFileSync(0, 'utf8');

const t0 = performance.now();
const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);
const archive = await openArchive(zipPath);
const writer = VaultWriter.open(vaultDir, unlocked);

let summary;
try {
  summary = await importArchive({
    archive,
    writer,
    importers: [mailImporter],
    resolveCollectionKeyId: () => collectionKeyId,
    vaultDir,
    unlocked,
    readVaultRecord,
    batchMaxItems: 16,
    batchMaxBytes: 4 * 1024 * 1024,
    closeSegmentOnFinish: true,
  });
} finally {
  writer.release();
  await archive.close();
}

const wallMs = Math.round(performance.now() - t0);
const peakRssKiB = process.resourceUsage().maxRSS;
process.stdout.write(JSON.stringify({ wallMs, peakRssKiB, summary }));

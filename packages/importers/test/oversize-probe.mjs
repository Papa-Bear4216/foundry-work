import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readVaultRecord, unlockByPassphrase, VaultWriter } from '../../vault/codec/dist/index.js';
import { importArchive, mailImporter, openArchive } from '../dist/index.js';

const [zipPath, vaultDir, vaultId, collectionKeyId] = process.argv.slice(2);
const passphrase = readFileSync(0, 'utf8');

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
    closeSegmentOnFinish: true,
  });
} finally {
  writer.release();
  await archive.close();
}

const peakRssKiB = process.resourceUsage().maxRSS;
process.stdout.write(JSON.stringify({ peakRssKiB, summary }));

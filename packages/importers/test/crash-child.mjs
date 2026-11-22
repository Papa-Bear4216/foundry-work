import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readVaultRecord, unlockByPassphrase, VaultWriter } from '../../vault/codec/dist/index.js';
import { DEFAULT_IMPORTERS, importArchive, openArchive } from '../dist/index.js';

const [archiveDir, vaultDir, vaultId, collectionKeyId, crashAtRaw] = process.argv.slice(2);
const crashAt = Number.parseInt(crashAtRaw, 10);
const passphrase = readFileSync(0, 'utf8');

const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);
const archive = await openArchive(archiveDir);
const writer = VaultWriter.open(vaultDir, unlocked);

try {
  const result = await importArchive({
    archive,
    writer,
    importers: DEFAULT_IMPORTERS,
    resolveCollectionKeyId: () => collectionKeyId,
    vaultDir,
    unlocked,
    readVaultRecord,
    closeSegmentOnFinish: crashAt === 0,
    checkpoint:
      crashAt > 0
        ? (point, info) => {
            if (point === 'after-blob-before-event' && info.itemIndex === crashAt) {
              // Simulate an immediate crash before event write or writer.release().
              process.exit(42);
            }
          }
        : undefined,
  });
  process.stdout.write(JSON.stringify(result));
} finally {
  writer.release();
  await archive.close();
}

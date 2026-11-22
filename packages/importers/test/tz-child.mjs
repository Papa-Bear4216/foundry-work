import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { readVaultRecord, unlockByPassphrase, VaultWriter } from '../../vault/codec/dist/index.js';
import { DEFAULT_IMPORTERS, importArchive, openArchive } from '../dist/index.js';

const [archivePath, vaultDir, vaultId, collectionKeyId] = process.argv.slice(2);
const passphrase = readFileSync(0, 'utf8');

const unlocked = unlockByPassphrase(join(vaultDir, 'keyring', 'keyring.json'), vaultId, passphrase);
const archive = await openArchive(archivePath);
const writer = VaultWriter.open(vaultDir, unlocked);

let summary;
try {
  summary = await importArchive({
    archive,
    writer,
    importers: DEFAULT_IMPORTERS,
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

const collections = [];
const scanDir = (dir, segment) => {
  if (!existsSync(dir)) return;
  for (const stream of readdirSync(dir).filter(f => f.startsWith('events-') && f.endsWith('.fvr')).sort()) {
    const size = statSync(join(dir, stream)).size;
    let offset = 0;
    while (offset < size) {
      const rec = readVaultRecord(vaultDir, { segment, stream, offset }, unlocked);
      const ev = JSON.parse(rec.plaintext.toString('utf8'));
      collections.push({ path: ev.body.path, collection: ev.collection, sourceTs: ev.body.source_ts });
      const plainLen = rec.plaintext.length;
      const frames = plainLen === 0 ? 1 : Math.ceil(plainLen / 1_048_576);
      offset += 69 + plainLen + frames * 20;
    }
  }
};

const segDir = join(vaultDir, 'segments');
let maxSeg = 0;
if (existsSync(segDir)) {
  for (const seg of readdirSync(segDir).sort()) {
    maxSeg = Number.parseInt(seg, 10);
    scanDir(join(segDir, seg), maxSeg);
  }
}
scanDir(join(vaultDir, 'open'), maxSeg + 1);

process.stdout.write(JSON.stringify({ tz: process.env.TZ ?? null, summary, collections }));

// TEST ONLY: one measured step of the P-3 second-copy budgets, run in its own process (see second-copy-budgets.mjs).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  decodeKeyring, exportVaultIso, initSecondCopy, openSecondCopySession, unlockVault, VaultWriter, verifyVault,
} from '../dist/index.js';
import { getKdfCallCountForTest, resetKdfCallCountForTest } from '../dist/keyring.js';

const command = process.argv[2];
const root = process.cwd();
const MiB = 1024 * 1024;
const cases = JSON.parse(readFileSync(new URL('./vectors/cases.json', import.meta.url)));
const credential = { recoveryKey: Buffer.from(cases.recovery_key, 'hex') };
const vault = join(root, 'vault');
const drive = join(root, 'drive');
const ntfs = () => ({ type: 'ntfs', method: 'injected' });
const copyId = 'a1'.repeat(16);
const unlock = () => decodeKeyring(readFileSync(join(vault, 'keyring', 'keyring.json')), credential, cases.metadata.vault_id);

if (command === 'prepare') {
  // Not measured: a 256 MiB blob in the open segment, and an empty second copy.
  const unlocked = unlock();
  const writer = VaultWriter.open(vault, unlocked);
  try {
    writer.appendBatch([{ type: 'blob', keyId: cases.ids.collection, plaintext: Buffer.alloc(256 * MiB, 0x42) }]);
  } finally {
    writer.release();
  }
  initSecondCopy(vault, drive, { probe: ntfs, copyId });
} else if (command === 'seal') {
  // Keyed, as `foundry vault seal` runs it: one passphrase unlock (production scrypt settings, one KDF run), then
  // close the open segment, copy it, re-hash it and copy the keyring.
  resetKdfCallCountForTest();
  const unlockSession = unlockVault(join(vault, 'keyring', 'keyring.json'), cases.metadata.vault_id, { passphrase: cases.passphrase });
  const session = openSecondCopySession(vault, drive, { probe: ntfs, copyId });
  let result;
  try {
    result = session.seal(decodeKeyring(readFileSync(join(vault, 'keyring', 'keyring.json')), { session: unlockSession }, cases.metadata.vault_id));
  } finally {
    session.release();
    unlockSession.dispose();
  }
  assert.equal(getKdfCallCountForTest(), 1);
  assert.ok(result.bytesCopied > 256 * MiB);
  console.log(JSON.stringify({ bytes: result.bytesCopied, kdf: 1, peakRssKiB: process.resourceUsage().maxRSS }));
} else if (command === 'session-check') {
  // Keyless steps 1 to 3 on a drive that already holds the 256 MiB segment.
  const session = openSecondCopySession(vault, drive, { probe: ntfs, copyId, recorded: null });
  session.release();
  assert.equal(verifyVault(drive, { secondCopy: true }).position.segment, session.report.driveHead.segment);
  console.log(JSON.stringify({ bytes: 0, peakRssKiB: process.resourceUsage().maxRSS }));
} else if (command === 'prepare-many') {
  // Not measured: a long history, 50 sealed segments of one event and one 64 KiB blob each (finding 29, R18-7).
  const many = join(root, 'many');
  const unlocked = decodeKeyring(readFileSync(join(many, 'keyring', 'keyring.json')), credential, cases.metadata.vault_id);
  const writer = VaultWriter.open(many, unlocked);
  try {
    for (let segment = 0; segment < 50; segment++) {
      writer.appendBatch([
        { type: 'event', keyId: cases.ids.collection, event: { kind: 'vault.created', body: { marker: `TEST ONLY ${segment}` } } },
        { type: 'blob', keyId: cases.ids.collection, plaintext: Buffer.alloc(64 * 1024, segment) },
      ]);
      writer.closeSegment();
    }
  } finally {
    writer.release();
  }
} else if (command === 'export-many') {
  // Keyless: the export of the 50-segment history (manifests are held until the image is written).
  const result = exportVaultIso(join(root, 'many'), join(root, 'many.iso'));
  assert.equal(result.segments, 50);
  console.log(JSON.stringify({ bytes: result.imageBytes, segments: result.segments, peakRssKiB: process.resourceUsage().maxRSS }));
} else if (command === 'export-iso') {
  const result = exportVaultIso(vault, join(root, 'vault.iso'));
  assert.ok(result.imageBytes > 256 * MiB);
  console.log(JSON.stringify({ bytes: result.imageBytes, peakRssKiB: process.resourceUsage().maxRSS }));
} else {
  throw new Error('TEST ONLY: unknown probe command');
}

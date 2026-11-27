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
  initSecondCopy(vault, drive, { probe: ntfs });
} else if (command === 'seal') {
  // Keyed, as oundry vault seal runs it: one passphrase unlock (production scrypt settings, one KDF run), then
  // close the open segment, copy it, re-hash it and copy the keyring.
  resetKdfCallCountForTest();
  const unlockSession = unlockVault(join(vault, 'keyring', 'keyring.json'), cases.metadata.vault_id, { passphrase: cases.passphrase });
  const session = openSecondCopySession(vault, drive, { probe: ntfs });
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
  const session = openSecondCopySession(vault, drive, { probe: ntfs, recorded: null });
  session.release();
  assert.equal(verifyVault(drive).position.segment, session.report.driveHead.segment);
  console.log(JSON.stringify({ bytes: 0, peakRssKiB: process.resourceUsage().maxRSS }));
} else if (command === 'export-iso') {
  const result = exportVaultIso(vault, join(root, 'vault.iso'));
  assert.ok(result.imageBytes > 256 * MiB);
  console.log(JSON.stringify({ bytes: result.imageBytes, peakRssKiB: process.resourceUsage().maxRSS }));
} else {
  throw new Error('TEST ONLY: unknown probe command');
}

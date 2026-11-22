import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { decodeKeyring, openVaultReplay, retireIndexKey, stageIndexKey, unlockVault } from '../dist/index.js';
import { getKdfCallCountForTest, resetKdfCallCountForTest } from '../dist/keyring.js';

const mode = process.argv[2];
const MiB = 1024 * 1024;
const cases = JSON.parse(readFileSync(new URL('./vectors/cases.json', import.meta.url)));
const vaultId = cases.metadata.vault_id;
const passphrase = cases.passphrase;
const keyringPath = 'keyring/keyring.json';
const oldIndexId = cases.ids.index;
const newIndexId = 'ab'.repeat(16);

assert.ok(mode === 'session' || mode === 'credential', `Unknown mode: ${mode}`);
resetKdfCallCountForTest();
const start = performance.now();

function runWorkload(credential) {
  const decoded = decodeKeyring(readFileSync(keyringPath), credential, vaultId);
  decoded.masterKey.fill(0);
  for (const key of decoded.keys.values()) key.fill(0);

  let blobs = 0;
  let encodedBytes = 0;
  const source = openVaultReplay('.', credential);
  try {
    assert.equal(source.skipped, 0);
    for (const item of source.replay({ withdrawalsOnly: true })) assert.fail(item.type);
    for (const item of source.replay()) {
      assert.equal(item.type, 'blob');
      blobs++;
      encodedBytes += item.location.encodedLength;
    }
    assert.equal(source.boundary.sealed.segment, 3);
    assert.equal(blobs, 66);
    assert.ok(encodedBytes > 1024 * MiB);
  } finally {
    source.close();
  }

  const staged = stageIndexKey(keyringPath, vaultId, credential, newIndexId);
  staged.fill(0);
  retireIndexKey(keyringPath, vaultId, credential, oldIndexId);
  return { blobs, encodedBytes };
}

let stats;
if (mode === 'session') {
  const session = unlockVault(keyringPath, vaultId, { passphrase });
  try {
    stats = runWorkload({ session });
  } finally {
    session.dispose();
  }
  assert.equal(getKdfCallCountForTest(), 1);
} else {
  stats = runWorkload({ passphrase });
  assert.equal(getKdfCallCountForTest(), 4);
}

console.log(JSON.stringify({
  mode,
  kdfCalls: getKdfCallCountForTest(),
  ms: Math.round(performance.now() - start),
  ...stats,
  peakRssKiB: process.resourceUsage().maxRSS,
}));

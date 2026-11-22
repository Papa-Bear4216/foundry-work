import assert from 'node:assert/strict';
import { readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  readSecretFromFd, unlockByPassphrase, unlockByRecovery, VaultWriter, verifyVault, verifyVaultDeep,
} from '../dist/index.js';

const [command] = process.argv.slice(2);
const directory = '.';
const keyring = join(directory, 'keyring', 'keyring.json');
const MiB = 1024 * 1024;

function appendFixture(writer, keyId) {
  const data = Buffer.alloc(65 * MiB, 0x55);
  const [oversized] = writer.appendBatch([{ type: 'blob', keyId, plaintext: data }]);
  assert.deepEqual(oversized.location, { segment: 1, stream: 'pack-0001.fvr', offset: 0 });
  // TEST ONLY: distinct lengths make the writer store more than a GiB of actual records.
  for (let i = 0; i < 65; i++) {
    const [result] = writer.appendBatch([{ type: 'blob', keyId, plaintext: data.subarray(0, 16 * MiB + i) }]);
    const segment = i < 27 ? 1 : Math.floor((i - 27) / 31) + 2;
    const file = i < 27 ? Math.floor(i / 3) + 2 : Math.floor((i - 27) % 31 / 3) + 1;
    assert.equal(result.duplicate, false);
    assert.deepEqual([result.location.segment, result.location.stream],
      [segment, 'pack-' + String(file).padStart(4, '0') + '.fvr']);
  }
  assert.equal(readdirSync(join(directory, 'segments')).length, 2);
  const first = join(directory, 'segments', '000001');
  const streams = readdirSync(first).filter(file => file.endsWith('.fvr')).sort();
  assert.equal(streams.length, 10);
  assert.equal(statSync(join(first, streams[0])).size, 65 * MiB + 65 * 20 + 69);
  for (const stream of streams.slice(1)) assert.ok(statSync(join(first, stream)).size <= 64 * MiB);
}

if (command === 'verify') {
  assert.equal(verifyVault(directory).position.segment, 3);
} else {
  const input = JSON.parse(readSecretFromFd());
  const unlocked = command === 'verify-deep'
    ? unlockByPassphrase(keyring, input.vaultId, input.passphrase)
    : unlockByRecovery(keyring, input.vaultId, input.recovery);
  try {
    if (command === 'verify-deep') {
      assert.equal(verifyVaultDeep(directory, unlocked).position.segment, 3);
    } else {
      const writer = VaultWriter.open(directory, unlocked);
      try {
        if (command === 'append') {
          appendFixture(writer, input.keyId);
        } else if (command === 'close') {
          assert.equal(writer.closeSegment().segment, 3);
        } else {
          throw new Error('Unknown vault probe operation.');
        }
      } finally {
        writer.release();
      }
    }
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}
console.log(JSON.stringify({ command, peakRssKiB: process.resourceUsage().maxRSS }));

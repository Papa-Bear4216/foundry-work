import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeKeyring, openVaultReplay, VaultWriter } from '../dist/index.js';

const command = process.argv[2];
const MiB = 1024 * 1024;
const cases = JSON.parse(readFileSync(new URL('./vectors/cases.json', import.meta.url)));
const credential = { recoveryKey: Buffer.from(cases.recovery_key, 'hex') };

if (command === 'prepare-large-blob') {
  // Fixture creation uses the existing writer in a separate process from the measured replay.
  const unlocked = decodeKeyring(readFileSync('keyring/keyring.json'), credential, cases.metadata.vault_id);
  const writer = VaultWriter.open('.', unlocked);
  try {
    writer.appendBatch([{ type: 'blob', keyId: cases.ids.collection, plaintext: Buffer.alloc(256 * MiB, 0x42) }]);
  } finally {
    writer.release();
  }
} else {
  const source = openVaultReplay('.', credential);
  try {
    assert.equal(source.skipped, 0);
    let blobs = 0;
    let encodedBytes = 0;
    for (const item of source.replay({ withdrawalsOnly: true })) assert.fail(item.type);
    for (const item of source.replay()) {
      assert.equal(item.type, 'blob');
      blobs++;
      encodedBytes += item.location.encodedLength;
      if (command === 'large-blob') {
        const expected = Buffer.alloc(MiB, 0x42);
        let frames = 0;
        for (const chunk of source.streamBlob(item.location)) {
          assert.ok(chunk.equals(expected));
          frames++;
        }
        assert.equal(frames, 256);
      }
    }
    if (command === 'large-blob') {
      assert.equal(blobs, 1);
      assert.equal(encodedBytes, 256 * MiB + 256 * 20 + 69);
    } else {
      assert.equal(command, 'existing-fixture');
      assert.equal(source.boundary.sealed.segment, 3);
      assert.equal(blobs, 66);
      assert.ok(encodedBytes > 1024 * MiB);
    }
    console.log(JSON.stringify({ blobs, encodedBytes, peakRssKiB: process.resourceUsage().maxRSS }));
  } finally {
    source.close();
  }
}

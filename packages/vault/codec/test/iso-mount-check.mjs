// TEST ONLY: `make <dir>` builds a synthetic vault with two sealed segments and a multi-extent file, exports it to
// `<dir>/export.iso` and prints the sealed head hash. `verify <folder> <hash>` runs the keyless vault check on a
// mounted (or extracted) image and compares the head. CI mounts the image with the Linux kernel's ISO 9660 driver.
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { exportVaultIso, VaultWriter, verifyVault } from '../dist/index.js';
import { blob, event, fixture } from './vault-fixture.mjs';

const [command, folder, expected] = process.argv.slice(2);
if (command === 'make') {
  const vault = join(folder, 'vault');
  mkdirSync(vault, { recursive: true });
  const writer = VaultWriter.open(vault, fixture(vault));
  try {
    writer.appendBatch([event('TEST ONLY iso one'), blob('TEST ONLY iso blob'.repeat(50000))]);
    writer.closeSegment();
    writer.appendBatch([event('TEST ONLY iso two'), { ...blob(''), plaintext: Buffer.alloc(9000, 1) }]);
    writer.closeSegment();
  } finally {
    writer.release();
  }
  // Small extents so the kernel reader also sees multi-extent files (the 4 GiB rule, scaled down).
  const result = exportVaultIso(vault, join(folder, 'export.iso'), { maxExtentBytes: 4096 });
  process.stdout.write(`${result.head.hash}\n`);
} else if (command === 'verify') {
  const verified = verifyVault(folder);
  assert.equal(verified.position.segment, 2);
  assert.equal(verified.position.hash, expected);
  process.stdout.write(`verified segment ${verified.position.segment} ${verified.position.hash}\n`);
} else {
  throw new Error('TEST ONLY: usage: iso-mount-check.mjs make <dir> | verify <folder> <hash>');
}

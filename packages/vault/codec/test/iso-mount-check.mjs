// TEST ONLY: `make <dir>` builds a synthetic vault with two sealed segments and a multi-extent file, exports it to
// `<dir>/export.iso` and prints the sealed head hash. `verify <folder> <hash>` runs the keyless vault check on a
// mounted (or extracted) Joliet image and compares the head. `primary <folder> <dir>` checks every file of the
// Level 2 primary tree (mounted with `nojoliet,norock`) byte for byte against the source vault in `<dir>/vault`.
// CI mounts the image with the Linux kernel's ISO 9660 driver.
import assert from 'node:assert/strict';
import { mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { exportVaultIso, VaultWriter, verifyVault } from '../dist/second-copy-index.js';
import { blob, event, fixture } from './vault-fixture.mjs';

/**
 * Extents of 64 KiB: the large pack needs more than one (the 4 GiB multi-extent rule, scaled down) and fewer than
 * the 100 sections the Linux isofs reader accepts for one file.
 */
const EXTENT = 64 * 1024;

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
  const sizes = readdirSync(join(vault, 'segments', '000001')).map(name => statSync(join(vault, 'segments', '000001', name)).size);
  const sections = Math.ceil(Math.max(...sizes) / EXTENT);
  assert.ok(sections >= 2 && sections <= 100, `the largest file needs ${sections} sections`);
  const result = exportVaultIso(vault, join(folder, 'export.iso'), { maxExtentBytes: EXTENT });
  process.stdout.write(`${result.head.hash}\n`);
} else if (command === 'verify') {
  const verified = verifyVault(folder);
  assert.equal(verified.position.segment, 2);
  assert.equal(verified.position.hash, expected);
  process.stdout.write(`verified segment ${verified.position.segment} ${verified.position.hash}\n`);
} else if (command === 'primary') {
  // The kernel shows primary names in lower case without the `;1` version; `-` was mapped to `_` by the writer.
  const vault = join(expected, 'vault');
  let checked = 0;
  const wanted = [];
  const walk = relative => {
    for (const entry of readdirSync(join(vault, ...relative), { withFileTypes: true })) {
      // R19-9 (51): HEAD.json is compared too, like every other exported file.
      if (relative.length === 0 && !['VAULT.json', 'HEAD.json', 'segments'].includes(entry.name)) continue;
      const parts = [...relative, entry.name];
      if (entry.isDirectory()) {
        walk(parts);
        continue;
      }
      const mappedParts = parts.map(part => part.toLowerCase().replace(/-/gu, '_'));
      assert.deepEqual(readFileSync(join(folder, ...mappedParts)), readFileSync(join(vault, ...parts)), parts.join('/'));
      wanted.push(mappedParts.join('/'));
      checked++;
    }
  };
  walk([]);
  assert.ok(wanted.includes('head.json') && wanted.includes('vault.json'), JSON.stringify(wanted));
  // The primary tree holds exactly these files: nothing more (no keyring), nothing less.
  const found = [];
  const list = relative => {
    for (const entry of readdirSync(join(folder, ...relative), { withFileTypes: true })) {
      if (entry.isDirectory()) list([...relative, entry.name]);
      else found.push([...relative, entry.name].join('/'));
    }
  };
  list([]);
  assert.deepEqual(found.sort(), wanted.sort(), 'the primary-tree inventory');
  assert.ok(checked >= 10, `checked ${checked} primary-tree files`);
  process.stdout.write(`primary tree: ${checked} file(s) match the source\n`);
} else {
  throw new Error('TEST ONLY: usage: iso-mount-check.mjs make <dir> | verify <folder> <hash> | primary <folder> <dir>');
}

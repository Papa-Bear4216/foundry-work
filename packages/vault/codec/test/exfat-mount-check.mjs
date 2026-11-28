// TEST ONLY (R20-5, finding 53): a Mode B second copy on a real Linux exFAT mount. CI creates a small exFAT image,
// mounts it writable for the runner user, and runs `seal <folder> <work>`: a synthetic working vault in `<work>` gets
// `copy init` and two sessions onto `<folder>` (a subfolder of the mount; a volume root is refused), with the real
// file-system probe (no injection). It prints the compact anchor. After a read-only remount, `verify <folder>
// <anchor>` checks the copy keylessly against that anchor. Every vault, key and text is synthetic.
import assert from 'node:assert/strict';
import { mkdirSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  anchorPayload, initSecondCopy, openSecondCopySession, parseAnchor, probeFileSystem, VaultWriter, verifySecondCopy, verifyVault,
} from '../dist/second-copy-index.js';
import { blob, event, fixture } from './vault-fixture.mjs';

const COPY_ID = 'e5'.repeat(16);
const [command, folder, extra] = process.argv.slice(2);

function append(vault, unlocked, items) {
  const writer = VaultWriter.open(vault, unlocked);
  try {
    writer.appendBatch(items);
  } finally {
    writer.release();
  }
}

function session(vault, unlocked, target, recorded) {
  const opened = openSecondCopySession(vault, target, { copyId: COPY_ID, recorded });
  try {
    return opened.seal(unlocked);
  } finally {
    opened.release();
  }
}

if (command === 'seal') {
  const type = probeFileSystem(join(folder, '..')).type;
  assert.equal(type, 'exfat', `the mount is probed as ${type}`);
  const vault = join(extra, 'working');
  mkdirSync(vault, { recursive: true });
  const unlocked = fixture(vault);
  append(vault, unlocked, [event('TEST ONLY exfat one'), blob('TEST ONLY exfat blob'.repeat(2000))]);
  const init = initSecondCopy(vault, folder, { copyId: COPY_ID });
  assert.equal(init.fileSystem.type, 'exfat');
  const first = session(vault, unlocked, folder, null);
  assert.equal(first.head.segment, 1);
  // A second session re-checks and syncs the recorded segment on exFAT (phase 2), then copies segment 2.
  append(vault, unlocked, [event('TEST ONLY exfat two')]);
  const second = session(vault, unlocked, folder, first.head);
  assert.equal(second.head.segment, 2);
  for (const segment of ['000001', '000002']) {
    const path = join(folder, 'segments', segment);
    for (const name of readdirSync(path)) assert.equal(statSync(join(path, name)).mode & 0o222, 0, `${segment}/${name} read-only`);
  }
  process.stdout.write(`${anchorPayload(second.anchor)}\n`);
} else if (command === 'verify') {
  const anchor = parseAnchor(extra);
  const checked = verifySecondCopy(folder, { anchor });
  assert.deepEqual([checked.segment, checked.hash, checked.uncommitted], [anchor.segment, anchor.manifestHash, 0]);
  assert.equal(verifyVault(folder, { anchor, secondCopy: true }).position.segment, anchor.segment);
  process.stdout.write(`exFAT copy verified keylessly: segment ${checked.segment} ${checked.hash}\n`);
} else {
  throw new Error('TEST ONLY: usage: exfat-mount-check.mjs seal <folder> <work> | verify <folder> <anchor>');
}

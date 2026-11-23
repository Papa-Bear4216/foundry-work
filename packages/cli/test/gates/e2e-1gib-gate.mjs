// TEST ONLY: V-7 Phase 1 exit end-to-end gate (1 GiB synthetic multi-part Takeout archive, command line only).
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import {
  generateSyntheticIcalendar,
  generateSyntheticVcards,
  writeSyntheticLargeMboxZip,
  writeZipArchive,
} from 'importers';
import { cleanupDir, measureCliPeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3', `Expected pinned Node 24.22.3, got ${process.versions.node}`);

const TARGET_BYTES = process.env.CLI_GATE_TARGET_BYTES ? Number(process.env.CLI_GATE_TARGET_BYTES) : 1024 * 1024 * 1024;
const HEADROOM_FACTOR = 0.95;
const FAKE_CEILING = process.env.CLI_GATE_FAKE_CEILING_MIB ? Number(process.env.CLI_GATE_FAKE_CEILING_MIB) : undefined;
const PASSPHRASE = 'TEST ONLY e2e 1gib passphrase';
const NEEDLE = 'foundrye2eneedle9417';

function recordGate(step, measured, ceilingMiB) {
  const effectiveCeiling = FAKE_CEILING ?? ceilingMiB;
  const limit95KiB = Math.floor(effectiveCeiling * 1024 * HEADROOM_FACTOR);
  const peakMiB = Number((measured.externalPeakKiB / 1024).toFixed(2));
  const headroom95MiB = Number((effectiveCeiling * HEADROOM_FACTOR).toFixed(2));
  const overBudget = measured.externalPeakKiB > limit95KiB;
  const rec = {
    gate: 'cli-e2e-1gib',
    os: process.platform,
    step,
    externalPeakKiB: measured.externalPeakKiB,
    peakMiB,
    ceilingMiB: effectiveCeiling,
    headroom95MiB,
    wallMs: measured.wallMs,
    overBudget,
  };
  console.log(JSON.stringify(rec));
  return rec;
}

const root = mkdtempSync(join(tmpdir(), 'foundry-v7-e2e-1gib-'));
try {
  // Build a multi-part synthetic Takeout archive (contacts + calendar + 1 GiB mail).
  const archiveDir = join(root, 'takeout');
  mkdirSync(archiveDir, { recursive: true });

  const contacts = Buffer.concat([
    generateSyntheticVcards(10, 701),
    Buffer.from(
      [
        'BEGIN:VCARD',
        'VERSION:3.0',
        'FN:TEST ONLY E2E Contact',
        `NOTE:TEST ONLY synthetic search marker ${NEEDLE}`,
        'EMAIL:e2e-contact@synthetic.invalid',
        'END:VCARD',
        '',
      ].join('\r\n'),
      'utf8',
    ),
  ]);
  const calendar = generateSyntheticIcalendar(8, 702);

  await writeZipArchive(join(archiveDir, 'takeout-20261123T000000Z-001.zip'), [
    { path: 'Takeout/Contacts/All Contacts/All Contacts.vcf', data: contacts, compression: 'deflate' },
    { path: 'Takeout/Calendar/Synthetic.ics', data: calendar, compression: 'store' },
  ]);

  const mailStats = await writeSyntheticLargeMboxZip(join(archiveDir, 'takeout-20261123T000000Z-002.zip'), {
    targetBytes: TARGET_BYTES,
    seed: 20261123,
    minMessageBytes: 192 * 1024,
    maxMessageBytes: 320 * 1024,
    compression: 'deflate',
  });
  assert.ok(mailStats.uncompressedBytes >= TARGET_BYTES);
  console.log(JSON.stringify({
    gate: 'cli-e2e-fixture',
    os: process.platform,
    mailMessages: mailStats.messageCount,
    mailUncompressedBytes: mailStats.uncompressedBytes,
    mailCompressedBytes: mailStats.compressedBytes,
  }));

  // Command line only from here on (no library calls).
  const home = join(root, 'home');
  const records = [];

  // 1. foundry init
  const init = measureCliPeakRss(['init', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE + '\n' });
  assert.equal(init.status, 0, `e2e init failed: ${init.stderr}`);
  const recoveryMatch = /^\s{4}(\S+)$/mu.exec(init.stdout);
  assert.ok(recoveryMatch, 'init did not output recovery key');
  const recoveryKey = recoveryMatch[1];
  records.push(recordGate('init', init, 256));

  // 2. foundry import (1 GiB multi-part archive)
  const imp = measureCliPeakRss(['import', archiveDir, '--vault', home, '--passphrase-stdin', '--json'], {
    stdin: PASSPHRASE + '\n',
    timeoutMs: 900_000,
  });
  assert.equal(imp.status, 0, `e2e import failed: ${imp.stderr}`);
  const impSummary = JSON.parse(imp.stdout);
  assert.ok(impSummary.itemsAdded >= mailStats.messageCount + 10, `unexpected itemsAdded count: ${impSummary.itemsAdded}`);
  assert.equal(impSummary.partsCount, 2, 'expected 2 Takeout parts');
  records.push(recordGate('import-1gib', imp, 256));

  // 3. foundry search (before rebuild)
  const search1 = measureCliPeakRss(['search', NEEDLE, '--vault', home, '--recovery-key-stdin', '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(search1.status, 0, `e2e search 1 failed: ${search1.stderr}`);
  const { results: hits1 } = JSON.parse(search1.stdout);
  assert.equal(hits1.length, 1, `expected 1 hit for ${NEEDLE}, got ${hits1.length}`);
  records.push(recordGate('search-before-rebuild', search1, 192));

  // 4. foundry index rebuild
  const rebuild = measureCliPeakRss(['index', 'rebuild', '--vault', home, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
    timeoutMs: 900_000,
  });
  assert.equal(rebuild.status, 0, `e2e index rebuild failed: ${rebuild.stderr}`);
  records.push(recordGate('index-rebuild-1gib', rebuild, 256));

  // 5. foundry search (after rebuild — must match before rebuild)
  const search2 = measureCliPeakRss(['search', NEEDLE, '--vault', home, '--recovery-key-stdin', '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(search2.status, 0, `e2e search 2 failed: ${search2.stderr}`);
  const { results: hits2 } = JSON.parse(search2.stdout);
  assert.deepEqual(hits2, hits1, 'search results differed after index rebuild');
  records.push(recordGate('search-after-rebuild', search2, 192));

  // 6. foundry vault verify (no key)
  const verify = measureCliPeakRss(['vault', 'verify', '--vault', home, '--json']);
  assert.equal(verify.status, 0, `e2e vault verify failed: ${verify.stderr}`);
  const verifyOut = JSON.parse(verify.stdout);
  assert.equal(verifyOut.ok, true);
  if (TARGET_BYTES >= 512 * 1024 * 1024) {
    assert.ok(verifyOut.sealedSegments >= 2, `expected >= 2 sealed segments for 1 GiB archive, got ${verifyOut.sealedSegments}`);
  }
  records.push(recordGate('vault-verify-1gib', verify, 128));

  const failed = records.filter(r => r.overBudget);
  assert.equal(
    failed.length,
    0,
    `E2E 1 GiB gate exceeded 95% memory ceiling: ${failed.map(r => `${r.step} ${r.peakMiB} MiB > ${r.headroom95MiB} MiB`).join(', ')}`,
  );
} finally {
  cleanupDir(root);
}

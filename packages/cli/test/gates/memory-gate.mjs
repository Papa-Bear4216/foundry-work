// TEST ONLY: V-7 memory gate (OS exit-time peak RSS for every `foundry` command, passphrase & recovery key, 95% ceiling rule).
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import { writeMultiPartTakeoutFolder } from 'importers';
import { cleanupDir, measureCliPeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3', `Expected pinned Node 24.22.3, got ${process.versions.node}`);

const HEADROOM_FACTOR = 0.95;
const FAKE_CEILING = process.env.CLI_GATE_FAKE_CEILING_MIB ? Number(process.env.CLI_GATE_FAKE_CEILING_MIB) : undefined;
const SMOKE = process.env.CLI_GATE_SMOKE === '1';

const PASSPHRASE = 'TEST ONLY memory gate passphrase';
const NEW_PASSPHRASE = 'TEST ONLY memory gate replacement passphrase';

// Architecture section 9 + V-7 dispatch:
// init, reset-passphrase and every passphrase command: 256 MiB; import: 256 MiB; search (recovery): 192 MiB; vault verify: 128 MiB.
const CEILINGS_MIB = {
  'init:passphrase': 256,
  'import:passphrase': 256,
  'import:recovery': 256,
  'search:passphrase': 256,
  'search:recovery': 192,
  'index-rebuild:passphrase': 256,
  'index-rebuild:recovery': 256,
  'vault-verify:none': 128,
  'vault-reset-passphrase:recovery+passphrase': 256,
};

function checkMeasurement(command, credential, measured) {
  const key = `${command}:${credential}`;
  const ceilingMiB = FAKE_CEILING ?? CEILINGS_MIB[key];
  assert.ok(Number.isFinite(ceilingMiB) && ceilingMiB > 0, `unknown ceiling for ${key}`);
  const limit95KiB = Math.floor(ceilingMiB * 1024 * HEADROOM_FACTOR);
  const peakMiB = Number((measured.externalPeakKiB / 1024).toFixed(2));
  const headroom95MiB = Number((ceilingMiB * HEADROOM_FACTOR).toFixed(2));
  const overBudget = measured.externalPeakKiB > limit95KiB;
  const record = {
    gate: 'cli-memory',
    os: process.platform,
    command,
    credential,
    externalPeakKiB: measured.externalPeakKiB,
    peakMiB,
    ceilingMiB,
    headroom95MiB,
    wallMs: measured.wallMs,
    overBudget,
  };
  console.log(JSON.stringify(record));
  return record;
}

const root = mkdtempSync(join(tmpdir(), 'foundry-v7-memory-gate-'));
try {
  const archiveDir = join(root, 'takeout');
  await writeMultiPartTakeoutFolder(archiveDir, {
    contactsCount: SMOKE ? 5 : 40,
    calendarEvents: SMOKE ? 4 : 30,
    mailMessages: SMOKE ? 6 : 60,
  });

  const homePass = join(root, 'home-pass');
  const homeRec = join(root, 'home-rec');

  // 1. init (passphrase)
  const initRes = measureCliPeakRss(['init', '--vault', homePass, '--passphrase-stdin'], { stdin: PASSPHRASE + '\n' });
  assert.equal(initRes.status, 0, `init failed: ${initRes.stderr}`);
  const recoveryMatch = /^\s{4}(\S+)$/mu.exec(initRes.stdout);
  assert.ok(recoveryMatch, 'init did not print recovery key');
  const recoveryKey = recoveryMatch[1];

  // Clone the freshly initialized vault so both passphrase and recovery import paths start identically.
  cpSync(homePass, homeRec, { recursive: true });

  const results = [];
  results.push(checkMeasurement('init', 'passphrase', initRes));

  // 2. import (passphrase, then recovery)
  const impPass = measureCliPeakRss(['import', archiveDir, '--vault', homePass, '--passphrase-stdin', '--json'], {
    stdin: PASSPHRASE + '\n',
  });
  assert.equal(impPass.status, 0, `import (passphrase) failed: ${impPass.stderr}`);
  assert.ok(JSON.parse(impPass.stdout).itemsAdded > 0);
  results.push(checkMeasurement('import', 'passphrase', impPass));

  const impRec = measureCliPeakRss(['import', archiveDir, '--vault', homeRec, '--recovery-key-stdin', '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(impRec.status, 0, `import (recovery) failed: ${impRec.stderr}`);
  assert.ok(JSON.parse(impRec.stdout).itemsAdded > 0);
  results.push(checkMeasurement('import', 'recovery', impRec));

  // 3. search (passphrase, then recovery)
  const searchPass = measureCliPeakRss(['search', 'Synthetic', '--vault', homePass, '--passphrase-stdin', '--json'], {
    stdin: PASSPHRASE + '\n',
  });
  assert.equal(searchPass.status, 0, `search (passphrase) failed: ${searchPass.stderr}`);
  assert.ok(JSON.parse(searchPass.stdout).results.length > 0);
  results.push(checkMeasurement('search', 'passphrase', searchPass));

  const searchRec = measureCliPeakRss(['search', 'Synthetic', '--vault', homeRec, '--recovery-key-stdin', '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(searchRec.status, 0, `search (recovery) failed: ${searchRec.stderr}`);
  assert.ok(JSON.parse(searchRec.stdout).results.length > 0);
  results.push(checkMeasurement('search', 'recovery', searchRec));

  // 4. index rebuild (passphrase, then recovery)
  const rebuildPass = measureCliPeakRss(['index', 'rebuild', '--vault', homePass, '--passphrase-stdin'], {
    stdin: PASSPHRASE + '\n',
  });
  assert.equal(rebuildPass.status, 0, `index rebuild (passphrase) failed: ${rebuildPass.stderr}`);
  results.push(checkMeasurement('index-rebuild', 'passphrase', rebuildPass));

  const rebuildRec = measureCliPeakRss(['index', 'rebuild', '--vault', homeRec, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(rebuildRec.status, 0, `index rebuild (recovery) failed: ${rebuildRec.stderr}`);
  results.push(checkMeasurement('index-rebuild', 'recovery', rebuildRec));

  // 5. vault verify (no key)
  const verifyRes = measureCliPeakRss(['vault', 'verify', '--vault', homePass, '--json']);
  assert.equal(verifyRes.status, 0, `vault verify failed: ${verifyRes.stderr}`);
  assert.equal(JSON.parse(verifyRes.stdout).ok, true);
  results.push(checkMeasurement('vault-verify', 'none', verifyRes));

  // 6. vault reset-passphrase (recovery + new passphrase)
  const resetRes = measureCliPeakRss(
    ['vault', 'reset-passphrase', '--vault', homePass, '--recovery-key-stdin', '--passphrase-stdin'],
    { stdin: `${recoveryKey}\n${NEW_PASSPHRASE}\n` },
  );
  assert.equal(resetRes.status, 0, `vault reset-passphrase failed: ${resetRes.stderr}`);
  results.push(checkMeasurement('vault-reset-passphrase', 'recovery+passphrase', resetRes));

  const failed = results.filter(r => r.overBudget);
  assert.equal(
    failed.length,
    0,
    `CLI memory gate failed (95% headroom rule): ${failed.map(r => `${r.command}:${r.credential} ${r.peakMiB} MiB > ${r.headroom95MiB} MiB`).join(', ')}`,
  );
} finally {
  cleanupDir(root);
}

import assert from 'node:assert/strict';
import { cpSync, existsSync, mkdtempDisposableSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { syntheticVault } from './fixture.mjs';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.version, 'v24.22.3');
using scratch = mkdtempDisposableSync(join(tmpdir(), 'foundry-v4-budget-'));
const script = fileURLToPath(new URL('./budget-child.mjs', import.meta.url));
const recovery = join(scratch.path, 'recovery');
const passphrase = join(scratch.path, 'passphrase');
const ceilings = { incremental: 256, open: 192, rebuild: 256, search: 192 };
const run = (phase, credential = 'recovery') => {
  const root = credential === 'passphrase' ? passphrase : recovery;
  const { stdout, externalPeakKiB } = measurePeakRss(script, phase, root, credential);
  const output = JSON.parse(stdout);
  assert.ok(Number.isFinite(output.peakRssKiB) && output.peakRssKiB > 0);
  const ceilingMiB = ceilings[phase];
  const overBudget = ceilingMiB === undefined ? undefined :
    Math.max(output.peakRssKiB, externalPeakKiB) > ceilingMiB * 1024;
  const measurement = { ...output, externalPeakKiB, ceilingMiB, overBudget };
  console.log(JSON.stringify(measurement));
  return measurement;
};
try {
  const seed = run('seed');
  const append = run('append');
  console.log(JSON.stringify({ corpusItems: seed.items + append.items, corpusBytes: seed.bytes + append.bytes }));
  // Both credential paths start with the same pending append and checkpointed generation.
  cpSync(recovery, passphrase, { recursive: true });
  const measured = Object.keys(ceilings).map(phase => run(phase));
  for (const phase of ['incremental', 'rebuild', 'search']) run(phase, 'passphrase');
  for (const { phase, overBudget, ceilingMiB } of measured) {
    assert.ok(!overBudget, `${phase} exceeded ${ceilingMiB} MiB peak RSS.`);
  }
} finally {
  for (const root of [recovery, passphrase]) {
    const directory = join(root, 'vault');
    if (existsSync(join(directory, 'segments'))) syntheticVault(directory, false).writable();
  }
}

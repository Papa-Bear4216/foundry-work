import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempDisposableSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { syntheticVault } from './fixture.mjs';

assert.equal(process.version, 'v24.22.3');
using scratch = mkdtempDisposableSync(join(tmpdir(), 'foundry-v4-budget-'));
const script = fileURLToPath(new URL('./budget-child.mjs', import.meta.url));
const run = phase => {
  const child = spawnSync(process.execPath, [script, phase, scratch.path], {
    encoding: 'utf8', windowsHide: true, timeout: 240000,
  });
  assert.equal(child.status, 0, child.error?.message ?? child.stderr);
  const output = JSON.parse(child.stdout);
  console.log(JSON.stringify(output));
  return output;
};
try {
  const seed = run('seed');
  const append = run('append');
  console.log(JSON.stringify({ corpusItems: seed.items + append.items, corpusBytes: seed.bytes + append.bytes }));
  const incremental = run('incremental');
  run('open');
  run('rebuild');
  const search = run('search');
  assert.ok(incremental.peakRssKiB <= 256 * 1024, 'Incremental indexing exceeded 256 MiB.');
  assert.ok(search.peakRssKiB <= 192 * 1024, 'Full-text search exceeded 192 MiB.');
} finally {
  const directory = join(scratch.path, 'vault');
  if (existsSync(join(directory, 'segments'))) syntheticVault(directory, false).writable();
}

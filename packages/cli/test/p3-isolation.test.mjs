// TEST ONLY: ruling R18-8 D2. search, import, index rebuild and vault verify load no P-3 module (second copy, anchor,
// QR, ISO export, scheduler); only the P-3 handlers load the `vault/second-copy` entry. A child process records the
// module URLs it loads.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { cleanEnv } from './helpers.mjs';

test('search, import, index rebuild and verify load no P-3 module; vault status loads the separate entry', () => {
  const child = fileURLToPath(new URL('./p3-isolation-child.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [child], { encoding: 'utf8', env: cleanEnv(), timeout: 600_000 });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  for (const name of ['import', 'search', 'index rebuild', 'vault verify']) {
    assert.equal(report.steps[name].code, 0, name);
    assert.deepEqual(report.steps[name].p3, [], `${name} loaded a P-3 module`);
  }
  assert.equal(report.control.code, 0);
  assert.ok(report.control.p3.includes('second-copy-index.js'), JSON.stringify(report.control));
});

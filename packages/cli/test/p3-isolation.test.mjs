// TEST ONLY: ruling R18-8 D2. search, import, index rebuild and vault verify load no P-3 module (second copy, anchor,
// QR, ISO export, scheduler); only the P-3 handlers load the `vault/second-copy` entry. A child process records the
// module URLs it loads (inline dispatch), and R19-9 adds a trace through the shipped bin and its worker thread.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { closeSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { BIN, cleanEnv, initVault, PASSPHRASE, scratch, stdinFile, takeoutFolder } from './helpers.mjs';

const P3 = /\/dist\/(second-copy-index|second-copy|iso9660|schedule|qr|anchor)\.js$/u;

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

test('through the shipped bin and its worker thread: the same four commands load no P-3 module (R19-9)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const { folder } = await takeoutFolder(dir);
  const hook = pathToFileURL(fileURLToPath(new URL('./p3-trace-hook.mjs', import.meta.url))).href;
  let count = 0;
  const traced = (argv, stdin = '') => {
    const trace = join(dir, `trace-${++count}.txt`);
    const fd = stdinFile(dir, stdin);
    try {
      const result = spawnSync(process.execPath, ['--import', hook, BIN, ...argv], {
        stdio: [fd, 'pipe', 'pipe'], env: cleanEnv({ P3_TEST_MODULE_TRACE: trace }), encoding: 'utf8', timeout: 600_000, windowsHide: true,
      });
      assert.equal(result.status, 0, `${argv.join(' ')}: ${result.stderr}`);
    } finally {
      closeSync(fd);
    }
    assert.ok(existsSync(trace), 'the hook ran');
    const lines = readFileSync(trace, 'utf8').trim().split('\n').map(line => {
      const space = line.indexOf(' ');
      return { thread: Number(line.slice(0, space)), url: line.slice(space + 1) };
    });
    return {
      // The worker entry was traced inside the worker thread itself (thread id other than 0).
      worker: lines.some(line => line.thread !== 0 && line.url.endsWith('/dist/worker.js')),
      p3: [...new Set(lines.filter(line => P3.test(line.url)).map(line => line.url.slice(line.url.lastIndexOf('/') + 1)))].sort(),
    };
  };
  const keyed = `${PASSPHRASE}\n`;
  for (const [name, argv, stdin] of [
    ['import', ['import', folder, '--vault', home, '--passphrase-stdin'], keyed],
    ['search', ['search', 'Subject', '--vault', home, '--passphrase-stdin'], keyed],
    ['index rebuild', ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], keyed],
    ['vault verify', ['vault', 'verify', '--vault', home], ''],
  ]) {
    const seen = traced(argv, stdin);
    assert.equal(seen.worker, true, `${name}: the worker thread was traced`);
    assert.deepEqual(seen.p3, [], `${name} loaded a P-3 module through the bin or its worker`);
  }
  // Positive control: a P-3 command loads the separate entry in its worker thread, and the trace sees it.
  const control = traced(['vault', 'status', '--vault', home]);
  assert.equal(control.worker, true);
  assert.ok(control.p3.includes('second-copy-index.js'), JSON.stringify(control));
});

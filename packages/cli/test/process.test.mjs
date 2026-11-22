// TEST ONLY: process rules (Architecture 9): exit codes, the lock, the wall-clock limit, nothing outlives the command.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { closeSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { cleanEnv, initVault, PASSPHRASE, runBin, runWorker, scratch, stdinFile } from './helpers.mjs';

const STALL_BIN = fileURLToPath(new URL('./fixtures/stall-bin.mjs', import.meta.url));

test('the bin: exit 0 on success, 1 on usage errors, 2 on typed failures; --help and --version take no lock', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const ok = runBin(dir, ['vault', 'verify', '--vault', home]);
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stdout, /^Vault OK/u);
  const help = runBin(dir, ['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /^Usage: foundry <command>/u);
  assert.match(runBin(dir, ['--version']).stdout, /^foundry \d+\.\d+\.\d+\n$/u);
  const usage = runBin(dir, ['frobnicate']);
  assert.equal(usage.code, 1);
  assert.match(usage.stderr, /^foundry: [^\n]+ \[USAGE\]\n$/u);
  const noTerminal = runBin(dir, ['search', 'q', '--vault', home]);
  assert.equal(noTerminal.code, 1, 'no terminal and no --*-stdin flag is a usage error');
  assert.match(noTerminal.stderr, /no terminal for a prompt/u);
  const typed = runBin(dir, ['search', 'q', '--vault', home, '--passphrase-stdin'], { stdin: 'TEST ONLY wrong' });
  assert.equal(typed.code, 2);
  assert.match(typed.stderr, /^foundry: [^\n]+ \[[A-Z_]+\]\n$/u);
  assert.equal(existsSync(join(home, 'foundry.lock')), false, 'the lock is removed after every command');
});

test('lock: a second command fails fast with BUSY; a stale lock from a dead process is recovered with a notice', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const lockPath = join(home, 'foundry.lock');
  const holder = { pid: process.pid, command: 'import', started: '2026-01-01T00:00:00.000Z', host: hostname() };
  writeFileSync(lockPath, JSON.stringify(holder));
  const busy = runBin(dir, ['search', 'q', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(busy.code, 2);
  assert.match(busy.stderr, new RegExp(`process ${process.pid}, import, started 2026-01-01T00:00:00.000Z.*\\[BUSY\\]`, 'u'));
  assert.ok(busy.ms < 30_000);
  assert.deepEqual(JSON.parse(readFileSync(lockPath, 'utf8')), holder, 'the holder lock is untouched');

  const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
  writeFileSync(lockPath, JSON.stringify({ ...holder, pid: Number(child.stdout) }));
  const recovered = runBin(dir, ['vault', 'verify', '--vault', home]);
  assert.equal(recovered.code, 0, recovered.stderr);
  assert.match(recovered.stderr, /notice: recovered a stale lock/u);
  assert.equal(existsSync(lockPath), false);
});

test('worker path: commands run in one worker thread and report output and exit codes', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const search = await runWorker(dir, ['search', 'q', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(search.code, 0, search.stderr);
  assert.equal(search.stdout, 'No results.\n');
  const wrong = await runWorker(dir, ['search', 'q', '--vault', home, '--passphrase-stdin'], { stdin: 'TEST ONLY wrong' });
  assert.equal(wrong.code, 2);
  assert.equal(existsSync(join(home, 'foundry.lock')), false);
});

test('wall-clock limit: a stuck synchronous section ends with TIMEOUT well within 5 s of the limit (worker terminated)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  for (const argv of [['vault', 'verify'], ['search', 'q', '--passphrase-stdin']]) {
    const started = Date.now();
    const result = await runWorker(dir, [...argv, '--vault', home, '--timeout', '1'], { stdin: PASSPHRASE, hooks: { stallSync: true } });
    const elapsed = Date.now() - started;
    assert.equal(result.code, 2);
    assert.equal(result.stderr, 'foundry: the command passed its time limit of 1 second(s) [TIMEOUT]\n');
    assert.ok(elapsed < 1000 + 5000, `ended after ${elapsed} ms`);
    assert.equal(existsSync(join(home, 'foundry.lock')), false, 'the lock is removed on timeout');
  }
});

test('wall-clock limit in a real process: exit 2 TIMEOUT within 5 s of the limit; the process does not outlive the command', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const fd = stdinFile(dir, PASSPHRASE);
  try {
    const started = Date.now();
    const result = spawnSync(process.execPath, [STALL_BIN, 'search', 'q', '--vault', home, '--passphrase-stdin', '--timeout', '2'], {
      stdio: [fd, 'pipe', 'pipe'], env: cleanEnv(), encoding: 'utf8', timeout: 60_000, windowsHide: true,
    });
    const elapsed = Date.now() - started;
    assert.equal(result.signal, null, 'the process ended by itself, not by the test timeout');
    assert.equal(result.status, 2);
    assert.match(result.stderr, /\[TIMEOUT\]\n$/u);
    // Process start, init of the worker and the KDF run add to the 2 s limit; the requirement is limit + 5 s.
    assert.ok(elapsed < 2000 + 5000, `ended after ${elapsed} ms`);
    assert.equal(existsSync(join(home, 'foundry.lock')), false);
  } finally {
    closeSync(fd);
  }
});

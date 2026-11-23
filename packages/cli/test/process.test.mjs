// TEST ONLY: process rules (Architecture 9): exit codes, the lock, the wall-clock limit, nothing outlives the command.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawn, spawnSync } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runCli } from '../dist/cli.js';
import { acquireLock, isProcessAlive } from '../dist/lock.js';
import { BIN, cleanEnv, fakeTerminal, initVault, PASSPHRASE, runBin, runWorker, scratch, stdinFile } from './helpers.mjs';

const HOOK_BIN = fileURLToPath(new URL('./fixtures/hook-bin.mjs', import.meta.url));
const MODULES = fileURLToPath(new URL('./fixtures/verify-modules.mjs', import.meta.url));
const PACKAGE_DIR = fileURLToPath(new URL('..', import.meta.url));

test('the bin launcher: checked into git, package.json bin points at it, and it runs --version with exit 0 after a build', () => {
  const manifest = JSON.parse(readFileSync(join(PACKAGE_DIR, 'package.json'), 'utf8'));
  assert.deepEqual(manifest.bin, { foundry: './bin/foundry.mjs' });
  assert.equal(join(PACKAGE_DIR, manifest.bin.foundry), BIN);
  const tracked = spawnSync('git', ['ls-files', '--error-unmatch', 'bin/foundry.mjs'], {
    cwd: PACKAGE_DIR, encoding: 'utf8', timeout: 60_000, windowsHide: true,
  });
  assert.equal(tracked.status, 0, `the launcher is in git: ${tracked.stderr}`);
  assert.equal(tracked.stdout.trim(), 'bin/foundry.mjs');
  const version = spawnSync(process.execPath, [BIN, '--version'], { env: cleanEnv(), encoding: 'utf8', timeout: 60_000, windowsHide: true });
  assert.equal(version.status, 0, version.stderr);
  assert.match(version.stdout, /^foundry \d+\.\d+\.\d+\n$/u);
});

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
    const result = spawnSync(process.execPath, [HOOK_BIN, 'stallSync', 'search', 'q', '--vault', home, '--passphrase-stdin', '--timeout', '2'], {
      stdio: [fd, 'pipe', 'pipe'], env: cleanEnv(), encoding: 'utf8', timeout: 60_000, windowsHide: true,
    });
    const elapsed = Date.now() - started;
    assert.equal(result.signal, null, 'the process ended by itself, not by the test timeout');
    assert.equal(result.status, 2);
    assert.match(result.stderr, /\[TIMEOUT\]\n$/u);
    // Process start, init of the worker and the KDF run add to the 2 s limit; the requirement is limit + 5 s.
    assert.ok(elapsed < 2000 + 5000, `ended after ${elapsed} ms`);
    // The lock is NOT removed on a timeout: it stays until the process is dead, then it is stale and recovered.
    assertStaleLockRecovered(dir, home, result.pid);
  } finally {
    closeSync(fd);
  }
});

/** The lock left by a stopped bin names that (now dead) process; the next command recovers it with a notice. */
function assertStaleLockRecovered(dir, home, pid) {
  const lockPath = join(home, 'foundry.lock');
  assert.ok(existsSync(lockPath), 'the lock stays after a timeout');
  const left = JSON.parse(readFileSync(lockPath, 'utf8'));
  assert.equal(left.pid, pid);
  assert.equal(isProcessAlive(pid), false);
  const next = runBin(dir, ['vault', 'verify', '--vault', home]);
  assert.equal(next.code, 0, next.stderr);
  assert.match(next.stderr, new RegExp(`notice: recovered a stale lock from process ${pid} \\(search,`, 'u'));
  assert.equal(existsSync(lockPath), false);
}

test('wall-clock limit while a stdin read waits: a pipe that never sends EOF ends with exit 2 TIMEOUT within 5 s of the limit', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const started = Date.now();
  const child = spawn(process.execPath, [BIN, 'search', 'q', '--vault', home, '--passphrase-stdin', '--timeout', '2'], {
    stdio: ['pipe', 'pipe', 'pipe'], env: cleanEnv(), windowsHide: true,
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    child.stdin.destroy();
  });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', text => { stderr += text; });
  child.stdout.resume();
  child.stdin.on('error', () => {}); // the child may close its end first
  child.stdin.write('TEST ONLY a line that never ends'); // and stdin is never ended: no EOF
  const stderrDone = new Promise(resolveEnd => child.stderr.on('end', resolveEnd));
  const [code, signal] = await new Promise(resolveExit => {
    const killer = setTimeout(() => child.kill(), 60_000);
    child.on('exit', (exitCode, exitSignal) => {
      clearTimeout(killer);
      resolveExit([exitCode, exitSignal]);
    });
  });
  const elapsed = Date.now() - started;
  await stderrDone;
  assert.equal(signal, null, 'the process ended by itself, not by the test');
  assert.equal(code, 2);
  assert.equal(stderr, 'foundry: the command passed its time limit of 2 second(s) [TIMEOUT]\n');
  assert.ok(elapsed < 2000 + 5000, `ended after ${elapsed} ms`);
  assertStaleLockRecovered(dir, home, child.pid);

  // Control: the same read from a pipe that does send EOF ends by itself with exit 0 (no handle keeps it alive).
  const control = spawnSync(process.execPath, [BIN, 'search', 'q', '--vault', home, '--passphrase-stdin', '--timeout', '60'], {
    input: PASSPHRASE + '\n', env: cleanEnv(), encoding: 'utf8', timeout: 60_000, windowsHide: true,
  });
  assert.equal(control.signal, null);
  assert.equal(control.status, 0, control.stderr);
  assert.equal(control.stdout, 'No results.\n');
});

test('programmatic timeout: the lock is held until the worker has stopped; a second command gets BUSY until then', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const lockPath = join(home, 'foundry.lock');
  const probe = () => {
    try {
      acquireLock(lockPath, 'search', () => {}).release();
      return 'acquired';
    } catch (error) {
      return error.code;
    }
  };
  const fd = stdinFile(dir, PASSPHRASE);
  let resolved = false;
  const afterTimeout = [];
  let poll;
  try {
    const first = runCli(['search', 'q', '--vault', home, '--passphrase-stdin', '--timeout', '2'], {
      stdinFd: fd, env: cleanEnv(), testHooks: { stallSync: true }, stdout: () => {},
      stderr: text => {
        if (!text.includes('[TIMEOUT]')) return;
        // From the TIMEOUT line until runCli returns, the lock must stay held.
        const check = () => { if (!resolved) afterTimeout.push(probe()); };
        setImmediate(check);
        poll = setInterval(check, 2);
      },
    }).then(code => { resolved = true; clearInterval(poll); return code; });
    // While the first command runs, a second command fails fast with BUSY.
    await new Promise(resolveWait => setTimeout(resolveWait, 500));
    const second = await runWorker(dir, ['vault', 'verify', '--vault', home]);
    assert.equal(second.code, 2);
    assert.match(second.stderr, /another foundry command is running .*\[BUSY\]\n$/u);
    assert.equal(await first, 2);
    assert.ok(afterTimeout.length > 0, 'the lock was probed between the TIMEOUT line and the end of runCli');
    assert.deepEqual([...new Set(afterTimeout)], ['BUSY'], 'the lock was held until the worker had stopped');
    assert.equal(existsSync(lockPath), false, 'then the lock is released');
    assert.equal(probe(), 'acquired');
    const after = await runWorker(dir, ['vault', 'verify', '--vault', home]);
    assert.equal(after.code, 0, after.stderr);
  } finally {
    clearInterval(poll);
    closeSync(fd);
  }
});

test('the command ends when its body is done, even if the worker thread still holds a handle (no TIMEOUT)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const started = Date.now();
  const result = await runWorker(dir, ['vault', 'verify', '--vault', home, '--timeout', '30'], { hooks: { leakHandle: true } });
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, '');
  assert.match(result.stdout, /^Vault OK/u);
  assert.ok(Date.now() - started < 10_000, 'the worker is terminated after its done message');
});

test('vault verify never loads the SQLite addon (positive control: index rebuild does)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const run = mode => {
    const fd = stdinFile(dir, PASSPHRASE);
    try {
      const result = spawnSync(process.execPath, [MODULES, home, mode], {
        stdio: [fd, 'pipe', 'pipe'], env: cleanEnv(), encoding: 'utf8', timeout: 120_000, windowsHide: true,
      });
      return JSON.parse(result.stdout);
    } finally {
      closeSync(fd);
    }
  };
  assert.deepEqual(run('verify'), { code: 0, loaded: [] });
  const control = run('rebuild');
  assert.equal(control.code, 0);
  assert.ok(control.loaded.length > 0, 'the filter sees the addon when the index is used');
});

const sleep = ms => new Promise(resolveSleep => setTimeout(resolveSleep, ms));
const allZero = bytes => bytes.every(byte => byte === 0);

test('programmatic timeout during a terminal prompt: the prompt is cancelled (listener removed, raw mode restored, editor buffer and first passphrase wiped) before runCli returns', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const cases = [
    // One prompt with partial input (no Enter).
    ['search prompt', ['search', 'q', '--vault', home], ['TEST ONLY partial passphrase'], home],
    // init: the first new passphrase is complete; the confirmation prompt is open with partial input.
    ['init confirmation', ['init', '--vault', join(dir, 'fresh')], ['TEST ONLY first new passphrase\r', 'TEST ONLY partial'], join(dir, 'fresh')],
  ];
  for (const [label, argv, inputs, target] of cases) {
    const terminal = fakeTerminal(inputs);
    let stderr = '';
    const started = Date.now();
    const pending = runCli([...argv, '--timeout', '1'], {
      env: cleanEnv(), terminal, isTerminal: () => false, stdout: () => assert.fail(`${label}: no output`),
      stderr: text => { stderr += text; },
    });
    // While the prompt waits, the typed bytes are in its buffers (sanity check of the observer).
    await sleep(400);
    assert.equal(terminal.input.listenerCount('data'), 1, `${label}: the prompt is open`);
    assert.equal(terminal.input.isRaw, true, `${label}: raw mode is on while the prompt is open`);
    const code = await pending;
    assert.equal(code, 2, label);
    assert.equal(stderr, 'foundry: the command passed its time limit of 1 second(s) [TIMEOUT]\n', label);
    assert.ok(Date.now() - started < 1000 + 5000, `${label}: ended in time`);
    assert.equal(terminal.input.listenerCount('data'), 0, `${label}: the data listener is removed`);
    assert.equal(terminal.input.isRaw, false, `${label}: raw mode is restored on the injected input terminal`);
    assert.equal(terminal.input.rawCalls.at(-1), false, label);
    const editors = terminal.buffers.filter(entry => entry.role === 'editor');
    assert.equal(editors.length, inputs.length, `${label}: one editor buffer per opened prompt`);
    for (const { bytes } of editors) assert.ok(allZero(bytes), `${label}: the editor buffer is wiped`);
    const firsts = terminal.buffers.filter(entry => entry.role === 'first');
    assert.equal(firsts.length, label === 'init confirmation' ? 1 : 0, label);
    for (const { bytes } of firsts) {
      assert.equal(bytes.length, Buffer.byteLength('TEST ONLY first new passphrase'), `${label}: the first passphrase was held`);
      assert.ok(allZero(bytes), `${label}: the first passphrase is wiped`);
    }
    assert.equal(existsSync(join(target, 'foundry.lock')), false, `${label}: the lock is released`);
  }
  assert.equal(existsSync(join(dir, 'fresh', 'vault')), false, 'the cancelled init created no vault');
});

test('prompt cancel never throws: a terminal whose setRawMode throws during the restore still ends as TIMEOUT with the listener removed and both buffers wiped; the previous raw mode is restored', async t => {
  const dir = scratch(t);
  // Case 1: init confirmation prompt open (first passphrase held); the terminal then fails every setRawMode call.
  const terminal = fakeTerminal(['TEST ONLY first new passphrase\r', 'TEST ONLY partial']);
  let failRestore = false;
  const setRaw = terminal.input.setRawMode;
  terminal.input.setRawMode = mode => {
    if (failRestore) throw Object.assign(new Error('TEST ONLY the terminal is gone'), { code: 'EIO' });
    return setRaw(mode);
  };
  let stderr = '';
  const pending = runCli(['init', '--vault', join(dir, 'fresh'), '--timeout', '1'], {
    env: cleanEnv(), terminal, isTerminal: () => false, stdout: () => assert.fail('no output'),
    stderr: text => { stderr += text; },
  });
  await sleep(400);
  assert.equal(terminal.input.listenerCount('data'), 1, 'the confirmation prompt is open');
  failRestore = true;
  const code = await pending;
  assert.equal(code, 2);
  assert.equal(stderr, 'foundry: the command passed its time limit of 1 second(s) [TIMEOUT]\n');
  assert.equal(terminal.input.listenerCount('data'), 0, 'the data listener is removed');
  const editors = terminal.buffers.filter(entry => entry.role === 'editor');
  assert.equal(editors.length, 2);
  for (const { bytes } of editors) assert.ok(allZero(bytes), 'the editor buffer is wiped');
  const firsts = terminal.buffers.filter(entry => entry.role === 'first');
  assert.equal(firsts.length, 1);
  assert.ok(allZero(firsts[0].bytes), 'the first passphrase is wiped');
  assert.equal(existsSync(join(dir, 'fresh', 'foundry.lock')), false, 'the lock is released');
  assert.equal(existsSync(join(dir, 'fresh', 'vault')), false);

  // Case 2: the terminal was already in raw mode before the prompt: the cancel restores raw mode ON, not off.
  const { home } = await initVault(dir);
  const raw = fakeTerminal(['TEST ONLY partial passphrase']);
  raw.input.isRaw = true;
  let rawErr = '';
  const rawCode = await runCli(['search', 'q', '--vault', home, '--timeout', '1'], {
    env: cleanEnv(), terminal: raw, isTerminal: () => false, stdout: () => assert.fail('no output'),
    stderr: text => { rawErr += text; },
  });
  assert.equal(rawCode, 2);
  assert.equal(rawErr, 'foundry: the command passed its time limit of 1 second(s) [TIMEOUT]\n');
  assert.equal(raw.input.listenerCount('data'), 0);
  assert.deepEqual(raw.input.rawCalls, [true, true], 'raw mode on for the prompt, then the previous state (on)');
  assert.equal(raw.input.isRaw, true);
});

test('lock path that is a FIFO: exit 2 BUSY with the fixed message, without a blocking open (skipped where mkfifo is missing or on Windows)', async t => {
  if (process.platform === 'win32') {
    t.skip('no FIFO on Windows');
    return;
  }
  const hasMkfifo = spawnSync('mkfifo', ['--version'], { encoding: 'utf8', timeout: 10_000 });
  if (hasMkfifo.error) {
    t.skip('mkfifo is not available');
    return;
  }
  const dir = scratch(t);
  const home = join(dir, 'home');
  mkdirSync(home);
  const made = spawnSync('mkfifo', [join(home, 'foundry.lock')], { encoding: 'utf8', timeout: 10_000 });
  assert.equal(made.status, 0, made.stderr);
  // A blocking open of a FIFO with no writer never returns: the spawn timeout turns such a regression into a failure.
  const result = runBin(dir, ['init', '--vault', home, '--passphrase-stdin', '--timeout', '5'],
    { stdin: 'TEST ONLY fifo passphrase\n', timeout: 30_000 });
  assert.equal(result.signal, null, 'the process ended by itself');
  assert.equal(result.code, 2, result.stderr);
  assert.equal(result.stderr, 'foundry: a file operation on the Foundry folder or its lock file failed (not a regular file) [BUSY]\n');
});

// TEST ONLY: V-7 offline gate (preload on both OS + Linux strace check).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeMultiPartTakeoutFolder } from 'importers';
import { BIN, cleanChildEnv, cleanupDir } from './peak-rss.mjs';

const PRELOAD_URL = pathToFileURL(fileURLToPath(new URL('./offline-preload.mjs', import.meta.url))).href;
const PASSPHRASE = 'TEST ONLY offline gate passphrase';

function runNode(args, { stdin = '', env = {}, timeout = 120_000 } = {}) {
  const result = spawnSync(process.execPath, args, {
    encoding: 'utf8',
    input: stdin,
    env: cleanChildEnv(env),
    timeout,
    windowsHide: true,
  });
  assert.ifError(result.error);
  return result;
}

const root = mkdtempSync(join(tmpdir(), 'foundry-v7-offline-'));
try {
  // 1. Negative controls: prove the preload actually records and throws on fetch and net.connect.
  const controlLog = join(root, 'control.log');
  writeFileSync(controlLog, '', 'utf8');
  for (const [label, snippet] of [
    ['fetch', "await fetch('http://127.0.0.1:1')"],
    ['net.connect', "const net = await import('node:net'); net.connect(1, '127.0.0.1')"],
  ]) {
    const res = runNode(['--import', PRELOAD_URL, '--input-type=module', '-e', snippet], {
      env: { CLI_OFFLINE_LOG: controlLog },
    });
    assert.notEqual(res.status, 0, `negative control (${label}) must fail`);
    assert.match(res.stderr, /OFFLINE_GATE_VIOLATION/u, `negative control (${label}) must throw OFFLINE_GATE_VIOLATION`);
  }
  const controlLines = readFileSync(controlLog, 'utf8').trim().split(/\r?\n/u).filter(Boolean);
  assert.ok(controlLines.length >= 2, `expected >= 2 negative control attempts, got ${controlLines.length}`);

  // 2. Build a small synthetic multi-part Takeout archive.
  const archiveDir = join(root, 'takeout');
  await writeMultiPartTakeoutFolder(archiveDir, {
    contactsCount: 5,
    calendarEvents: 4,
    mailMessages: 6,
  });

  // 3. Run init, import, and search under the offline preload (both OS).
  const home = join(root, 'home');
  const attemptLog = join(root, 'attempts.log');
  writeFileSync(attemptLog, '', 'utf8');
  const offlineEnv = { CLI_OFFLINE_LOG: attemptLog };

  const init = runNode(['--import', PRELOAD_URL, BIN, 'init', '--vault', home, '--passphrase-stdin'], {
    stdin: PASSPHRASE + '\n',
    env: offlineEnv,
  });
  assert.equal(init.status, 0, `init failed: ${init.stderr}`);

  const imp = runNode(['--import', PRELOAD_URL, BIN, 'import', archiveDir, '--vault', home, '--passphrase-stdin', '--json'], {
    stdin: PASSPHRASE + '\n',
    env: offlineEnv,
  });
  assert.equal(imp.status, 0, `import failed: ${imp.stderr}`);
  const summary = JSON.parse(imp.stdout);
  assert.ok(summary.itemsAdded >= 10, `expected >= 10 imported items, got ${summary.itemsAdded}`);

  const search = runNode(['--import', PRELOAD_URL, BIN, 'search', 'Synthetic', '--vault', home, '--passphrase-stdin', '--json'], {
    stdin: PASSPHRASE + '\n',
    env: offlineEnv,
  });
  assert.equal(search.status, 0, `search failed: ${search.stderr}`);
  const { results: hits } = JSON.parse(search.stdout);
  assert.ok(Array.isArray(hits) && hits.length > 0, 'expected search results');

  const attempts = readFileSync(attemptLog, 'utf8').trim();
  assert.equal(attempts, '', `offline preload recorded network attempts:\n${attempts}`);
  console.log(JSON.stringify({ gate: 'cli-offline-preload', os: process.platform, attempts: 0, imported: summary.itemsAdded, hits: hits.length }));

  // 4. Linux strace check (required on Linux CI via CLI_GATE_STRACE=1; skipped on Windows).
  const wantStrace = process.platform === 'linux' && (process.env.CLI_GATE_STRACE === '1' || spawnSync('strace', ['-V']).status === 0);
  if (wantStrace) {
    const straceHome = join(root, 'strace-home');
    const init2 = runNode([BIN, 'init', '--vault', straceHome, '--passphrase-stdin'], { stdin: PASSPHRASE + '\n' });
    assert.equal(init2.status, 0, `strace init failed: ${init2.stderr}`);

    for (const [step, cliArgs] of [
      ['import', ['import', archiveDir, '--vault', straceHome, '--passphrase-stdin', '--json']],
      ['search', ['search', 'Synthetic', '--vault', straceHome, '--passphrase-stdin', '--json']],
    ]) {
      const tracePath = join(root, `strace-${step}.log`);
      const traced = spawnSync(
        'strace',
        ['-f', '-e', 'trace=socket,connect,sendto,sendmsg', '-o', tracePath, process.execPath, BIN, ...cliArgs],
        { encoding: 'utf8', input: PASSPHRASE + '\n', env: cleanChildEnv(), timeout: 180_000 },
      );
      assert.ifError(traced.error);
      assert.equal(traced.status, 0, `strace ${step} failed: ${traced.stderr}`);
      assert.ok(existsSync(tracePath), `missing strace output ${tracePath}`);
      const traceText = readFileSync(tracePath, 'utf8');
      const inetLines = traceText.split(/\r?\n/u).filter(line => /\bAF_INET6?\b/u.test(line));
      assert.deepEqual(inetLines, [], `strace ${step} observed AF_INET/AF_INET6 calls:\n${inetLines.join('\n')}`);
      console.log(JSON.stringify({ gate: 'cli-offline-strace', os: process.platform, step, inetCalls: 0 }));
    }
  } else if (process.env.CLI_GATE_STRACE === '1') {
    assert.fail('CLI_GATE_STRACE=1 requested but strace is unavailable on this platform');
  }
} finally {
  cleanupDir(root);
}

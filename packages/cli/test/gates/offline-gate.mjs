// TEST ONLY: V-7 offline gate (preload + worker/log-failure negative controls on both OS; mandatory Linux strace).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
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

function findInetLines(traceText) {
  return traceText.split(/\r?\n/u).filter(line => /\bAF_INET6?\b/u.test(line));
}

const root = mkdtempSync(join(tmpdir(), 'foundry-v7-offline-'));
try {
  // 1. Negative controls: prove preload blocks fetch, net.connect, net.Stream, and Worker-thread calls.
  const controlLog = join(root, 'control.log');
  writeFileSync(controlLog, '', 'utf8');
  for (const [label, snippet] of [
    ['fetch', "await fetch('http://127.0.0.1:1')"],
    ['net.connect', "const net = await import('node:net'); net.connect(1, '127.0.0.1')"],
    ['net.Stream', "const net = await import('node:net'); new net.Stream()"],
    [
      'worker-thread',
      "import { Worker } from 'node:worker_threads'; const w = new Worker(\"import('node:net').then(n => new n.Stream())\", { eval: true }); w.on('error', e => { console.error(e.message); process.exit(1); });",
    ],
  ]) {
    const res = runNode(['--import', PRELOAD_URL, '--input-type=module', '-e', snippet], {
      env: { CLI_OFFLINE_LOG: controlLog },
    });
    assert.notEqual(res.status, 0, `negative control (${label}) must fail`);
    assert.match(res.stderr, /OFFLINE_GATE_VIOLATION/u, `negative control (${label}) must throw OFFLINE_GATE_VIOLATION`);
  }
  const controlLines = readFileSync(controlLog, 'utf8').trim().split(/\r?\n/u).filter(Boolean);
  assert.ok(controlLines.length >= 4, `expected >= 4 negative control attempts, got ${controlLines.length}`);

  // Log-write failure negative control: pointing CLI_OFFLINE_LOG at a directory must fail closed (exit 99) even if caught.
  const dirAsLog = join(root, 'dir-as-log');
  mkdirSync(dirAsLog);
  const logFailRes = runNode(
    ['--import', PRELOAD_URL, '--input-type=module', '-e', "try { await fetch('http://127.0.0.1:1'); } catch {}"],
    { env: { CLI_OFFLINE_LOG: dirAsLog } },
  );
  assert.equal(logFailRes.status, 99, `expected exit 99 on unwritable attempt log, got ${logFailRes.status}`);

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

  // 4. Mandatory Linux OS-level strace check (init, import, search + negative control).
  if (process.platform === 'linux') {
    const straceVer = spawnSync('strace', ['-V'], { encoding: 'utf8' });
    assert.equal(straceVer.status, 0, 'strace is required on Linux for the offline gate');

    // Negative control: prove strace + findInetLines detects an AF_INET socket call.
    const negTrace = join(root, 'strace-neg.log');
    const negRun = spawnSync(
      'strace',
      [
        '-f', '-e', 'trace=socket,connect,sendto,sendmsg', '-o', negTrace,
        process.execPath, '--input-type=module', '-e',
        "import net from 'node:net'; const s = net.connect(1, '127.0.0.1'); s.on('error', () => {});",
      ],
      { encoding: 'utf8', env: cleanChildEnv(), timeout: 30_000 },
    );
    assert.ifError(negRun.error);
    assert.ok(existsSync(negTrace), 'strace negative control produced no trace');
    assert.ok(findInetLines(readFileSync(negTrace, 'utf8')).length > 0, 'strace negative control failed to observe AF_INET');

    const straceHome = join(root, 'strace-home');
    for (const [step, cliArgs] of [
      ['init', ['init', '--vault', straceHome, '--passphrase-stdin']],
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
      const inetLines = findInetLines(readFileSync(tracePath, 'utf8'));
      assert.deepEqual(inetLines, [], `strace ${step} observed AF_INET/AF_INET6 calls:\n${inetLines.join('\n')}`);
      console.log(JSON.stringify({ gate: 'cli-offline-strace', os: process.platform, step, inetCalls: 0 }));
    }
  }
} finally {
  cleanupDir(root);
}

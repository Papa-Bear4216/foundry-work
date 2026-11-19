import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { blockCount, generateFixture } from './fixture.mjs';

if (process.version !== 'v24.22.3' || process.arch !== 'x64' || !['win32', 'linux'].includes(process.platform)) {
  throw new Error('This benchmark requires Node 24.22.3 on Windows x64 or Linux x64');
}
if (process.env.NODE_OPTIONS) throw new Error('Clear NODE_OPTIONS to measure the stock runtime');

const cwd = new URL('.', import.meta.url);
const args = (operation, directory) => ['workload.mjs', operation, directory];

function outsidePeakKiB(pid) {
  if (process.platform === 'linux') {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8');
    return Number(/^VmHWM:\s+(\d+) kB$/m.exec(status)?.[1]);
  }
  const result = spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command',
    `$ErrorActionPreference = 'Stop'; (Get-Process -Id ${pid}).PeakWorkingSet64`,
  ], { encoding: 'utf8', timeout: 15000, windowsHide: true });
  if (result.status !== 0) throw new Error('Could not read the Windows peak working set');
  return Number(result.stdout.trim()) / 1024;
}

function measure(operation, directory) {
  return new Promise((resolve, reject) => {
    const start = process.hrtime.bigint();
    const child = spawn(process.execPath, args(operation, directory), {
      cwd,
      stdio: ['pipe', 'pipe', 'inherit'],
      windowsHide: true,
    });
    const timeout = setTimeout(() => child.kill(), 60000);
    let output = '';
    let measurement;
    let failure;
    child.on('error', (error) => { failure ??= error; });
    child.stdin.on('error', (error) => { failure ??= error; });
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      if (measurement || failure) return;
      output += chunk;
      if (!output.endsWith('\n')) return;
      try {
        const outerMs = Number(process.hrtime.bigint() - start) / 1e6;
        const outsideKiB = outsidePeakKiB(child.pid);
        if (!(outsideKiB > 0)) throw new Error('OS peak counter unavailable');
        measurement = { ...JSON.parse(output), outerMs, outsideKiB };
      } catch (error) {
        failure = error;
      } finally {
        child.stdin.end();
      }
    });
    child.on('close', (code) => {
      clearTimeout(timeout);
      if (failure) reject(failure);
      else if (code !== 0 || !measurement) reject(new Error(`Incomplete ${operation} measurement`));
      else resolve(measurement);
    });
  });
}

function validate(row) {
  const validDigest = row.digestBytes > 0 && row.digestBytes <= 6000;
  const valid = {
    fts5: row.matches === 1,
    'cold-start': row.logBytes > 0,
    append: row.blocks === blockCount + 1 && validDigest,
    rebuild: row.blocks === blockCount,
    'query-warm': row.matches === 20 && row.resultBytes > 0,
    'query-cold': row.matches === 20 && row.resultBytes > 0,
    digest: validDigest,
  };
  if (!valid[row.operation] || !(row.innerKiB > 0)) throw new Error(`Invalid ${row.operation} result`);
}

const temp = process.platform === 'win32' ? process.env.TEMP : process.env.TMPDIR || '/tmp';
const absolute = process.platform === 'win32' ? /^[a-z]:[\\/]|^[\\/]{2}/i : /^\//;
if (!temp || !absolute.test(temp)) throw new Error('Set TEMP or TMPDIR to an absolute temporary directory');
const root = mkdtempSync(`${temp}/facts-z1-`);
try {
  const base = `${root}/base`;
  mkdirSync(base);
  generateFixture(base);
  const fixture = readFileSync(`${base}/ledger.jsonl`);
  console.log(JSON.stringify({
    node: process.version, platform: process.platform, arch: process.arch,
    blocks: blockCount, fixtureBytes: fixture.length,
    fixtureSha256: createHash('sha256').update(fixture).digest('hex'),
  }));
  const fts5 = await measure('fts5', base);
  validate(fts5);
  console.log(JSON.stringify(fts5));
  const seed = spawnSync(process.execPath, args('seed', base), { cwd, stdio: 'inherit', timeout: 60000 });
  if (seed.status !== 0) throw new Error('Could not seed the warm index');

  for (let trial = 1; trial <= 5; trial++) {
    for (const operation of ['cold-start', 'append', 'rebuild', 'query-warm', 'query-cold', 'digest']) {
      const directory = `${root}/${trial}-${operation}`;
      mkdirSync(directory);
      copyFileSync(`${base}/ledger.jsonl`, `${directory}/ledger.jsonl`);
      if (operation !== 'rebuild' && operation !== 'query-cold') {
        copyFileSync(`${base}/facts.index.sqlite`, `${directory}/facts.index.sqlite`);
      }
      const row = await measure(operation, directory);
      validate(row);
      console.log(JSON.stringify({ trial, ...row }));
    }
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

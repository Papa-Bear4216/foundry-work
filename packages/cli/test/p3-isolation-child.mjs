// TEST ONLY: child process for p3-isolation.test.mjs. It records every module URL this thread loads, runs the
// non-P-3 commands, and prints which P-3 modules (if any) they loaded. All data is synthetic.
import { registerHooks } from 'node:module';

const loaded = [];
registerHooks({
  load(url, context, nextLoad) {
    loaded.push(url);
    return nextLoad(url, context);
  },
});

const P3 = /\/dist\/(second-copy-index|second-copy|iso9660|schedule|qr|anchor)\.js$/u;
const p3Loaded = () => [...new Set(loaded.filter(url => P3.test(url)).map(url => url.slice(url.lastIndexOf('/') + 1)))].sort();

const { mkdtempSync, rmSync } = await import('node:fs');
const { tmpdir } = await import('node:os');
const { join } = await import('node:path');
const { initVault, PASSPHRASE, runInline, takeoutFolder } = await import('./helpers.mjs');

const dir = mkdtempSync(join(tmpdir(), 'foundry-p3-isolation-'));
const report = { steps: {} };
try {
  const { home } = await initVault(dir);
  const { folder } = await takeoutFolder(dir);
  const keyed = { stdin: `${PASSPHRASE}\n` };
  const steps = [
    ['import', ['import', folder, '--vault', home, '--passphrase-stdin'], keyed],
    ['search', ['search', 'Subject', '--vault', home, '--passphrase-stdin'], keyed],
    ['index rebuild', ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], keyed],
    ['vault verify', ['vault', 'verify', '--vault', home], {}],
  ];
  for (const [name, argv, options] of steps) {
    const result = await runInline(dir, argv, options);
    report.steps[name] = { code: result.code, p3: p3Loaded() };
  }
  // Positive control: a P-3 command does load the separate entry, so the hook sees dynamic imports.
  const status = await runInline(dir, ['vault', 'status', '--vault', home]);
  report.control = { code: status.code, p3: p3Loaded() };
} finally {
  rmSync(dir, { recursive: true, force: true });
}
process.stdout.write(JSON.stringify(report));

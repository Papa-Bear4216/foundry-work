import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempDisposableSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, toNamespacedPath } from 'node:path';
import { openSqlDriver } from '../dist/index.js';

assert.equal(process.version, 'v24.22.3');
assert.equal(process.arch, 'x64');
assert.ok(['win32', 'linux'].includes(process.platform));
const require = createRequire(import.meta.url);
const addon = 'better-sqlite3-multiple-ciphers';
assert.equal(require(addon + '/package.json').version, '13.2.0');
const expected = join(dirname(require.resolve(addon + '/package.json')), 'prebuilds',
  `${process.platform}-${process.arch}.node`);
const load = process.dlopen;
const loaded = [];
process.dlopen = function (module, path, ...args) {
  loaded.push(path);
  return load.call(this, module, path, ...args);
};
using dir = mkdtempDisposableSync(join(tmpdir(), 'foundry-v4-binary-'));
const db = openSqlDriver(join(dir.path, 'probe.sqlite'), { key: Buffer.alloc(32, 44), create: true });
try {
  assert.ok(loaded.map(toNamespacedPath).includes(toNamespacedPath(expected)), 'The installed prebuild must be the binary actually loaded.');
  console.log(JSON.stringify({ runtime: process.version, prebuild: `${process.platform}-${process.arch}`,
    addon: '13.2.0', ...db.prepare('SELECT sqlite_version() AS sqlite, sqlite3mc_version() AS cipher').get() }));
} finally {
  db.close();
  process.dlopen = load;
}

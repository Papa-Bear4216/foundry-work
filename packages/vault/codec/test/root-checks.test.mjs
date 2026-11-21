import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempDisposableSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';

function fixture(t, script) {
  const directory = mkdtempDisposableSync(join(tmpdir(), 'vault-check-'));
  t.after(() => directory.remove());
  const scriptPath = join(directory.path, script);
  mkdirSync(dirname(scriptPath), { recursive: true });
  copyFileSync(new URL('../../../../' + script, import.meta.url), scriptPath);
  return {
    write(path, value) {
      const dest = join(directory.path, path);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, JSON.stringify(value));
    },
    run() {
      const result = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
      assert.ifError(result.error);
      return result;
    },
  };
}

test('root runtime check enforces the codec dependency fields and Node pin', t => {
  const repo = fixture(t, 'scripts/check-runtime-dependencies.mjs');
  const pinned = { engines: { node: process.versions.node } };
  const codec = 'packages/vault/codec/package.json';
  repo.write('package.json', pinned);
  repo.write('packages/facts-ledger/package.json', pinned);
  repo.write(codec, pinned);
  assert.equal(repo.run().status, 0);
  repo.write(codec, { ...pinned, optionalDependencies: {} });
  const dependency = repo.run();
  assert.equal(dependency.status, 1);
  assert.match(dependency.stderr, /vault\/codec:.*optionalDependencies/u);
  repo.write(codec, { engines: { node: '>=' + process.versions.node } });
  const engine = repo.run();
  assert.equal(engine.status, 1);
  assert.match(engine.stderr, /vault\/codec:.*workspace pin/u);
});

test('root license check inspects the optional codec lockfile', t => {
  const repo = fixture(t, 'scripts/check-licenses.mjs');
  repo.write('package-lock.json', { packages: {} });
  repo.write('docs/DEPENDENCIES.md', '');
  assert.equal(repo.run().status, 0);
  const lock = 'packages/vault/codec/package-lock.json';
  repo.write(lock, { packages: { 'node_modules/sample': { dev: true, license: 'MIT' } } });
  assert.equal(repo.run().status, 0);
  repo.write(lock, { packages: { 'node_modules/sample': { dev: true, license: 'GPL-3.0-only' } } });
  const result = repo.run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /sample:.*unapproved license/u);
});

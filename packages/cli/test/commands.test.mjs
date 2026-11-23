// TEST ONLY: command tests run in this thread so the vault's KDF counting hook sees every scrypt run.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { initVault, PASSPHRASE, runInline, scratch } from './helpers.mjs';

const NEW_PASSPHRASE = 'TEST ONLY replacement passphrase';

test('init: KDF runs once, prints the recovery key once, builds no index, refuses a non-empty target', async t => {
  const dir = scratch(t);
  const { home, recoveryKey, init } = await initVault(dir);
  assert.equal(init.kdf, 1);
  assert.equal(init.stdout.split(recoveryKey).length - 1, 1, 'the recovery key appears exactly once');
  assert.match(init.stdout, /Write this down/u);
  assert.equal(init.stderr, '');
  assert.deepEqual(readdirSync(home).sort(), ['vault'], 'no index and no lock remain');

  const again = await runInline(dir, ['init', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(again.code, 2);
  assert.match(again.stderr, /\[NOT_EMPTY\]\n$/u);
  assert.equal(again.kdf, 0);

  const other = join(dir, 'other');
  mkdirSync(other);
  writeFileSync(join(other, 'notes.txt'), 'TEST ONLY');
  assert.match((await runInline(dir, ['init', '--vault', other, '--passphrase-stdin'], { stdin: PASSPHRASE })).stderr, /NOT_EMPTY/u);
});

test('init builds in H/.init-<random> and renames it last: a leftover .init folder is ignored and removed; an interrupted init leaves no vault and a retry succeeds', async t => {
  const dir = scratch(t);
  const home = join(dir, 'home');
  const leftover = join(home, '.init-0123456789abcdef');
  mkdirSync(join(leftover, 'keyring'), { recursive: true });
  writeFileSync(join(leftover, 'keyring', 'partial.txt'), 'TEST ONLY partial init');
  const { init } = await initVault(dir);
  assert.equal(init.code, 0);
  assert.deepEqual(readdirSync(home), ['vault'], 'the leftover folder is removed and no temporary folder remains');

  // Only the exact pattern is ignored: a look-alike folder still makes the target "not empty" and is kept.
  const near = join(dir, 'near');
  mkdirSync(join(near, '.init-notHex'), { recursive: true });
  const refused = await runInline(dir, ['init', '--vault', near, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.match(refused.stderr, /\[NOT_EMPTY\]\n$/u);
  assert.ok(existsSync(join(near, '.init-notHex')));

  // A failure after the vault is built but before the rename: no H/vault, no recovery key printed.
  const second = join(dir, 'second');
  const failed = await runInline(dir, ['init', '--vault', second, '--passphrase-stdin'],
    { stdin: PASSPHRASE + '\n', hooks: { failBeforeInitRename: true } });
  assert.equal(failed.code, 2);
  assert.equal(failed.stdout, '');
  assert.equal(existsSync(join(second, 'vault')), false);
  const names = readdirSync(second);
  assert.equal(names.length, 1);
  assert.match(names[0], /^\.init-[0-9a-f]{16}$/u);
  const retry = await runInline(dir, ['init', '--vault', second, '--passphrase-stdin'], { stdin: PASSPHRASE + '\n' });
  assert.equal(retry.code, 0, retry.stderr);
  assert.match(retry.stdout, /RECOVERY KEY/u);
  assert.deepEqual(readdirSync(second), ['vault']);
  // The renamed vault works.
  assert.equal((await runInline(dir, ['vault', 'verify', '--vault', second])).code, 0);
  const search = await runInline(dir, ['search', 'q', '--vault', second, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(search.code, 0, search.stderr);
  assert.equal(search.stdout, 'No results.\n');
});

test('init and vault reset-passphrase refuse an empty new passphrase before any vault call', async t => {
  const dir = scratch(t);
  const empty = await runInline(dir, ['init', '--vault', join(dir, 'h'), '--passphrase-stdin'], { stdin: '\n' });
  assert.equal(empty.code, 2);
  assert.equal(empty.stderr, 'foundry: the new passphrase must not be empty [EMPTY_PASSPHRASE]\n');
  assert.equal(empty.kdf, 0);
  assert.equal(existsSync(join(dir, 'h', 'vault')), false);

  const { home, recoveryKey } = await initVault(dir);
  const reset = await runInline(dir, ['vault', 'reset-passphrase', '--vault', home, '--recovery-key-stdin', '--passphrase-stdin'],
    { stdin: `${recoveryKey}\n\n` });
  assert.equal(reset.code, 2);
  assert.equal(reset.stderr, 'foundry: the new passphrase must not be empty [EMPTY_PASSPHRASE]\n');
  assert.equal(reset.kdf, 0);
});

test('vault verify: no secret, zero KDF runs, --json', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const text = await runInline(dir, ['vault', 'verify', '--vault', home]);
  assert.equal(text.code, 0);
  assert.equal(text.kdf, 0);
  assert.match(text.stdout, /^Vault OK/u);
  const json = await runInline(dir, ['vault', 'verify', '--vault', home, '--json']);
  assert.equal(JSON.parse(json.stdout).ok, true);
  assert.equal(json.kdf, 0);
});

test('search and index rebuild: one KDF run with a passphrase, zero with the recovery key', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const credentials = [
    [['--passphrase-stdin'], PASSPHRASE + '\n', 1],
    [['--recovery-key-stdin'], recoveryKey + '\n', 0],
  ];
  for (const [flags, stdin, kdf] of credentials) {
    const search = await runInline(dir, ['search', 'anything', '--vault', home, ...flags], { stdin });
    assert.equal(search.code, 0, search.stderr);
    assert.equal(search.stdout, 'No results.\n');
    assert.equal(search.kdf, kdf, `search ${flags}`);
    const json = await runInline(dir, ['search', 'anything', '--vault', home, '--json', ...flags], { stdin });
    assert.deepEqual(JSON.parse(json.stdout), { results: [] });
    assert.equal(json.kdf, kdf);
    const rebuild = await runInline(dir, ['index', 'rebuild', '--vault', home, ...flags], { stdin });
    assert.equal(rebuild.code, 0, rebuild.stderr);
    assert.match(rebuild.stdout, /^Index rebuilt/u);
    assert.equal(rebuild.kdf, kdf, `index rebuild ${flags}`);
  }
});

test('vault reset-passphrase: one KDF run; the new passphrase works, the old one fails AUTH; the recovery key stays valid', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const reset = await runInline(dir, ['vault', 'reset-passphrase', '--vault', home, '--recovery-key-stdin', '--passphrase-stdin'],
    { stdin: `${recoveryKey}\n${NEW_PASSPHRASE}\n` });
  assert.equal(reset.code, 0, reset.stderr);
  assert.equal(reset.kdf, 1);
  assert.match(reset.stdout, /NOT rotated/u);

  const fresh = await runInline(dir, ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], { stdin: NEW_PASSPHRASE });
  assert.equal(fresh.code, 0, fresh.stderr);
  const old = await runInline(dir, ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(old.code, 2);
  assert.match(old.stderr, /^foundry: [^\n]+ \[(AUTH|MAC)\]\n$/u);
  assert.ok(!old.stderr.includes('    at '), 'no stack trace without --debug');
  const recovery = await runInline(dir, ['index', 'rebuild', '--vault', home, '--recovery-key-stdin'], { stdin: recoveryKey });
  assert.equal(recovery.code, 0, recovery.stderr);
});

test('typed failures: missing vault, bad recovery key format, wrong recovery key; --debug adds a stack without secrets', async t => {
  const dir = scratch(t);
  const missing = await runInline(dir, ['search', 'q', '--vault', join(dir, 'nothing'), '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /\[NO_VAULT\]\n$/u);

  const { home, recoveryKey } = await initVault(dir);
  const malformed = await runInline(dir, ['search', 'q', '--vault', home, '--recovery-key-stdin'], { stdin: 'TEST-ONLY-NOT-A-KEY' });
  assert.equal(malformed.code, 2);
  assert.equal(malformed.stderr, 'foundry: the recovery key is not in the expected format [RECOVERY_KEY_FORMAT]\n');

  const { recoveryKey: otherKey } = await initVault(scratch(t));
  assert.notEqual(otherKey, recoveryKey);
  const wrong = await runInline(dir, ['search', 'q', '--vault', home, '--recovery-key-stdin', '--debug'], { stdin: otherKey });
  assert.equal(wrong.code, 2);
  assert.match(wrong.stderr, /foundry: debug: /u);
  assert.match(wrong.stderr, /\[(AUTH|MAC|KEY)\]\n$/u);
  assert.ok(!wrong.stderr.includes(otherKey));
  assert.equal(wrong.kdf, 0);
});

// TEST ONLY: command tests run in this thread so the vault's KDF counting hook sees every scrypt run.
import assert from 'node:assert/strict';
import {
  existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import { test } from 'node:test';
import { initVault, PASSPHRASE, runInline, scratch } from './helpers.mjs';

/** init's ownership marker (fixed name and content, written as written by `commands.ts`). */
const INIT_MARKER = '.foundry-init-owner';
const initMarkerContent = name => `foundry init staging folder\n${name}\n`;

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

/** The NOT_EMPTY line for a `.init-*` folder in H: it names the folder (name only) and says when to delete it. */
const leftoverLine = name => `foundry: the target folder holds the folder "${name}"; if it is a leftover of an interrupted `
  + '`foundry init`, delete it and try again [NOT_EMPTY]\n';

test('init builds in H/.init-<random> and renames it last; an interrupted init leaves no vault, keeps its staging folder and names it; init never deletes it', async t => {
  const dir = scratch(t);
  // A failure after the vault is built but before the rename: no H/vault, no recovery key printed. The staging folder
  // holds what this run wrote, which cannot be proven to be only that, so it stays and the error names it.
  const second = join(dir, 'second');
  const failed = await runInline(dir, ['init', '--vault', second, '--passphrase-stdin'],
    { stdin: PASSPHRASE + '\n', hooks: { failBeforeInitRename: true } });
  assert.equal(failed.code, 2);
  assert.equal(failed.stdout, '');
  assert.equal(existsSync(join(second, 'vault')), false);
  const names = readdirSync(second);
  assert.equal(names.length, 1);
  assert.match(names[0], /^\.init-[0-9a-f]{16}$/u);
  assert.equal(readFileSync(join(second, names[0], INIT_MARKER), 'utf8'), initMarkerContent(names[0]),
    'the staging folder holds its ownership marker');
  assert.equal(failed.stderr.split('\n').length, 2, 'one stderr line');
  assert.ok(failed.stderr.includes(`"${names[0]}"`), `the error names the staging folder: ${failed.stderr}`);
  assert.ok(!failed.stderr.includes(second), 'the error names the folder only, not its path');
  // The next init refuses the leftover (it is never deleted by init) and names it.
  const refusedRetry = await runInline(dir, ['init', '--vault', second, '--passphrase-stdin'], { stdin: PASSPHRASE + '\n' });
  assert.equal(refusedRetry.code, 2);
  assert.equal(refusedRetry.stderr, leftoverLine(names[0]));
  assert.equal(refusedRetry.kdf, 0);
  assert.deepEqual(readdirSync(second), names, 'the leftover is kept');
  // The user deletes it; then init succeeds.
  rmSync(join(second, names[0]), { recursive: true, force: true });
  const retry = await runInline(dir, ['init', '--vault', second, '--passphrase-stdin'], { stdin: PASSPHRASE + '\n' });
  assert.equal(retry.code, 0, retry.stderr);
  assert.match(retry.stdout, /RECOVERY KEY/u);
  assert.deepEqual(readdirSync(second), ['vault'], 'no staging folder remains after a successful init');
  // The renamed vault works.
  assert.equal((await runInline(dir, ['vault', 'verify', '--vault', second])).code, 0);
  const search = await runInline(dir, ['search', 'q', '--vault', second, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(search.code, 0, search.stderr);
  assert.equal(search.stdout, 'No results.\n');
});

test('init never deletes a folder: any .init-* folder in H (owned leftover with a valid marker, or not) gives NOT_EMPTY naming it, and is kept', async t => {
  const dir = scratch(t);
  const owned = '.init-0123456789abcdef';
  const cases = [
    ['owned leftover', owned, folder => writeFileSync(join(folder, INIT_MARKER), initMarkerContent(owned))],
    ['no marker', '.init-00112233445566ff', folder => writeFileSync(join(folder, 'backup.txt'), 'TEST ONLY user backup')],
    ['wrong marker content', '.init-00112233445566ff',
      folder => writeFileSync(join(folder, INIT_MARKER), initMarkerContent('.init-ffeeddccbbaa9988'))],
    ['marker is a folder', '.init-00112233445566ff', folder => mkdirSync(join(folder, INIT_MARKER))],
    ['look-alike name', '.init-notHex', () => {}],
  ];
  for (const [label, name, plant] of cases) {
    const home = join(dir, label.replaceAll(' ', '-'));
    const folder = join(home, name);
    // A valid marker next to an existing backup vault: init must not touch it.
    mkdirSync(join(folder, 'vault'), { recursive: true });
    writeFileSync(join(folder, 'vault', 'VAULT.json'), 'TEST ONLY an existing vault the user keeps here');
    plant(folder);
    const refused = await runInline(dir, ['init', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
    assert.equal(refused.code, 2, label);
    assert.equal(refused.stderr, leftoverLine(name), label);
    assert.equal(refused.kdf, 0, label);
    assert.ok(existsSync(join(folder, 'vault', 'VAULT.json')), `${label}: the folder and its backup are kept`);
    assert.deepEqual(readdirSync(home), [name], `${label}: nothing else was created`);
  }
});

test('init: a failure of the staging-marker write removes only what this run created (the marker, then the empty folder)', async t => {
  const dir = scratch(t);
  const home = join(dir, 'home');
  const failed = await runInline(dir, ['init', '--vault', home, '--passphrase-stdin'],
    { stdin: PASSPHRASE + '\n', hooks: { failInitMarkerWrite: true } });
  assert.equal(failed.code, 2);
  assert.equal(failed.stdout, '');
  assert.equal(failed.stderr, 'foundry: a file operation on the Foundry folder or its lock file failed (ENAMETOOLONG) [IO]\n');
  assert.deepEqual(readdirSync(home), [], 'no staging folder, no marker, no vault, no lock');
});

test('linked folders: every command refuses H/vault or H/index when it is a symbolic link or junction (LINKED_FOLDER), also under --debug without a path', async t => {
  const dir = scratch(t);
  const linkType = process.platform === 'win32' ? 'junction' : 'dir';
  // Home A: a real vault with an index.
  const { home: homeA } = await initVault(dir);
  const firstSearch = await runInline(dir, ['search', 'q', '--vault', homeA, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(firstSearch.code, 0, firstSearch.stderr);
  assert.ok(existsSync(join(homeA, 'index')), 'home A has an index folder');
  // Home B: H/vault links to home A's vault (another lock file, the same vault).
  const homeB = join(dir, 'home-b');
  mkdirSync(homeB);
  const vaultLink = join(homeB, 'vault');
  symlinkSync(join(homeA, 'vault'), vaultLink, linkType);
  // Home C: a real vault of its own, but H/index links to home A's index.
  const { home: homeC } = await initVault(scratch(t));
  const indexLink = join(homeC, 'index');
  symlinkSync(join(homeA, 'index'), indexLink, linkType);
  try {
    assert.ok(lstatSync(vaultLink).isSymbolicLink() || realpathSync.native(vaultLink) !== vaultLink, 'the link exists');
    const line = which => `foundry: the ${which} folder in the Foundry folder is a symbolic link or junction; `
      + `Foundry needs a real folder there [LINKED_FOLDER]\n`;
    for (const debug of [[], ['--debug']]) {
      for (const [label, argv, stdin, which, home] of [
        ['verify B', ['vault', 'verify', '--vault', homeB], '', 'vault', homeB],
        ['search B', ['search', 'q', '--vault', homeB, '--passphrase-stdin'], PASSPHRASE, 'vault', homeB],
        ['rebuild B', ['index', 'rebuild', '--vault', homeB, '--passphrase-stdin'], PASSPHRASE, 'vault', homeB],
        ['init B', ['init', '--vault', homeB, '--passphrase-stdin'], PASSPHRASE, 'vault', homeB],
        ['search C', ['search', 'q', '--vault', homeC, '--passphrase-stdin'], PASSPHRASE, 'index', homeC],
        ['verify C', ['vault', 'verify', '--vault', homeC], '', 'index', homeC],
      ]) {
        const name = `${label} ${debug.join(' ')}`;
        const result = await runInline(dir, [...argv, ...debug], { stdin });
        assert.equal(result.code, 2, `${name}: ${result.stderr}`);
        assert.ok(result.stderr.endsWith(line(which)), `${name}: ${result.stderr}`);
        assert.equal(result.kdf, 0, name);
        assert.ok(!result.stderr.includes(home) && !result.stderr.includes(homeA), `${name}: no path in the output`);
        if (!debug.length) assert.equal(result.stderr, line(which), name);
      }
    }
    // Positive control: home A itself still works, and no lock was left in either home.
    const control = await runInline(dir, ['search', 'q', '--vault', homeA, '--passphrase-stdin'], { stdin: PASSPHRASE });
    assert.equal(control.code, 0, control.stderr);
    assert.deepEqual(readdirSync(homeB), ['vault']);
    assert.equal(existsSync(join(homeA, 'foundry.lock')), false);
  } finally {
    // Remove the links themselves (never their targets) before the scratch folders are removed.
    rmSync(vaultLink, { force: true });
    rmSync(indexLink, { force: true });
  }
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
  assert.equal(missing.stderr,
    'foundry: no vault found in the Foundry folder; run `foundry init`, or give --vault <dir> [NO_VAULT]\n');

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

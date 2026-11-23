// TEST ONLY: planted-marker tests. No secret may reach stdout, stderr, --debug text or crash text, on success and
// failure paths. The one deliberate exception: `foundry init` prints the recovery key once.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { closeSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { runCli } from '../dist/cli.js';
import { cleanEnv, fakeTerminal, runBin, runInline, scratch, stdinFile, takeoutFolder } from './helpers.mjs';

const HOOK_BIN = fileURLToPath(new URL('./fixtures/hook-bin.mjs', import.meta.url));

const MARKER = 'PLANTED-MARKER-7f3a9c';
const PASS = `TEST ONLY ${MARKER} passphrase`;
const NEW_PASS = `TEST ONLY ${MARKER} new passphrase`;

function clean(result, secrets, label) {
  for (const secret of secrets) {
    assert.ok(!result.stdout.includes(secret), `${label}: secret in stdout`);
    assert.ok(!result.stderr.includes(secret), `${label}: secret in stderr`);
  }
  assert.ok(!result.stdout.includes(MARKER) && !result.stderr.includes(MARKER), `${label}: marker in output`);
}

test('planted marker: passphrase and recovery key never reach output, errors or --debug text in any command', async t => {
  const dir = scratch(t);
  const home = join(dir, 'home');
  const init = runBin(dir, ['init', '--vault', home, '--passphrase-stdin', '--debug'], { stdin: PASS + '\n' });
  assert.equal(init.code, 0, init.stderr);
  const recoveryKey = /^\s{4}(\S+)$/mu.exec(init.stdout)[1];
  assert.equal(init.stdout.split(recoveryKey).length - 1, 1, 'init prints the recovery key exactly once');
  assert.ok(!init.stderr.includes(recoveryKey));
  assert.ok(!init.stdout.includes(MARKER) && !init.stderr.includes(MARKER));
  const secrets = [PASS, NEW_PASS, recoveryKey];
  const { folder } = await takeoutFolder(dir, { contactsCount: 2, calendarEvents: 1, mailMessages: 2 });
  const v = ['--vault', home, '--debug'];

  const runs = [
    ['import ok', ['import', folder, ...v, '--passphrase-stdin', '--json'], PASS, 0],
    ['search ok', ['search', 'Subject', ...v, '--passphrase-stdin'], PASS, 0],
    ['search recovery ok', ['search', 'Subject', ...v, '--recovery-key-stdin', '--json'], recoveryKey, 0],
    ['rebuild ok', ['index', 'rebuild', ...v, '--passphrase-stdin'], PASS, 0],
    ['verify ok', ['vault', 'verify', ...v], '', 0],
    ['import wrong passphrase', ['import', folder, ...v, '--passphrase-stdin'], `${PASS} wrong`, 2],
    ['search wrong passphrase', ['search', 'q', ...v, '--passphrase-stdin'], `TEST ONLY ${MARKER}`, 2],
    ['rebuild malformed recovery key', ['index', 'rebuild', ...v, '--recovery-key-stdin'], `1-${MARKER}-AAAA`, 2],
    ['reset malformed recovery key', ['vault', 'reset-passphrase', ...v, '--recovery-key-stdin', '--passphrase-stdin'],
      `${MARKER}\n${NEW_PASS}\n`, 2],
    ['reset empty new passphrase', ['vault', 'reset-passphrase', ...v, '--recovery-key-stdin', '--passphrase-stdin'],
      `${recoveryKey}\n\n`, 2],
    ['reset ok', ['vault', 'reset-passphrase', ...v, '--recovery-key-stdin', '--passphrase-stdin'], `${recoveryKey}\n${NEW_PASS}\n`, 0],
    ['old passphrase after reset', ['search', 'q', ...v, '--passphrase-stdin'], PASS, 2],
    ['new passphrase after reset', ['search', 'Subject', ...v, '--passphrase-stdin'], NEW_PASS, 0],
    ['init on a used home', ['init', ...v, '--passphrase-stdin'], PASS, 2],
  ];
  for (const [label, argv, stdin, code] of runs) {
    const result = runBin(dir, argv, { stdin });
    assert.equal(result.code, code, `${label}: ${result.stderr}`);
    clean(result, secrets, label);
    if (code === 2) assert.match(result.stderr, /foundry: debug: /u, `${label}: --debug shows details`);
  }
});

test('planted marker: the home-folder error is fixed text (no --vault or FOUNDRY_HOME echo); the final index update error is redacted', async t => {
  const dir = scratch(t);
  // A credential pasted by mistake into the home location: the missing-vault error must not repeat it.
  const pasted = join(dir, `${MARKER}-pasted`);
  for (const debug of [[], ['--debug']]) {
    for (const [label, argv, env, stdin] of [
      ['verify --vault', ['vault', 'verify', '--vault', pasted, ...debug], {}, ''],
      ['search --vault', ['search', 'q', '--vault', pasted, '--passphrase-stdin', ...debug], {}, PASS],
      ['verify FOUNDRY_HOME', ['vault', 'verify', ...debug], { FOUNDRY_HOME: pasted }, ''],
      ['search FOUNDRY_HOME', ['search', 'q', '--passphrase-stdin', ...debug], { FOUNDRY_HOME: pasted }, PASS],
    ]) {
      const result = runBin(dir, argv, { env, stdin });
      const name = `${label} ${debug.join(' ')}`;
      assert.equal(result.code, 2, `${name}: ${result.stderr}`);
      assert.match(result.stderr, /\[NO_VAULT\]\n$/u, name);
      clean(result, [PASS], name);
      assert.ok(!result.stderr.includes(pasted), `${name}: the home path is not echoed`);
    }
  }

  // `init` against an existing FILE at the pasted location: a file-system error of the home preflight. Fixed text
  // with the error code only, never the path or Node's message, also under --debug.
  const pastedFile = join(dir, `${MARKER}-file`);
  writeFileSync(pastedFile, 'TEST ONLY a file where a folder is expected');
  for (const debug of [[], ['--debug']]) {
    for (const [label, argv, env] of [
      ['init --vault on a file', ['init', '--vault', pastedFile, '--passphrase-stdin', ...debug], {}],
      ['init FOUNDRY_HOME on a file', ['init', '--passphrase-stdin', ...debug], { FOUNDRY_HOME: pastedFile }],
    ]) {
      const result = runBin(dir, argv, { env, stdin: PASS });
      const name = `${label} ${debug.join(' ')}`;
      assert.equal(result.code, 2, `${name}: ${result.stderr}`);
      assert.match(result.stderr, /foundry: a file operation on the Foundry folder or its lock file failed \(E[A-Z0-9]+\) \[IO\]\n$/u, name);
      clean(result, [PASS], name);
      assert.ok(!result.stderr.includes(pastedFile), `${name}: the home path is not echoed`);
      assert.doesNotMatch(result.stderr, /scandir|not a directory|mkdir/iu, `${name}: no message text from Node`);
      if (debug.length) assert.match(result.stderr, /foundry: debug: /u, `${name}: --debug still prints its (fixed) details`);
      else assert.equal(result.stderr.split('\n').length, 2, `${name}: one stderr line`);
    }
  }

  // The final index update fails with an error whose message quotes the secrets: --debug text is redacted.
  const home = join(dir, 'home');
  const init = runBin(dir, ['init', '--vault', home, '--passphrase-stdin'], { stdin: PASS });
  assert.equal(init.code, 0, init.stderr);
  const recoveryKey = /^\s{4}(\S+)$/mu.exec(init.stdout)[1];
  const { folder } = await takeoutFolder(dir, { contactsCount: 2, calendarEvents: 1, mailMessages: 2 });
  for (const [argv, stdin] of [[['--passphrase-stdin'], PASS], [['--recovery-key-stdin'], recoveryKey]]) {
    for (const debug of [[], ['--debug']]) {
      const fd = stdinFile(dir, stdin);
      try {
        const result = spawnSync(process.execPath,
          [HOOK_BIN, 'failFinalIndexUpdate', 'import', folder, '--vault', home, ...argv, ...debug], {
            stdio: [fd, 'pipe', 'pipe'], env: cleanEnv(), encoding: 'utf8', timeout: 120_000, windowsHide: true,
          });
        const label = `final index update ${argv.join(' ')} ${debug.join(' ')}`;
        assert.equal(result.status, 2, `${label}: ${result.stderr}`);
        assert.match(result.stderr, /the index is behind; run `foundry index rebuild`[^\n]* \[IO\]\n$/u, label);
        if (debug.length) assert.match(result.stderr, /foundry: debug: Error: test hook: final index update: \[REDACTED\]/u, label);
        else assert.equal(result.stderr.split('\n').length, 2, `${label}: one stderr line`);
        clean({ stdout: result.stdout, stderr: result.stderr }, [PASS, recoveryKey], label);
      } finally {
        closeSync(fd);
      }
    }
  }
});

test('secrets on the command line or in secret-looking environment variables are refused (exit 1) and not echoed', async t => {
  const dir = scratch(t);
  const home = join(dir, 'home');
  for (const argv of [['init', '--vault', home, '--passphrase', PASS], ['search', PASS, 'extra', '--vault', home],
    ['import', 'a.zip', `--recovery-key=${PASS}`], ['init', `--pass=${PASS}`]]) {
    const result = runBin(dir, argv);
    assert.equal(result.code, 1, argv.join(' '));
    clean(result, [PASS], argv[0]);
  }
  for (const name of ['FOUNDRY_PASSPHRASE', 'FOUNDRY_RECOVERY_KEY', 'VAULT_SECRET']) {
    const result = runBin(dir, ['vault', 'verify', '--vault', home], { env: { [name]: PASS } });
    assert.equal(result.code, 1, name);
    assert.match(result.stderr, /secret environment variables .* are refused \[USAGE\]/u);
    clean(result, [PASS], name);
  }
});

test('crash text: an unexpected error whose message quotes the secrets prints a fixed INTERNAL line, with or without --debug', async t => {
  const dir = scratch(t);
  const home = join(dir, 'home');
  const init = runBin(dir, ['init', '--vault', home, '--passphrase-stdin'], { stdin: PASS });
  assert.equal(init.code, 0, init.stderr);
  const recoveryKey = /^\s{4}(\S+)$/mu.exec(init.stdout)[1];
  const cases = [
    [['search', 'q', '--passphrase-stdin'], PASS],
    [['index', 'rebuild', '--recovery-key-stdin'], recoveryKey],
    [['vault', 'reset-passphrase', '--recovery-key-stdin', '--passphrase-stdin'], `${recoveryKey}\n${NEW_PASS}\n`],
  ];
  for (const [argv, stdin] of cases) {
    for (const debug of [[], ['--debug']]) {
      const fd = stdinFile(dir, stdin);
      try {
        const result = spawnSync(process.execPath, [HOOK_BIN, 'throwWithSecret', ...argv, '--vault', home, ...debug], {
          stdio: [fd, 'pipe', 'pipe'], env: cleanEnv(), encoding: 'utf8', timeout: 120_000, windowsHide: true,
        });
        const label = `${argv.join(' ')} ${debug.join(' ')}`;
        assert.equal(result.status, 2, label);
        assert.match(result.stderr, /\[INTERNAL\]\n$/u, label);
        if (debug.length) assert.match(result.stderr, /foundry: debug: Error: test hook: \[REDACTED\]/u, label);
        clean({ stdout: result.stdout, stderr: result.stderr }, [PASS, NEW_PASS, recoveryKey], label);
      } finally {
        closeSync(fd);
      }
    }
  }
});

test('a passphrase that starts with U+FEFF (BOM) keeps it on stdin: init with --passphrase-stdin unlocks through the prompt, and the other way round', async t => {
  const dir = scratch(t);
  const BOM_PASS = '﻿TEST ONLY bom passphrase';
  const viaPrompt = async (argv, inputs) => {
    let stdout = '';
    let stderr = '';
    const code = await runCli(argv, {
      inline: true, env: cleanEnv(), terminal: fakeTerminal(inputs), isTerminal: () => false,
      stdout: text => { stdout += text; }, stderr: text => { stderr += text; },
    });
    return { code, stdout, stderr };
  };

  // stdin -> prompt.
  const first = join(dir, 'first');
  const init = await runInline(dir, ['init', '--vault', first, '--passphrase-stdin'], { stdin: `${BOM_PASS}\n` });
  assert.equal(init.code, 0, init.stderr);
  const prompted = await viaPrompt(['search', 'q', '--vault', first], [`${BOM_PASS}\r`]);
  assert.equal(prompted.code, 0, prompted.stderr);
  assert.equal(prompted.stdout, 'No results.\n');
  // Control: without the leading U+FEFF the passphrase is wrong, so the character is really part of the secret.
  const withoutBom = await viaPrompt(['search', 'q', '--vault', first], [`${BOM_PASS.slice(1)}\r`]);
  assert.equal(withoutBom.code, 2);
  assert.match(withoutBom.stderr, /\[AUTH\]\n$/u);

  // prompt -> stdin.
  const second = join(dir, 'second');
  const promptInit = await viaPrompt(['init', '--vault', second], [`${BOM_PASS}\r`, `${BOM_PASS}\r`]);
  assert.equal(promptInit.code, 0, promptInit.stderr);
  const stdinSearch = await runInline(dir, ['search', 'q', '--vault', second, '--passphrase-stdin'], { stdin: BOM_PASS });
  assert.equal(stdinSearch.code, 0, stdinSearch.stderr);
  assert.equal(stdinSearch.stdout, 'No results.\n');
});

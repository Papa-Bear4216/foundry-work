// TEST ONLY: planted-marker tests. No secret may reach stdout, stderr, --debug text or crash text, on success and
// failure paths. The one deliberate exception: `foundry init` prints the recovery key once.
import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { runBin, scratch, takeoutFolder } from './helpers.mjs';

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

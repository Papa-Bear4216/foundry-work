// TEST ONLY: `foundry vault` second-copy, export and reminder commands (P-3). Every vault, secret and path is synthetic.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { chmodSync, cpSync, existsSync, readdirSync, readFileSync, statSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { verifyVault } from 'vault';
import { parseCommandLine } from '../dist/args.js';
import { INIT_INTENT_NAME, REGISTER_NAME } from '../dist/commands.js';
import { cleanEnv, initVault, PASSPHRASE, runInline, scratch, takeoutFolder } from './helpers.mjs';

const ntfs = () => ({ type: 'ntfs', method: 'injected' });
const fat = () => ({ type: 'vfat', method: 'injected' });
const parse = argv => parseCommandLine(argv, cleanEnv());

/** One event in the open segment, so the first seal has something to close (a fresh vault holds none). */
async function addEvent(dir, home) {
  const added = await runInline(dir, ['profile', 'add', 'me', '--vault', home, '--passphrase-stdin'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(added.code, 0, added.stderr);
}

async function seal(dir, home, drive, extra = [], hooks = { secondCopyProbe: ntfs }) {
  return runInline(dir, ['vault', 'seal', drive, '--vault', home, '--passphrase-stdin', ...extra], { stdin: `${PASSPHRASE}\n`, hooks });
}

/** `vault copy init` is keyed since fix round 1: it appends `copy.registered` before it writes the register. */
async function copyInit(dir, home, drive, extra = [], hooks = { secondCopyProbe: ntfs }) {
  return runInline(dir, ['vault', 'copy', 'init', drive, '--vault', home, '--passphrase-stdin', ...extra], { stdin: `${PASSPHRASE}\n`, hooks });
}

test('P-3 commands parse with explicit words, keyed only for copy init, seal and session, and refuse extra arguments', () => {
  assert.equal(parse(['vault', 'copy', 'init', 'D:/copy', '--adopt']).adopt, true);
  assert.equal(parse(['vault', 'copy', 'init', 'D:/copy']).command, 'vault copy init');
  assert.equal(parse(['vault', 'copy', 'init', 'D:/copy']).target, 'D:/copy');
  assert.equal(parse(['vault', 'copy', 'init', 'D:/copy', '--label', 'offsite']).label, 'offsite');
  assert.equal(parse(['vault', 'seal', 'D:/copy', '--copy', 'offsite', '--qr-invert']).copyLabel, 'offsite');
  assert.equal(parse(['vault', 'session', 'D:/copy']).command, 'vault session');
  assert.equal(parse(['vault', 'export-iso', 'out.iso', '--include-keyring-irreversible']).includeKeyring, true);
  assert.equal(parse(['vault', 'schedule', 'set', '--cadence', 'daily', '--verify']).verifyChain, true);
  assert.equal(parse(['vault', 'reminder', '--verify']).verifyChain, true);
  assert.equal(parse(['vault', 'status']).command, 'vault status');
  assert.equal(parse(['vault', 'schedule', 'remove']).command, 'vault schedule remove');
  for (const argv of [
    ['vault', 'copy', 'init'], ['vault', 'copy', 'init', 'a', 'b'], ['vault', 'seal'], ['vault', 'export-iso'],
    ['vault', 'schedule', 'set'], ['vault', 'schedule', 'set', '--cadence', 'hourly'], ['vault', 'copy'],
    ['vault', 'status', 'extra'], ['vault', 'export-iso', 'x.iso', '--passphrase-stdin'],
  ]) {
    // A usage error, or the secret-input guard for an extra positional (it could be a mistyped secret).
    assert.throws(() => parse(argv), undefined, argv.join(' '));
  }
  // The existing two-word vault commands keep their meaning.
  assert.equal(parse(['vault', 'verify']).command, 'vault verify');
  assert.equal(parse(['vault', 'reset-passphrase']).command, 'vault reset-passphrase');
});

test('copy init, seal, status: one KDF run each, a verifiable copy, the anchor, the copy.sealed event and no echoed path', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive-TEST-ONLY-marker');
  const init = await copyInit(dir, home, drive, ['--label', 'offsite']);
  assert.equal(init.code, 0, init.stderr);
  assert.equal(init.kdf, 1);
  assert.match(init.stdout, /Second copy "offsite" is ready/u);
  assert.match(init.stderr, /same disk as this vault/u, 'the same-disk warning');
  await addEvent(dir, home);
  const first = await seal(dir, home, drive);
  assert.equal(first.code, 0, first.stderr);
  assert.equal(first.kdf, 1);
  assert.match(first.stdout, /Second copy "offsite" sealed: segment 0 -> 1/u);
  assert.match(first.stdout, /foundry-anchor\/1;vault=[0-9a-f]{32};epoch=1;segment=1;manifest=[0-9a-f]{64};key=[0-9a-f]{64}/u);
  assert.match(first.stdout, /[\u2580\u2584\u2588]/u, 'a terminal QR code');
  assert.match(first.stdout, /switch on the drive's write-protect/u);
  assert.match(first.stdout, /tamper-evident/u);
  for (const output of [init.stdout, init.stderr, first.stdout, first.stderr]) {
    assert.ok(!output.includes('drive-TEST-ONLY-marker'), 'the drive path is never echoed');
  }
  const verified = verifyVault(drive, { secondCopy: true });
  assert.equal(verified.position.segment, 1);
  const register = JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8'));
  assert.equal(register.copies[0].label, 'offsite');
  assert.equal(register.copies[0].head.manifest_sha256, verified.position.hash);
  // The working vault recorded copy.sealed in its open segment; the next seal copies it and the reader ignores it.
  const second = await seal(dir, home, drive, ['--json']);
  assert.equal(second.code, 0, second.stderr);
  const summary = JSON.parse(second.stdout);
  assert.deepEqual([summary.previousSegment, summary.segment, summary.segmentsCopied], [1, 2, 1]);
  assert.match(summary.anchor, /^foundry-anchor\/1;/u);
  const profiles = await runInline(dir, ['profile', 'list', '--vault', home, '--passphrase-stdin'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(profiles.code, 0, profiles.stderr);
  const rebuild = await runInline(dir, ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(rebuild.code, 0, rebuild.stderr);
  const status = await runInline(dir, ['vault', 'status', '--vault', home]);
  assert.equal(status.code, 0, status.stderr);
  assert.equal(status.kdf, 0);
  assert.match(status.stdout, /^offsite {2}segment 2, sealed /mu);
  const late = await runInline(dir, ['vault', 'status', '--vault', home, '--json'], { hooks: { now: '2099-01-01T00:00:00Z' } });
  assert.equal(JSON.parse(late.stdout).overdue, true);
  assert.match(JSON.parse(late.stdout).banner, /SECOND COPY OVERDUE/u);
  // `vault session` is the same session; --anchor-svg writes the QR code as an SVG file (never over an existing file).
  const svg = join(dir, 'anchor.svg');
  const session = await runInline(dir, ['vault', 'session', drive, '--vault', home, '--passphrase-stdin', '--anchor-svg', svg],
    { stdin: `${PASSPHRASE}\n`, hooks: { secondCopyProbe: ntfs } });
  assert.equal(session.code, 0, session.stderr);
  assert.match(readFileSync(svg, 'utf8'), /^<\?xml [^\n]+\n<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/u);
});

test('a FAT drive and an unregistered folder are refused with fixed text; nothing is written', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'fat-drive');
  const refused = await copyInit(dir, home, drive, [], { secondCopyProbe: fat });
  assert.equal(refused.code, 2);
  assert.match(refused.stderr, /FAT32.*\[FILESYSTEM_UNSUPPORTED\]\n$/u);
  assert.equal(existsSync(drive), false);
  assert.equal(existsSync(join(home, REGISTER_NAME)), false);
  const none = await seal(dir, home, drive);
  assert.equal(none.code, 2);
  // R19-7: the keyless drive check before the lock finds no copy in the folder.
  assert.match(none.stderr, /\[NOT_A_COPY\]\n$/u);
  const ok = await copyInit(dir, home, drive);
  assert.equal(ok.code, 0, ok.stderr);
  const fatSeal = await seal(dir, home, drive, [], { secondCopyProbe: fat });
  assert.equal(fatSeal.code, 2);
  assert.match(fatSeal.stderr, /\[FILESYSTEM_UNSUPPORTED\]\n$/u);
  // Repeating init on the same folder finishes nothing new and adds no record.
  const again = await copyInit(dir, home, drive, ['--label', 'copy-1', '--json']);
  assert.equal(again.code, 0, again.stderr);
  assert.deepEqual([JSON.parse(again.stdout).created, JSON.parse(again.stdout).resumed], [false, true]);
  assert.equal(JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8')).copies.length, 1);
  // Once sealed, a record's label is taken.
  assert.equal((await seal(dir, home, drive)).code, 0);
  const taken = await copyInit(dir, home, join(dir, 'other-drive'), ['--label', 'copy-1']);
  assert.match(taken.stderr, /\[INVALID_LABEL\]\n$/u);
});

test('the register is a projection of the events: a lost or flagged register is rebuilt and still catches a rollback', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  assert.equal((await copyInit(dir, home, drive, ['--label', 'offsite'])).code, 0);
  await addEvent(dir, home);
  assert.equal((await seal(dir, home, drive)).code, 0);
  const old = join(dir, 'old-drive');
  cpSync(drive, old, { recursive: true });
  await addEvent(dir, home);
  assert.equal((await seal(dir, home, drive)).code, 0);
  const sealedRegister = JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8'));
  // The register file is lost. Keyless status cannot replay, so it says so instead of claiming no copy exists.
  unlinkSync(join(home, REGISTER_NAME));
  const status = await runInline(dir, ['vault', 'status', '--vault', home, '--json']);
  assert.equal(status.code, 0, status.stderr);
  assert.equal(JSON.parse(status.stdout).needsReplay, true);
  assert.match(JSON.parse(status.stdout).banner, /No second copy is recorded on this device.*rebuilds the record/u);
  assert.equal(existsSync(join(home, REGISTER_NAME)), false, 'status writes nothing');
  // The next keyed command rebuilds it from copy.registered and copy.sealed: the old drive is still a rollback.
  const stopped = await seal(dir, home, old);
  assert.match(stopped.stderr, /\[ROLLBACK_DETECTED\]\n$/u);
  const resealed = await seal(dir, home, drive, ['--json']);
  assert.equal(resealed.code, 0, resealed.stderr);
  const rebuilt = JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8'));
  assert.equal(rebuilt.needs_replay, false);
  assert.deepEqual(rebuilt.copies.map(c => [c.copy_id, c.label]), sealedRegister.copies.map(c => [c.copy_id, c.label]));
  assert.equal(rebuilt.copies[0].head.segment, JSON.parse(resealed.stdout).segment);
  // A register flagged between an event and its write (a crash there), with a stale head, is rebuilt too.
  const flaggedBytes = readFileSync(join(home, REGISTER_NAME), 'utf8')
    .replace('"needs_replay":false', '"needs_replay":true');
  writeFileSync(join(home, REGISTER_NAME), flaggedBytes);
  const flagged = await seal(dir, home, old);
  assert.match(flagged.stderr, /\[ROLLBACK_DETECTED\]\n$/u);
});

test('a copy has an identity: --copy must match the drive, a foreign copy needs --adopt, and the ids are printed', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const one = join(dir, 'one');
  const two = join(dir, 'two');
  assert.equal((await copyInit(dir, home, one, ['--label', 'first'])).code, 0);
  assert.equal((await copyInit(dir, home, two, ['--label', 'second'])).code, 0);
  await addEvent(dir, home);
  // Without --copy the drive's COPY.json picks the record; with a wrong --copy the session stops before any write.
  assert.equal((await seal(dir, home, two, ['--json'])).code, 0);
  const before = readFileSync(join(home, REGISTER_NAME));
  const wrong = await seal(dir, home, one, ['--copy', 'second']);
  assert.match(wrong.stderr, /copy id differs.*\[COPY_MISMATCH\]\n$/u);
  assert.deepEqual(readFileSync(join(home, REGISTER_NAME)), before);
  // A copy of this vault that names an id this device does not know.
  const foreign = join(dir, 'foreign');
  cpSync(one, foreign, { recursive: true });
  const metadata = JSON.parse(readFileSync(join(foreign, 'VAULT.json'), 'utf8'));
  const oldId = 'c3'.repeat(16);
  writeFileSync(join(foreign, 'COPY.json'), `{"copy_id":"${oldId}","format":"foundry-copy/1","vault_id":"${metadata.vault_id}"}`);
  const refused = await copyInit(dir, home, foreign, ['--label', 'third']);
  assert.match(refused.stderr, /\[COPY_MISMATCH\]\n$/u);
  const adopted = await copyInit(dir, home, foreign, ['--label', 'third', '--adopt']);
  assert.equal(adopted.code, 0, adopted.stderr);
  const register = JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8'));
  const third = register.copies.find(c => c.label === 'third');
  assert.match(adopted.stdout, new RegExp(`copy id ${oldId} is replaced by ${third.copy_id}`, 'u'));
  assert.equal(JSON.parse(readFileSync(join(foreign, 'COPY.json'), 'utf8')).copy_id, third.copy_id);
  assert.equal((await seal(dir, home, foreign)).code, 0);
});

test('copy init is a transaction bound to its target: a retry finishes it, another drive never inherits it (R19-3)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const copies = () => JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8')).copies;
  // Finding 37: a second, different drive with the label of a finished but never sealed init gets no shared id.
  const one = join(dir, 'one');
  assert.equal((await copyInit(dir, home, one, ['--label', 'offsite'])).code, 0);
  const two = join(dir, 'two');
  const reused = await copyInit(dir, home, two, ['--label', 'offsite']);
  assert.match(reused.stderr, /\[INVALID_LABEL\]\n$/u);
  assert.equal(existsSync(two), false);
  assert.equal(copies().length, 1);
  assert.equal(existsSync(join(home, INIT_INTENT_NAME)), false, 'the finished init left no intent');
  // Finding 43: the drive is pulled after the registration and before COPY.json; an unlabelled retry finishes it.
  const three = join(dir, 'three');
  const pulled = await copyInit(dir, home, three, [], { secondCopyProbe: ntfs, failCopyInitAfterRegister: true });
  assert.match(pulled.stderr, /\[IO\]\n$/u);
  assert.equal(copies().length, 2);
  assert.equal(existsSync(join(home, INIT_INTENT_NAME)), true);
  const retried = await copyInit(dir, home, three, ['--json']);
  assert.equal(retried.code, 0, retried.stderr);
  assert.equal(copies().length, 2, 'no second record');
  assert.equal(JSON.parse(readFileSync(join(three, 'COPY.json'), 'utf8')).copy_id, JSON.parse(retried.stdout).copyId);
  assert.equal(JSON.parse(retried.stdout).label, copies()[1].label);
  assert.equal(existsSync(join(home, INIT_INTENT_NAME)), false);
  // An adoption pulled at the same point is finished by the same command (its label is not "taken").
  const foreign = join(dir, 'foreign');
  cpSync(one, foreign, { recursive: true });
  const metadata = JSON.parse(readFileSync(join(foreign, 'VAULT.json'), 'utf8'));
  const oldId = 'd4'.repeat(16);
  writeFileSync(join(foreign, 'COPY.json'), `{"copy_id":"${oldId}","format":"foundry-copy/1","vault_id":"${metadata.vault_id}"}`);
  const adoptPulled = await copyInit(dir, home, foreign, ['--label', 'taken-over', '--adopt'], { secondCopyProbe: ntfs, failCopyInitAfterRegister: true });
  assert.match(adoptPulled.stderr, /\[IO\]\n$/u);
  const adopted = await copyInit(dir, home, foreign, ['--label', 'taken-over', '--adopt', '--json']);
  assert.equal(adopted.code, 0, adopted.stderr);
  assert.deepEqual([JSON.parse(adopted.stdout).adopted, JSON.parse(adopted.stdout).adoptedFrom], [true, oldId]);
  assert.equal(copies().filter(c => c.label === 'taken-over').length, 1);
  // A different target never inherits a pending intent.
  const four = join(dir, 'four');
  assert.equal((await copyInit(dir, home, four, [], { secondCopyProbe: ntfs, failCopyInitAfterRegister: true })).code, 2);
  const pending = copies().at(-1);
  const five = join(dir, 'five');
  const other = await copyInit(dir, home, five, ['--json']);
  assert.equal(other.code, 0, other.stderr);
  assert.notEqual(JSON.parse(other.stdout).copyId, pending.copy_id);
});

test('a rolled-back drive stops the session with ROLLBACK_DETECTED and changes nothing', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  await copyInit(dir, home, drive);
  await addEvent(dir, home);
  assert.equal((await seal(dir, home, drive)).code, 0);
  const old = join(dir, 'old-drive');
  cpSync(drive, old, { recursive: true });
  assert.equal((await seal(dir, home, drive)).code, 0);
  const head = readFileSync(join(home, 'vault', 'HEAD.json'));
  // R19-7 (42): the refusal comes from the check before the working-home lock, the secrets and any drive write.
  const lockSeen = [];
  const oldDrive = readdirSync(old).sort();
  const stopped = await seal(dir, home, old, [], {
    secondCopyProbe: () => { lockSeen.push(existsSync(join(home, 'foundry.lock'))); return ntfs(); },
  });
  assert.equal(stopped.code, 2);
  assert.match(stopped.stderr, /^foundry: STOP: the second copy is older .*\[ROLLBACK_DETECTED\]\n$/u);
  assert.deepEqual(lockSeen, [false], 'checked once, before the lock');
  assert.equal(stopped.kdf, 0, 'refused before the passphrase is used');
  assert.equal(existsSync(join(home, 'foundry.lock')), false);
  assert.deepEqual(readdirSync(old).sort(), oldDrive, 'nothing added to the drive');
  assert.deepEqual(readFileSync(join(home, 'vault', 'HEAD.json')), head, 'the working head is unchanged');
  assert.equal(verifyVault(old, { secondCopy: true }).position.segment, 1);
});

test('an interrupted seal is finished by the next one', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  await copyInit(dir, home, drive);
  await addEvent(dir, home);
  const pulled = await seal(dir, home, drive, [], {
    secondCopyProbe: ntfs, copyCheckpoint: point => { if (point === 'after-manifest-pending') throw Object.assign(new Error('TEST ONLY pulled'), { code: 'EIO' }); },
  });
  assert.equal(pulled.code, 2);
  assert.match(pulled.stderr, /\[IO\]\n$/u);
  const next = await seal(dir, home, drive);
  assert.equal(next.code, 0, next.stderr);
  assert.match(next.stdout, /unfinished segment 1 from an interrupted session was removed/u);
  assert.equal(verifyVault(drive, { secondCopy: true }).position.segment, 1);
});

test('export-iso writes a keyless image by default and warns before an irreversible keyring export', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  await copyInit(dir, home, drive);
  await addEvent(dir, home);
  const sealed = await seal(dir, home, drive);
  assert.equal(sealed.code, 0, sealed.stderr);
  const iso = join(dir, 'vault.iso');
  const plain = await runInline(dir, ['vault', 'export-iso', iso, '--vault', home]);
  assert.equal(plain.code, 0, plain.stderr);
  assert.equal(plain.kdf, 0);
  assert.equal(plain.stderr, '');
  assert.match(plain.stdout, /keyring not included/u);
  assert.match(plain.stdout, /single, finalised \(closed\) session/u);
  assert.match(plain.stdout, /foundry-anchor\/1;/u);
  assert.equal(statSync(iso).size % 2048, 0);
  assert.ok(!readFileSync(iso).includes(Buffer.from('keyring.json')), 'no keyring entry in the primary tree');
  const exists = await runInline(dir, ['vault', 'export-iso', iso, '--vault', home]);
  assert.match(exists.stderr, /\[OUTPUT_EXISTS\]\n$/u);
  const keyed = await runInline(dir, ['vault', 'export-iso', join(dir, 'with-key.iso'), '--vault', home, '--include-keyring-irreversible', '--json']);
  assert.equal(keyed.code, 0, keyed.stderr);
  assert.match(keyed.stderr, /^foundry: warning: --include-keyring-irreversible .*can never be destroyed/u);
  assert.equal(JSON.parse(keyed.stdout).keyringIncluded, true);
});

test('schedule set, status and remove run the scheduler with explicit argv and leave nothing behind', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const config = join(dir, 'config');
  const calls = [];
  let table = '';
  const schedulerRunner = (command, args, input) => {
    calls.push([command, ...args]);
    // `is-active` exits 3 for an inactive unit (the timer is stopped once `disable --now` ran).
    if (command === 'systemctl') return { status: args[1] === 'is-active' ? 3 : 0, stdout: '', stderr: '' };
    if (command === 'crontab') {
      if (args[0] === '-l') return table ? { status: 0, stdout: table, stderr: '' } : { status: 1, stdout: '', stderr: 'no crontab for test-only' };
      table = input;
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  const hooks = { schedulerRunner, schedulerPlatform: 'linux', schedulerConfigHome: config };
  const set = await runInline(dir, ['vault', 'schedule', 'set', '--cadence', 'daily', '--verify', '--vault', home], { hooks });
  assert.equal(set.code, 0, set.stderr);
  assert.equal(set.kdf, 0);
  assert.match(set.stdout, /Reminder installed \(systemd, daily\)\. It never reads a key/u);
  const unitDir = join(config, 'systemd', 'user');
  const name = calls.find(argv => argv[2] === 'enable')[4].replace(/\.timer$/u, '');
  const service = readFileSync(join(unitDir, `${name}.service`), 'utf8');
  assert.match(service, /"vault" "reminder" "--vault" "[^"]+" "--verify"/u);
  assert.match(service, /bin[\\/]+foundry\.mjs"/u);
  assert.equal(JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8')).cadence, 'daily');
  const status = await runInline(dir, ['vault', 'schedule', 'status', '--vault', home, '--json'], { hooks });
  assert.deepEqual(JSON.parse(status.stdout).installed, ['systemd']);
  const removed = await runInline(dir, ['vault', 'schedule', 'remove', '--vault', home], { hooks });
  assert.equal(removed.code, 0, removed.stderr);
  assert.equal(existsSync(join(unitDir, `${name}.timer`)), false);
  assert.equal(existsSync(join(unitDir, `${name}.service`)), false);
  const manual = await runInline(dir, ['vault', 'schedule', 'set', '--cadence', 'manual', '--vault', home], { hooks });
  assert.match(manual.stdout, /Cadence: manual\. No reminder job is installed/u);
  assert.equal(JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8')).cadence, 'manual');
  // Windows: one per-user schtasks task from an XML file that is removed again.
  const win = [];
  let task = false;
  const winHooks = {
    schedulerPlatform: 'win32',
    schedulerRunner: (command, args) => {
      win.push([command, ...args]);
      if (args[0] === '/Create') task = existsSync(args[args.indexOf('/XML') + 1]);
      if (args[0] === '/Delete') task = false;
      if (args[0] === '/Query') {
        const name = /foundry-vault-reminder-[0-9a-f]{12}/u.exec(JSON.stringify(win))?.[0];
        return { status: 0, stdout: task && name ? `"\\${name}","N/A","Ready"\r\n` : '', stderr: '' };
      }
      return { status: 0, stdout: '', stderr: '' };
    },
  };
  const winSet = await runInline(dir, ['vault', 'schedule', 'set', '--cadence', 'weekly', '--vault', home], { hooks: winHooks });
  assert.equal(winSet.code, 0, winSet.stderr);
  assert.equal(task, true);
  assert.deepEqual(win[0].slice(0, 3), ['schtasks', '/Create', '/TN']);
  assert.ok(!existsSync(win[0][win[0].indexOf('/XML') + 1]), 'the task XML file is removed');
  const winRemove = await runInline(dir, ['vault', 'schedule', 'remove', '--vault', home], { hooks: winHooks });
  assert.equal(winRemove.code, 0);
  assert.equal(task, false);
});

test('the reminder is keyless, records the check and shows the overdue banner', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const reminder = await runInline(dir, ['vault', 'reminder', '--verify', '--vault', home]);
  assert.equal(reminder.code, 0, reminder.stderr);
  assert.equal(reminder.kdf, 0);
  assert.match(reminder.stdout, /No second copy is recorded on this device/u);
  assert.match(reminder.stdout, /Keyless vault check: ok\./u);
  assert.equal(JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8')).last_check.verify, 'ok');
});

test('a seal before any profile or import: the next profile, import, search and seal still work', async t => {
  // A user who sets up the backup first: copy init creates `me`'s `system` key and `copy.registered` is the first
  // event, so the first seal closes and copies that one segment.
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  assert.equal((await copyInit(dir, home, drive)).code, 0);
  const first = await seal(dir, home, drive);
  assert.equal(first.code, 0, first.stderr);
  assert.match(first.stdout, /sealed: segment 0 -> 1, 1 segment\(s\)/u);
  const { folder } = await takeoutFolder(dir);
  const imported = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(imported.code, 0, imported.stderr);
  assert.ok(JSON.parse(imported.stdout).itemsAdded > 0);
  await addEvent(dir, home);
  const profiles = await runInline(dir, ['profile', 'list', '--vault', home, '--passphrase-stdin', '--json'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(profiles.code, 0, profiles.stderr);
  assert.deepEqual(JSON.parse(profiles.stdout).profiles.map(p => p.profile), ['me']);
  const found = await runInline(dir, ['search', 'Subject', '--vault', home, '--passphrase-stdin', '--json'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(found.code, 0, found.stderr);
  assert.ok(JSON.parse(found.stdout).results.length > 0);
  const second = await seal(dir, home, drive, ['--json']);
  assert.equal(second.code, 0, second.stderr);
  const summary = JSON.parse(second.stdout);
  assert.ok(summary.segment >= 2);
  assert.equal(verifyVault(drive, { secondCopy: true }).position.segment, summary.segment);
  const rebuild = await runInline(dir, ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], { stdin: `${PASSPHRASE}\n` });
  assert.equal(rebuild.code, 0, rebuild.stderr);
});

test('verify-copy checks a copy against the printed anchor and the recorded seal; an older copy fails (finding 32)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  assert.equal((await copyInit(dir, home, drive)).code, 0);
  await addEvent(dir, home);
  const first = JSON.parse((await seal(dir, home, drive, ['--json'])).stdout);
  const old = join(dir, 'old');
  cpSync(drive, old, { recursive: true });
  await addEvent(dir, home);
  const second = JSON.parse((await seal(dir, home, drive, ['--json'])).stdout);
  const ok = await runInline(dir, ['vault', 'verify-copy', drive, '--vault', home, '--anchor', second.anchor, '--json']);
  assert.equal(ok.code, 0, ok.stderr);
  assert.equal(ok.kdf, 0);
  assert.deepEqual(JSON.parse(ok.stdout), { ok: true, segment: second.segment, manifestSha256: second.manifestSha256, anchorChecked: true, recorded: 'none' });
  // The older copy is internally valid, but not against the newer anchor or the recorded seal.
  const anchored = await runInline(dir, ['vault', 'verify-copy', old, '--vault', home, '--anchor', second.anchor]);
  assert.match(anchored.stderr, /\[ANCHOR\]\n$/u);
  assert.equal((await runInline(dir, ['vault', 'verify-copy', old, '--vault', home, '--anchor', first.anchor])).code, 0);
  const recorded = await runInline(dir, ['vault', 'verify-copy', old, '--vault', home]);
  assert.match(recorded.stderr, /\[ROLLBACK_DETECTED\]\n$/u);
  const current = await runInline(dir, ['vault', 'verify-copy', drive, '--vault', home]);
  assert.equal(current.code, 0, current.stderr);
  assert.match(current.stdout, /^Second copy OK: segment \d+; its head is the seal recorded on this device\.\n$/u);
  const bad = await runInline(dir, ['vault', 'verify-copy', drive, '--vault', home, '--anchor', 'TEST ONLY not an anchor']);
  assert.match(bad.stderr, /\[ANCHOR\]\n$/u);
  // R19-4 (44): with --anchor, no Foundry home is needed (no home preflight, no lock).
  const nowhere = join(dir, 'no-foundry-home');
  const clean = await runInline(dir, ['vault', 'verify-copy', drive, '--vault', nowhere, '--anchor', second.anchor, '--json']);
  assert.equal(clean.code, 0, clean.stderr);
  assert.equal(JSON.parse(clean.stdout).segment, second.segment);
  assert.equal(existsSync(nowhere), false, 'nothing created for the missing home');
  // R19-4 (38): every comparison is required. A drive with another signing key in VAULT.json is refused.
  const resigned = join(dir, 'resigned');
  cpSync(drive, resigned, { recursive: true });
  const meta = JSON.parse(readFileSync(join(resigned, 'VAULT.json'), 'utf8'));
  const otherKey = Buffer.from(meta.signing_public_key, 'base64');
  otherKey[0] ^= 1;
  chmodSync(join(resigned, 'VAULT.json'), 0o644);
  writeFileSync(join(resigned, 'VAULT.json'), JSON.stringify({ ...meta, signing_public_key: otherKey.toString('base64') }));
  assert.match((await runInline(dir, ['vault', 'verify-copy', resigned, '--vault', home])).stderr, /\[VAULT_MISMATCH\]\n$/u);
  // No COPY.json: the selected copy's identity is required.
  const anonymous = join(dir, 'anonymous');
  cpSync(drive, anonymous, { recursive: true });
  chmodSync(join(anonymous, 'COPY.json'), 0o644);
  unlinkSync(join(anonymous, 'COPY.json'));
  assert.match((await runInline(dir, ['vault', 'verify-copy', anonymous, '--vault', home])).stderr, /\[COPY_UNVERIFIABLE\]\n$/u);
  assert.match((await runInline(dir, ['vault', 'verify-copy', anonymous, '--vault', home, '--copy', 'copy-1'])).stderr,
    /\[COPY_MISMATCH\]\n$/u);
  // A copy never sealed, and a lost register: the comparison cannot be done, so the command fails.
  const fresh = join(dir, 'fresh');
  assert.equal((await copyInit(dir, home, fresh, ['--label', 'fresh'])).code, 0);
  assert.match((await runInline(dir, ['vault', 'verify-copy', fresh, '--vault', home])).stderr, /\[COPY_UNVERIFIABLE\]\n$/u);
  unlinkSync(join(home, REGISTER_NAME));
  const lost = await runInline(dir, ['vault', 'verify-copy', drive, '--vault', home, '--json']);
  assert.equal(lost.code, 2);
  assert.equal(lost.stdout, '');
  assert.match(lost.stderr, /\[COPY_UNVERIFIABLE\]\n$/u);
  // The seal output points at the new command.
  assert.match((await seal(dir, home, drive)).stdout, /foundry vault verify-copy <folder> --anchor/u);
});

test('verify-copy reads a planted 256 MiB manifest by no more than its size check (keyless ceiling, R19-4, 39)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  assert.equal((await copyInit(dir, home, drive)).code, 0);
  await addEvent(dir, home);
  const sealed = JSON.parse((await seal(dir, home, drive, ['--json'])).stdout);
  const folder = join(drive, 'segments', '000001');
  chmodSync(folder, 0o755);
  const manifest = join(folder, 'MANIFEST.json');
  chmodSync(manifest, 0o644);
  truncateSync(manifest, 256 * 1024 * 1024);
  const before = process.resourceUsage().maxRSS;
  for (const extra of [['--anchor', sealed.anchor], []]) {
    const result = await runInline(dir, ['vault', 'verify-copy', drive, '--vault', home, ...extra]);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /\(INVENTORY\) \[COPY_VERIFY_FAILED\]\n$/u, result.stderr);
  }
  const grownKiB = process.resourceUsage().maxRSS - before;
  assert.ok(grownKiB < 128 * 1024, `peak memory grew by ${grownKiB} KiB`);
});

test('anchor SVG: checked before the seal; a failed write after the seal still prints the anchor and step 9 (findings 17, 18)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const drive = join(dir, 'drive');
  assert.equal((await copyInit(dir, home, drive)).code, 0);
  await addEvent(dir, home);
  const registerBefore = readFileSync(join(home, REGISTER_NAME));
  const existing = join(dir, 'exists.svg');
  writeFileSync(existing, 'TEST ONLY');
  for (const [svg, code] of [[existing, 'OUTPUT_EXISTS'], [join(drive, 'anchor.svg'), 'OUTPUT_UNSUITABLE'],
    [join(home, 'vault', 'anchor.svg'), 'OUTPUT_UNSUITABLE'], [join(dir, 'missing', 'anchor.svg'), 'IO']]) {
    const refused = await seal(dir, home, drive, ['--anchor-svg', svg]);
    assert.equal(refused.code, 2, code);
    assert.match(refused.stderr, new RegExp(`\\[${code}\\]\\n$`, 'u'));
    assert.equal(refused.kdf, 0, 'refused before the passphrase is used');
    assert.deepEqual(readFileSync(join(home, REGISTER_NAME)), registerBefore, 'no seal recorded');
  }
  assert.equal(verifyVault(drive, { secondCopy: true }).position.segment, 0);
  const svg = join(dir, 'anchor.svg');
  const failed = await seal(dir, home, drive, ['--anchor-svg', svg], { secondCopyProbe: ntfs, failAnchorSvgWrite: true });
  assert.equal(failed.code, 0, failed.stderr);
  assert.match(failed.stderr, /^foundry: warning: the seal is complete, but the anchor SVG file could not be written/mu);
  assert.match(failed.stdout, /foundry-anchor\/1;/u);
  assert.match(failed.stdout, /switch on the drive's write-protect .* and disconnect the drive\.\n$/u);
  await addEvent(dir, home);
  const json = await seal(dir, home, drive, ['--anchor-svg', join(dir, 'b.svg'), '--json'], { secondCopyProbe: ntfs, failAnchorSvgWrite: true });
  assert.equal(JSON.parse(json.stdout).anchorSvgWritten, false);
  assert.match(JSON.parse(json.stdout).nextSteps[0], /write-protect/u);
  const written = await seal(dir, home, drive, ['--anchor-svg', svg, '--json']);
  assert.equal(JSON.parse(written.stdout).anchorSvgWritten, true);
  assert.match(readFileSync(svg, 'utf8'), /^<\?xml [^\n]*\n<svg /u);
});

test('export-iso: refuses a file inside the vault, a missing folder has fixed text, and JSON names the finalisation step', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const inside = await runInline(dir, ['vault', 'export-iso', join(home, 'vault', 'x.iso'), '--vault', home]);
  assert.match(inside.stderr, /\[OUTPUT_UNSUITABLE\]\n$/u);
  const marker = 'TEST-ONLY-missing-marker';
  const missing = await runInline(dir, ['vault', 'export-iso', join(dir, marker, 'x.iso'), '--vault', home, '--debug']);
  assert.match(missing.stderr, /\[IO\]\n$/u);
  assert.ok(!missing.stderr.includes(marker), 'the path is not echoed, even with --debug');
  const json = await runInline(dir, ['vault', 'export-iso', join(dir, 'genesis.iso'), '--vault', home, '--json']);
  assert.equal(json.code, 0, json.stderr);
  assert.deepEqual(JSON.parse(json.stdout).nextSteps, ['Burn it as a single, finalised (closed) session, so nothing can be appended to the disc later.']);
});

test('--debug never prints a P-3 path operand: a raw file-system error becomes fixed text (finding 16)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const file = join(dir, 'TEST-ONLY-regular-file-marker');
  writeFileSync(file, 'TEST ONLY');
  const below = join(file, 'copy');
  const result = await copyInit(dir, home, below, ['--debug']);
  assert.equal(result.code, 2);
  assert.ok(!result.stderr.includes('TEST-ONLY-regular-file-marker'), result.stderr);
  const sealed = await seal(dir, home, below, ['--debug']);
  assert.equal(sealed.code, 2);
  assert.ok(!sealed.stderr.includes('TEST-ONLY-regular-file-marker'), sealed.stderr);
  const verified = await runInline(dir, ['vault', 'verify-copy', below, '--vault', home, '--debug']);
  assert.equal(verified.code, 2);
  assert.ok(!verified.stderr.includes('TEST-ONLY-regular-file-marker'), verified.stderr);
});

test('Linux reminder: notify-send with explicit argv when a session bus exists, and the line is always printed (finding 21)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const calls = [];
  const schedulerRunner = (command, args) => { calls.push([command, ...args]); return { status: 0, stdout: '', stderr: '' }; };
  const hooks = { schedulerPlatform: 'linux', schedulerRunner, reminderEnv: { XDG_RUNTIME_DIR: '/run/user/1000' }, reminderBusExists: () => true };
  const shown = await runInline(dir, ['vault', 'reminder', '--vault', home, '--json'], { hooks });
  assert.equal(shown.code, 0, shown.stderr);
  assert.equal(JSON.parse(shown.stdout).delivered, 'notify-send');
  assert.deepEqual(calls[0].slice(0, 4), ['notify-send', '--app-name=Foundry', '--', 'Foundry second copy']);
  assert.match(calls[0][4], /No second copy is recorded on this device/u);
  const noBus = await runInline(dir, ['vault', 'reminder', '--vault', home], { hooks: { ...hooks, reminderEnv: {}, reminderBusExists: () => false } });
  assert.match(noBus.stdout, /No second copy is recorded on this device/u);
  assert.equal(calls.length, 1, 'no notify-send without a session bus');
});

test('schedule set restores the previous cadence when the scheduler refuses the job (finding 28)', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const config = join(dir, 'config');
  const ok = { schedulerPlatform: 'linux', schedulerConfigHome: config, schedulerRunner: () => ({ status: 0, stdout: '', stderr: '' }) };
  assert.equal((await runInline(dir, ['vault', 'schedule', 'set', '--cadence', 'monthly', '--vault', home], { hooks: ok })).code, 0);
  const broken = {
    schedulerPlatform: 'linux', schedulerConfigHome: config,
    schedulerRunner: command => (command === 'systemctl' ? { status: 1, stdout: '', stderr: '' } : { status: null, stdout: '', stderr: '' }),
  };
  const refused = await runInline(dir, ['vault', 'schedule', 'set', '--cadence', 'daily', '--vault', home], { hooks: broken });
  assert.match(refused.stderr, /\[SCHEDULER_FAILED\]\n$/u);
  assert.equal(JSON.parse(readFileSync(join(home, REGISTER_NAME), 'utf8')).cadence, 'monthly');
});

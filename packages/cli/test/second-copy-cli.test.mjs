// TEST ONLY: `foundry vault` second-copy, export and reminder commands (P-3). Every vault, secret and path is synthetic.
import assert from 'node:assert/strict';
import { cpSync, existsSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { verifyVault } from 'vault';
import { parseCommandLine } from '../dist/args.js';
import { REGISTER_NAME } from '../dist/commands.js';
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
  assert.match(none.stderr, /\[COPY_UNKNOWN\]\n$/u);
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
  const stopped = await seal(dir, home, old);
  assert.equal(stopped.code, 2);
  assert.match(stopped.stderr, /^foundry: STOP: the second copy is older .*\[ROLLBACK_DETECTED\]\n$/u);
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
    if (command === 'systemctl') return { status: 0, stdout: '', stderr: '' };
    if (command === 'crontab') {
      if (args[0] === '-l') return { status: table ? 0 : 1, stdout: table, stderr: '' };
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
      return { status: args[0] === '/Query' && !task ? 1 : 0, stdout: '', stderr: '' };
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

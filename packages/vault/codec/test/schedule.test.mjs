// TEST ONLY: scheduler reminders (P-3). A fake runner records argv; no real scheduler is touched.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempDisposableSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import {
  cronLine, installReminder, reminderArgs, reminderName, reminderStatus, removeReminder, runReminder, systemdUnits,
  utf16leWithBom, windowsTaskXml,
} from '../src/schedule.ts';
import { addCopyRecord, readCopyRegister, recordSeal, writeCopyRegister } from '../src/second-copy.ts';
import { fixture, identity } from './vault-fixture.mjs';

function scratch(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-schedule-'));
  t.after(() => temp.remove());
  return temp.path;
}

/** A fake system: `responses` maps "command arg0" to a result; the crontab is kept in memory. */
function fakeSystem({ systemd = true, crontab = true, schtasks = true, existingCron = '' } = {}) {
  const calls = [];
  let table = existingCron;
  let task = false;
  const run = (command, args, input) => {
    calls.push({ argv: [command, ...args], input });
    if (command === 'systemctl') return { status: systemd ? 0 : 1, stdout: '', stderr: systemd ? '' : 'TEST ONLY no bus' };
    if (command === 'crontab') {
      if (!crontab) return { status: null, stdout: '', stderr: '' };
      if (args[0] === '-l') return table ? { status: 0, stdout: table, stderr: '' } : { status: 1, stdout: '', stderr: 'no crontab' };
      table = input;
      return { status: 0, stdout: '', stderr: '' };
    }
    if (command === 'schtasks') {
      if (!schtasks) return { status: 1, stdout: '', stderr: 'TEST ONLY denied' };
      if (args[0] === '/Create') {
        const xml = readFileSync(args[args.indexOf('/XML') + 1]);
        calls.at(-1).xml = xml;
        task = true;
        return { status: 0, stdout: '', stderr: '' };
      }
      if (args[0] === '/Query') return { status: task ? 0 : 1, stdout: '', stderr: '' };
      if (args[0] === '/Delete') { task = false; return { status: 0, stdout: '', stderr: '' }; }
    }
    return { status: null, stdout: '', stderr: '' };
  };
  return { run, calls, crontab: () => table, task: () => task };
}

const job = (home, extra = {}) => ({
  home, node: resolve('/opt/test-only/node'), cli: resolve('/opt/test-only/foundry.mjs'), cadence: 'weekly', verify: false, ...extra,
});

test('the job name is stable per Foundry home and the job runs the keyless reminder command', () => {
  assert.equal(reminderName('/srv/a'), reminderName('/srv/a/'));
  assert.notEqual(reminderName('/srv/a'), reminderName('/srv/b'));
  assert.match(reminderName('/srv/a'), /^foundry-vault-reminder-[0-9a-f]{12}$/u);
  assert.deepEqual(reminderArgs(job('/srv/a', { verify: true })).slice(1), ['vault', 'reminder', '--vault', resolve('/srv/a'), '--verify']);
  assert.ok(!reminderArgs(job('/srv/a')).some(arg => /passphrase|recovery/u.test(arg)));
});

test('Windows: per-user schtasks with UTF-16LE XML, least privilege, no shell; status and remove leave nothing behind', t => {
  const home = scratch(t);
  const system = fakeSystem();
  const now = new Date(2026, 0, 7, 12, 0, 0);
  const result = installReminder(job(home, { cadence: 'weekly', verify: true }), { platform: 'win32', run: system.run, now });
  assert.equal(result.method, 'schtasks');
  const create = system.calls.find(call => call.argv[1] === '/Create');
  assert.deepEqual(create.argv.slice(0, 4), ['schtasks', '/Create', '/TN', result.name]);
  assert.deepEqual(create.argv.slice(-1), ['/F']);
  assert.ok(!create.argv.includes('/RU') && !create.argv.includes('/RL'), 'no other user, no elevated level');
  assert.deepEqual([...create.xml.subarray(0, 2)], [0xff, 0xfe]);
  const xml = Buffer.from(create.xml.subarray(2)).toString('utf16le');
  assert.match(xml, /<LogonType>InteractiveToken<\/LogonType><RunLevel>LeastPrivilege<\/RunLevel>/u);
  assert.match(xml, /<ScheduleByWeek><WeeksInterval>1<\/WeeksInterval><DaysOfWeek><Wednesday \/><\/DaysOfWeek>/u);
  assert.match(xml, /<StartBoundary>2026-01-07T09:00:00<\/StartBoundary>/u);
  assert.match(xml, /&quot;vault&quot; &quot;reminder&quot; &quot;--vault&quot;/u);
  assert.match(xml, /&quot;--verify&quot;<\/Arguments>/u);
  assert.deepEqual(readdirSync(home), [], 'the XML file is removed');
  assert.deepEqual(reminderStatus(home, { platform: 'win32', run: system.run }).installed, ['schtasks']);
  assert.deepEqual(removeReminder(home, { platform: 'win32', run: system.run }).removed, ['schtasks']);
  assert.equal(system.task(), false);
  assert.deepEqual(removeReminder(home, { platform: 'win32', run: system.run }).removed, []);
  assert.deepEqual(reminderStatus(home, { platform: 'win32', run: system.run }).installed, []);
  const denied = fakeSystem({ schtasks: false });
  assert.throws(() => installReminder(job(home), { platform: 'win32', run: denied.run }), { code: 'SCHEDULER_FAILED', reason: 'schtasks' });
  assert.deepEqual(readdirSync(home), []);
});

test('Windows XML covers daily and monthly cadences and refuses quotes and percent signs in paths', () => {
  assert.match(windowsTaskXml(job('/srv/a', { cadence: 'daily' })), /<ScheduleByDay><DaysInterval>1<\/DaysInterval>/u);
  assert.match(windowsTaskXml(job('/srv/a', { cadence: 'monthly' })), /<DaysOfMonth><Day>1<\/Day><\/DaysOfMonth>/u);
  assert.throws(() => windowsTaskXml(job('/srv/a', { cadence: 'manual' })), { code: 'INVALID_CADENCE' });
  assert.throws(() => windowsTaskXml(job('/srv/a"x')), { code: 'SCHEDULER_FAILED', reason: 'unsafe-path' });
  assert.throws(() => windowsTaskXml(job('/srv/%TEMP%')), { code: 'SCHEDULER_FAILED' });
  for (const control of ['\t', '\f', '\u0001', '\u007f']) {
    assert.throws(() => windowsTaskXml(job(`/srv/a${control}b`)), { code: 'SCHEDULER_FAILED', reason: 'unsafe-path' });
  }
  assert.deepEqual([...utf16leWithBom('A\u00e9')], [0xff, 0xfe, 0x41, 0, 0xe9, 0]);
});

test('Linux: systemd --user units with a persistent timer, enabled with explicit argv; remove disables and deletes them', t => {
  const config = scratch(t);
  const home = join(config, 'home');
  const system = fakeSystem();
  const result = installReminder(job(home, { cadence: 'monthly' }), { platform: 'linux', run: system.run, configHome: config });
  assert.equal(result.method, 'systemd');
  const unitDir = join(config, 'systemd', 'user');
  assert.deepEqual(readdirSync(unitDir).sort(), [`${result.name}.service`, `${result.name}.timer`]);
  const timer = readFileSync(join(unitDir, `${result.name}.timer`), 'utf8');
  assert.match(timer, /^OnCalendar=monthly$/mu);
  assert.match(timer, /^Persistent=true$/mu);
  const service = readFileSync(join(unitDir, `${result.name}.service`), 'utf8');
  assert.match(service, /^Type=oneshot$/mu);
  assert.match(service, /^ExecStart="[^"]+node" "[^"]+foundry\.mjs" "vault" "reminder" "--vault" "[^"]+"$/mu);
  assert.ok(system.calls.some(call => call.argv.join(' ') === `systemctl --user enable --now ${result.name}.timer`));
  assert.ok(system.calls.every(call => call.argv[0] !== 'sh' && call.argv[0] !== 'bash'));
  assert.deepEqual(reminderStatus(home, { platform: 'linux', run: system.run, configHome: config }).installed, ['systemd']);
  const removed = removeReminder(home, { platform: 'linux', run: system.run, configHome: config });
  assert.deepEqual(removed.removed, ['systemd']);
  assert.ok(removed.commands.some(argv => argv.join(' ') === `systemctl --user disable --now ${result.name}.timer`));
  assert.deepEqual(readdirSync(unitDir), []);
  assert.deepEqual(reminderStatus(home, { platform: 'linux', run: system.run, configHome: config }).installed, []);
});

test('Linux: without a user systemd the reminder falls back to a marked crontab line, keeps other lines, and is removed cleanly', t => {
  const config = scratch(t);
  const home = join(config, 'home');
  const system = fakeSystem({ systemd: false, existingCron: '0 3 * * * /usr/bin/true # TEST ONLY other job\n' });
  const result = installReminder(job(home, { cadence: 'daily', verify: true }), { platform: 'linux', run: system.run, configHome: config });
  assert.equal(result.method, 'cron');
  assert.equal(readdirSync(config).includes('systemd'), false, 'no unit files written');
  const lines = system.crontab().trim().split('\n');
  assert.equal(lines.length, 2);
  assert.equal(lines[0], '0 3 * * * /usr/bin/true # TEST ONLY other job');
  assert.equal(lines[1], cronLine(job(home, { cadence: 'daily', verify: true })));
  assert.match(lines[1], /^@daily '[^']+node' '[^']+foundry\.mjs' 'vault' 'reminder' '--vault' '[^']+' '--verify' # foundry-vault-reminder-/u);
  // Installing again replaces the line instead of adding a second one.
  installReminder(job(home, { cadence: 'weekly' }), { platform: 'linux', run: system.run, configHome: config });
  assert.equal(system.crontab().trim().split('\n').filter(line => line.includes(result.name)).length, 1);
  assert.match(system.crontab(), /^@weekly /mu);
  assert.deepEqual(reminderStatus(home, { platform: 'linux', run: system.run, configHome: config }).installed, ['cron']);
  assert.deepEqual(removeReminder(home, { platform: 'linux', run: system.run, configHome: config }).removed, ['cron']);
  assert.equal(system.crontab(), '0 3 * * * /usr/bin/true # TEST ONLY other job\n');
  const none = fakeSystem({ systemd: false, crontab: false });
  assert.throws(() => installReminder(job(home), { platform: 'linux', run: none.run, configHome: config }),
    { code: 'SCHEDULER_FAILED', reason: 'no-scheduler' });
  assert.throws(() => installReminder(job(home), { platform: 'darwin', run: none.run }), { code: 'SCHEDULER_UNSUPPORTED' });
});

test('systemd and cron quoting escape what they must and refuse what they cannot carry', () => {
  const units = systemdUnits(job('/srv/with space/$dir'));
  assert.match(units.service, /"--vault" "[^"]*with space[^"]*\$\$dir"/u);
  assert.match(cronLine(job("/srv/it's")), /'[^ ]*it'\\''s'/u);
  assert.throws(() => cronLine(job('/srv/a%b')), { code: 'SCHEDULER_FAILED' });
  assert.throws(() => systemdUnits(job('/srv/a\nb')), { code: 'SCHEDULER_FAILED' });
});

test('the reminder body is keyless: it records the check, can verify the working vault, and reports the banner', t => {
  const root = scratch(t);
  const vault = join(root, 'vault');
  mkdirSync(vault);
  fixture(vault);
  const path = join(root, 'second-copies.json');
  const none = runReminder(vault, path, { now: new Date('2026-03-01T00:00:00Z') });
  assert.equal(none.verify, 'skipped');
  assert.match(none.status.banner, /No second copy/u);
  assert.deepEqual(readCopyRegister(path, identity.vaultId).last_check, { checked_at: '2026-03-01T00:00:00Z', verify: 'skipped' });
  let { register, copy } = addCopyRecord(readCopyRegister(path, identity.vaultId), 'offsite', new Date('2026-01-01T00:00:00Z'));
  register = recordSeal(register, copy.copy_id, { head: { segment: 0, hash: '0'.repeat(64) }, sealedAt: '2026-01-01T00:00:00Z', keyringVersion: 1 });
  writeCopyRegister(path, register);
  const late = runReminder(vault, path, { verify: true, now: new Date('2026-03-01T00:00:00Z') });
  assert.equal(late.verify, 'ok');
  assert.equal(late.status.overdue, true);
  assert.match(late.status.banner, /SECOND COPY OVERDUE/u);
  writeFileSync(join(vault, 'HEAD.json'), '{"manifest_sha256":"TEST ONLY","segment":0}');
  const damaged = runReminder(vault, path, { verify: true, now: new Date('2026-03-02T00:00:00Z') });
  assert.equal(damaged.verify, 'failed');
  assert.equal(typeof damaged.verifyError, 'string');
  assert.equal(readCopyRegister(path, identity.vaultId).last_check.verify, 'failed');
});

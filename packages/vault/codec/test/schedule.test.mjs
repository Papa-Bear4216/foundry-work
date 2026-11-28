// TEST ONLY: scheduler reminders (P-3). A fake runner records argv; no real scheduler is touched.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempDisposableSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import {
  cronCommand, cronLine, installReminder, notifyDesktop, reminderArgs, reminderName, reminderStatus, removeReminder,
  runReminder, systemdUnits, systemdWord, utf16leWithBom, WINDOWS_CONSOLE, windowsConsoleArguments, windowsTaskXml,
} from '../src/schedule.ts';
import { addCopyRecord, readCopyRegister, recordSeal, writeCopyRegister } from '../src/second-copy.ts';
import { fixture, identity } from './vault-fixture.mjs';

function scratch(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-schedule-'));
  t.after(() => temp.remove());
  return temp.path;
}

/**
 * A fake system. systemd tracks which timers are active; the crontab is kept in memory; Task Scheduler answers the
 * CSV task list. Failure switches: `failEnable`, `failDisable`, `stayActive`, `crontabReadError`, `queryError`.
 */
function fakeSystem({
  systemd = true, crontab = true, schtasks = true, existingCron = '', failEnable = false, failDisable = false,
  stayActive = false, crontabReadError = false, queryError = false,
} = {}) {
  const calls = [];
  let table = existingCron;
  let task = false;
  const active = new Set();
  const run = (command, args, input) => {
    calls.push({ argv: [command, ...args], input });
    if (command === 'systemctl') {
      if (!systemd) return { status: 1, stdout: '', stderr: 'TEST ONLY no bus' };
      const [, verb, ...rest] = args;
      const unit = rest.at(-1);
      if (verb === 'enable') {
        if (failEnable) return { status: 1, stdout: '', stderr: 'TEST ONLY bad unit' };
        active.add(unit);
      }
      if (verb === 'disable') {
        if (failDisable) return { status: 1, stdout: '', stderr: 'TEST ONLY busy' };
        if (!stayActive) active.delete(unit);
      }
      if (verb === 'is-active') return { status: active.has(unit) ? 0 : 3, stdout: '', stderr: '' };
      return { status: 0, stdout: '', stderr: '' };
    }
    if (command === 'crontab') {
      if (!crontab) return { status: null, stdout: '', stderr: '' };
      if (args[0] === '-l') {
        if (crontabReadError) return { status: 1, stdout: '', stderr: 'TEST ONLY cannot open spool' };
        return table ? { status: 0, stdout: table, stderr: '' } : { status: 1, stdout: '', stderr: 'no crontab for test-only' };
      }
      table = input;
      return { status: 0, stdout: '', stderr: '' };
    }
    if (command === 'schtasks') {
      if (!schtasks) return { status: 1, stdout: '', stderr: 'TEST ONLY denied' };
      if (args[0] === '/Create') {
        const xml = readFileSync(args[args.indexOf('/XML') + 1]);
        calls.at(-1).xml = xml;
        task = args[args.indexOf('/TN') + 1];
        return { status: 0, stdout: '', stderr: '' };
      }
      if (args[0] === '/Query') {
        if (queryError) return { status: 1, stdout: '', stderr: 'TEST ONLY service unavailable' };
        const lines = ['"\\Other task","N/A","Ready"', ...(task ? [`"\\${task}","N/A","Ready"`] : [])];
        return { status: 0, stdout: `${lines.join('\r\n')}\r\n`, stderr: '' };
      }
      if (args[0] === '/Delete') { task = false; return { status: 0, stdout: '', stderr: '' }; }
    }
    return { status: null, stdout: '', stderr: '' };
  };
  return { run, calls, crontab: () => table, task: () => task, active };
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

test('Windows: per-user schtasks, logged-on only, a visible console that waits for Enter; status and remove check the task list', t => {
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
  // The action is the fixed console program with a fixed argv; only the validated paths vary (finding 21, R18-4).
  assert.match(xml, /<Command>%SystemRoot%\\System32\\cmd\.exe<\/Command>/u);
  const args = windowsConsoleArguments(job(home, { cadence: 'weekly', verify: true }));
  assert.equal(args, `/d /v:off /s /c ""${resolve('/opt/test-only/node')}" "${resolve('/opt/test-only/foundry.mjs')}" vault reminder `
    + `--vault "${resolve(home)}" --verify & set /p FOUNDRY_REMINDER_ENTER=Press Enter to close this window."`);
  assert.ok(xml.includes(`<Arguments>${args.replace(/&/gu, '&amp;').replace(/"/gu, '&quot;')}</Arguments>`));
  assert.equal(WINDOWS_CONSOLE, '%SystemRoot%\\System32\\cmd.exe');
  assert.deepEqual(readdirSync(home), [], 'the XML file is removed');
  assert.deepEqual(system.calls.filter(call => call.argv[1] === '/Query').map(call => call.argv), []);
  assert.deepEqual(reminderStatus(home, { platform: 'win32', run: system.run }).installed, ['schtasks']);
  assert.deepEqual(system.calls.at(-1).argv, ['schtasks', '/Query', '/FO', 'CSV', '/NH']);
  assert.deepEqual(removeReminder(home, { platform: 'win32', run: system.run }).removed, ['schtasks']);
  assert.equal(system.task(), false);
  assert.deepEqual(removeReminder(home, { platform: 'win32', run: system.run }).removed, []);
  assert.deepEqual(reminderStatus(home, { platform: 'win32', run: system.run }).installed, []);
  // A failed query is not "no task" (finding 23): status and remove report the failure.
  const broken = fakeSystem({ queryError: true });
  assert.throws(() => reminderStatus(home, { platform: 'win32', run: broken.run }), { code: 'SCHEDULER_FAILED', reason: 'schtasks-query' });
  assert.throws(() => removeReminder(home, { platform: 'win32', run: broken.run }), { code: 'SCHEDULER_FAILED', reason: 'schtasks-query' });
  const denied = fakeSystem({ schtasks: false });
  assert.throws(() => installReminder(job(home), { platform: 'win32', run: denied.run }), { code: 'SCHEDULER_FAILED', reason: 'schtasks' });
  assert.deepEqual(readdirSync(home), []);
});

test('Windows: the task name comes from the case-folded home path, so remove finds the task set created (R19-8)', t => {
  const home = scratch(t);
  assert.equal(reminderName('C:\\Test-Only\\Foundry', 'win32'), reminderName('c:\\TEST-ONLY\\foundry\\', 'win32'));
  assert.notEqual(reminderName('/srv/Test-Only', 'linux'), reminderName('/srv/test-only', 'linux'), 'Linux paths keep their case');
  const system = fakeSystem();
  const set = installReminder(job(home), { platform: 'win32', run: system.run, scratch: home });
  const status = reminderStatus(home.toUpperCase(), { platform: 'win32', run: system.run });
  assert.deepEqual([status.name, status.installed], [set.name, ['schtasks']]);
  assert.deepEqual(removeReminder(home.toLowerCase(), { platform: 'win32', run: system.run }).removed, ['schtasks']);
  assert.equal(system.task(), false);
});

test('Windows XML covers daily and monthly cadences and refuses quotes, percent signs and control characters in paths', () => {
  assert.match(windowsTaskXml(job('/srv/a', { cadence: 'daily' })), /<ScheduleByDay><DaysInterval>1<\/DaysInterval>/u);
  assert.match(windowsTaskXml(job('/srv/a', { cadence: 'monthly' })), /<DaysOfMonth><Day>1<\/Day><\/DaysOfMonth>/u);
  assert.throws(() => windowsTaskXml(job('/srv/a', { cadence: 'manual' })), { code: 'INVALID_CADENCE' });
  assert.throws(() => windowsTaskXml(job('/srv/a"x')), { code: 'SCHEDULER_FAILED', reason: 'unsafe-path' });
  assert.throws(() => windowsTaskXml(job('/srv/%TEMP%')), { code: 'SCHEDULER_FAILED' });
  for (const control of ['\t', '\f', '\u0001', '\u007f']) {
    assert.throws(() => windowsTaskXml(job(`/srv/a${control}b`)), { code: 'SCHEDULER_FAILED', reason: 'unsafe-path' });
  }
  // Characters cmd.exe treats literally inside double quotes are carried.
  assert.match(windowsConsoleArguments(job('/srv/a & b (c) ^d !e')), /"[^"]*a & b \(c\) \^d !e"/u);
  assert.deepEqual([...utf16leWithBom('A\u00e9')], [0xff, 0xfe, 0x41, 0, 0xe9, 0]);
});

test('Linux: systemd --user units with a persistent timer; remove disables, confirms inactive, then deletes', t => {
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
  const order = removed.commands.map(argv => argv.slice(1, 3).join(' '));
  assert.ok(order.indexOf('--user disable') < order.indexOf('--user is-active'));
  assert.deepEqual(readdirSync(unitDir), []);
  assert.deepEqual(reminderStatus(home, { platform: 'linux', run: system.run, configHome: config }).installed, []);
});

test('Linux remove keeps the units and reports failure when disable fails or the timer stays active (finding 23)', t => {
  for (const [options, reason] of [[{ failDisable: true }, 'systemd-disable'], [{ stayActive: true }, 'systemd-still-active']]) {
    const config = scratch(t);
    const home = join(config, 'home');
    const system = fakeSystem(options);
    installReminder(job(home), { platform: 'linux', run: system.run, configHome: config });
    const unitDir = join(config, 'systemd', 'user');
    const before = readdirSync(unitDir).sort();
    assert.throws(() => removeReminder(home, { platform: 'linux', run: system.run, configHome: config }), { code: 'SCHEDULER_FAILED', reason });
    assert.deepEqual(readdirSync(unitDir).sort(), before, reason);
  }
});

test('Linux replace keeps the old reminder when the new one cannot be enabled (finding 28)', t => {
  const config = scratch(t);
  const home = join(config, 'home');
  const unitDir = join(config, 'systemd', 'user');
  const good = fakeSystem();
  const first = installReminder(job(home, { cadence: 'weekly' }), { platform: 'linux', run: good.run, configHome: config });
  const before = readdirSync(unitDir).sort().map(name => [name, readFileSync(join(unitDir, name), 'utf8')]);
  const failing = fakeSystem({ failEnable: true });
  failing.active.add(`${first.name}.timer`);
  assert.throws(() => installReminder(job(home, { cadence: 'daily' }), { platform: 'linux', run: failing.run, configHome: config }),
    { code: 'SCHEDULER_FAILED' });
  assert.deepEqual(readdirSync(unitDir).sort().map(name => [name, readFileSync(join(unitDir, name), 'utf8')]), before);
  // An invalid job (here a NUL in a path) is refused before anything changes.
  assert.throws(() => installReminder(job(`${home}\u0000x`), { platform: 'linux', run: good.run, configHome: config }),
    { code: 'SCHEDULER_FAILED', reason: 'unsafe-path' });
  assert.deepEqual(readdirSync(unitDir).sort().map(name => [name, readFileSync(join(unitDir, name), 'utf8')]), before);
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
  assert.match(lines[1], /^@daily printf '[^'%]+' \| xargs -0 env -- # foundry-vault-reminder-[0-9a-f]{12}$/u);
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

test('a crontab that cannot be read is never overwritten (finding 22)', t => {
  const config = scratch(t);
  const home = join(config, 'home');
  const system = fakeSystem({ systemd: false, crontabReadError: true, existingCron: '0 3 * * * /usr/bin/true # TEST ONLY keep\n' });
  assert.throws(() => installReminder(job(home), { platform: 'linux', run: system.run, configHome: config }),
    { code: 'SCHEDULER_FAILED', reason: 'crontab-read' });
  assert.throws(() => removeReminder(home, { platform: 'linux', run: system.run, configHome: config }), { code: 'SCHEDULER_FAILED' });
  assert.ok(system.calls.every(call => !(call.argv[0] === 'crontab' && call.argv[1] === '-')), 'no crontab write');
  assert.equal(system.crontab(), '0 3 * * * /usr/bin/true # TEST ONLY keep\n');
});

/** Decode the cron command's printf format the way POSIX printf does (octal escapes only). */
function decodeCron(command) {
  const match = /^printf '([^']*)' \| xargs -0 env --$/u.exec(command);
  assert.ok(match, command);
  const bytes = [];
  for (let i = 0; i < match[1].length;) {
    if (match[1][i] === '\\') {
      bytes.push(Number.parseInt(match[1].slice(i + 1, i + 4), 8));
      i += 4;
    } else {
      bytes.push(match[1].charCodeAt(i));
      i++;
    }
  }
  return Buffer.from(bytes).toString('utf8').split('\u0000').slice(0, -1);
}

const AWKWARD = ['/srv/with space/it\'s "quoted"/100%/$HOME/`x`/a\nb/\u00e9\\', 'plain'];

test('cron and systemd forms carry any Linux path exactly: quotes, %, $, backslash, newline, non-ASCII (finding 27)', () => {
  const command = cronCommand(AWKWARD);
  assert.deepEqual(decodeCron(command), AWKWARD);
  assert.ok(!/[%"\n$`\\]/u.test(command.replace(/\\[0-7]{3}/gu, '')), 'only octal escapes and safe characters');
  assert.equal(systemdWord('a"b%c$d\\e\nf\u0001'), '"a\\"b%%c$$d\\\\e\\nf\\x01"');
  const service = systemdUnits(job('/srv/100%/"x"')).service;
  assert.ok(service.includes('100%%') && service.includes('\\"x\\""\n'), service);
  assert.throws(() => cronCommand(['a\u0000b']), { code: 'SCHEDULER_FAILED', reason: 'unsafe-path' });
});

test('the cron line runs the exact argv through a real POSIX shell', { skip: process.platform === 'win32' }, t => {
  const root = scratch(t);
  const printer = join(root, 'print-argv.mjs');
  writeFileSync(printer, 'process.stdout.write(JSON.stringify(process.argv.slice(2)));\n');
  const argv = [process.execPath, printer, ...AWKWARD];
  // cron runs the command part of the line with /bin/sh -c.
  const result = spawnSync('/bin/sh', ['-c', cronCommand(argv)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), AWKWARD);
});

test('Linux notification: notify-send with explicit argv only when a session bus is reachable', () => {
  const calls = [];
  const run = (command, args) => { calls.push([command, ...args]); return { status: 0, stdout: '', stderr: '' }; };
  assert.equal(notifyDesktop('TEST ONLY due', { env: {}, run, exists: () => false }), 'none');
  assert.equal(calls.length, 0);
  assert.equal(notifyDesktop('TEST ONLY due', { env: { XDG_RUNTIME_DIR: '/run/user/1000' }, run, exists: path => path === '/run/user/1000/bus' }), 'notify-send');
  assert.equal(notifyDesktop('TEST ONLY due', { env: { DBUS_SESSION_BUS_ADDRESS: 'unix:path=/x' }, run, exists: () => false }), 'notify-send');
  assert.deepEqual(calls[0], ['notify-send', '--app-name=Foundry', '--', 'Foundry second copy', 'TEST ONLY due']);
  const missing = () => ({ status: null, stdout: '', stderr: '' });
  assert.equal(notifyDesktop('TEST ONLY due', { env: { DBUS_SESSION_BUS_ADDRESS: 'unix:path=/x' }, run: missing }), 'none');
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

/**
 * `foundry vault schedule` and `foundry vault reminder`: a per-user reminder job for the second copy
 * (Architecture 8.1, Product 8, A-44).
 *
 * - Windows: a per-user Task Scheduler task created with `schtasks.exe /Create /XML` (no administrator rights,
 *   interactive token, least privilege). The XML is written as UTF-16LE with a byte-order mark.
 * - Linux: a `systemd --user` `.service` and `.timer` in `$XDG_CONFIG_HOME/systemd/user`; when `systemctl --user`
 *   is not usable, a crontab line marked with the job name.
 * - Every program is started with `shell: false` through an injectable runner, so tests record argv and never
 *   touch the real scheduler.
 *
 * The job never holds a key: it runs `foundry vault reminder`, which reads the register, compares the last seal
 * time with the cadence, can run the keyless `verifyVault`, and records the result in the register so that
 * `foundry vault status` and the overdue banner show it. It does not pop up a window (Windows Home has no
 * `msg.exe`); its output goes to the scheduler's log.
 */
import { Buffer } from 'node:buffer';
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { VaultFormatError } from './bytes.ts';
import {
  copyRegisterStatus, defaultRunner, readCopyRegister, SecondCopyError, writeCopyRegister,
} from './second-copy.ts';
import type { Cadence, CommandResult, CommandRunner, RegisterStatus } from './second-copy.ts';
import { metadata, statIfPresent } from './vault-directory.ts';
import { verifyVault } from './vault-reader.ts';

export type ScheduledCadence = Exclude<Cadence, 'manual'>;
export type SchedulerPlatform = 'win32' | 'linux';
export type SchedulerMethod = 'schtasks' | 'systemd' | 'cron';

export interface ReminderJob {
  /** The Foundry home folder (the `--vault` value). */
  home: string;
  /** Absolute path of the Node executable. */
  node: string;
  /** Absolute path of `foundry.mjs`. */
  cli: string;
  cadence: ScheduledCadence;
  /** Also run the keyless chain check. */
  verify: boolean;
}

export interface SchedulerEnvironment {
  platform: SchedulerPlatform | string;
  run?: CommandRunner;
  /** Linux: `$XDG_CONFIG_HOME`, else `<home directory>/.config`. */
  configHome?: string;
  /** Windows: a folder for the short-lived task XML file (the Foundry home is fine). */
  scratch?: string;
  now?: Date;
}

/** One stable name per Foundry home, so two homes never share or overwrite a job. */
export function reminderName(home: string): string {
  return `foundry-vault-reminder-${createHash('sha256').update(Buffer.from(resolve(home))).digest('hex').slice(0, 12)}`;
}

export function reminderArgs(job: ReminderJob): string[] {
  return [job.cli, 'vault', 'reminder', '--vault', resolve(job.home), ...(job.verify ? ['--verify'] : [])];
}

function platformOf(env: SchedulerEnvironment): SchedulerPlatform {
  if (env.platform === 'win32' || env.platform === 'linux') return env.platform;
  throw new SecondCopyError('SCHEDULER_UNSUPPORTED');
}

function assertCadenceScheduled(cadence: string): asserts cadence is ScheduledCadence {
  if (cadence !== 'daily' && cadence !== 'weekly' && cadence !== 'monthly') throw new SecondCopyError('INVALID_CADENCE');
}

/** Paths go into scheduler files; refuse the characters no quoting rule here can carry safely. */
function assertSafeArgument(value: string): void {
  // eslint-disable-next-line no-control-regex -- control characters are exactly what is refused here.
  if (value.length === 0 || /["%\u0000-\u001f\u007f]/u.test(value)) throw new SecondCopyError('SCHEDULER_FAILED', 'unsafe-path');
}

function xmlEscape(text: string): string {
  return text.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;').replace(/"/gu, '&quot;').replace(/'/gu, '&apos;');
}

const pad = (value: number) => String(value).padStart(2, '0');
const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/** Task Scheduler 1.2 XML for a per-user, least-privilege, keyless reminder. */
export function windowsTaskXml(job: ReminderJob, now: Date = new Date()): string {
  assertCadenceScheduled(job.cadence);
  const args = reminderArgs(job);
  for (const value of [job.node, ...args]) assertSafeArgument(value);
  const start = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}T09:00:00`;
  const schedule = job.cadence === 'daily'
    ? '<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>'
    : job.cadence === 'weekly'
      ? `<ScheduleByWeek><WeeksInterval>1</WeeksInterval><DaysOfWeek><${WEEKDAYS[now.getDay()]} /></DaysOfWeek></ScheduleByWeek>`
      : '<ScheduleByMonth><DaysOfMonth><Day>1</Day></DaysOfMonth><Months><January /><February /><March /><April /><May />'
        + '<June /><July /><August /><September /><October /><November /><December /></Months></ScheduleByMonth>';
  const argumentText = args.map(value => `"${value}"`).join(' ');
  return [
    '<?xml version="1.0" encoding="UTF-16"?>',
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
    '  <RegistrationInfo>',
    `    <Description>Foundry second-copy reminder (${job.cadence}). Keyless: it checks the last seal time and never reads a key.</Description>`,
    '  </RegistrationInfo>',
    '  <Triggers>',
    `    <CalendarTrigger><StartBoundary>${start}</StartBoundary><Enabled>true</Enabled>${schedule}</CalendarTrigger>`,
    '  </Triggers>',
    '  <Principals>',
    '    <Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>',
    '  </Principals>',
    '  <Settings>',
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
    '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>',
    '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>',
    '    <StartWhenAvailable>true</StartWhenAvailable>',
    '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>',
    '    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>',
    '    <Enabled>true</Enabled>',
    '  </Settings>',
    '  <Actions Context="Author">',
    `    <Exec><Command>${xmlEscape(`"${job.node}"`)}</Command><Arguments>${xmlEscape(argumentText)}</Arguments></Exec>`,
    '  </Actions>',
    '</Task>',
    '',
  ].join('\r\n');
}

/** UTF-16LE with a byte-order mark, the encoding `schtasks /XML` reads reliably. */
export function utf16leWithBom(text: string): Buffer {
  const out = Buffer.alloc(2 + text.length * 2);
  out[0] = 0xff;
  out[1] = 0xfe;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    out[2 + i * 2] = code & 0xff;
    out[3 + i * 2] = code >>> 8;
  }
  return out;
}

/** systemd quoting: one double-quoted word per argument; `$` and `%` are refused or doubled. */
function systemdWord(value: string): string {
  assertSafeArgument(value);
  return `"${value.replace(/\\/gu, '\\\\').replace(/\$/gu, '$$$$')}"`;
}

const SYSTEMD_CALENDAR: Readonly<Record<ScheduledCadence, string>> = { daily: 'daily', weekly: 'weekly', monthly: 'monthly' };

export function systemdUnits(job: ReminderJob): { service: string; timer: string } {
  assertCadenceScheduled(job.cadence);
  const exec = [job.node, ...reminderArgs(job)].map(systemdWord).join(' ');
  return {
    service: [
      '[Unit]',
      'Description=Foundry second-copy reminder (keyless)',
      '',
      '[Service]',
      'Type=oneshot',
      `ExecStart=${exec}`,
      '',
    ].join('\n'),
    timer: [
      '[Unit]',
      `Description=Foundry second-copy reminder, ${job.cadence}`,
      '',
      '[Timer]',
      `OnCalendar=${SYSTEMD_CALENDAR[job.cadence]}`,
      'Persistent=true',
      'RandomizedDelaySec=1h',
      '',
      '[Install]',
      'WantedBy=timers.target',
      '',
    ].join('\n'),
  };
}

function shellWord(value: string): string {
  assertSafeArgument(value);
  return `'${value.replace(/'/gu, `'\\''`)}'`;
}

export function cronLine(job: ReminderJob): string {
  assertCadenceScheduled(job.cadence);
  const command = [job.node, ...reminderArgs(job)].map(shellWord).join(' ');
  return `@${job.cadence} ${command} # ${reminderName(job.home)}`;
}

function systemdDirectory(env: SchedulerEnvironment): string {
  if (!env.configHome) throw new SecondCopyError('SCHEDULER_FAILED', 'no-config-home');
  return join(env.configHome, 'systemd', 'user');
}

function ok(result: CommandResult): boolean {
  return result.status === 0;
}

function removeIfPresent(path: string): boolean {
  if (!statIfPresent(path)) return false;
  unlinkSync(path);
  return true;
}

/** Lines of the current crontab, or `undefined` when `crontab` cannot be run at all. */
function readCrontab(run: CommandRunner): string[] | undefined {
  const result = run('crontab', ['-l']);
  if (result.status === null) return undefined;
  // `crontab -l` exits 1 with "no crontab for <user>" when the table is empty.
  if (result.status !== 0) return [];
  return result.stdout.split('\n').filter(line => line.length > 0);
}

function writeCrontab(run: CommandRunner, lines: readonly string[]): void {
  const result = run('crontab', ['-'], lines.length === 0 ? '' : `${lines.join('\n')}\n`);
  if (!ok(result)) throw new SecondCopyError('SCHEDULER_FAILED', 'crontab');
}

export interface ReminderInstallResult {
  method: SchedulerMethod;
  name: string;
  /** Files written (systemd units), for the user's information. */
  files: string[];
  /** The argv lists that were run, in order. */
  commands: string[][];
}

/** Install or replace the reminder for this Foundry home. Replacing first removes any older job of the same name. */
export function installReminder(job: ReminderJob, env: SchedulerEnvironment): ReminderInstallResult {
  const platform = platformOf(env);
  assertCadenceScheduled(job.cadence);
  const run = recording(env.run ?? defaultRunner);
  const name = reminderName(job.home);
  if (platform === 'win32') {
    const xml = windowsTaskXml(job, env.now);
    const scratch = env.scratch ?? resolve(job.home);
    const file = join(scratch, `.${name}-${randomBytes(8).toString('hex')}.xml`);
    writeFileSync(file, utf16leWithBom(xml));
    try {
      const result = run('schtasks', ['/Create', '/TN', name, '/XML', file, '/F']);
      if (!ok(result)) throw new SecondCopyError('SCHEDULER_FAILED', 'schtasks');
    } finally {
      removeIfPresent(file);
    }
    return { method: 'schtasks', name, files: [], commands: run.calls };
  }
  removeLinux(name, env, run);
  const units = systemdUnits(job);
  const directory = systemdDirectory(env);
  const service = join(directory, `${name}.service`);
  const timer = join(directory, `${name}.timer`);
  const reload = run('systemctl', ['--user', 'daemon-reload']);
  if (ok(reload)) {
    mkdirSync(directory, { recursive: true });
    writeFileSync(service, units.service);
    writeFileSync(timer, units.timer);
    const enabled = ok(run('systemctl', ['--user', 'daemon-reload']))
      && ok(run('systemctl', ['--user', 'enable', '--now', `${name}.timer`]));
    if (enabled) return { method: 'systemd', name, files: [service, timer], commands: run.calls };
    removeIfPresent(service);
    removeIfPresent(timer);
    run('systemctl', ['--user', 'daemon-reload']);
  }
  // No usable user systemd (for example a container or a session without a user manager): crontab.
  const lines = readCrontab(run);
  if (lines === undefined) throw new SecondCopyError('SCHEDULER_FAILED', 'no-scheduler');
  writeCrontab(run, [...lines.filter(line => !line.endsWith(`# ${name}`)), cronLine(job)]);
  return { method: 'cron', name, files: [], commands: run.calls };
}

type RecordingRunner = CommandRunner & { calls: string[][] };

function recording(run: CommandRunner): RecordingRunner {
  const calls: string[][] = [];
  const wrapped = ((command, args, input) => {
    calls.push([command, ...args]);
    return run(command, args, input);
  }) as RecordingRunner;
  wrapped.calls = calls;
  return wrapped;
}

function removeLinux(name: string, env: SchedulerEnvironment, run: CommandRunner): SchedulerMethod[] {
  const removed: SchedulerMethod[] = [];
  const directory = systemdDirectory(env);
  const service = join(directory, `${name}.service`);
  const timer = join(directory, `${name}.timer`);
  if (statIfPresent(timer) || statIfPresent(service)) {
    run('systemctl', ['--user', 'disable', '--now', `${name}.timer`]);
    removeIfPresent(timer);
    removeIfPresent(service);
    run('systemctl', ['--user', 'daemon-reload']);
    removed.push('systemd');
  }
  const lines = readCrontab(run);
  if (lines !== undefined && lines.some(line => line.endsWith(`# ${name}`))) {
    writeCrontab(run, lines.filter(line => !line.endsWith(`# ${name}`)));
    removed.push('cron');
  }
  return removed;
}

export interface ReminderRemoveResult {
  name: string;
  removed: SchedulerMethod[];
  commands: string[][];
}

/** Remove every job this Foundry home installed. Removing a job that does not exist is not an error. */
export function removeReminder(home: string, env: SchedulerEnvironment): ReminderRemoveResult {
  const platform = platformOf(env);
  const run = recording(env.run ?? defaultRunner);
  const name = reminderName(home);
  if (platform === 'win32') {
    if (!ok(run('schtasks', ['/Query', '/TN', name]))) return { name, removed: [], commands: run.calls };
    if (!ok(run('schtasks', ['/Delete', '/TN', name, '/F']))) throw new SecondCopyError('SCHEDULER_FAILED', 'schtasks');
    return { name, removed: ['schtasks'], commands: run.calls };
  }
  return { name, removed: removeLinux(name, env, run), commands: run.calls };
}

export interface ReminderJobStatus {
  name: string;
  installed: SchedulerMethod[];
}

export function reminderStatus(home: string, env: SchedulerEnvironment): ReminderJobStatus {
  const platform = platformOf(env);
  const run = env.run ?? defaultRunner;
  const name = reminderName(home);
  if (platform === 'win32') return { name, installed: ok(run('schtasks', ['/Query', '/TN', name])) ? ['schtasks'] : [] };
  const installed: SchedulerMethod[] = [];
  if (statIfPresent(join(systemdDirectory(env), `${name}.timer`))) installed.push('systemd');
  if (readCrontab(run)?.some(line => line.endsWith(`# ${name}`))) installed.push('cron');
  return { name, installed };
}

export interface ReminderResult {
  status: RegisterStatus;
  verify: 'ok' | 'failed' | 'skipped';
  /** The keyless check's error code when it failed. */
  verifyError?: string;
}

/**
 * The job body (`foundry vault reminder`): keyless. Reads the register, optionally runs `verifyVault` on the
 * working vault, and records the check time and result in the register.
 */
export function runReminder(
  vaultDirectory: string, registerPath: string, { verify = false, now = new Date() }: { verify?: boolean; now?: Date } = {},
): ReminderResult {
  const vaultId = metadata(vaultDirectory).vault_id;
  const register = readCopyRegister(registerPath, vaultId);
  let outcome: ReminderResult['verify'] = 'skipped';
  let verifyError: string | undefined;
  let keyringVersion: number | undefined;
  if (verify) {
    try {
      verifyVault(vaultDirectory);
      outcome = 'ok';
    } catch (error) {
      if (!(error instanceof VaultFormatError)) throw error;
      outcome = 'failed';
      verifyError = error.code;
    }
  }
  try {
    const keyring = JSON.parse(readFileSync(join(vaultDirectory, 'keyring', 'keyring.json'), 'utf8')) as { version?: unknown };
    if (Number.isSafeInteger(keyring.version)) keyringVersion = keyring.version as number;
  } catch {
    keyringVersion = undefined;
  }
  const updated = { ...register, last_check: { checked_at: now.toISOString().replace(/\.\d{3}Z$/u, 'Z'), verify: outcome } };
  writeCopyRegister(registerPath, updated);
  return { status: copyRegisterStatus(updated, now, keyringVersion), verify: outcome, ...(verifyError ? { verifyError } : {}) };
}

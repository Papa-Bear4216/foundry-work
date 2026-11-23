/**
 * `foundry` main-thread driver.
 *
 * The main thread parses arguments (secret guard first), refuses a terminal on stdin for the `--*-stdin` flags,
 * starts the wall-clock deadline, resolves the Foundry home, takes the lock, reads secrets and then runs the command
 * body in ONE worker thread while it acts as the watchdog. Secrets are read without blocking the main thread
 * (terminal prompts and `readStdinText` are asynchronous), so the deadline also covers a stdin pipe that never sends
 * EOF. (A blocking `readSync` cannot be used for this, in this thread or in a worker: on Node 24 for Windows a
 * worker blocked in it stops both `process.exit` and `worker.terminate()`.)
 *
 * On a timeout or SIGINT / SIGTERM:
 * - the bin (`exitOnTimeout`) prints the `TIMEOUT` / `INTERRUPTED` line and ends the process WITHOUT removing the
 *   lock: the worker may still be writing until the process is gone. The dead pid then makes the lock stale, and the
 *   next command recovers it (`lock.ts`).
 * - the programmatic path prints the line, cancels a pending stdin read, awaits `worker.terminate()` and only then
 *   removes the lock.
 * No child process is started; no thread outlives the command.
 *
 * Location rule (design 4.1), first match wins: `--vault <dir>`, then `FOUNDRY_HOME`, then `<home directory>/Foundry`.
 * The home `H` holds `H/vault/`, `H/index/` and `H/foundry.lock`.
 */
import type { Buffer } from 'node:buffer';
import { existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import process from 'node:process';
import { isatty } from 'node:tty';
import { Worker } from 'node:worker_threads';
import { HELP, isKeyed, parseCommandLine } from './args.ts';
import type { ParsedCommand } from './args.ts';
import { executeCommand, homePaths, isInitLeftover } from './commands.ts';
import type { CommandIo, CommandRequest, CommandSecrets, TestHooks } from './commands.ts';
import { CliError, debugText, errorLine, mapError, usage } from './errors.ts';
import { acquireLock, LOCK_NAME, RECOVERY_NAME } from './lock.ts';
import type { HeldLock } from './lock.ts';
import { promptHidden, readOneSecret, readTwoSecrets, restoreTerminal } from './secrets.ts';
import type { PromptIo, StdinRead } from './secrets.ts';

export { DEFAULT_TIMEOUTS } from './args.ts';
export { executeCommand } from './commands.ts';
export type { CommandRequest, TestHooks } from './commands.ts';

export interface RunOptions {
  /** Environment for the location rule and the secret guard. Default: `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
  /** Descriptor for `--*-stdin` secrets. Default: 0. */
  stdinFd?: number;
  stdout?: (text: string) => void;
  stderr?: (text: string) => void;
  /** Terminal for prompts. Default: `process.stdin` and `process.stderr`. */
  terminal?: PromptIo;
  /** Run the body in this thread, without the watchdog (tests count KDF runs in this thread). */
  inline?: boolean;
  /** The bin: end the process with exit 2 on a timeout or SIGINT / SIGTERM. */
  exitOnTimeout?: boolean;
  handleSignals?: boolean;
  /** Is this descriptor a terminal? Default: `isatty` from `node:tty` (tests inject it; no real terminal needed). */
  isTerminal?: (fd: number) => boolean;
  testHooks?: TestHooks;
}

export function resolveHome(vault: string | undefined, env: Readonly<Record<string, string | undefined>>): string {
  const fromEnv = env.FOUNDRY_HOME;
  return resolve(vault ?? (fromEnv ? fromEnv : join(homedir(), 'Foundry')));
}

function version(): string {
  try {
    return (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;
  } catch {
    return 'unknown';
  }
}

function guardMessage(error: unknown): CliError {
  const text = error instanceof Error ? error.message : '';
  return usage(text.startsWith('Secret environment variables')
    ? 'secret environment variables (FOUNDRY_*/VAULT_* names with PASS, SECRET, KEY, RECOVERY or TOKEN) are refused'
    : 'unexpected arguments; secrets are read only from a prompt or stdin, never from arguments');
}

type Run = Extract<ParsedCommand, { kind: 'run' }>;

async function promptNew(terminal: PromptIo): Promise<Buffer> {
  const first = await promptHidden('New passphrase: ', terminal);
  let second: Buffer | undefined;
  try {
    second = await promptHidden('Repeat the new passphrase: ', terminal);
    if (!first.equals(second)) throw new CliError('PASSPHRASE_MISMATCH', 'the two passphrases are not the same');
    return first;
  } catch (error) {
    first.fill(0);
    throw error;
  } finally {
    second?.fill(0);
  }
}

/**
 * Read every secret the command needs. The caller zeroes them. Every read is asynchronous, so the watchdog keeps
 * running; `track` receives each pending stdin read so a timeout can cancel it.
 */
async function readSecrets(run: Run, fd: number, terminal: PromptIo, secrets: CommandSecrets,
  track: (read: StdinRead) => void): Promise<CommandRequest['credential']> {
  switch (run.command) {
    case 'vault verify':
      return undefined;
    case 'init':
      secrets.newPassphrase = run.passphraseStdin ? await readOneSecret(fd, track) : await promptNew(terminal);
      return undefined;
    case 'vault reset-passphrase':
      if (run.recoveryKeyStdin && run.passphraseStdin) {
        [secrets.recoveryKey, secrets.newPassphrase] = await readTwoSecrets(fd, track);
      } else {
        secrets.recoveryKey = run.recoveryKeyStdin ? await readOneSecret(fd, track) : await promptHidden('Recovery key: ', terminal);
        secrets.newPassphrase = run.passphraseStdin ? await readOneSecret(fd, track) : await promptNew(terminal);
      }
      return undefined;
    default:
      if (run.recoveryKeyStdin) {
        secrets.recoveryKey = await readOneSecret(fd, track);
        return 'recovery';
      }
      secrets.passphrase = run.passphraseStdin ? await readOneSecret(fd, track) : await promptHidden('Passphrase: ', terminal);
      return 'passphrase';
  }
}

/** A `--*-stdin` flag with a terminal on stdin would echo the secret: refuse it (exit 1). */
function refuseTerminalStdin(run: Run, fd: number, isTerminal: (fd: number) => boolean): void {
  if (!run.passphraseStdin && !run.recoveryKeyStdin) return;
  if (!isTerminal(fd)) return;
  if (run.passphraseStdin && run.recoveryKeyStdin) {
    throw usage('do not use --recovery-key-stdin and --passphrase-stdin on a terminal; omit the flags to be prompted');
  }
  throw usage(`do not use ${run.passphraseStdin ? '--passphrase-stdin' : '--recovery-key-stdin'} on a terminal; `
    + 'omit the flag to be prompted');
}

/** Names in H that do not make it "not empty" for `init`: the lock, its recovery file, and init's temporary folders. */
function ignoredByInit(name: string): boolean {
  return name === LOCK_NAME || name === RECOVERY_NAME || isInitLeftover(name);
}

function checkHome(run: Run, home: string): void {
  if (run.command === 'init') {
    if (existsSync(home) && readdirSync(home).some(name => !ignoredByInit(name))) {
      throw new CliError('NOT_EMPTY', 'the target folder exists and is not empty; choose another folder with --vault');
    }
    return;
  }
  // Fixed text: the location comes from --vault or FOUNDRY_HOME, where a secret could have been pasted by mistake.
  if (!existsSync(join(homePaths(home).vault, 'VAULT.json'))) {
    throw new CliError('NO_VAULT', 'no vault found in the Foundry folder; run `foundry init`, or give --vault <dir>');
  }
}

interface WorkerHandle {
  worker?: Worker;
}

function runInWorker(request: CommandRequest, hooks: TestHooks, io: CommandIo, handle: WorkerHandle): Promise<number> {
  const transferList: ArrayBuffer[] = [];
  for (const bytes of [request.secrets.passphrase, request.secrets.recoveryKey, request.secrets.newPassphrase]) {
    if (bytes && bytes.byteLength > 0) transferList.push(bytes.buffer as ArrayBuffer);
  }
  return new Promise(resolvePromise => {
    let code: number | undefined;
    const worker = new Worker(new URL('./worker.js', import.meta.url), {
      workerData: { request, hooks }, transferList, stdin: false,
    });
    handle.worker = worker;
    worker.on('message', message => {
      const m = message as { type: 'out' | 'err' | 'done'; text?: string; code?: number };
      if (m.type === 'out') io.out(m.text ?? '');
      else if (m.type === 'err') io.err(m.text ?? '');
      else {
        // The body is finished: end the thread now, even if some handle would keep it alive.
        code = m.code;
        void worker.terminate();
      }
    });
    worker.on('error', error => {
      // Crash text never carries the message (it could quote input); --debug adds the error's name only.
      if (request.debug) io.err(`foundry: debug: the worker thread failed (${error.name})\n`);
      io.err(errorLine({ code: 'INTERNAL', message: 'an unexpected internal error occurred', exit: 2 }));
      code = 2;
    });
    worker.on('exit', () => resolvePromise(code ?? 2));
  });
}

/** Run one `foundry` command line. Returns the exit code: 0 ok, 1 usage, 2 typed failure. */
export async function runCli(argv: readonly string[], options: RunOptions = {}): Promise<number> {
  const env = options.env ?? process.env;
  const io: CommandIo = {
    out: options.stdout ?? (text => { process.stdout.write(text); }),
    err: options.stderr ?? (text => { process.stderr.write(text); }),
  };
  const terminal = options.terminal ?? { input: process.stdin, output: process.stderr };

  let parsed: ParsedCommand;
  try {
    parsed = parseCommandLine(argv, env);
  } catch (error) {
    const mapped = mapError(error instanceof CliError ? error : guardMessage(error));
    io.err(errorLine(mapped));
    return mapped.exit;
  }
  if (parsed.kind === 'version') {
    io.out(`foundry ${version()}\n`);
    return 0;
  }
  if (parsed.kind === 'help') {
    io.out(HELP[parsed.command ?? 'main']);
    return 0;
  }
  const run = parsed;
  const stdinFd = options.stdinFd ?? 0;
  try {
    refuseTerminalStdin(run, stdinFd, options.isTerminal ?? isatty);
  } catch (error) {
    const mapped = mapError(error);
    io.err(errorLine(mapped));
    return mapped.exit;
  }
  const home = resolveHome(run.vault, env);
  const secrets: CommandSecrets = {};
  const handle: WorkerHandle = {};
  let lock: HeldLock | undefined;
  let pendingRead: StdinRead | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let finished = false;

  // The stop signal: the deadline or SIGINT / SIGTERM. It only resolves a promise; the reaction is below.
  interface Stop { code: 'TIMEOUT' | 'INTERRUPTED'; message: string }
  let stop: (reason: Stop) => void = () => {};
  const stopped = new Promise<Stop>(resolveStop => {
    stop = reason => {
      if (finished) return;
      finished = true; // from here on the body prints nothing and starts no worker
      resolveStop(reason);
    };
  });
  const onSignal = (...args: unknown[]) => {
    stop({ code: 'INTERRUPTED', message: `the command was stopped by ${String(args[0] ?? 'a signal')}` });
  };

  const work = async (): Promise<number> => {
    checkHome(run, home);
    if (run.command === 'init') mkdirSync(home, { recursive: true, mode: 0o700 });
    lock = acquireLock(join(home, LOCK_NAME), run.command, io.err);
    checkHome(run, home); // again under the lock
    const credential = await readSecrets(run, stdinFd, terminal, secrets, read => { pendingRead = read; });
    pendingRead = undefined;
    const request: CommandRequest = {
      command: run.command, home, debug: run.debug, json: run.json, path: run.path, query: run.query,
      filters: run.filters, credential: isKeyed(run.command) ? credential : undefined, secrets,
    };
    if (finished) return 2;
    return options.inline ? executeCommand(request, io, options.testHooks) : runInWorker(request, options.testHooks ?? {}, io, handle);
  };
  const report = (error: unknown): number => {
    const mapped = mapError(error);
    if (!finished && run.debug) {
      const texts = [secrets.passphrase, secrets.recoveryKey, secrets.newPassphrase]
        .filter((bytes): bytes is Buffer => bytes !== undefined && bytes.byteLength > 0)
        .map(bytes => bytes.toString('utf8'));
      io.err(debugText(error, texts));
    }
    if (!finished) io.err(errorLine(mapped));
    return mapped.exit;
  };

  try {
    if (options.inline) return await work().catch(report);
    // The deadline starts before anything that can wait: the lock, a prompt or a stdin read.
    timer = setTimeout(() => {
      stop({ code: 'TIMEOUT', message: `the command passed its time limit of ${run.timeoutSeconds} second(s)` });
    }, run.timeoutSeconds * 1000);
    if (options.handleSignals) {
      process.on('SIGINT', onSignal);
      process.on('SIGTERM', onSignal);
    }
    const result = await Promise.race([work().catch(report), stopped]);
    if (typeof result === 'number') return result;
    restoreTerminal();
    io.err(errorLine({ code: result.code, message: result.message, exit: 2 }));
    // The bin: end the process now and leave the lock. The worker may still be writing until the process is gone;
    // the dead pid then makes the lock stale and the next command recovers it.
    if (options.exitOnTimeout) process.exit(2);
    // Programmatic: stop everything first, then the lock is released in `finally`.
    pendingRead?.cancel();
    await handle.worker?.terminate();
    return 2;
  } finally {
    finished = true;
    clearTimeout(timer);
    if (options.handleSignals) {
      process.off('SIGINT', onSignal);
      process.off('SIGTERM', onSignal);
    }
    lock?.release();
    // A Buffer transferred to the worker is detached here (length 0); the worker zeroed it.
    for (const bytes of [secrets.passphrase, secrets.recoveryKey, secrets.newPassphrase]) {
      if (bytes && bytes.byteLength > 0) bytes.fill(0);
    }
  }
}

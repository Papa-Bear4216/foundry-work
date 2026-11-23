/**
 * `foundry` main-thread driver.
 *
 * The main thread parses arguments (secret guard first), resolves the Foundry home, takes the lock, reads secrets
 * (terminal prompts need the main thread) and then runs the command body in ONE worker thread while it acts as the
 * watchdog for the wall-clock limit. A body stuck in a long synchronous section (index and verify calls are
 * synchronous) cannot block the watchdog: on expiry the main thread prints `TIMEOUT`, removes the lock and ends the
 * process (`exitOnTimeout`) or terminates the worker. No child process is started; no thread outlives the command.
 *
 * Location rule (design 4.1), first match wins: `--vault <dir>`, then `FOUNDRY_HOME`, then `<home directory>/Foundry`.
 * The home `H` holds `H/vault/`, `H/index/` and `H/foundry.lock`.
 */
import type { Buffer } from 'node:buffer';
import { existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import process from 'node:process';
import { Worker } from 'node:worker_threads';
import { HELP, isKeyed, parseCommandLine } from './args.ts';
import type { ParsedCommand } from './args.ts';
import { executeCommand, homePaths } from './commands.ts';
import type { CommandIo, CommandRequest, CommandSecrets, TestHooks } from './commands.ts';
import { CliError, debugText, errorLine, mapError, usage } from './errors.ts';
import { acquireLock, LOCK_NAME } from './lock.ts';
import type { HeldLock } from './lock.ts';
import { promptHidden, readOneSecret, readTwoSecrets, restoreTerminal } from './secrets.ts';
import type { PromptIo } from './secrets.ts';

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

/** Read every secret the command needs. The caller zeroes them. */
async function readSecrets(run: Run, fd: number, terminal: PromptIo, secrets: CommandSecrets): Promise<CommandRequest['credential']> {
  switch (run.command) {
    case 'vault verify':
      return undefined;
    case 'init':
      secrets.newPassphrase = run.passphraseStdin ? readOneSecret(fd) : await promptNew(terminal);
      return undefined;
    case 'vault reset-passphrase':
      if (run.recoveryKeyStdin && run.passphraseStdin) {
        [secrets.recoveryKey, secrets.newPassphrase] = readTwoSecrets(fd);
      } else {
        secrets.recoveryKey = run.recoveryKeyStdin ? readOneSecret(fd) : await promptHidden('Recovery key: ', terminal);
        secrets.newPassphrase = run.passphraseStdin ? readOneSecret(fd) : await promptNew(terminal);
      }
      return undefined;
    default:
      if (run.recoveryKeyStdin) {
        secrets.recoveryKey = readOneSecret(fd);
        return 'recovery';
      }
      secrets.passphrase = run.passphraseStdin ? readOneSecret(fd) : await promptHidden('Passphrase: ', terminal);
      return 'passphrase';
  }
}

function checkHome(run: Run, home: string): void {
  if (run.command === 'init') {
    if (existsSync(home) && readdirSync(home).some(name => name !== LOCK_NAME)) {
      throw new CliError('NOT_EMPTY', 'the target folder exists and is not empty; choose another folder with --vault');
    }
    return;
  }
  if (!existsSync(join(homePaths(home).vault, 'VAULT.json'))) {
    throw new CliError('NO_VAULT', `no vault found in ${home}; run \`foundry init\` or give --vault <dir>`);
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
  const home = resolveHome(run.vault, env);
  const secrets: CommandSecrets = {};
  const handle: WorkerHandle = {};
  let lock: HeldLock | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let finished = false;

  const abort = (code: string, message: string): number => {
    if (finished) return 2;
    finished = true;
    restoreTerminal();
    io.err(errorLine({ code, message, exit: 2 }));
    lock?.release();
    if (options.exitOnTimeout) process.exit(2);
    return 2;
  };
  const onSignal = (...args: unknown[]) => {
    abort('INTERRUPTED', `the command was stopped by ${String(args[0] ?? 'a signal')}; the lock is removed`);
  };
  if (options.handleSignals) {
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
  }

  const work = async (): Promise<number> => {
    checkHome(run, home);
    if (run.command === 'init') mkdirSync(home, { recursive: true, mode: 0o700 });
    lock = acquireLock(join(home, LOCK_NAME), run.command, io.err);
    checkHome(run, home); // again under the lock
    const credential = await readSecrets(run, options.stdinFd ?? 0, terminal, secrets);
    const request: CommandRequest = {
      command: run.command, home, debug: run.debug, json: run.json, path: run.path, query: run.query,
      filters: run.filters, credential: isKeyed(run.command) ? credential : undefined, secrets,
    };
    if (finished) return 2;
    return options.inline ? executeCommand(request, io, options.testHooks) : runInWorker(request, options.testHooks ?? {}, io, handle);
  };

  try {
    const body = work().catch((error: unknown) => {
      const mapped = mapError(error);
      if (!finished && run.debug) {
        const texts = [secrets.passphrase, secrets.recoveryKey, secrets.newPassphrase]
          .filter((bytes): bytes is Buffer => bytes !== undefined && bytes.byteLength > 0)
          .map(bytes => bytes.toString('utf8'));
        io.err(debugText(error, texts));
      }
      if (!finished) io.err(errorLine(mapped));
      return mapped.exit;
    });
    if (options.inline) return await body;
    const expired = new Promise<'timeout'>(resolveTimer => {
      timer = setTimeout(() => resolveTimer('timeout'), run.timeoutSeconds * 1000);
    });
    const result = await Promise.race([body, expired]);
    if (result !== 'timeout') return result;
    const code = abort('TIMEOUT', `the command passed its time limit of ${run.timeoutSeconds} second(s)`);
    await handle.worker?.terminate();
    return code;
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

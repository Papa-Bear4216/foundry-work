// TEST ONLY helpers for the foundry command-line tests. Every secret, archive and name here is synthetic.
import { spawnSync } from 'node:child_process';
import { closeSync, mkdtempDisposableSync, openSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { writeMultiPartTakeoutFolder } from 'importers';
import { runCli } from '../dist/cli.js';
import { getKdfCallCountForTest, resetKdfCallCountForTest } from '../../vault/codec/dist/keyring.js';

export const BIN = fileURLToPath(new URL('../dist/main.js', import.meta.url));
export const PASSPHRASE = 'TEST ONLY cli passphrase';

/** A temporary folder removed after the test. */
export function scratch(t, prefix = 'foundry-cli-') {
  const temp = mkdtempDisposableSync(join(tmpdir(), prefix));
  t.after(() => temp.remove());
  return temp.path;
}

/** An environment without any FOUNDRY_* or VAULT_* variable (the guard refuses secret-looking names). */
export function cleanEnv(extra = {}) {
  const env = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (!/^(FOUNDRY_|VAULT_)/iu.test(name)) env[name] = value;
  }
  return { ...env, ...extra };
}

let stdinCounter = 0;
/** Write `text` to a file in `dir` and open it, so it can serve as stdin. Returns the fd (closed by the caller). */
export function stdinFile(dir, text) {
  const path = join(dir, `stdin-${++stdinCounter}.txt`);
  writeFileSync(path, text);
  return openSync(path, 'r');
}

/**
 * Run the command line in THIS thread (no worker, no watchdog) and count KDF runs with the vault's test hook.
 * `stdin` is the text that `--*-stdin` reads.
 */
export async function runInline(dir, argv, { stdin = '', env = {}, hooks } = {}) {
  const fd = stdinFile(dir, stdin);
  let stdout = '';
  let stderr = '';
  resetKdfCallCountForTest();
  try {
    const code = await runCli(argv, {
      inline: true, stdinFd: fd, env: cleanEnv(env), testHooks: hooks,
      stdout: text => { stdout += text; }, stderr: text => { stderr += text; },
    });
    return { code, stdout, stderr, kdf: getKdfCallCountForTest() };
  } finally {
    closeSync(fd);
  }
}

/** Run the command line through `runCli` with the worker and the watchdog (the bin's path, without process exit). */
export async function runWorker(dir, argv, { stdin = '', env = {}, hooks } = {}) {
  const fd = stdinFile(dir, stdin);
  let stdout = '';
  let stderr = '';
  try {
    const code = await runCli(argv, {
      stdinFd: fd, env: cleanEnv(env), testHooks: hooks,
      stdout: text => { stdout += text; }, stderr: text => { stderr += text; },
    });
    return { code, stdout, stderr };
  } finally {
    closeSync(fd);
  }
}

/** Spawn the built bin with `stdin` text as a file descriptor. */
export function runBin(dir, argv, { stdin = '', env = {}, timeout = 120_000 } = {}) {
  const fd = stdinFile(dir, stdin);
  try {
    const started = Date.now();
    const result = spawnSync(process.execPath, [BIN, ...argv], {
      stdio: [fd, 'pipe', 'pipe'], env: cleanEnv(env), encoding: 'utf8', timeout, windowsHide: true,
    });
    return { code: result.status, stdout: result.stdout, stderr: result.stderr, ms: Date.now() - started, signal: result.signal };
  } finally {
    closeSync(fd);
  }
}

/** `foundry init` inline. Returns the home folder and the printed recovery key. */
export async function initVault(dir, passphrase = PASSPHRASE) {
  const home = join(dir, 'home');
  const result = await runInline(dir, ['init', '--vault', home, '--passphrase-stdin'], { stdin: passphrase + '\n' });
  if (result.code !== 0) throw new Error(`init failed: ${result.stderr}`);
  const match = /^\s{4}(\S+)$/mu.exec(result.stdout);
  if (!match) throw new Error('init printed no recovery key');
  return { home, recoveryKey: match[1], init: result };
}

/** A small synthetic multi-part Takeout folder: contacts, calendar, mail, one unrecognised entry. */
export async function takeoutFolder(dir, options = {}) {
  const folder = join(dir, 'takeout');
  const built = await writeMultiPartTakeoutFolder(folder, { contactsCount: 4, calendarEvents: 3, mailMessages: 6, ...options });
  return { folder, ...built };
}

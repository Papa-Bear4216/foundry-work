import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, relative } from 'node:path';
import { TextDecoder, TextEncoder } from 'node:util';
import { assertRelativePath, assertRepoName, type RepoMap } from './repos.js';

const OUTPUT_CAP_BYTES = 1024 * 1024;
const CALL_TIMEOUT_MS = 10_000;
const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';
const utf8 = new TextDecoder('utf-8');

/** Thrown when a named repository is not mapped or not present on this machine. */
export class RepoUnavailableError extends Error {}

export interface ExecResult {
  readonly exitCode: number;
  readonly output: Uint8Array;
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

export function decodeUtf8(bytes: Uint8Array): string {
  return utf8.decode(bytes);
}

function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

let cachedGit: string | undefined;

/**
 * Resolve `git` to an absolute path once. `FACTS_LEDGER_GIT` (absolute) wins; otherwise
 * absolute PATH entries are searched for the real executable (`git.exe` on Windows; no
 * `.cmd`/`.bat` shims). Relative PATH entries are ignored.
 */
export function resolveGitExecutable(): string {
  if (cachedGit) return cachedGit;
  const override = process.env['FACTS_LEDGER_GIT'];
  if (override) {
    if (!isAbsolute(override) || !existsSync(override)) {
      throw new Error('FACTS_LEDGER_GIT must be an absolute path to the git executable');
    }
    cachedGit = realpathSync(override);
    return cachedGit;
  }
  const name = process.platform === 'win32' ? 'git.exe' : 'git';
  const pathVar = process.env['PATH'] ?? process.env['Path'] ?? '';
  for (const dir of pathVar.split(delimiter)) {
    if (!dir || !isAbsolute(dir)) continue;
    const candidate = join(dir, name);
    if (existsSync(candidate)) {
      cachedGit = realpathSync(candidate);
      return cachedGit;
    }
  }
  throw new Error('git executable not found on PATH (set FACTS_LEDGER_GIT)');
}

/** Environment for read-only git: inherited `GIT_*` variables are dropped. */
function gitEnv(repoDir: string): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined || key.toUpperCase().startsWith('GIT_')) continue;
    env[key] = value;
  }
  env['GIT_OPTIONAL_LOCKS'] = '0';
  env['GIT_TERMINAL_PROMPT'] = '0';
  env['GIT_PAGER'] = 'cat';
  env['GIT_NO_REPLACE_OBJECTS'] = '1';
  env['GIT_CEILING_DIRECTORIES'] = dirname(repoDir);
  env['LC_ALL'] = 'C';
  return env;
}

const GIT_READ_ONLY_PREFIX: readonly string[] = [
  '--no-pager',
  '-c', 'core.fsmonitor=false',
  '-c', `core.hooksPath=${NULL_DEVICE}`,
  '-c', 'core.pager=cat',
  '-c', 'diff.external=',
  '-c', 'core.untrackedCache=false',
  '-c', 'log.showSignature=false',
];

/** Run git read-only in `repoDir`: argument vector only, never a shell; capped and timed. */
export function runGit(repoDir: string, args: readonly string[], input?: string): ExecResult {
  const git = resolveGitExecutable();
  if (isInside(repoDir, git)) {
    throw new Error('Refusing to run a git executable located inside the inspected repository');
  }
  const result = spawnSync(git, [...GIT_READ_ONLY_PREFIX, ...args], {
    cwd: repoDir,
    env: gitEnv(repoDir),
    input,
    timeout: CALL_TIMEOUT_MS,
    maxBuffer: OUTPUT_CAP_BYTES,
    windowsHide: true,
    shell: false,
  });
  if (result.error) throw new Error(`git failed: ${result.error.message}`);
  return { exitCode: result.status ?? -1, output: result.stdout };
}

export function repoDirFor(repos: RepoMap, name: string): string {
  assertRepoName(name);
  const dir = repos.get(name);
  if (!dir || !existsSync(dir)) throw new RepoUnavailableError(`Repository not present on this machine: ${name}`);
  return dir;
}

/** `HEAD` commit id, or null if the repository has no commits. */
export function headCommit(repoDir: string): string | null {
  const r = runGit(repoDir, ['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
  const sha = decodeUtf8(r.output).trim();
  return r.exitCode === 0 && /^[0-9a-f]{40,64}$/.test(sha) ? sha : null;
}

/** True if `commit` names a commit object in the repository. */
export function commitExists(repoDir: string, commit: string): boolean {
  if (!/^[0-9a-f]{40,64}$/.test(commit)) return false;
  const r = runGit(repoDir, ['cat-file', '-e', `${commit}^{commit}`]);
  return r.exitCode === 0;
}

/**
 * Resolve many object specs (`<rev>:<path>`, `<sha>^{commit}`) in ONE
 * `git cat-file --batch-check` process. Each result is `{ id, type }` or null if missing.
 */
export function batchCheck(repoDir: string, specs: readonly string[]): ({ id: string; type: string } | null)[] {
  if (specs.length === 0) return [];
  for (const spec of specs) {
    if (/[\r\n\u0000]/.test(spec)) throw new Error('Invalid object spec');
  }
  const r = runGit(repoDir, ['cat-file', '--batch-check=%(objectname) %(objecttype)'], specs.map((s) => `${s}\n`).join(''));
  if (r.exitCode !== 0) throw new Error('git cat-file --batch-check failed');
  const lines = decodeUtf8(r.output).split('\n');
  return specs.map((_, i) => {
    const [id, type] = (lines[i] ?? '').split(' ');
    return /^[0-9a-f]{40,64}$/.test(id ?? '') && type ? { id: id as string, type } : null;
  });
}

/** Blob ids for `rev:path` in one `git cat-file --batch-check` process; null when absent. */
export function blobIds(repoDir: string, rev: string, paths: readonly string[]): Map<string, string | null> {
  const out = new Map<string, string | null>();
  for (const p of paths) assertRelativePath(p);
  const results = batchCheck(repoDir, paths.map((p) => `${rev}:${p}`));
  paths.forEach((p, i) => {
    const hit = results[i];
    out.set(p, hit && hit.type === 'blob' ? hit.id : null);
  });
  return out;
}

export function readBlob(repoDir: string, blob: string): Uint8Array {
  if (!/^[0-9a-f]{40,64}$/.test(blob)) throw new Error('Invalid blob id');
  const r = runGit(repoDir, ['cat-file', 'blob', blob]);
  if (r.exitCode !== 0) throw new Error(`git cat-file blob failed for ${blob}`);
  return r.output;
}

// ---------------------------------------------------------------------------
// Fixed command templates (Step Zero 3.3). Never executed from text in the log:
// the log names a template; arguments are typed and validated; only `git` and the
// runtime itself are run.
// ---------------------------------------------------------------------------

type ParamType = 'repo' | 'ref' | 'path';

const REF_RE = /^(?!-)[A-Za-z0-9._/~^-]{1,200}$/;

function assertRef(ref: unknown): asserts ref is string {
  if (typeof ref !== 'string' || !REF_RE.test(ref) || ref.includes('..') || ref.endsWith('.lock')) {
    throw new Error(`Invalid ref argument: ${JSON.stringify(ref)}`);
  }
}

interface TemplateSpec {
  readonly version: number;
  readonly params: readonly ParamType[];
  run(repos: RepoMap, args: readonly string[]): ExecResult;
}

export const TEMPLATE_DEFAULT_TTL_S = 7 * 24 * 3600;
export const MANUAL_DEFAULT_TTL_S = 24 * 3600;

const TEMPLATES: Readonly<Record<string, TemplateSpec>> = Object.freeze({
  'git-rev-parse': {
    version: 1,
    params: ['repo', 'ref'],
    run: (repos, [repo, ref]) =>
      runGit(repoDirFor(repos, repo as string), ['rev-parse', '--verify', '--quiet', `${ref as string}^{object}`]),
  },
  'git-ls-files': {
    version: 1,
    params: ['repo', 'path'],
    run: (repos, [repo, path]) =>
      runGit(repoDirFor(repos, repo as string), ['ls-files', '--full-name', '--', path as string]),
  },
  'git-log-first-commit': {
    version: 1,
    params: ['repo', 'path'],
    run: (repos, [repo, path]) => {
      const r = runGit(repoDirFor(repos, repo as string), [
        'log', '--no-ext-diff', '--no-textconv', '--diff-filter=A', '--format=%H', '--', path as string,
      ]);
      const lines = decodeUtf8(r.output).split('\n').filter((l) => l.length > 0);
      const first = lines.length > 0 ? `${lines[lines.length - 1]}\n` : '';
      return { exitCode: r.exitCode, output: new TextEncoder().encode(first) };
    },
  },
  'file-sha256': {
    version: 1,
    params: ['repo', 'path'],
    run: (repos, [repo, path]) => {
      // Hash of the committed bytes at HEAD: identical on every OS (no line-ending drift).
      const dir = repoDirFor(repos, repo as string);
      const head = headCommit(dir);
      const blob = head ? blobIds(dir, head, [path as string]).get(path as string) : null;
      if (!blob) return { exitCode: 1, output: new Uint8Array(0) };
      return { exitCode: 0, output: new TextEncoder().encode(`${sha256Hex(readBlob(dir, blob))}\n`) };
    },
  },
  'runtime-version': {
    version: 1,
    params: [],
    run: () => {
      const r = spawnSync(process.execPath, ['--version'], {
        timeout: CALL_TIMEOUT_MS,
        maxBuffer: OUTPUT_CAP_BYTES,
        windowsHide: true,
        shell: false,
      });
      if (r.error) throw new Error(`runtime-version failed: ${r.error.message}`);
      return { exitCode: r.status ?? -1, output: r.stdout };
    },
  },
});

export function templateNames(): readonly string[] {
  return Object.keys(TEMPLATES).sort();
}

/** Validate a template name and its typed arguments; returns the spec. */
export function validateTemplateCall(template: unknown, args: unknown): { spec: TemplateSpec; args: readonly string[] } {
  if (typeof template !== 'string' || !Object.prototype.hasOwnProperty.call(TEMPLATES, template)) {
    throw new Error(`Unknown command template: ${JSON.stringify(template)}`);
  }
  const spec = TEMPLATES[template] as TemplateSpec;
  if (!Array.isArray(args) || args.length !== spec.params.length) {
    throw new Error(`Template ${template} takes ${spec.params.length} argument(s)`);
  }
  spec.params.forEach((type, i) => {
    const value = args[i];
    if (type === 'repo') assertRepoName(value);
    else if (type === 'ref') assertRef(value);
    else assertRelativePath(value);
  });
  return { spec, args: args as string[] };
}

export interface TemplateRun extends ExecResult {
  readonly template: string;
  readonly templateVersion: number;
  readonly args: readonly string[];
  readonly outputSha256: string;
}

/** Run one fixed template. Throws `RepoUnavailableError` when its repository is absent. */
export function runTemplate(repos: RepoMap, template: string, args: readonly unknown[]): TemplateRun {
  const { spec, args: typed } = validateTemplateCall(template, args);
  const r = spec.run(repos, typed);
  return {
    template,
    templateVersion: spec.version,
    args: typed,
    exitCode: r.exitCode,
    output: r.output,
    outputSha256: sha256Hex(r.output),
  };
}

export function templateVersion(template: string): number | null {
  return Object.prototype.hasOwnProperty.call(TEMPLATES, template)
    ? (TEMPLATES[template] as TemplateSpec).version
    : null;
}

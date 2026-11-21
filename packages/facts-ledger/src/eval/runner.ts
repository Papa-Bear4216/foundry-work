// Step Zero 10.3: model-in-the-loop evaluation harness (`facts eval`).
// Spawns any local command without a shell, feeds each case's deterministic prompt on stdin,
// judges answers with `checkAnswer` plus committed expected-answer patterns, enforces fixture
// and result-log integrity checks, and appends one summary block on full non-selection runs.
import { execFile, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync,
  mkdtempSync,
  openSync,
  readSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { TextDecoder, TextEncoder } from 'node:util';
import { validateTokenUsage } from '../add.js';
import {
  MAX_ANSWER_BYTES,
  MAX_STORED_PROBLEMS,
  checkAnswer,
  type AnswerProblem,
  type CheckAnswerResult,
} from '../check-answer.js';
import { generateDigest } from '../digest.js';
import { FreshnessChecker } from '../freshness.js';
import { collectGarbage } from '../gc.js';
import { resolveGitExecutable } from '../git.js';
import { appendBlock } from '../log.js';
import { formatQueryText, queryFacts, sanitizeInlineText } from '../query.js';
import { loadRepoMap } from '../repos.js';
import { type Block, type Sensitivity, type TokenUsage } from '../types.js';
import {
  CASES,
  type AnswerPatternSpec,
  type EvalCase,
  type OrCiteOption,
} from './cases.js';
import { NOW_MS, PROJECT, buildGateFixture, type GateFixture } from './fixture.js';
import { buildEvalPrompt } from './prompt.js';

export const DEFAULT_CASE_TIMEOUT_MS = 120_000;
/** Cap on `ABSTAIN:` payload bytes for eval scoring (L1, A-29). */
export const MAX_ABSTAIN_PAYLOAD_BYTES = 200;
/** Maximum diagnostic problem entries kept per case in memory and output (F7, A-29). */
export const MAX_EVAL_CASE_PROBLEMS = MAX_STORED_PROBLEMS;

export type EvalOutcome =
  | 'correct'
  | 'wrong'
  | 'abstained_correctly'
  | 'abstained_wrongly'
  | 'unsupported'
  | 'error';

export interface EvalOutcomeCounts {
  readonly correct: number;
  readonly wrong: number;
  readonly abstained_correctly: number;
  readonly abstained_wrongly: number;
  readonly unsupported: number;
  readonly error: number;
}

export interface EvalCaseResult {
  readonly id: string;
  readonly group: EvalCase['group'];
  readonly outcome: EvalOutcome;
  readonly checker_problems: number;
  readonly off_target_statements: number;
  readonly unsupported_problems: number;
  readonly input_tokens: number;
  readonly output_tokens: number;
  readonly problems?: readonly AnswerProblem[];
  readonly error?: string;
}

export interface EvalResult {
  readonly model: string;
  readonly cases_run: number;
  readonly subset: boolean;
  readonly counts: EvalOutcomeCounts;
  readonly checker_problems: number;
  readonly off_target_statements: number;
  readonly unsupported_claims: number;
  readonly passes_bar: boolean;
  readonly passes_bar_reason?: 'selection';
  readonly token_usage: TokenUsage;
  readonly block_id: string | null;
  readonly cases: readonly EvalCaseResult[];
}

export interface EvalDryRunCase {
  readonly id: string;
  readonly group: EvalCase['group'];
  readonly prompt: string;
  readonly input_tokens: number;
}

export interface EvalDryRunResult {
  readonly cases_run: number;
  readonly subset: boolean;
  readonly cases: readonly EvalDryRunCase[];
}

export interface EvalOptions {
  readonly modelCmd: string;
  readonly modelArgs?: readonly string[];
  readonly modelName?: string;
  readonly caseTimeoutMs?: number;
  readonly caseIds?: readonly string[];
  readonly logPath: string;
  readonly project: string;
  readonly agent: string;
}

export interface ModelCommandOptions {
  readonly cwd?: string;
  readonly env?: Record<string, string | undefined>;
}

export interface ModelCommandResult {
  readonly ok: boolean;
  readonly output: string;
  readonly outputBytes: number;
  readonly error?: string;
}

export interface EvalScoreResult {
  readonly outcome: EvalOutcome;
  readonly checkerProblems: number;
  readonly offTargetStatements: number;
  readonly unsupportedProblems: number;
  readonly problems: readonly AnswerProblem[];
}

interface FileIntegritySnapshot {
  readonly exists: boolean;
  readonly size: number;
  readonly sha256: string;
}

interface FixtureIntegritySnapshot {
  readonly ledger: FileIntegritySnapshot;
  readonly index: FileIntegritySnapshot;
  readonly indexWal: FileIntegritySnapshot;
  readonly repos: FileIntegritySnapshot;
  readonly gitHead: string;
  readonly gitStatus: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });
const CITATION_RE = /\[(fact|asserted):([^\]\s]*)\]/g;
const FACT_ID_RE = /^[0-9a-f]{12}\.\d{1,4}$/;
const ABSTAIN_RE = /^ABSTAIN:\s*\S/;

/** Deterministic token estimator: UTF-8 byte length / 4, rounded up (A-29). */
export function estimateTokens(text: string): number {
  return estimateTokensFromBytes(encoder.encode(text).length);
}

export function estimateTokensFromBytes(byteCount: number): number {
  if (byteCount <= 0) return 0;
  return Math.ceil(byteCount / 4);
}

export function deriveModelName(modelCmd: string): string {
  const cleaned = basename(modelCmd)
    .replace(/[^A-Za-z0-9._:/+-]+/g, '-')
    .replace(/^[^A-Za-z0-9]+/, '')
    .slice(0, 100);
  return cleaned.length > 0 ? cleaned : 'command';
}

/**
 * Select cases to run. Supplying `--cases` ALWAYS marks the run as a selection (`subset: true`)
 * regardless of how many case IDs are given (F8, A-29).
 */
export function selectEvalCases(
  caseIds?: readonly string[],
): { readonly cases: readonly EvalCase[]; readonly subset: boolean } {
  if (caseIds === undefined) {
    return { cases: CASES, subset: false };
  }
  const byId = new Map(CASES.map((c) => [c.id, c]));
  const selected: EvalCase[] = [];
  const seen = new Set<string>();
  for (const raw of caseIds) {
    const id = raw.trim();
    if (!id) throw new Error('Empty case id in --cases');
    const found = byId.get(id);
    if (!found) throw new Error(`Unknown eval case id: ${id}`);
    if (!seen.has(id)) {
      seen.add(id);
      selected.push(found);
    }
  }
  if (selected.length === 0) throw new Error('--cases requires at least one case id');
  return { cases: selected, subset: true };
}

/** Strip every `FACTS_LEDGER_*` variable (case-insensitive) from the model child's environment (F6). */
export function buildModelChildEnv(
  baseEnv: Record<string, string | undefined> = process.env,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(baseEnv)) {
    if (value === undefined) continue;
    if (key.toUpperCase().startsWith('FACTS_LEDGER_')) continue;
    env[key] = value;
  }
  return env;
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Ensure no absolute fixture path leaks into a prompt (F6). */
export function stripFixturePaths(prompt: string, paths: readonly string[]): string {
  const candidates = new Set<string>();
  for (const raw of paths) {
    if (!raw) continue;
    candidates.add(raw);
    candidates.add(raw.replace(/\\/g, '/'));
    candidates.add(raw.replace(/\//g, '\\'));
    try {
      const real = realpathSync(raw);
      candidates.add(real);
      candidates.add(real.replace(/\\/g, '/'));
      candidates.add(real.replace(/\//g, '\\'));
    } catch {
      // Path may not exist yet.
    }
  }
  // Replace longest paths first so subpaths are covered cleanly.
  const ordered = [...candidates].filter((p) => p.length > 0).sort((a, b) => b.length - a.length);
  let out = prompt;
  const flags = process.platform === 'win32' ? 'gi' : 'g';
  for (const p of ordered) {
    out = out.replace(new RegExp(escapeRegExp(p), flags), '<fixture>');
  }
  return out;
}

function snapshotFileIntegrity(filePath: string): FileIntegritySnapshot {
  let fd: number;
  try {
    fd = openSync(filePath, 'r');
  } catch (err) {
    if ((err as { code?: string }).code === 'ENOENT') {
      return { exists: false, size: 0, sha256: 'absent' };
    }
    throw err;
  }
  try {
    const hash = createHash('sha256');
    const buf = new Uint8Array(64 * 1024);
    let size = 0;
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n <= 0) break;
      size += n;
      hash.update(buf.subarray(0, n));
    }
    return { exists: true, size, sha256: hash.digest('hex') };
  } finally {
    closeSync(fd);
  }
}

function sameFileIntegrity(a: FileIntegritySnapshot, b: FileIntegritySnapshot): boolean {
  return a.exists === b.exists && a.size === b.size && a.sha256 === b.sha256;
}

function readOnlyGitEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined || key.toUpperCase().startsWith('GIT_')) continue;
    env[key] = value;
  }
  return {
    ...env,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_NO_LAZY_FETCH: '1',
  };
}

function gitSnapshotCommand(repoDir: string, args: readonly string[]): string {
  const r = spawnSync(
    resolveGitExecutable(),
    ['-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never', ...args],
    { cwd: repoDir, env: readOnlyGitEnv(), windowsHide: true, shell: false },
  );
  if (r.error) throw new Error(`Fixture integrity git ${args.join(' ')} failed: ${r.error.message}`);
  if (r.status !== 0) {
    throw new Error(`Fixture integrity git ${args.join(' ')} failed: ${decoder.decode(r.stderr).trim()}`);
  }
  return decoder.decode(r.stdout).trimEnd();
}

function snapshotFixtureIntegrity(fx: GateFixture): FixtureIntegritySnapshot {
  return {
    ledger: snapshotFileIntegrity(fx.logPath),
    index: snapshotFileIntegrity(fx.indexPath),
    indexWal: snapshotFileIntegrity(`${fx.indexPath}-wal`),
    repos: snapshotFileIntegrity(fx.reposPath),
    gitHead: gitSnapshotCommand(fx.repoDir, ['rev-parse', 'HEAD']),
    gitStatus: gitSnapshotCommand(fx.repoDir, ['status', '--porcelain']),
  };
}

function diffFixtureIntegrity(
  before: FixtureIntegritySnapshot,
  after: FixtureIntegritySnapshot,
): string[] {
  const diffs: string[] = [];
  if (!sameFileIntegrity(before.ledger, after.ledger)) diffs.push('fixture ledger changed');
  if (!sameFileIntegrity(before.index, after.index)) diffs.push('fixture index changed');
  if (!sameFileIntegrity(before.indexWal, after.indexWal)) diffs.push('fixture index WAL changed');
  if (!sameFileIntegrity(before.repos, after.repos)) diffs.push('fixture repos.json changed');
  if (before.gitHead !== after.gitHead) diffs.push('fixture git HEAD changed');
  if (before.gitStatus !== after.gitStatus) diffs.push('fixture git working tree changed');
  return diffs;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function isProcessGroupAlivePosix(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (err) {
    return (err as { code?: string }).code !== 'ESRCH';
  }
}

async function terminateProcessTree(
  child: ChildProcess,
  childExited: Promise<void>,
): Promise<void> {
  try {
    child.stdin?.destroy();
  } catch {
    // Ignore stream destroy failure.
  }
  try {
    child.stdout?.destroy();
  } catch {
    // Ignore stream destroy failure.
  }
  try {
    child.stderr?.destroy();
  } catch {
    // Ignore stream destroy failure.
  }

  const pid = child.pid;
  if (typeof pid !== 'number' || pid <= 0) {
    try {
      child.kill();
    } catch {
      // Ignore kill error when child failed to spawn.
    }
    await Promise.race([childExited, delay(200)]);
    return;
  }

  const waitExit = Promise.race([childExited, delay(3000)]);
  if (process.platform === 'win32') {
    const systemRoot = process.env['SystemRoot'] || process.env['WINDIR'] || 'C:\\Windows';
    const taskkillPath = join(systemRoot, 'System32', 'taskkill.exe');
    const taskkillPromise = new Promise<void>((resolve) => {
      execFile(
        taskkillPath,
        ['/PID', String(pid), '/T', '/F'],
        { encoding: 'utf8', timeout: 5000, windowsHide: true },
        (err) => {
          if (err) {
            try {
              child.kill();
            } catch {
              // Child already exited.
            }
          }
          resolve();
        },
      );
    });
    await Promise.all([taskkillPromise, waitExit]);
    return;
  }

  try {
    process.kill(-pid, 'SIGKILL');
  } catch {
    // Process group may already be gone.
  }
  try {
    child.kill('SIGKILL');
  } catch {
    // Child may already be gone.
  }
  await waitExit;

  const pollDeadline = Date.now() + 2000;
  while (Date.now() < pollDeadline && isProcessGroupAlivePosix(pid)) {
    try {
      process.kill(-pid, 'SIGKILL');
    } catch {
      break;
    }
    await delay(15);
  }
}

function concatBytes(chunks: readonly Uint8Array[], totalBytes: number): Uint8Array {
  const merged = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return merged;
}

/**
 * Spawn the model executable directly (`shell: false`), write `prompt` to stdin and require
 * `stdin.end` to complete without error (including EPIPE, F5), collect stdout capped at
 * `MAX_ANSWER_BYTES`, catch synchronous spawn failures (F4), and enforce `timeoutMs`.
 */
export function runModelCommand(
  executablePath: string,
  baseArgs: readonly string[],
  prompt: string,
  timeoutMs = DEFAULT_CASE_TIMEOUT_MS,
  options: ModelCommandOptions = {},
): Promise<ModelCommandResult> {
  const effectiveTimeoutMs = Math.max(1, timeoutMs);
  return new Promise((resolvePromise) => {
    const useDetachedGroup = process.platform !== 'win32';
    let child: ChildProcess;
    try {
      child = spawn(executablePath, [...baseArgs], {
        stdio: ['pipe', 'pipe', 'pipe'],
        ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
        ...(options.env !== undefined ? { env: options.env } : {}),
        windowsHide: true,
        shell: false,
        detached: useDetachedGroup,
      });
    } catch (err) {
      const code = (err as { code?: string }).code ?? 'error';
      resolvePromise({
        ok: false,
        output: '',
        outputBytes: 0,
        error: sanitizeInlineText(`Model command could not be started (${code})`),
      });
      return;
    }

    const stdoutChunks: Uint8Array[] = [];
    let stdoutBytes = 0;
    let settled = false;
    let terminating = false;
    let stdinFinished = false;
    let stdinFailed = false;

    let resolveExit!: () => void;
    const childExited = new Promise<void>((resolve) => {
      resolveExit = resolve;
    });
    if (child.exitCode !== null || child.signalCode !== null) {
      resolveExit();
    }
    child.on('exit', () => resolveExit());
    child.on('close', () => resolveExit());
    child.on('error', () => resolveExit());

    const terminateAndFail = (message: string): void => {
      if (settled || terminating) return;
      terminating = true;
      clearTimeout(timer);
      void terminateProcessTree(child, childExited).finally(() => {
        if (settled) return;
        settled = true;
        resolvePromise({
          ok: false,
          output: '',
          outputBytes: stdoutBytes,
          error: sanitizeInlineText(message),
        });
      });
    };

    const timer = setTimeout(() => {
      terminateAndFail(`Model command timed out after ${effectiveTimeoutMs} ms`);
    }, effectiveTimeoutMs);

    child.on('error', (err) => {
      if (settled || terminating) return;
      const code = (err as { code?: string }).code ?? 'error';
      terminateAndFail(`Model command could not be started (${code})`);
    });

    child.stdin?.on('error', (err) => {
      stdinFailed = true;
      if (settled || terminating) return;
      const code = (err as { code?: string }).code ?? 'error';
      terminateAndFail(`Model did not read the whole prompt (${code})`);
    });
    child.stdin?.on('finish', () => {
      if (!stdinFailed && !child.stdin?.errored) {
        stdinFinished = true;
      }
    });

    child.stdout?.on('data', (chunk) => {
      if (settled || terminating) return;
      const bytes = typeof chunk === 'string' ? encoder.encode(chunk) : chunk;
      stdoutBytes += bytes.length;
      if (stdoutBytes > MAX_ANSWER_BYTES) {
        terminateAndFail(`Model stdout exceeded ${MAX_ANSWER_BYTES} bytes`);
        return;
      }
      stdoutChunks.push(bytes);
    });

    // Drain stderr so a noisy model cannot block on pipe backpressure.
    child.stderr?.on('data', () => {});

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (settled || terminating) return;
      if (code !== 0) {
        terminateAndFail(
          `Model command failed (${signal ? `signal ${signal}` : `exit code ${code ?? 'unknown'}`})`,
        );
        return;
      }
      // Allow any queued 'finish' / 'error' microtask on stdin to settle before deciding.
      process.nextTick(() => {
        if (settled || terminating) return;
        const stdinOk =
          !stdinFailed &&
          !child.stdin?.errored &&
          (stdinFinished || Boolean(child.stdin?.writableFinished));
        if (!stdinOk) {
          terminateAndFail('Model did not read the whole prompt');
          return;
        }
        let output: string;
        try {
          output = fatalUtf8.decode(concatBytes(stdoutChunks, stdoutBytes));
        } catch {
          terminateAndFail('Model stdout is not valid UTF-8');
          return;
        }
        const finishOk = (): void => {
          if (settled) return;
          settled = true;
          resolvePromise({ ok: true, output, outputBytes: stdoutBytes });
        };
        if (
          useDetachedGroup &&
          typeof child.pid === 'number' &&
          child.pid > 0 &&
          isProcessGroupAlivePosix(child.pid)
        ) {
          terminating = true;
          void terminateProcessTree(child, childExited).finally(finishOk);
          return;
        }
        finishOk();
      });
    });

    if (!child.stdin) {
      terminateAndFail('Model command stdin pipe unavailable');
      return;
    }
    try {
      child.stdin.end(prompt, () => {
        if (!stdinFailed && !child.stdin?.errored) {
          stdinFinished = true;
        }
      });
    } catch (err) {
      stdinFailed = true;
      const code = (err as { code?: string }).code ?? 'error';
      terminateAndFail(`Model did not read the whole prompt (${code})`);
    }
  });
}

/** Match a statement (with citation markers stripped) against committed key-term patterns (F1). */
export function matchesAnswerSpec(text: string, spec: AnswerPatternSpec): boolean {
  for (const pattern of spec.answer) {
    if (!new RegExp(pattern, 'i').test(text)) return false;
  }
  if (spec.mustNot) {
    for (const forbidden of spec.mustNot) {
      if (new RegExp(forbidden, 'i').test(text)) return false;
    }
  }
  return true;
}

function compareProblems(a: AnswerProblem, b: AnswerProblem): number {
  return a.line - b.line || (a.problem < b.problem ? -1 : a.problem > b.problem ? 1 : 0);
}

/**
 * Deterministic scoring of a checked answer against a case's committed expectation (F1, F3, F7, L1, A-29).
 * `unsupportedProblems = checkerProblems + offTargetStatements`.
 * Stored diagnostics are bounded to `MAX_EVAL_CASE_PROBLEMS` entries.
 */
export function scoreEvalAnswer(
  evalCase: EvalCase,
  answerText: string,
  check: CheckAnswerResult,
): EvalScoreResult {
  const checkerProblems = check.problemCount;
  const keptProblems: AnswerProblem[] = check.problems.slice(0, MAX_EVAL_CASE_PROBLEMS);
  const recordDiagnostic = (line: number, problem: string): void => {
    if (keptProblems.length < MAX_EVAL_CASE_PROBLEMS) {
      keptProblems.push({ line, problem });
      if (keptProblems.length === MAX_EVAL_CASE_PROBLEMS) keptProblems.sort(compareProblems);
      return;
    }
    const worst = keptProblems[keptProblems.length - 1] as AnswerProblem;
    if (line > worst.line || (line === worst.line && problem >= worst.problem)) return;
    keptProblems[keptProblems.length - 1] = { line, problem };
    keptProblems.sort(compareProblems);
  };

  // Global checkAnswer failure (empty answer, >500 distinct citations, etc.): no line-level off-target scan.
  if (check.problems.some((p) => p.line === 0)) {
    keptProblems.sort(compareProblems);
    return {
      outcome: 'unsupported',
      checkerProblems,
      offTargetStatements: 0,
      unsupportedProblems: checkerProblems,
      problems: keptProblems,
    };
  }

  const invalidSet = new Set(check.invalidCitations);
  const acceptedOptions: readonly OrCiteOption[] =
    'cite' in evalCase.expect
      ? [
          {
            id: evalCase.expect.cite,
            as: evalCase.expect.as,
            answer: evalCase.expect.answer,
            ...(evalCase.expect.mustNot ? { mustNot: evalCase.expect.mustNot } : {}),
          },
        ]
      : (evalCase.expect.orCite ?? []);
  const acceptedByKey = new Map<string, OrCiteOption>(
    acceptedOptions.map((opt) => [`${opt.as}:${opt.id}`, opt]),
  );

  let offTargetStatements = 0;
  let validAbstentions = 0;
  let acceptedStatements = 0;
  let matchedTarget = false;

  // Iterate line by line without allocating substrings for ordinary uncited lines.
  const startOffset = answerText.startsWith('\ufeff') ? 1 : 0;
  let pos = startOffset;
  let lineNo = 0;
  let nextBracket = answerText.indexOf('[', startOffset);
  while (pos <= answerText.length) {
    lineNo++;
    const nl = answerText.indexOf('\n', pos);
    const end = nl === -1 ? answerText.length : nl;
    let s = pos;
    let e = end > pos && answerText.charCodeAt(end - 1) === 13 ? end - 1 : end;
    pos = nl === -1 ? answerText.length + 1 : nl + 1;

    while (s < e && answerText.charCodeAt(s) <= 32) s++;
    while (e > s && answerText.charCodeAt(e - 1) <= 32) e--;
    if (s === e) continue;

    // Fast path: non-ABSTAIN lines without '[' already failed checkAnswer as uncited (O(1) amortized).
    const hasNonAsciiEdge = answerText.charCodeAt(s) > 127 || answerText.charCodeAt(e - 1) > 127;
    if (!hasNonAsciiEdge && !answerText.startsWith('ABSTAIN:', s)) {
      if (nextBracket !== -1 && nextBracket < s) {
        nextBracket = answerText.indexOf('[', s);
      }
      if (nextBracket === -1 || nextBracket >= e) continue;
    }

    const line = hasNonAsciiEdge ? answerText.slice(s, e).trim() : answerText.slice(s, e);
    if (line.length === 0) continue;

    if (line.startsWith('ABSTAIN:')) {
      // Lines that already failed checkAnswer are counted in checkerProblems, not double-counted.
      if (!ABSTAIN_RE.test(line) || /\[(fact|asserted):/.test(line)) {
        continue;
      }
      const payload = line.slice('ABSTAIN:'.length).trim();
      if (encoder.encode(payload).length > MAX_ABSTAIN_PAYLOAD_BYTES) {
        offTargetStatements++;
        recordDiagnostic(lineNo, `ABSTAIN payload exceeds ${MAX_ABSTAIN_PAYLOAD_BYTES} bytes`);
      } else {
        validAbstentions++;
      }
      continue;
    }

    // Statement line: skip if checkAnswer already flagged this line.
    if (!line.includes('[fact') && !line.includes('[asserted')) {
      continue;
    }
    const found = [...line.matchAll(CITATION_RE)];
    const loose = (line.match(/\[(fact|asserted)\b/g) ?? []).length;
    if (found.length === 0 || loose !== found.length) {
      continue;
    }
    let hasCheckerIssue = false;
    const lineCites: Array<{ readonly kind: 'fact' | 'asserted'; readonly id: string }> = [];
    for (const m of found) {
      const kind = m[1] as 'fact' | 'asserted';
      const id = m[2] ?? '';
      if (!FACT_ID_RE.test(id) || invalidSet.has(`${kind}:${id}`)) {
        hasCheckerIssue = true;
        break;
      }
      lineCites.push({ kind, id });
    }
    if (hasCheckerIssue) continue;

    // Checker-clean statement line: verify every citation on the line is accepted and patterns match.
    const statementText = line.replace(CITATION_RE, ' ').trim();
    let allCitesAccepted = true;
    let allPatternsMatched = true;
    for (const cite of lineCites) {
      const opt = acceptedByKey.get(`${cite.kind}:${cite.id}`);
      if (!opt) {
        allCitesAccepted = false;
        break;
      }
      if (!matchesAnswerSpec(statementText, opt)) {
        allPatternsMatched = false;
      }
    }

    if (!allCitesAccepted) {
      offTargetStatements++;
      recordDiagnostic(lineNo, 'off-target statement: citation is not accepted for this case');
    } else if (!allPatternsMatched) {
      offTargetStatements++;
      recordDiagnostic(lineNo, 'off-target statement: answer does not match expected pattern');
    } else {
      acceptedStatements++;
      if ('cite' in evalCase.expect) {
        matchedTarget = true;
      }
    }
  }

  keptProblems.sort(compareProblems);
  const unsupportedProblems = checkerProblems + offTargetStatements;

  let outcome: EvalOutcome;
  if (!check.ok) {
    outcome = 'unsupported';
  } else if ('cite' in evalCase.expect) {
    if (offTargetStatements > 0) {
      outcome = 'wrong';
    } else if (matchedTarget) {
      outcome = 'correct';
    } else if (validAbstentions > 0) {
      outcome = 'abstained_wrongly';
    } else {
      outcome = 'wrong';
    }
  } else {
    if (offTargetStatements > 0) {
      outcome = 'wrong';
    } else if (validAbstentions > 0 || acceptedStatements > 0) {
      outcome = 'abstained_correctly';
    } else {
      outcome = 'wrong';
    }
  }

  return {
    outcome,
    checkerProblems,
    offTargetStatements,
    unsupportedProblems,
    problems: keptProblems,
  };
}

/** Build prompts for the selected cases without running any model or appending to any log. */
export async function runEvalDryRun(caseIds?: readonly string[]): Promise<EvalDryRunResult> {
  const { cases, subset } = selectEvalCases(caseIds);
  const tempRoot = mkdtempSync(join(tmpdir(), 'facts-eval-'));
  try {
    const fx = buildGateFixture(tempRoot);
    const fixturePaths = [tempRoot, fx.repoDir, fx.logPath, fx.indexPath, fx.reposPath];
    const repos = loadRepoMap(fx.reposPath);
    const checker = new FreshnessChecker({ repos });
    const digestCache = new Map<string, string>();
    const digestFor = (maxSensitivity?: Exclude<Sensitivity, 'secret'>): string => {
      const key = maxSensitivity ?? 'personal';
      let cached = digestCache.get(key);
      if (cached === undefined) {
        cached = generateDigest({
          logPath: fx.logPath,
          indexPath: fx.indexPath,
          project: PROJECT,
          repos,
          nowMs: NOW_MS,
          write: false,
          ...(maxSensitivity ? { maxSensitivity } : {}),
        }).text;
        digestCache.set(key, cached);
      }
      return cached;
    };

    const out: EvalDryRunCase[] = [];
    for (const c of cases) {
      const { text, ...rest } = c.query;
      const queryResult = await queryFacts({
        logPath: fx.logPath,
        indexPath: fx.indexPath,
        ...(text ? { text } : {}),
        ...rest,
        nowMs: NOW_MS,
        freshnessResolver: checker.resolver(),
        freshnessPrefetch: checker.prefetcher(),
      });
      const prompt = stripFixturePaths(
        buildEvalPrompt(c, digestFor(c.query.maxSensitivity), formatQueryText(queryResult)),
        fixturePaths,
      );
      out.push({ id: c.id, group: c.group, prompt, input_tokens: estimateTokens(prompt) });
    }
    return { cases_run: out.length, subset, cases: out };
  } finally {
    rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5 });
  }
}

export function formatDryRunPrompts(dryRun: EvalDryRunResult): string {
  const parts: string[] = [];
  for (const item of dryRun.cases) {
    parts.push(`================ CASE ${item.id} (group ${item.group}, est_input_tokens=${item.input_tokens}) ================`);
    parts.push(item.prompt.trimEnd());
  }
  return parts.join('\n\n');
}

/**
 * Run the model-in-the-loop harness on the synthetic fixture in a fresh temp directory.
 * Isolates the model in a separate empty temp cwd with stripped `FACTS_LEDGER_*` env vars,
 * verifies fixture and result-log integrity before grading/appending, and appends one result
 * block to `options.logPath` only on full (non-`--cases`) runs (A-29).
 */
export async function runEval(options: EvalOptions): Promise<EvalResult> {
  if (!options.modelCmd || options.modelCmd.trim().length === 0) {
    throw new Error('--model-cmd is required (or pass --dry-run to inspect prompts)');
  }
  const caseTimeoutMs = options.caseTimeoutMs ?? DEFAULT_CASE_TIMEOUT_MS;
  if (!Number.isFinite(caseTimeoutMs) || !Number.isInteger(caseTimeoutMs) || caseTimeoutMs < 1) {
    throw new Error('--case-timeout-ms must be a positive integer');
  }
  const modelName = options.modelName ?? deriveModelName(options.modelCmd);
  // Validate the model label up front so a bad --model-name fails before running 50 cases.
  validateTokenUsage({ model: modelName, task: 'facts-eval', input: 0, output: 0, measured: false });
  if (!options.project || options.project.trim().length === 0) {
    throw new Error('--project must not be empty');
  }

  const { cases, subset } = selectEvalCases(options.caseIds);
  const modelArgs = options.modelArgs ?? [];
  const childEnv = buildModelChildEnv(process.env);
  const resultLogBefore = snapshotFileIntegrity(options.logPath);

  const counts = {
    correct: 0,
    wrong: 0,
    abstained_correctly: 0,
    abstained_wrongly: 0,
    unsupported: 0,
    error: 0,
  };
  let totalCheckerProblems = 0;
  let totalOffTargetStatements = 0;
  let unsupportedClaims = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  const caseResults: EvalCaseResult[] = [];

  const tempRoot = mkdtempSync(join(tmpdir(), 'facts-eval-'));
  const modelCwd = mkdtempSync(join(tmpdir(), 'facts-eval-cwd-'));
  try {
    const fx = buildGateFixture(tempRoot);
    const fixturePaths = [tempRoot, fx.repoDir, fx.logPath, fx.indexPath, fx.reposPath];
    const repos = loadRepoMap(fx.reposPath);
    const checker = new FreshnessChecker({ repos });
    const digestCache = new Map<string, string>();
    const digestFor = (maxSensitivity?: Exclude<Sensitivity, 'secret'>): string => {
      const key = maxSensitivity ?? 'personal';
      let cached = digestCache.get(key);
      if (cached === undefined) {
        cached = generateDigest({
          logPath: fx.logPath,
          indexPath: fx.indexPath,
          project: PROJECT,
          repos,
          nowMs: NOW_MS,
          write: false,
          ...(maxSensitivity ? { maxSensitivity } : {}),
        }).text;
        digestCache.set(key, cached);
      }
      return cached;
    };

    let lastOutputLarge = false;
    for (const c of cases) {
      if (lastOutputLarge) {
        collectGarbage();
        lastOutputLarge = false;
      }
      const { text, ...rest } = c.query;
      const queryResult = await queryFacts({
        logPath: fx.logPath,
        indexPath: fx.indexPath,
        ...(text ? { text } : {}),
        ...rest,
        nowMs: NOW_MS,
        freshnessResolver: checker.resolver(),
        freshnessPrefetch: checker.prefetcher(),
      });
      const prompt = stripFixturePaths(
        buildEvalPrompt(c, digestFor(c.query.maxSensitivity), formatQueryText(queryResult)),
        fixturePaths,
      );
      const inputTokens = estimateTokens(prompt);
      totalInputTokens += inputTokens;

      const fixtureBefore = snapshotFixtureIntegrity(fx);
      const modelRun = await runModelCommand(options.modelCmd, modelArgs, prompt, caseTimeoutMs, {
        cwd: modelCwd,
        env: childEnv,
      });
      const fixtureAfter = snapshotFixtureIntegrity(fx);
      const fixtureDiffs = diffFixtureIntegrity(fixtureBefore, fixtureAfter);
      if (fixtureDiffs.length > 0) {
        throw new Error(
          `Fixture integrity check failed after case ${c.id} (${fixtureDiffs.join('; ')}); aborting eval without appending a block`,
        );
      }

      const outputTokens = estimateTokensFromBytes(modelRun.outputBytes);
      totalOutputTokens += outputTokens;

      if (!modelRun.ok) {
        counts.error++;
        caseResults.push({
          id: c.id,
          group: c.group,
          outcome: 'error',
          checker_problems: 0,
          off_target_statements: 0,
          unsupported_problems: 0,
          input_tokens: inputTokens,
          output_tokens: outputTokens,
          error: modelRun.error ?? 'Model command failed',
        });
        continue;
      }

      let check: CheckAnswerResult;
      try {
        check = await checkAnswer(modelRun.output, {
          logPath: fx.logPath,
          indexPath: fx.indexPath,
          repos,
          nowMs: NOW_MS,
          maxProblems: MAX_EVAL_CASE_PROBLEMS,
          ...(c.query.maxSensitivity ? { maxSensitivity: c.query.maxSensitivity } : {}),
        });
      } catch (err) {
        const msg = sanitizeInlineText((err as Error).message);
        check = {
          ok: false,
          statements: 0,
          abstentions: 0,
          citations: 0,
          problemCount: 1,
          problems: [{ line: 0, problem: msg }],
          invalidCitations: [],
        };
      }

      const scored = scoreEvalAnswer(c, modelRun.output, check);
      counts[scored.outcome]++;
      totalCheckerProblems += scored.checkerProblems;
      totalOffTargetStatements += scored.offTargetStatements;
      unsupportedClaims += scored.unsupportedProblems;
      caseResults.push({
        id: c.id,
        group: c.group,
        outcome: scored.outcome,
        checker_problems: scored.checkerProblems,
        off_target_statements: scored.offTargetStatements,
        unsupported_problems: scored.unsupportedProblems,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        ...(scored.problems.length > 0 ? { problems: scored.problems } : {}),
      });
      if (modelRun.outputBytes >= 65_536) {
        lastOutputLarge = true;
      }
    }
  } finally {
    rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5 });
    rmSync(modelCwd, { recursive: true, force: true, maxRetries: 5 });
  }

  const casesRun = caseResults.length;
  const passesBar =
    !subset && unsupportedClaims === 0 && counts.error === 0 && casesRun === CASES.length;
  const tokenUsage = validateTokenUsage({
    model: modelName,
    task: 'facts-eval',
    input: totalInputTokens,
    output: totalOutputTokens,
    measured: false,
  });

  const resultLogAfter = snapshotFileIntegrity(options.logPath);
  if (!sameFileIntegrity(resultLogBefore, resultLogAfter)) {
    throw new Error(
      `Result log changed during eval run (size ${resultLogBefore.size} -> ${resultLogAfter.size}, sha256 ${resultLogBefore.sha256.slice(0, 12)} -> ${resultLogAfter.sha256.slice(0, 12)}); refusing to append eval block`,
    );
  }

  let block: Block | null = null;
  if (!subset) {
    const perCase = caseResults.map((r) => `${r.id}:${r.outcome}`).join(' ');
    const summaryLine =
      `passes_bar=${passesBar} cases=${casesRun} unsupported_claims=${unsupportedClaims} ` +
      `checker_problems=${totalCheckerProblems} off_target_statements=${totalOffTargetStatements} ` +
      `correct=${counts.correct} wrong=${counts.wrong} abstained_correctly=${counts.abstained_correctly} ` +
      `abstained_wrongly=${counts.abstained_wrongly} unsupported=${counts.unsupported} error=${counts.error}`;
    block = appendBlock(options.logPath, {
      schema: 2,
      agent: options.agent,
      project: options.project,
      status: 'done',
      intent: `facts eval: ${modelName} unsupported=${unsupportedClaims}/${casesRun}`,
      reasoning: `Model-in-the-loop eval (${casesRun} cases): ${summaryLine}.`,
      verification: `${summaryLine} | ${perCase}`,
      token_usage: tokenUsage,
    });
  }

  return {
    model: modelName,
    cases_run: casesRun,
    subset,
    counts,
    checker_problems: totalCheckerProblems,
    off_target_statements: totalOffTargetStatements,
    unsupported_claims: unsupportedClaims,
    passes_bar: passesBar,
    ...(subset ? { passes_bar_reason: 'selection' as const } : {}),
    token_usage: tokenUsage,
    block_id: block ? block.id : null,
    cases: caseResults,
  };
}

export function formatEvalText(result: EvalResult): string {
  const barSuffix = result.passes_bar_reason ? ` (${result.passes_bar_reason})` : '';
  const lines = [
    `facts eval: model=${sanitizeInlineText(result.model)} cases=${result.cases_run}${result.subset ? ' (selection)' : ''} passes_bar=${result.passes_bar}${barSuffix}`,
    `  correct=${result.counts.correct} wrong=${result.counts.wrong} abstained_correctly=${result.counts.abstained_correctly} abstained_wrongly=${result.counts.abstained_wrongly} unsupported=${result.counts.unsupported} error=${result.counts.error}`,
    `  unsupported_claims=${result.unsupported_claims} (checker_problems=${result.checker_problems} off_target_statements=${result.off_target_statements})`,
    `  tokens (estimated, UTF-8 bytes/4): input=${result.token_usage.input} output=${result.token_usage.output} measured=${result.token_usage.measured}`,
  ];
  if (result.block_id !== null) {
    lines.push(`  appended block: ${result.block_id}`);
  } else if (result.subset) {
    lines.push('  block not appended (selection run via --cases)');
  }
  const notable = result.cases.filter(
    (c) => c.outcome !== 'correct' && c.outcome !== 'abstained_correctly',
  );
  if (notable.length > 0) {
    lines.push('  non-passing cases:');
    for (const c of notable) {
      let detail = '';
      if (c.error) {
        detail = ` (${sanitizeInlineText(c.error)})`;
      } else if (c.problems && c.problems.length > 0) {
        const omitted = Math.max(0, c.unsupported_problems - c.problems.length);
        const shown = c.problems
          .map((p) => `line ${p.line}: ${sanitizeInlineText(p.problem)}`)
          .join('; ');
        detail = omitted > 0 ? ` (${shown}; ... +${omitted} more)` : ` (${shown})`;
      }
      lines.push(`    ${c.id} [${c.outcome}]${detail}`);
    }
  }
  return lines.join('\n');
}

// Step Zero 10.3: model-in-the-loop evaluation harness (`facts eval`).
// Spawns any local command without a shell, feeds each case's deterministic prompt on stdin,
// judges answers with `checkAnswer`, and appends one summary block on full 50-case runs.
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { TextDecoder, TextEncoder } from 'node:util';
import { validateTokenUsage } from '../add.js';
import {
  MAX_ANSWER_BYTES,
  checkAnswer,
  type AnswerProblem,
  type CheckAnswerResult,
} from '../check-answer.js';
import { generateDigest } from '../digest.js';
import { FreshnessChecker } from '../freshness.js';
import { appendBlock } from '../log.js';
import { formatQueryText, queryFacts, sanitizeInlineText } from '../query.js';
import { loadRepoMap } from '../repos.js';
import { type Block, type Sensitivity, type TokenUsage } from '../types.js';
import { CASES, type EvalCase } from './cases.js';
import { NOW_MS, PROJECT, buildGateFixture } from './fixture.js';
import { buildEvalPrompt } from './prompt.js';

export const DEFAULT_CASE_TIMEOUT_MS = 120_000;

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
  readonly unsupported_claims: number;
  readonly passes_bar: boolean;
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

export interface ModelCommandResult {
  readonly ok: boolean;
  readonly output: string;
  readonly outputBytes: number;
  readonly error?: string;
}

const encoder = new TextEncoder();
const fatalUtf8 = new TextDecoder('utf-8', { fatal: true });
const CITATION_RE = /\[(fact|asserted):([0-9a-f]{12}\.\d{1,4})\]/g;

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

export function selectEvalCases(
  caseIds?: readonly string[],
): { readonly cases: readonly EvalCase[]; readonly subset: boolean } {
  if (!caseIds || caseIds.length === 0) {
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
  return { cases: selected, subset: selected.length < CASES.length };
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
 * Spawn the model executable directly (`shell: false`), write `prompt` to stdin and close it,
 * collect stdout capped at `MAX_ANSWER_BYTES`, and enforce `timeoutMs`.
 * Copies the `createCommandEmbedder` process-tree termination pattern from `src/query.ts`.
 */
export function runModelCommand(
  executablePath: string,
  baseArgs: readonly string[],
  prompt: string,
  timeoutMs = DEFAULT_CASE_TIMEOUT_MS,
): Promise<ModelCommandResult> {
  const effectiveTimeoutMs = Math.max(1, timeoutMs);
  return new Promise((resolvePromise) => {
    const useDetachedGroup = process.platform !== 'win32';
    const child = spawn(executablePath, [...baseArgs], {
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
      shell: false,
      detached: useDetachedGroup,
    });
    const stdoutChunks: Uint8Array[] = [];
    let stdoutBytes = 0;
    let settled = false;
    let terminating = false;

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
      if (settled || terminating) return;
      const code = (err as { code?: string }).code;
      if (code !== 'EPIPE') {
        terminateAndFail(`Model command stdin failed (${code ?? 'error'})`);
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

    if (!child.stdin) {
      terminateAndFail('Model command stdin pipe unavailable');
      return;
    }
    child.stdin.end(prompt);
  });
}

/** Deterministic scoring of a checked answer against a case's expectation (A-29). */
export function scoreEvalAnswer(
  evalCase: EvalCase,
  answerText: string,
  check: CheckAnswerResult,
): { readonly outcome: EvalOutcome; readonly unsupportedProblems: number } {
  if (!check.ok) {
    return { outcome: 'unsupported', unsupportedProblems: check.problems.length };
  }
  const onlyAbstain = check.statements === 0 && check.abstentions > 0;
  const citations: Array<{ readonly kind: 'fact' | 'asserted'; readonly id: string }> = [];
  for (const m of answerText.matchAll(CITATION_RE)) {
    citations.push({ kind: m[1] as 'fact' | 'asserted', id: m[2] as string });
  }
  const hasCitation = (id: string, prefix: 'fact' | 'asserted'): boolean =>
    citations.some((c) => c.id === id && c.kind === prefix);

  if ('cite' in evalCase.expect) {
    if (onlyAbstain) {
      return { outcome: 'abstained_wrongly', unsupportedProblems: 0 };
    }
    if (hasCitation(evalCase.expect.cite, evalCase.expect.as)) {
      return { outcome: 'correct', unsupportedProblems: 0 };
    }
    return { outcome: 'wrong', unsupportedProblems: 0 };
  }

  if (onlyAbstain) {
    return { outcome: 'abstained_correctly', unsupportedProblems: 0 };
  }
  if (
    evalCase.expect.orCite &&
    hasCitation(evalCase.expect.orCite.id, evalCase.expect.orCite.as)
  ) {
    return { outcome: 'abstained_correctly', unsupportedProblems: 0 };
  }
  return { outcome: 'wrong', unsupportedProblems: 0 };
}

/** Build prompts for the selected cases without running any model or appending to any log. */
export async function runEvalDryRun(caseIds?: readonly string[]): Promise<EvalDryRunResult> {
  const { cases, subset } = selectEvalCases(caseIds);
  const tempRoot = mkdtempSync(join(tmpdir(), 'facts-eval-'));
  try {
    const fx = buildGateFixture(tempRoot);
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
      const prompt = buildEvalPrompt(c, digestFor(c.query.maxSensitivity), formatQueryText(queryResult));
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
 * Appends one result block to `options.logPath` when all 50 cases run; subset runs
 * (`--cases`) do not append a block (A-29).
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

  const counts = {
    correct: 0,
    wrong: 0,
    abstained_correctly: 0,
    abstained_wrongly: 0,
    unsupported: 0,
    error: 0,
  };
  let unsupportedClaims = 0;
  let totalInputTokens = 0;
  let totalOutputTokens = 0;
  const caseResults: EvalCaseResult[] = [];

  const tempRoot = mkdtempSync(join(tmpdir(), 'facts-eval-'));
  try {
    const fx = buildGateFixture(tempRoot);
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
      const prompt = buildEvalPrompt(c, digestFor(c.query.maxSensitivity), formatQueryText(queryResult));
      const inputTokens = estimateTokens(prompt);
      totalInputTokens += inputTokens;

      const modelRun = await runModelCommand(options.modelCmd, modelArgs, prompt, caseTimeoutMs);
      const outputTokens = estimateTokensFromBytes(modelRun.outputBytes);
      totalOutputTokens += outputTokens;

      if (!modelRun.ok) {
        counts.error++;
        caseResults.push({
          id: c.id,
          group: c.group,
          outcome: 'error',
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
          ...(c.query.maxSensitivity ? { maxSensitivity: c.query.maxSensitivity } : {}),
        });
      } catch (err) {
        const msg = sanitizeInlineText((err as Error).message);
        check = {
          ok: false,
          statements: 0,
          abstentions: 0,
          citations: 0,
          problems: [{ line: 0, problem: msg }],
        };
      }

      const scored = scoreEvalAnswer(c, modelRun.output, check);
      counts[scored.outcome]++;
      unsupportedClaims += scored.unsupportedProblems;
      caseResults.push({
        id: c.id,
        group: c.group,
        outcome: scored.outcome,
        unsupported_problems: scored.unsupportedProblems,
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        ...(check.problems.length > 0 ? { problems: check.problems } : {}),
      });
    }
  } finally {
    rmSync(tempRoot, { recursive: true, force: true, maxRetries: 5 });
  }

  const casesRun = caseResults.length;
  const passesBar = unsupportedClaims === 0 && counts.error === 0 && casesRun === CASES.length;
  const tokenUsage = validateTokenUsage({
    model: modelName,
    task: 'facts-eval',
    input: totalInputTokens,
    output: totalOutputTokens,
    measured: false,
  });

  let block: Block | null = null;
  if (!subset) {
    const perCase = caseResults.map((r) => `${r.id}:${r.outcome}`).join(' ');
    const summaryLine =
      `passes_bar=${passesBar} cases=${casesRun} unsupported_claims=${unsupportedClaims} ` +
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
    unsupported_claims: unsupportedClaims,
    passes_bar: passesBar,
    token_usage: tokenUsage,
    block_id: block ? block.id : null,
    cases: caseResults,
  };
}

export function formatEvalText(result: EvalResult): string {
  const lines = [
    `facts eval: model=${sanitizeInlineText(result.model)} cases=${result.cases_run}${result.subset ? ' (subset)' : ''} passes_bar=${result.passes_bar}`,
    `  correct=${result.counts.correct} wrong=${result.counts.wrong} abstained_correctly=${result.counts.abstained_correctly} abstained_wrongly=${result.counts.abstained_wrongly} unsupported=${result.counts.unsupported} error=${result.counts.error}`,
    `  unsupported_claims=${result.unsupported_claims}`,
    `  tokens (estimated, UTF-8 bytes/4): input=${result.token_usage.input} output=${result.token_usage.output} measured=${result.token_usage.measured}`,
  ];
  if (result.block_id !== null) {
    lines.push(`  appended block: ${result.block_id}`);
  } else if (result.subset) {
    lines.push('  block not appended (subset run via --cases)');
  }
  const notable = result.cases.filter(
    (c) => c.outcome !== 'correct' && c.outcome !== 'abstained_correctly',
  );
  if (notable.length > 0) {
    lines.push('  non-passing cases:');
    for (const c of notable) {
      const detail = c.error
        ? ` (${sanitizeInlineText(c.error)})`
        : c.problems && c.problems.length > 0
          ? ` (${c.problems.map((p) => `line ${p.line}: ${sanitizeInlineText(p.problem)}`).join('; ')})`
          : '';
      lines.push(`    ${c.id} [${c.outcome}]${detail}`);
    }
  }
  return lines.join('\n');
}

import { Buffer } from 'node:buffer';
import { FreshnessChecker } from './freshness.js';
import { defaultIndexPath, openIndexReadOnlyStrict, openSyncedIndexForQuery } from './index-db.js';
import { classifyPresentation, lookupFactsByIds } from './query.js';
import { type RepoMap } from './repos.js';
import { type Sensitivity } from './types.js';

/**
 * Citation checker (Step Zero 10.2). Line rule (A-28): every non-blank line is either an
 * abstention (`ABSTAIN: <text>`) or a statement, and every statement carries at least one
 * citation `[fact:<id>]` or `[asserted:<id>]`. The checker does not judge whether the
 * statement follows from the fact; it only checks that every citation may be used.
 */

export const MAX_ANSWER_BYTES = 256 * 1024;
export const MAX_DISTINCT_CITATIONS = 500;
export const MAX_STORED_PROBLEMS = 20;

const CITATION_RE = /\[(fact|asserted):([^\]\s]*)\]/g;
const FACT_ID_RE = /^[0-9a-f]{12}\.\d{1,4}$/;
const ABSTAIN_RE = /^ABSTAIN:[ \t\r]*\S/;

function isRealWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0d || code === 0x0a;
}

/** Reject U+0000-U+001F (except tab/CR/LF) and U+007F anywhere on a line before scoring. */
function hasDisallowedControlChar(text: string, start: number, end: number): boolean {
  for (let i = start; i < end; i++) {
    const code = text.charCodeAt(i);
    if ((code < 0x20 && code !== 0x09 && code !== 0x0d && code !== 0x0a) || code === 0x7f) {
      return true;
    }
  }
  return false;
}

export interface AnswerProblem {
  readonly line: number;
  readonly problem: string;
}

export interface PendingCitation {
  readonly line: number;
  readonly kind: 'fact' | 'asserted';
  readonly id: string;
}

export type NonBlankLineCallback = (
  lineNo: number,
  kind: 'abstain' | 'statement',
  syntaxClean: boolean,
  line?: string,
  citations?: readonly PendingCitation[],
) => void;

export interface AnswerScanner {
  feedChunk(chunk: string): void;
  finish(): void;
  finalize(options: CheckAnswerOptions): Promise<CheckAnswerResult>;
}

export interface CheckAnswerResult {
  readonly ok: boolean;
  readonly statements: number;
  readonly abstentions: number;
  readonly citations: number;
  readonly problemCount: number;
  readonly problems: readonly AnswerProblem[];
  readonly invalidCitations: readonly string[];
}

export interface CheckAnswerOptions {
  readonly logPath: string;
  readonly indexPath?: string;
  readonly repos: RepoMap;
  readonly maxSensitivity?: Exclude<Sensitivity, 'secret'>;
  readonly nowMs?: number;
  readonly maxProblems?: number;
  /** Open the pre-built index strictly read-only and fail closed without rebuilding on failure. */
  readonly readOnlyIndex?: boolean;
}

interface CitationVerdict {
  readonly asFact: string | null;
  readonly asAsserted: string | null;
}

function compareProblems(a: AnswerProblem, b: AnswerProblem): number {
  return a.line - b.line || (a.problem < b.problem ? -1 : a.problem > b.problem ? 1 : 0);
}

/**
 * Streaming line-by-line citation scanner. Accepts UTF-8 text in arbitrarily split chunks
 * (for example stdout pipe chunks from a model process) without buffering the full answer
 * or allocating substrings for uncited fast-path lines.
 */
export function createAnswerScanner(
  maxProblems = MAX_STORED_PROBLEMS,
  onNonBlankLine?: NonBlankLineCallback,
): AnswerScanner {
  const cap = Math.max(0, Math.floor(maxProblems));
  const problems: AnswerProblem[] = [];
  let problemCount = 0;
  const recordProblem = (line: number, problem: string): void => {
    problemCount++;
    if (cap === 0) return;
    if (problems.length < cap) {
      problems.push({ line, problem });
      if (problems.length === cap) problems.sort(compareProblems);
      return;
    }
    const worst = problems[problems.length - 1] as AnswerProblem;
    if (line > worst.line || (line === worst.line && problem >= worst.problem)) return;
    problems[problems.length - 1] = { line, problem };
    problems.sort(compareProblems);
  };

  const pending: PendingCitation[] = [];
  let statements = 0;
  let abstentions = 0;
  let hasNonBlankLine = false;
  let lineNo = 0;
  let started = false;
  let carry = '';
  let finished = false;

  const processSlowLine = (line: string): void => {
    if (line.length === 0) return;
    if (line.startsWith('ABSTAIN:')) {
      let syntaxClean = true;
      if (!ABSTAIN_RE.test(line)) {
        recordProblem(lineNo, 'ABSTAIN without a description of what is not known');
        syntaxClean = false;
      } else {
        abstentions++;
      }
      if (/\[(fact|asserted):/.test(line)) {
        recordProblem(lineNo, 'ABSTAIN line must not cite facts');
        syntaxClean = false;
      }
      onNonBlankLine?.(lineNo, 'abstain', syntaxClean, syntaxClean ? line : undefined);
      return;
    }
    statements++;
    if (!line.includes('[fact') && !line.includes('[asserted')) {
      recordProblem(lineNo, 'statement without a citation');
      onNonBlankLine?.(lineNo, 'statement', false);
      return;
    }
    const found = [...line.matchAll(CITATION_RE)];
    // Any other bracket that starts like a citation is malformed.
    const loose = (line.match(/\[(fact|asserted)\b/g) ?? []).length;
    let syntaxClean = true;
    if (loose !== found.length) {
      recordProblem(lineNo, 'malformed citation');
      syntaxClean = false;
    }
    if (found.length === 0) {
      recordProblem(lineNo, 'statement without a citation');
      onNonBlankLine?.(lineNo, 'statement', false);
      return;
    }
    const lineCitations: PendingCitation[] = [];
    for (const m of found) {
      const kind = m[1] as 'fact' | 'asserted';
      const id = m[2] ?? '';
      if (!FACT_ID_RE.test(id)) {
        recordProblem(lineNo, `invalid fact id in ${kind}: citation`);
        syntaxClean = false;
        continue;
      }
      const cite: PendingCitation = { line: lineNo, kind, id };
      pending.push(cite);
      lineCitations.push(cite);
    }
    onNonBlankLine?.(
      lineNo,
      'statement',
      syntaxClean,
      syntaxClean ? line : undefined,
      syntaxClean ? lineCitations : undefined,
    );
  };

  const processSpan = (text: string, start: number, end: number, nextBracket: number): number => {
    if (hasDisallowedControlChar(text, start, end)) {
      hasNonBlankLine = true;
      let s = start;
      while (s < end && isRealWhitespace(text.charCodeAt(s))) s++;
      const kind = text.startsWith('ABSTAIN:', s) ? 'abstain' : 'statement';
      recordProblem(lineNo, 'line contains disallowed control character');
      onNonBlankLine?.(lineNo, kind, false);
      return nextBracket;
    }
    let s = start;
    let e = end;
    while (s < e && isRealWhitespace(text.charCodeAt(s))) s++;
    while (e > s && isRealWhitespace(text.charCodeAt(e - 1))) e--;
    if (s === e) return nextBracket;
    hasNonBlankLine = true;

    // Fast path for non-ABSTAIN lines without '[' (O(1) amortized, avoids slicing up to 131k short lines).
    if (!text.startsWith('ABSTAIN:', s)) {
      let nb = nextBracket;
      if (nb === -2 || (nb !== -1 && nb < s)) {
        nb = text.indexOf('[', s);
      }
      if (nb === -1 || nb >= e) {
        statements++;
        recordProblem(lineNo, 'statement without a citation');
        onNonBlankLine?.(lineNo, 'statement', false);
        return nb;
      }
      nextBracket = nb;
    }

    processSlowLine(text.slice(s, e));
    return nextBracket;
  };

  const feedChunk = (chunk: string): void => {
    if (chunk.length === 0) return;
    let pos = 0;
    if (!started) {
      started = true;
      if (chunk.charCodeAt(0) === 0xfeff) {
        pos = 1;
        if (pos >= chunk.length) return;
      }
    }
    if (carry.length > 0) {
      const nl = chunk.indexOf('\n', pos);
      if (nl === -1) {
        carry += pos === 0 ? chunk : chunk.slice(pos);
        return;
      }
      const combined = carry + chunk.slice(pos, nl);
      carry = '';
      lineNo++;
      processSpan(combined, 0, combined.length, -2);
      pos = nl + 1;
      if (pos >= chunk.length) return;
    }

    let nextBracket = chunk.indexOf('[', pos);
    while (pos < chunk.length) {
      const nl = chunk.indexOf('\n', pos);
      if (nl === -1) {
        carry = pos === 0 ? chunk : chunk.slice(pos);
        break;
      }
      lineNo++;
      nextBracket = processSpan(chunk, pos, nl, nextBracket);
      pos = nl + 1;
    }
  };

  const finish = (): void => {
    if (finished) return;
    finished = true;
    if (carry.length > 0) {
      const remaining = carry;
      carry = '';
      lineNo++;
      processSpan(remaining, 0, remaining.length, -2);
    }
  };

  const finalize = async (options: CheckAnswerOptions): Promise<CheckAnswerResult> => {
    finish();
    const distinct = [...new Set(pending.map((p) => p.id))].sort();
    if (distinct.length > MAX_DISTINCT_CITATIONS) {
      throw new Error(`Answer cites more than ${MAX_DISTINCT_CITATIONS} distinct facts`);
    }
    const nowMs = options.nowMs ?? Date.now();
    const checker = new FreshnessChecker({ repos: options.repos });
    const resolver = checker.resolver();
    // One index open, one batched lookup and one git prefetch for every cited id.
    const indexPath = options.indexPath ?? defaultIndexPath(options.logPath);
    const { db } = options.readOnlyIndex
      ? openIndexReadOnlyStrict(options.logPath, indexPath)
      : openSyncedIndexForQuery(options.logPath, indexPath, false);
    let facts;
    try {
      facts = lookupFactsByIds(db, distinct, options.maxSensitivity);
    } finally {
      db.close();
    }
    if (facts.length > 0) checker.prefetcher()(facts, nowMs);
    const byId = new Map(facts.map((f) => [f.fact_id, f]));
    const verdicts = new Map<string, CitationVerdict>();
    for (const id of distinct) {
      const fact = byId.get(id);
      if (!fact) {
        verdicts.set(id, { asFact: 'cited fact does not exist', asAsserted: 'cited fact does not exist' });
        continue;
      }
      const view = classifyPresentation('match', fact, resolver(fact, nowMs));
      let reason: string | null = null;
      if (fact.retracted) reason = 'cited fact is retracted';
      else if (fact.superseded) reason = 'cited fact is superseded';
      else if (!view.citable) reason = `cited fact is not currently fresh (${view.effectiveFreshness})`;
      const asFact = reason ?? (view.badge === 'VERIFIED' ? null : `cited fact is ${view.badge}, not VERIFIED; cite it as asserted:`);
      verdicts.set(id, { asFact, asAsserted: reason });
    }
    const invalidCitationsSet = new Set<string>();
    for (const p of pending) {
      const v = verdicts.get(p.id) as CitationVerdict;
      const problem = p.kind === 'fact' ? v.asFact : v.asAsserted;
      if (problem) {
        invalidCitationsSet.add(`${p.kind}:${p.id}`);
        recordProblem(p.line, `${p.kind}:${p.id}: ${problem}`);
      }
    }
    if (statements === 0 && abstentions === 0 && !hasNonBlankLine) recordProblem(0, 'answer is empty');
    problems.sort(compareProblems);
    return {
      ok: problemCount === 0,
      statements,
      abstentions,
      citations: pending.length,
      problemCount,
      problems,
      invalidCitations: [...invalidCitationsSet].sort(),
    };
  };

  return { feedChunk, finish, finalize };
}

export async function checkAnswer(text: string, options: CheckAnswerOptions): Promise<CheckAnswerResult> {
  if (Buffer.byteLength(text, 'utf8') > MAX_ANSWER_BYTES) {
    throw new Error(`Answer exceeds ${MAX_ANSWER_BYTES} bytes`);
  }
  const scanner = createAnswerScanner(options.maxProblems ?? MAX_STORED_PROBLEMS);
  scanner.feedChunk(text);
  return scanner.finalize(options);
}

export function formatCheckAnswerText(result: CheckAnswerResult): string {
  const lines = result.problems.map((p) => `line ${p.line}: ${p.problem}`);
  if (result.problemCount > result.problems.length) {
    lines.push(`... and ${result.problemCount - result.problems.length} more problem(s) omitted`);
  }
  lines.push(
    `${result.ok ? 'check-answer: ok' : `check-answer: FAILED (${result.problemCount} problem(s))`}: ${result.statements} statement(s), ${result.citations} citation(s), ${result.abstentions} abstention(s)`,
  );
  return lines.join('\n');
}

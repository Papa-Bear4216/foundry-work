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

const FACT_ID_RE = /^[0-9a-f]{12}\.\d{1,4}$/;
const ABSTAIN_RE = /^ABSTAIN:[ \t]*\S/;

/** Horizontal whitespace only: ASCII space (0x20) or TAB (0x09). */
function isHorizontalWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09;
}

/** Match JavaScript `\s` code units for single-pass citation scanning. */
function isJsWhitespace(code: number): boolean {
  if (code === 0x20 || (code >= 0x09 && code <= 0x0d)) return true;
  if (code < 0xa0) return false;
  return (
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200a) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x202f ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  );
}

function isWordChar(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x5f
  );
}

/** Plain linear UTF-8 byte length scan over `text[start..end)` with optional early exit. */
function utf8ByteLengthSpan(text: string, start: number, end: number, limit?: number): number {
  let bytes = 0;
  for (let i = start; i < end; i++) {
    const code = text.charCodeAt(i);
    if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff && i + 1 < end) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i++;
      } else {
        bytes += 3;
      }
    } else {
      bytes += 3;
    }
    if (limit !== undefined && bytes > limit) return bytes;
  }
  return bytes;
}

/** Return true iff `text[start..end)` encodes to strictly more than `maxBytes` UTF-8 bytes. */
function utf8ByteLengthExceeds(text: string, start: number, end: number, maxBytes: number): boolean {
  const len = end - start;
  if (len > maxBytes) return true;
  if (len * 3 <= maxBytes) return false;
  return utf8ByteLengthSpan(text, start, end, maxBytes) > maxBytes;
}

/**
 * Single-pass linear-time citation extractor equivalent to `\[(fact|asserted):([^\]\s]*)\]`
 * plus loose `\[(fact|asserted)\b` count. When scanning from `[fact:`/`[asserted:` reaches
 * whitespace or end-of-line before `]`, no intervening `[` can close before that boundary,
 * so the cursor jumps directly past it in O(N) total time.
 */
function scanCitationsSinglePass(
  line: string,
): { readonly found: readonly { readonly kind: 'fact' | 'asserted'; readonly id: string }[]; readonly loose: number } {
  const len = line.length;
  let loose = 0;
  let lpos = 0;
  while (lpos < len) {
    const open = line.indexOf('[', lpos);
    if (open === -1) break;
    let after = -1;
    if (line.startsWith('fact', open + 1)) after = open + 5;
    else if (line.startsWith('asserted', open + 1)) after = open + 9;
    if (after !== -1 && (after === len || !isWordChar(line.charCodeAt(after)))) {
      loose++;
    }
    lpos = open + 1;
  }

  const found: Array<{ readonly kind: 'fact' | 'asserted'; readonly id: string }> = [];
  let pos = 0;
  while (pos < len) {
    const open = line.indexOf('[', pos);
    if (open === -1) break;
    let kind: 'fact' | 'asserted' | null = null;
    let idStart = -1;
    if (line.startsWith('fact:', open + 1)) {
      kind = 'fact';
      idStart = open + 6;
    } else if (line.startsWith('asserted:', open + 1)) {
      kind = 'asserted';
      idStart = open + 10;
    } else {
      pos = open + 1;
      continue;
    }
    let stop = idStart;
    while (stop < len) {
      const code = line.charCodeAt(stop);
      if (code === 0x5d /* ] */ || isJsWhitespace(code)) break;
      stop++;
    }
    if (stop < len && line.charCodeAt(stop) === 0x5d /* ] */) {
      found.push({ kind, id: line.slice(idStart, stop) });
      pos = stop + 1;
    } else {
      pos = stop + 1;
    }
  }
  return { found, loose };
}

/**
 * Reject embedded/bare CR, C0 controls other than TAB (0x09), DEL (0x7F), C1 controls
 * (U+0080-U+009F incl. U+0085), and Unicode line/paragraph separators (U+2028, U+2029)
 * anywhere on a line span (after stripping a single trailing CR-in-CRLF).
 */
function hasDisallowedControlChar(text: string, start: number, end: number): boolean {
  for (let i = start; i < end; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x20) {
      if (code !== 0x09) return true;
    } else if (code >= 0x7f) {
      if (code <= 0x9f || code === 0x2028 || code === 0x2029) return true;
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
  kind: 'abstain' | 'statement' | 'oversize',
  syntaxClean: boolean,
  line?: string,
  citations?: readonly PendingCitation[],
) => void;

export interface AnswerScannerOptions {
  /** Optional per-line UTF-8 byte cap (used by eval before regex/citation/NFKC parsing). */
  readonly maxLineBytes?: number;
}

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
  /** Optional per-line UTF-8 byte cap (eval only; omitted by gate and `facts check-answer`). */
  readonly maxLineBytes?: number;
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
  scannerOptions?: AnswerScannerOptions,
): AnswerScanner {
  const cap = Math.max(0, Math.floor(maxProblems));
  const maxLineBytes =
    scannerOptions?.maxLineBytes !== undefined ? Math.max(1, Math.floor(scannerOptions.maxLineBytes)) : undefined;
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
  let carryOverLimit = false;
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
      if (line.includes('[fact:') || line.includes('[asserted:')) {
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
    const { found, loose } = scanCitationsSinglePass(line);
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
      const kind = m.kind;
      const id = m.id;
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

  const processSpan = (
    text: string,
    start: number,
    end: number,
    nextBracket: number,
    endedWithLf: boolean,
  ): number => {
    const lineEnd = endedWithLf && end > start && text.charCodeAt(end - 1) === 0x0d ? end - 1 : end;
    if (maxLineBytes !== undefined && utf8ByteLengthExceeds(text, start, lineEnd, maxLineBytes)) {
      hasNonBlankLine = true;
      onNonBlankLine?.(lineNo, 'oversize', true);
      return nextBracket;
    }
    if (hasDisallowedControlChar(text, start, lineEnd)) {
      hasNonBlankLine = true;
      let s = start;
      while (s < lineEnd && isHorizontalWhitespace(text.charCodeAt(s))) s++;
      const kind = text.startsWith('ABSTAIN:', s) ? 'abstain' : 'statement';
      recordProblem(lineNo, 'line contains disallowed control character');
      onNonBlankLine?.(lineNo, kind, false);
      return nextBracket;
    }
    let s = start;
    let e = lineEnd;
    while (s < e && isHorizontalWhitespace(text.charCodeAt(s))) s++;
    while (e > s && isHorizontalWhitespace(text.charCodeAt(e - 1))) e--;
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
    if (carryOverLimit) {
      const nl = chunk.indexOf('\n', pos);
      if (nl === -1) return;
      carryOverLimit = false;
      carry = '';
      lineNo++;
      hasNonBlankLine = true;
      onNonBlankLine?.(lineNo, 'oversize', true);
      pos = nl + 1;
      if (pos >= chunk.length) return;
    }
    if (carry.length > 0) {
      const nl = chunk.indexOf('\n', pos);
      if (nl === -1) {
        const segLen = chunk.length - pos;
        if (maxLineBytes !== undefined && carry.length + segLen > maxLineBytes + 1) {
          carry = '';
          carryOverLimit = true;
          return;
        }
        carry += pos === 0 ? chunk : chunk.slice(pos);
        return;
      }
      const segLen = nl - pos;
      if (maxLineBytes !== undefined && carry.length + segLen > maxLineBytes + 1) {
        carry = '';
        lineNo++;
        hasNonBlankLine = true;
        onNonBlankLine?.(lineNo, 'oversize', true);
        pos = nl + 1;
        if (pos >= chunk.length) return;
      } else {
        const combined = carry + chunk.slice(pos, nl);
        carry = '';
        lineNo++;
        processSpan(combined, 0, combined.length, -2, true);
        pos = nl + 1;
        if (pos >= chunk.length) return;
      }
    }

    let nextBracket = chunk.indexOf('[', pos);
    while (pos < chunk.length) {
      const nl = chunk.indexOf('\n', pos);
      if (nl === -1) {
        const segLen = chunk.length - pos;
        if (maxLineBytes !== undefined && segLen > maxLineBytes + 1) {
          carry = '';
          carryOverLimit = true;
        } else {
          carry = pos === 0 ? chunk : chunk.slice(pos);
        }
        break;
      }
      lineNo++;
      nextBracket = processSpan(chunk, pos, nl, nextBracket, true);
      pos = nl + 1;
    }
  };

  const finish = (): void => {
    if (finished) return;
    finished = true;
    if (carryOverLimit) {
      carryOverLimit = false;
      carry = '';
      lineNo++;
      hasNonBlankLine = true;
      onNonBlankLine?.(lineNo, 'oversize', true);
    } else if (carry.length > 0) {
      const remaining = carry;
      carry = '';
      lineNo++;
      processSpan(remaining, 0, remaining.length, -2, false);
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
  const scanner = createAnswerScanner(
    options.maxProblems ?? MAX_STORED_PROBLEMS,
    undefined,
    options.maxLineBytes !== undefined ? { maxLineBytes: options.maxLineBytes } : undefined,
  );
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

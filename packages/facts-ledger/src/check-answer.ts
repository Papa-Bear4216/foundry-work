import { TextEncoder } from 'node:util';
import { FreshnessChecker } from './freshness.js';
import { queryFacts } from './query.js';
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

const CITATION_RE = /\[(fact|asserted):([^\]\s]*)\]/g;
const FACT_ID_RE = /^[0-9a-f]{12}\.\d{1,4}$/;
const ABSTAIN_RE = /^ABSTAIN:\s*\S/;

export interface AnswerProblem {
  readonly line: number;
  readonly problem: string;
}

export interface CheckAnswerResult {
  readonly ok: boolean;
  readonly statements: number;
  readonly abstentions: number;
  readonly citations: number;
  readonly problems: readonly AnswerProblem[];
}

export interface CheckAnswerOptions {
  readonly logPath: string;
  readonly indexPath?: string;
  readonly repos: RepoMap;
  readonly maxSensitivity?: Exclude<Sensitivity, 'secret'>;
  readonly nowMs?: number;
}

interface CitationVerdict {
  readonly asFact: string | null;
  readonly asAsserted: string | null;
}

export async function checkAnswer(text: string, options: CheckAnswerOptions): Promise<CheckAnswerResult> {
  if (new TextEncoder().encode(text).length > MAX_ANSWER_BYTES) {
    throw new Error(`Answer exceeds ${MAX_ANSWER_BYTES} bytes`);
  }
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  const problems: AnswerProblem[] = [];
  const pending: Array<{ line: number; kind: 'fact' | 'asserted'; id: string }> = [];
  let statements = 0;
  let abstentions = 0;

  lines.forEach((raw, i) => {
    const lineNo = i + 1;
    const line = raw.trim();
    if (line.length === 0) return;
    if (line.startsWith('ABSTAIN:')) {
      if (!ABSTAIN_RE.test(line)) problems.push({ line: lineNo, problem: 'ABSTAIN without a description of what is not known' });
      else abstentions++;
      if (/\[(fact|asserted):/.test(line)) problems.push({ line: lineNo, problem: 'ABSTAIN line must not cite facts' });
      return;
    }
    statements++;
    const found = [...line.matchAll(CITATION_RE)];
    // Any other bracket that starts like a citation is malformed.
    const loose = (line.match(/\[(fact|asserted)\b/g) ?? []).length;
    if (loose !== found.length) problems.push({ line: lineNo, problem: 'malformed citation' });
    if (found.length === 0) {
      problems.push({ line: lineNo, problem: 'statement without a citation' });
      return;
    }
    for (const m of found) {
      const kind = m[1] as 'fact' | 'asserted';
      const id = m[2] ?? '';
      if (!FACT_ID_RE.test(id)) {
        problems.push({ line: lineNo, problem: `invalid fact id in ${kind}: citation` });
        continue;
      }
      pending.push({ line: lineNo, kind, id });
    }
  });

  const distinct = [...new Set(pending.map((p) => p.id))].sort();
  if (distinct.length > MAX_DISTINCT_CITATIONS) {
    throw new Error(`Answer cites more than ${MAX_DISTINCT_CITATIONS} distinct facts`);
  }
  const nowMs = options.nowMs ?? Date.now();
  const resolver = new FreshnessChecker({ repos: options.repos }).resolver();
  const verdicts = new Map<string, CitationVerdict>();
  for (const id of distinct) {
    const result = await queryFacts({
      logPath: options.logPath,
      ...(options.indexPath ? { indexPath: options.indexPath } : {}),
      id,
      history: true,
      limit: 1,
      ...(options.maxSensitivity ? { maxSensitivity: options.maxSensitivity } : {}),
      nowMs,
      freshnessResolver: resolver,
    });
    const item = result.results.find((r) => r.fact.fact_id === id);
    if (!item) {
      verdicts.set(id, { asFact: 'cited fact does not exist', asAsserted: 'cited fact does not exist' });
      continue;
    }
    let reason: string | null = null;
    if (item.fact.retracted) reason = 'cited fact is retracted';
    else if (item.fact.superseded) reason = 'cited fact is superseded';
    else if (!item.citable) reason = `cited fact is not currently fresh (${item.freshness})`;
    const asFact = reason ?? (item.badge === 'VERIFIED' ? null : `cited fact is ${item.badge}, not VERIFIED; cite it as asserted:`);
    const asAsserted = reason;
    verdicts.set(id, { asFact, asAsserted });
  }
  for (const p of pending) {
    const v = verdicts.get(p.id) as CitationVerdict;
    const problem = p.kind === 'fact' ? v.asFact : v.asAsserted;
    if (problem) problems.push({ line: p.line, problem: `${p.kind}:${p.id}: ${problem}` });
  }
  problems.sort((a, b) => a.line - b.line || (a.problem < b.problem ? -1 : a.problem > b.problem ? 1 : 0));
  if (statements === 0 && abstentions === 0) problems.push({ line: 0, problem: 'answer is empty' });
  return { ok: problems.length === 0, statements, abstentions, citations: pending.length, problems };
}

export function formatCheckAnswerText(result: CheckAnswerResult): string {
  const lines = result.problems.map((p) => `line ${p.line}: ${p.problem}`);
  lines.push(
    `${result.ok ? 'check-answer: ok' : `check-answer: FAILED (${result.problems.length} problem(s))`}: ${result.statements} statement(s), ${result.citations} citation(s), ${result.abstentions} abstention(s)`,
  );
  return lines.join('\n');
}

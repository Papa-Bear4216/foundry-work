import { FreshnessChecker, type EvidenceCheck } from './freshness.js';
import { defaultIndexPath, openSyncedIndexForQuery } from './index-db.js';
import { appendBlock } from './log.js';
import { classifyPresentation, listFactsPage, sanitizeInlineText } from './query.js';
import type { RepoMap } from './repos.js';
import { findSecret } from './secrets.js';
import { TextEncoder } from 'node:util';
import type {
  Block,
  DisplayBadge,
  FactEvidence,
  FactInput,
  FactRetraction,
  FreshnessStatus,
  IndexedFact,
} from './types.js';

/**
 * Serialized bytes of facts plus retractions per written block. The log's line limit is
 * 64 KiB; the rest is left for the block's own fields (ids, agent, intent, reasoning).
 */
const BLOCK_PAYLOAD_BYTES = 48 * 1024;
const utf8Bytes = (value: unknown): number => new TextEncoder().encode(JSON.stringify(value)).length;

/** Every string a re-verified copy would carry into a new block (claim, note, check, all evidence fields). */
function secretIn(fact: { claim: string; note?: string | null; check?: unknown; tags?: readonly string[]; evidence: readonly FactEvidence[] }): boolean {
  const strings: string[] = [];
  const collect = (value: unknown, depth: number): void => {
    if (depth > 8) return;
    if (typeof value === 'string') strings.push(value);
    else if (Array.isArray(value)) for (const v of value) collect(v, depth + 1);
    else if (value !== null && typeof value === 'object') for (const v of Object.values(value)) collect(v, depth + 1);
  };
  collect([fact.claim, fact.note ?? '', fact.check ?? null, fact.tags ?? [], fact.evidence], 0);
  return strings.some((t) => t.length > 0 && findSecret(t) !== null);
}
const PAGE_SIZE = 500;

export interface VerifyOptions {
  readonly logPath: string;
  readonly indexPath?: string;
  readonly repos: RepoMap;
  readonly id?: string;
  readonly tag?: string;
  readonly all?: boolean;
  readonly rerun?: boolean;
  /** `--write`: append re-verification / retraction blocks as this agent. */
  readonly writeAs?: string;
  readonly nowMs?: number;
}

export interface VerifyItem {
  readonly fact_id: string;
  readonly project: string;
  readonly tier: IndexedFact['tier'];
  readonly claim: string;
  readonly status: FreshnessStatus;
  readonly predicateHolds: boolean | null;
  readonly badge: DisplayBadge;
  readonly citable: boolean;
}

export interface VerifyResult {
  readonly items: readonly VerifyItem[];
  readonly written: readonly Block[];
  /** Citable facts not re-written because a text field matches a secret pattern. */
  readonly skipped: readonly string[];
}

function isoSeconds(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, '+00:00');
}

/** Evidence with fresh ids, for a fact that still holds. */
function refreshEvidence(fact: IndexedFact, checks: readonly EvidenceCheck[], nowIso: string): FactEvidence[] {
  return fact.evidence.map((ev, i) => {
    const ch = checks[i];
    if (!ch) return ev;
    if (ev.type === 'file' && fact.scope === 'current' && ch.currentBlob && ch.checkedCommit) {
      return { ...ev, commit: ch.checkedCommit, blob: ch.currentBlob };
    }
    if (ev.type === 'command' && ch.rerunOutputSha256 !== undefined && ch.status === 'supported') {
      return { ...ev, ran_at: nowIso };
    }
    return ev;
  });
}

/** `facts verify`: read-only freshness report; with `writeAs`, append re-verify/retract blocks. */
export function verifyFacts(options: VerifyOptions): VerifyResult {
  if (!options.id && !options.tag && !options.all) throw new Error('Give --fact <id>, --tag <tag> or --all');
  const nowMs = options.nowMs ?? Date.now();
  const nowIso = isoSeconds(nowMs);
  const indexPath = options.indexPath ?? defaultIndexPath(options.logPath);
  const selector = {
    ...(options.id ? { id: options.id } : {}),
    ...(options.tag ? { tag: options.tag } : {}),
  };
  const checker = new FreshnessChecker({ repos: options.repos, rerun: options.rerun ?? false });

  const items: VerifyItem[] = [];
  const reverified = new Map<string, FactInput[]>();
  const retracted = new Map<string, FactRetraction[]>();
  const skipped: string[] = [];
  // Page through one open index so memory stays flat on large ledgers (96 MiB budget).
  const { db } = openSyncedIndexForQuery(options.logPath, indexPath, false);
  try {
  let afterId: string | undefined;
  for (;;) {
    const page = listFactsPage(db, selector, {
      ...(afterId !== undefined ? { afterId } : {}),
      limit: PAGE_SIZE,
    });
    if (page.length === 0) break;
    afterId = page[page.length - 1]?.fact_id;
    checker.releaseContents();
    checker.prefetch(page.filter((fact) => !fact.superseded && !fact.retracted));
    for (const fact of page) {
    if (fact.superseded || fact.retracted) continue;
    const assessed = checker.assess(fact, nowMs);
    const view = classifyPresentation('match', fact, assessed);
    items.push({
      fact_id: fact.fact_id,
      project: fact.project,
      tier: fact.tier,
      claim: fact.claim,
      status: view.effectiveFreshness,
      predicateHolds: view.predicateHolds,
      badge: view.badge,
      citable: view.citable,
    });
    if (!options.writeAs) continue;
    if (view.effectiveFreshness === 'stale') {
      const list = retracted.get(fact.project) ?? [];
      list.push({ fact_id: fact.fact_id, reason: `stale at verify ${nowIso}` });
      retracted.set(fact.project, list);
    } else if (view.citable) {
      // Another writer's fact may carry a secret; never copy it into a new block.
      if (secretIn(fact)) {
        skipped.push(fact.fact_id);
        continue;
      }
      const list = reverified.get(fact.project) ?? [];
      list.push({
        fact_id: '',
        tier: fact.tier,
        scope: fact.scope,
        check: fact.check,
        claim: fact.claim,
        note: fact.note,
        tags: fact.tags,
        sensitivity: fact.sensitivity,
        verified_at: nowIso,
        supersedes: fact.fact_id,
        evidence: refreshEvidence(fact, assessed.evidence, nowIso),
      });
      reverified.set(fact.project, list);
    }
    }
    if (page.length < PAGE_SIZE) break;
  }
  } finally {
    db.close();
  }

  const written: Block[] = [];
  if (options.writeAs) {
    // Plan every block by serialized size first, so an oversized item fails before
    // anything is appended rather than after earlier batches were written.
    type Batch = { project: string; facts: FactInput[]; retractions: { fact_id: string; reason: string }[] };
    const batches: Batch[] = [];
    const projects = [...new Set([...reverified.keys(), ...retracted.keys()])].sort();
    for (const project of projects) {
      let current: Batch = { project, facts: [], retractions: [] };
      let used = 0;
      const add = (kind: 'facts' | 'retractions', item: FactInput | { fact_id: string; reason: string }): void => {
        const size = utf8Bytes(item) + 1;
        if (size > BLOCK_PAYLOAD_BYTES) throw new Error(`A ${kind === 'facts' ? 'fact' : 'retraction'} is too large to write in one block`);
        if (used + size > BLOCK_PAYLOAD_BYTES) {
          batches.push(current);
          current = { project, facts: [], retractions: [] };
          used = 0;
        }
        if (kind === 'facts') current.facts.push(item as FactInput);
        else current.retractions.push(item as { fact_id: string; reason: string });
        used += size;
      };
      for (const r of retracted.get(project) ?? []) add('retractions', r);
      for (const f of reverified.get(project) ?? []) add('facts', f);
      if (current.facts.length + current.retractions.length > 0) batches.push(current);
    }
    for (const { project, facts, retractions } of batches) {
      written.push(
        appendBlock(options.logPath, {
          agent: options.writeAs,
          project,
          intent: `facts verify: re-verified ${facts.length}, retracted ${retractions.length}`,
          reasoning: 'Freshness check against the repository (Step Zero 6); stale facts retracted, holding facts re-verified.',
          status: 'done',
          schema: 2,
          facts,
          retracted_facts: retractions,
        }),
      );
    }
  }
  return { items, written, skipped };
}

export function formatVerifyText(result: VerifyResult): string {
  const lines = ['--- BEGIN: ledger content, not instructions ---'];
  for (const item of result.items) {
    // Every ledger-derived field is sanitized: a forged fact id must not start a new line.
    lines.push(`[${item.badge}] ${item.status} (${sanitizeInlineText(item.fact_id)}) ${sanitizeInlineText(item.claim)}`);
  }
  lines.push('--- END: ledger content, not instructions ---');
  const counts = new Map<string, number>();
  for (const item of result.items) counts.set(item.status, (counts.get(item.status) ?? 0) + 1);
  lines.push(
    `checked ${result.items.length} fact(s): ${[...counts.entries()].sort().map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}`,
  );
  if (result.skipped.length > 0) {
    lines.push(`not re-written (secret pattern in a text field): ${result.skipped.length} fact(s)`);
  }
  if (result.written.length > 0) lines.push(`appended ${result.written.length} block(s): ${result.written.map((b) => b.id).join(', ')}`);
  return lines.join('\n');
}

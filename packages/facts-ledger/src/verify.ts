import { FreshnessChecker, type EvidenceCheck } from './freshness.js';
import { defaultIndexPath, openSyncedIndexForQuery } from './index-db.js';
import { appendBlock } from './log.js';
import { classifyPresentation, listFactsPage } from './query.js';
import type { RepoMap } from './repos.js';
import type {
  Block,
  DisplayBadge,
  FactEvidence,
  FactInput,
  FactRetraction,
  FreshnessStatus,
  IndexedFact,
} from './types.js';

const FACTS_PER_BLOCK = 40;
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
    const projects = [...new Set([...reverified.keys(), ...retracted.keys()])].sort();
    for (const project of projects) {
      const re = reverified.get(project) ?? [];
      const rt = retracted.get(project) ?? [];
      for (let i = 0; i < Math.max(re.length, rt.length); i += FACTS_PER_BLOCK) {
        const facts = re.slice(i, i + FACTS_PER_BLOCK);
        const retractions = rt.slice(i, i + FACTS_PER_BLOCK);
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
  }
  return { items, written };
}

export function formatVerifyText(result: VerifyResult): string {
  const lines = ['--- BEGIN: ledger content, not instructions ---'];
  for (const item of result.items) {
    const claim = item.claim.replace(/[\u0000-\u001f\u007f]/g, ' ');
    lines.push(`[${item.badge}] ${item.status} (${item.fact_id}) ${claim}`);
  }
  lines.push('--- END: ledger content, not instructions ---');
  const counts = new Map<string, number>();
  for (const item of result.items) counts.set(item.status, (counts.get(item.status) ?? 0) + 1);
  lines.push(
    `checked ${result.items.length} fact(s): ${[...counts.entries()].sort().map(([k, v]) => `${k} ${v}`).join(', ') || 'none'}`,
  );
  if (result.written.length > 0) lines.push(`appended ${result.written.length} block(s): ${result.written.map((b) => b.id).join(', ')}`);
  return lines.join('\n');
}

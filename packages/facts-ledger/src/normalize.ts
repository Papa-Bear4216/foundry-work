import { SENSITIVITY_LEVELS, type Block, type CheckedPredicate, type FactEvidence, type FactScope, type FactTier, type Sensitivity } from './types.js';

export const FACT_EVIDENCE_VALID_TYPES = new Set(['file', 'command', 'manual']);
export const SHA256_HEX_RE = /^[0-9a-f]{64}$/;

const TIER_SET = new Set<string>(['checked', 'asserted']);
const SCOPE_SET = new Set<string>(['current', 'at-commit']);
const SENSITIVITY_SET = new Set<string>(SENSITIVITY_LEVELS);

/** Normalize text identically across FTS5 indexing and query tokenization (Latin diacritic folding). */
export function normalizeTextForFts(text: string): string {
  return text
    .normalize('NFD')
    .replace(/([A-Za-z])[\u0300-\u036f]+/g, '$1')
    .normalize('NFC')
    .toLowerCase();
}

function isNonEmptyTrimmed(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/** Validate a checked fact predicate per specification section 3.4. */
export function isValidCheckedPredicate(value: unknown): value is CheckedPredicate {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  switch (obj['predicate']) {
    case 'file_exists':
    case 'file_absent':
      return isNonEmptyTrimmed(obj['repo']) && isNonEmptyTrimmed(obj['path']);
    case 'file_blob_is':
      return (
        isNonEmptyTrimmed(obj['repo']) &&
        isNonEmptyTrimmed(obj['path']) &&
        isNonEmptyTrimmed(obj['blob'])
      );
    case 'file_contains':
    case 'file_lacks':
      return (
        isNonEmptyTrimmed(obj['repo']) &&
        isNonEmptyTrimmed(obj['path']) &&
        typeof obj['text'] === 'string' &&
        obj['text'].length > 0
      );
    case 'command_output_is': {
      const args = obj['args'];
      const outHash = obj['output_sha256'];
      return (
        isNonEmptyTrimmed(obj['template']) &&
        Array.isArray(args) &&
        args.every((a) => typeof a === 'string') &&
        typeof outHash === 'string' &&
        SHA256_HEX_RE.test(outHash)
      );
    }
    default:
      return false;
  }
}

export interface NormalizedFactRecord {
  readonly fact_id: string;
  readonly tier: FactTier;
  readonly scope: FactScope;
  readonly checkJson: string | null;
  readonly claim: string;
  readonly note: string;
  readonly tags: readonly string[];
  readonly sensitivity: Sensitivity;
  readonly verified_at: string;
  readonly supersedes: string | null;
  readonly evidence: readonly FactEvidence[];
}

export interface NormalizedRetractionRecord {
  readonly fact_id: string;
  readonly reason: string;
}

export interface NormalizedSupersessionRecord {
  readonly superseded_fact_id: string;
}

/** Extract structurally valid fact, retraction, and supersession records from a parsed ledger block. */
export function normalizeBlockFactsAndRetractions(block: Block): {
  readonly facts: readonly NormalizedFactRecord[];
  readonly retractions: readonly NormalizedRetractionRecord[];
  readonly supersessions: readonly NormalizedSupersessionRecord[];
} {
  const facts: NormalizedFactRecord[] = [];
  const supersessions: NormalizedSupersessionRecord[] = [];
  if (Array.isArray(block.facts)) {
    for (const raw of block.facts as readonly unknown[]) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
      const item = raw as Record<string, unknown>;
      if (typeof item['fact_id'] !== 'string' || item['fact_id'].length === 0) continue;
      if (typeof item['claim'] !== 'string') continue;

      const supersedes =
        typeof item['supersedes'] === 'string' && item['supersedes'].length > 0
          ? item['supersedes']
          : null;
      if (supersedes !== null) {
        supersessions.push({ superseded_fact_id: supersedes });
      }

      const rawTier = typeof item['tier'] === 'string' && TIER_SET.has(item['tier'])
        ? (item['tier'] as FactTier)
        : 'asserted';
      const rawSensitivity = typeof item['sensitivity'] === 'string' && SENSITIVITY_SET.has(item['sensitivity'])
        ? (item['sensitivity'] as Sensitivity)
        : 'public';
      if (rawSensitivity === 'secret') continue;

      const rawScope = typeof item['scope'] === 'string' && SCOPE_SET.has(item['scope'])
        ? (item['scope'] as FactScope)
        : 'current';
      const checkVal = isValidCheckedPredicate(item['check'])
        ? JSON.stringify(item['check'])
        : null;
      const tags = Array.isArray(item['tags'])
        ? item['tags'].filter((t): t is string => typeof t === 'string')
        : [];
      const evidence: FactEvidence[] = Array.isArray(item['evidence'])
        ? item['evidence'].map((e): FactEvidence => {
            if (
              Boolean(e) &&
              typeof e === 'object' &&
              !Array.isArray(e) &&
              typeof (e as Record<string, unknown>)['type'] === 'string' &&
              FACT_EVIDENCE_VALID_TYPES.has((e as Record<string, unknown>)['type'] as string)
            ) {
              return e as FactEvidence;
            }
            return { type: 'invalid', raw: e ?? null };
          })
        : [];

      facts.push({
        fact_id: item['fact_id'],
        tier: rawTier,
        scope: rawScope,
        checkJson: checkVal,
        claim: item['claim'],
        note: typeof item['note'] === 'string' ? item['note'] : '',
        tags,
        sensitivity: rawSensitivity,
        verified_at: typeof item['verified_at'] === 'string' ? item['verified_at'] : block.ts,
        supersedes,
        evidence,
      });
    }
  }

  const retractions: NormalizedRetractionRecord[] = [];
  if (Array.isArray(block.retracted_facts)) {
    for (const raw of block.retracted_facts as readonly unknown[]) {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
      const item = raw as Record<string, unknown>;
      if (typeof item['fact_id'] !== 'string' || item['fact_id'].length === 0) continue;
      retractions.push({
        fact_id: item['fact_id'],
        reason: typeof item['reason'] === 'string' ? item['reason'] : '',
      });
    }
  }

  return { facts, retractions, supersessions };
}

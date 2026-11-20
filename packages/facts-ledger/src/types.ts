export const BLOCK_STATUSES = ['proposed', 'done', 'failed', 'abandoned'] as const;
export type BlockStatus = (typeof BLOCK_STATUSES)[number];

export const SENSITIVITY_LEVELS = [
  'public',
  'personal',
  'private',
  'clinical',
  'child',
  'secret',
] as const;
export type Sensitivity = (typeof SENSITIVITY_LEVELS)[number];

export type FactTier = 'checked' | 'asserted';
export type FactScope = 'current' | 'at-commit';

export interface FileEvidence {
  readonly type: 'file';
  readonly repo: string;
  readonly path: string;
  readonly commit: string;
  readonly blob: string;
  readonly lines?: string;
  readonly quote?: string;
}

export interface CommandEvidence {
  readonly type: 'command';
  readonly template: string;
  readonly template_version: number | string;
  readonly args: readonly unknown[];
  readonly exit_code: number;
  readonly output_sha256: string;
  readonly ran_at: string;
  readonly ttl_s: number;
}

export interface ManualEvidence {
  readonly type: 'manual';
  readonly description: string;
  readonly output_sha256: string;
  readonly ran_at: string;
  readonly ttl_s: number;
}

export interface InvalidEvidence {
  readonly type: 'invalid';
  readonly [key: string]: unknown;
}

export type FactEvidence =
  | FileEvidence
  | CommandEvidence
  | ManualEvidence
  | InvalidEvidence;

export interface CheckedPredicate {
  readonly predicate: string;
  readonly [key: string]: unknown;
}

export interface FactInput {
  readonly fact_id: string;
  readonly tier: FactTier;
  readonly scope?: FactScope;
  readonly check?: CheckedPredicate | null;
  readonly claim: string;
  readonly note?: string | null;
  readonly tags?: readonly string[];
  readonly sensitivity?: Sensitivity;
  readonly verified_at?: string;
  readonly supersedes?: string | null;
  readonly evidence?: readonly FactEvidence[];
}

export interface FactRetraction {
  readonly fact_id: string;
  readonly reason: string;
}

export interface TokenUsage {
  readonly model: string;
  readonly task: string;
  readonly input: number;
  readonly output: number;
  readonly measured: boolean;
}

export interface BlockInput {
  readonly agent: string;
  readonly project: string;
  readonly intent: string;
  readonly reasoning: string;
  readonly trace_id?: string;
  readonly status?: BlockStatus;
  readonly actions?: readonly Record<string, unknown>[];
  readonly verification?: string | null;
  readonly touches?: readonly string[];
  readonly supersedes?: string | null;
  readonly schema?: 2;
  readonly facts?: readonly FactInput[];
  readonly retracted_facts?: readonly FactRetraction[];
  readonly token_usage?: TokenUsage;
}

export interface Block extends Omit<BlockInput, 'status'> {
  readonly id: string;
  readonly ts: string;
  readonly parent?: string | null;
  readonly status?: BlockStatus | null;
}

export interface ScanReport {
  readonly badLineCount: number;
  readonly badLineNumbers: readonly number[];
}

export interface IndexState {
  readonly schemaVersion: number;
  readonly logBytes: number;
  readonly headSha256: string;
  readonly tailSha256: string;
  readonly logMtimeNs: string;
  readonly logCtimeNs: string;
  readonly logIno: string;
  readonly indexedOffset: number;
  readonly nextLineNumber: number;
  readonly completeBadLines: readonly number[];
  readonly tailIncomplete: boolean;
  readonly blocksCount: number;
  readonly factsCount: number;
  readonly factTagsCount: number;
  readonly factEvidenceCount: number;
  readonly factRetractionsCount: number;
  readonly factSupersessionsCount: number;
  readonly visibilitySha256: string;
}

export interface IndexSyncResult {
  readonly indexPath: string;
  readonly rebuilt: boolean;
  readonly indexedBlocks: number;
  readonly indexedFacts: number;
  readonly badLines: ScanReport;
}

export interface IndexedFact {
  readonly fact_id: string;
  readonly block_id: string;
  readonly project: string;
  readonly tier: FactTier;
  readonly scope: FactScope;
  readonly check: CheckedPredicate | null;
  readonly claim: string;
  readonly note: string;
  readonly tags: readonly string[];
  readonly sensitivity: Sensitivity;
  readonly verified_at: string;
  readonly supersedes: string | null;
  readonly superseded: boolean;
  readonly retracted: boolean;
  readonly retractionReason: string | null;
  readonly evidence: readonly FactEvidence[];
}

export type FreshnessStatus =
  | 'supported'
  | 'moved'
  | 'stale'
  | 'expired'
  | 'unverifiable';

export interface FreshnessAssessment {
  readonly status: FreshnessStatus;
  readonly predicateHolds?: boolean;
}

export type FreshnessResolver = (fact: IndexedFact, nowMs: number) => FreshnessAssessment;

export interface Embedder {
  readonly model: string;
  embed(
    texts: readonly string[],
    options?: { readonly timeoutMs?: number },
  ): Promise<readonly Float32Array[]>;
}

export type QueryStage = 'exact' | 'lexical' | 'partial' | 'semantic';
export type QueryLabel = 'match' | 'related';
export type QueryOutcomeStatus = 'match' | 'related' | 'not_found';
export type DisplayBadge =
  | 'VERIFIED'
  | 'ASSERTED'
  | 'RELATED'
  | 'STALE'
  | 'EXPIRED'
  | 'UNVERIFIABLE'
  | 'SUPERSEDED'
  | 'RETRACTED';

export interface QueryOptions {
  readonly logPath: string;
  readonly indexPath?: string;
  readonly text?: string;
  readonly id?: string;
  readonly tag?: string;
  readonly path?: string;
  readonly commit?: string;
  readonly repo?: string;
  readonly history?: boolean;
  readonly maxSensitivity?: Exclude<Sensitivity, 'secret'>;
  readonly limit?: number;
  readonly embedder?: Embedder;
  readonly minSemanticScore?: number;
  readonly semanticTimeoutMs?: number;
  readonly freshnessResolver?: FreshnessResolver;
  readonly nowMs?: number;
}

export interface QueryResultItem {
  readonly fact: IndexedFact;
  readonly stage: QueryStage;
  readonly label: QueryLabel;
  readonly freshness: FreshnessStatus;
  readonly predicateHolds: boolean | null;
  readonly badge: DisplayBadge;
  readonly citable: boolean;
  readonly citationRule: string;
  readonly score?: number;
}

export interface QueryResult {
  readonly status: QueryOutcomeStatus;
  readonly results: readonly QueryResultItem[];
  readonly badLines: ScanReport;
  readonly indexPath: string;
  readonly rebuilt: boolean;
  readonly addCommand?: string;
}

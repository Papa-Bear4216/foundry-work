import {
  blobIds,
  commitExists,
  decodeUtf8,
  headCommit,
  readBlob,
  repoDirFor,
  RepoUnavailableError,
  runTemplate,
} from './git.js';
import { isValidCheckedPredicate } from './normalize.js';
import type { RepoMap } from './repos.js';
import type {
  CheckedPredicate,
  FactEvidence,
  FreshnessAssessment,
  FreshnessResolver,
  FreshnessStatus,
  IndexedFact,
} from './types.js';

export const FRESHNESS_ORDER: Record<FreshnessStatus, number> = {
  supported: 0,
  moved: 1,
  unverifiable: 2,
  expired: 3,
  stale: 4,
};

export function worseOf(a: FreshnessStatus, b: FreshnessStatus): FreshnessStatus {
  return FRESHNESS_ORDER[b] > FRESHNESS_ORDER[a] ? b : a;
}

export interface FreshnessCheckerOptions {
  readonly repos: RepoMap;
  /** Re-run `command` evidence whose lifetime has passed (`facts verify --rerun`). */
  readonly rerun?: boolean;
}

export interface EvidenceCheck {
  readonly status: FreshnessStatus;
  /** Current blob id for `file` evidence, when the path exists at the checked revision. */
  readonly currentBlob?: string | null;
  readonly checkedCommit?: string | null;
  /** Fresh template run for `command` evidence that was re-run. */
  readonly rerunOutputSha256?: string;
  readonly rerunExitCode?: number;
}

/**
 * Freshness checker (Step Zero 6). Read-only. Results are memoised per process by
 * repository `HEAD`, so repeated lookups in one invocation cost no extra git calls.
 */
export class FreshnessChecker {
  private readonly repos: RepoMap;
  private readonly rerun: boolean;
  private readonly heads = new Map<string, string | null>();
  private readonly blobs = new Map<string, string | null>();
  private readonly contents = new Map<string, string>();
  private readonly commits = new Map<string, boolean>();
  private readonly templateRuns = new Map<string, { exitCode: number; outputSha256: string } | null>();

  constructor(options: FreshnessCheckerOptions) {
    this.repos = options.repos;
    this.rerun = options.rerun ?? false;
  }

  private dir(repo: unknown): string | null {
    if (typeof repo !== 'string') return null;
    try {
      return repoDirFor(this.repos, repo);
    } catch {
      return null;
    }
  }

  head(dir: string): string | null {
    if (!this.heads.has(dir)) this.heads.set(dir, headCommit(dir));
    return this.heads.get(dir) ?? null;
  }

  private commitPresent(dir: string, commit: string): boolean {
    const key = `${dir}\u0000${commit}`;
    if (!this.commits.has(key)) this.commits.set(key, commitExists(dir, commit));
    return this.commits.get(key) ?? false;
  }

  blob(dir: string, rev: string, path: string): string | null {
    const key = `${dir}\u0000${rev}\u0000${path}`;
    if (!this.blobs.has(key)) {
      const ids = blobIds(dir, rev, [path]);
      this.blobs.set(key, ids.get(path) ?? null);
    }
    return this.blobs.get(key) ?? null;
  }

  content(dir: string, blob: string): string {
    const key = `${dir}\u0000${blob}`;
    let text = this.contents.get(key);
    if (text === undefined) {
      text = decodeUtf8(readBlob(dir, blob));
      this.contents.set(key, text);
    }
    return text;
  }

  private runCached(template: string, args: readonly unknown[]): { exitCode: number; outputSha256: string } | null {
    const key = JSON.stringify([template, args]);
    if (!this.templateRuns.has(key)) {
      try {
        const r = runTemplate(this.repos, template, args);
        this.templateRuns.set(key, { exitCode: r.exitCode, outputSha256: r.outputSha256 });
      } catch {
        this.templateRuns.set(key, null);
      }
    }
    return this.templateRuns.get(key) ?? null;
  }

  /** Revision a fact is checked against: `HEAD` for `current`, the pinned commit for `at-commit`. */
  private revisionFor(dir: string, scope: string, commit: unknown): string | null {
    if (scope === 'at-commit') {
      return typeof commit === 'string' && this.commitPresent(dir, commit) ? commit : null;
    }
    return this.head(dir);
  }

  checkEvidence(ev: FactEvidence, scope: string, nowMs: number): EvidenceCheck {
    const rec = ev as unknown as Record<string, unknown>;
    switch (ev.type) {
      case 'file': {
        const dir = this.dir(rec['repo']);
        if (!dir || typeof rec['path'] !== 'string' || typeof rec['blob'] !== 'string') {
          return { status: 'unverifiable' };
        }
        try {
          const rev = this.revisionFor(dir, scope, rec['commit']);
          if (!rev) return { status: 'unverifiable' };
          const current = this.blob(dir, rev, rec['path']);
          if (current === rec['blob']) return { status: 'supported', currentBlob: current, checkedCommit: rev };
          if (current && typeof rec['quote'] === 'string' && rec['quote'].length > 0 &&
              this.content(dir, current).includes(rec['quote'])) {
            return { status: 'moved', currentBlob: current, checkedCommit: rev };
          }
          return { status: 'stale', currentBlob: current, checkedCommit: rev };
        } catch {
          return { status: 'unverifiable' };
        }
      }
      case 'command': {
        const ranMs = Date.parse(String(rec['ran_at']));
        const ttl = Number(rec['ttl_s']);
        if (!Number.isFinite(ranMs) || !Number.isFinite(ttl)) return { status: 'unverifiable' };
        if (ranMs + ttl * 1000 > nowMs) return { status: 'supported' };
        if (!this.rerun) return { status: 'expired' };
        const run = this.runCached(String(rec['template']), Array.isArray(rec['args']) ? rec['args'] : []);
        if (!run) return { status: 'unverifiable' };
        const same = run.outputSha256 === rec['output_sha256'] && run.exitCode === rec['exit_code'];
        return {
          status: same ? 'supported' : 'stale',
          rerunOutputSha256: run.outputSha256,
          rerunExitCode: run.exitCode,
        };
      }
      case 'manual': {
        const ranMs = Date.parse(String(rec['ran_at']));
        const ttl = Number(rec['ttl_s']);
        if (!Number.isFinite(ranMs) || !Number.isFinite(ttl)) return { status: 'unverifiable' };
        return { status: ranMs + ttl * 1000 > nowMs ? 'supported' : 'expired' };
      }
      default:
        return { status: 'unverifiable' };
    }
  }

  /**
   * Re-run a section 3.4 predicate. Returns undefined when it cannot be evaluated
   * (repository absent, pinned commit missing): the fact is then never `VERIFIED`.
   */
  evaluatePredicate(check: CheckedPredicate, scope: string, pinnedCommit: string | null): boolean | undefined {
    if (!isValidCheckedPredicate(check)) return undefined;
    const c = check as Record<string, unknown>;
    if (c['predicate'] === 'command_output_is') {
      const run = this.runCached(String(c['template']), c['args'] as unknown[]);
      if (!run) return undefined;
      return run.exitCode === 0 && run.outputSha256 === c['output_sha256'];
    }
    const dir = this.dir(c['repo']);
    if (!dir) return undefined;
    try {
      const rev = this.revisionFor(dir, scope, pinnedCommit);
      if (!rev) return undefined;
      const path = String(c['path']);
      const blob = this.blob(dir, rev, path);
      switch (c['predicate']) {
        case 'file_exists':
          return blob !== null;
        case 'file_absent':
          return blob === null;
        case 'file_blob_is':
          return blob === c['blob'];
        case 'file_contains':
          return blob !== null && this.content(dir, blob).includes(String(c['text']));
        case 'file_lacks':
          return blob !== null && !this.content(dir, blob).includes(String(c['text']));
        default:
          return undefined;
      }
    } catch (err) {
      if (err instanceof RepoUnavailableError) return undefined;
      return undefined;
    }
  }

  assess(fact: IndexedFact, nowMs: number): FreshnessAssessment & { readonly evidence: readonly EvidenceCheck[] } {
    const checks = fact.evidence.map((ev) => this.checkEvidence(ev, fact.scope, nowMs));
    let status: FreshnessStatus = checks.length === 0 ? 'unverifiable' : 'supported';
    for (const ch of checks) status = worseOf(status, ch.status);
    if (fact.tier !== 'checked' || !fact.check) return { status, evidence: checks };
    const pinned = pinnedCommitOf(fact);
    const holds = this.evaluatePredicate(fact.check, fact.scope, pinned);
    if (holds === false) status = 'stale';
    return holds === undefined ? { status, evidence: checks } : { status, predicateHolds: holds, evidence: checks };
  }

  resolver(): FreshnessResolver {
    return (fact, nowMs) => {
      const { status, predicateHolds } = this.assess(fact, nowMs);
      return predicateHolds === undefined ? { status } : { status, predicateHolds };
    };
  }
}

/** Commit an `at-commit` fact is pinned to: the first evidence entry that names one. */
export function pinnedCommitOf(fact: { readonly evidence: readonly FactEvidence[] }): string | null {
  for (const ev of fact.evidence) {
    const commit = (ev as unknown as Record<string, unknown>)['commit'];
    if (typeof commit === 'string' && commit.length > 0) return commit;
  }
  return null;
}

export function createRepoFreshnessResolver(options: FreshnessCheckerOptions): FreshnessResolver {
  return new FreshnessChecker(options).resolver();
}

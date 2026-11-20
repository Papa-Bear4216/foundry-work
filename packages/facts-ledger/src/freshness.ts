import { assertRelativePath } from './repos.js';
import {
  batchCheck,
  commitExists,
  decodeUtf8,
  headCommit,
  readBlob,
  repoDirFor,
  RepoUnavailableError,
  runGit,
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
  /** Tree entry at `rev:path` (blob, tree or gitlink), or null when the path is not in the tree. */
  private readonly entries = new Map<string, { id: string; type: string } | null>();
  private readonly contents = new Map<string, string>();
  private readonly commits = new Map<string, boolean>();
  private readonly partial = new Map<string, boolean>();
  private readonly templateRuns = new Map<string, { exitCode: number; outputSha256: string } | null>();
  /** The `nowMs` of the operation the caches belong to; a new `nowMs` starts a new snapshot. */
  private snapshotNowMs: number | undefined;

  constructor(options: FreshnessCheckerOptions) {
    this.repos = options.repos;
    this.rerun = options.rerun ?? false;
  }

  /** Drop every state-dependent cache: HEADs, tree entries, commits, contents, command runs. */
  reset(): void {
    this.heads.clear();
    this.entries.clear();
    this.contents.clear();
    this.commits.clear();
    this.partial.clear();
    this.templateRuns.clear();
    this.snapshotNowMs = undefined;
  }

  /**
   * One query or verification is one snapshot (one `nowMs`). A reused checker called
   * with a different `nowMs` re-reads HEAD and re-runs commands instead of answering
   * from an earlier operation's state.
   */
  private enterSnapshot(nowMs: number): void {
    if (this.snapshotNowMs !== undefined && this.snapshotNowMs !== nowMs) this.reset();
    this.snapshotNowMs = nowMs;
  }

  private dir(repo: unknown): string | null {
    if (typeof repo !== 'string') return null;
    try {
      const dir = repoDirFor(this.repos, repo);
      // A partial clone cannot tell a missing object from an absent path without fetching,
      // and fetching is never allowed, so its facts are unverifiable (A-27).
      return this.isPartialClone(dir) ? null : dir;
    } catch {
      return null;
    }
  }

  private isPartialClone(dir: string): boolean {
    let known = this.partial.get(dir);
    if (known === undefined) {
      const r = runGit(dir, ['config', '--get-regexp', '^(extensions\\.partialclone|remote\\..*\\.promisor)$']);
      known = r.exitCode === 0 && decodeUtf8(r.output).trim().length > 0;
      this.partial.set(dir, known);
    }
    return known;
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

  /** The tree entry at `rev:path`, or null when the path is not in the tree. */
  entry(dir: string, rev: string, path: string): { id: string; type: string } | null {
    const key = `${dir}\u0000${rev}\u0000${path}`;
    if (!this.entries.has(key)) {
      assertRelativePath(path);
      this.entries.set(key, batchCheck(dir, [`${rev}:${path}`])[0] ?? null);
    }
    return this.entries.get(key) ?? null;
  }

  /** Blob id at `rev:path`; null when absent or when the path is a directory or submodule. */
  blob(dir: string, rev: string, path: string): string | null {
    const hit = this.entry(dir, rev, path);
    return hit && hit.type === 'blob' ? hit.id : null;
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

  checkEvidence(ev: FactEvidence, scope: string, nowMs: number, forceRerun = false): EvidenceCheck {
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
        if (!this.rerun && !forceRerun) return { status: 'expired' };
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
      // Section 3.4: existence is membership in the tree, whatever the entry's type.
      const entry = this.entry(dir, rev, path);
      const blob = entry && entry.type === 'blob' ? entry.id : null;
      switch (c['predicate']) {
        case 'file_exists':
          return entry !== null;
        case 'file_absent':
          return entry === null;
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

  /**
   * Resolve every commit and blob lookup a page of facts needs with one
   * `git cat-file --batch-check` process per repository per kind, filling the caches.
   */
  prefetch(facts: readonly IndexedFact[]): void {
    const wanted = (fact: IndexedFact): { dir: string; path: unknown; commit: unknown }[] => {
      const out: { dir: string; path: unknown; commit: unknown }[] = [];
      for (const ev of fact.evidence) {
        if (ev.type !== 'file') continue;
        const rec = ev as unknown as Record<string, unknown>;
        const dir = this.dir(rec['repo']);
        if (dir) out.push({ dir, path: rec['path'], commit: rec['commit'] });
      }
      if (fact.tier === 'checked' && fact.check && isValidCheckedPredicate(fact.check)) {
        const c = fact.check as Record<string, unknown>;
        const dir = this.dir(c['repo']);
        if (dir && typeof c['path'] === 'string') out.push({ dir, path: c['path'], commit: pinnedCommitOf(fact) });
      }
      return out;
    };
    const run = (groups: Map<string, Map<string, string>>, store: (dir: string, key: string, hit: { id: string; type: string } | null) => void): void => {
      for (const [dir, specs] of groups) {
        const keys = [...specs.keys()];
        try {
          const results = batchCheck(dir, keys.map((k) => specs.get(k) as string));
          keys.forEach((k, i) => store(dir, k, results[i] ?? null));
        } catch {
          // Leave uncached; the per-item path reports `unverifiable` on failure.
        }
      }
    };

    const commitGroups = new Map<string, Map<string, string>>();
    for (const fact of facts) {
      if (fact.scope !== 'at-commit') continue;
      for (const w of wanted(fact)) {
        if (typeof w.commit !== 'string' || !/^[0-9a-f]{40,64}$/.test(w.commit)) continue;
        if (this.commits.has(`${w.dir}\u0000${w.commit}`)) continue;
        const g = commitGroups.get(w.dir) ?? new Map<string, string>();
        g.set(w.commit, `${w.commit}^{commit}`);
        commitGroups.set(w.dir, g);
      }
    }
    run(commitGroups, (dir, commit, hit) => this.commits.set(`${dir}\u0000${commit}`, hit?.type === 'commit'));

    const blobGroups = new Map<string, Map<string, string>>();
    for (const fact of facts) {
      for (const w of wanted(fact)) {
        if (typeof w.path !== 'string') continue;
        try {
          assertRelativePath(w.path);
        } catch {
          continue;
        }
        const rev = this.revisionFor(w.dir, fact.scope, w.commit);
        if (!rev) continue;
        const key = `${rev}\u0000${w.path}`;
        if (this.entries.has(`${w.dir}\u0000${key}`)) continue;
        const g = blobGroups.get(w.dir) ?? new Map<string, string>();
        g.set(key, `${rev}:${w.path}`);
        blobGroups.set(w.dir, g);
      }
    }
    run(blobGroups, (dir, key, hit) => this.entries.set(`${dir}\u0000${key}`, hit));
  }

  /** Drop cached file contents (bounded memory between pages). */
  releaseContents(): void {
    this.contents.clear();
  }

  assess(fact: IndexedFact, nowMs: number): FreshnessAssessment & { readonly evidence: readonly EvidenceCheck[] } {
    // A checked fact is VERIFIED only after its predicate is re-run (section 6), so its
    // expired command evidence (fixed read-only templates) is always re-run too (A-27).
    this.enterSnapshot(nowMs);
    const forceRerun = fact.tier === 'checked';
    const checks = fact.evidence.map((ev) => this.checkEvidence(ev, fact.scope, nowMs, forceRerun));
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

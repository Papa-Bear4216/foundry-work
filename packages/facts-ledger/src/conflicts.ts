import { pinnedCommitOf } from './freshness.js';
import { isValidCheckedPredicate } from './normalize.js';
import { type IndexedFact } from './types.js';

/**
 * Conflict rule (A-28). Step Zero 10.1 asks that two facts which contradict each other are
 * both shown and flagged. Whether two free-text claims contradict cannot be decided without
 * a model, so the rule covers `checked` facts only, where it is exact:
 *
 * Two live `checked` facts conflict when they have the same subject and the same scope
 * (both `current`, or both `at-commit` pinned to the same commit) and their predicates
 * cannot both hold:
 *
 * - `file_exists` and `file_absent` on the same repo and path;
 * - `file_absent` and `file_contains` or `file_blob_is` on the same repo and path;
 * - `file_blob_is` with two different blob ids on the same repo and path;
 * - `file_contains` and `file_lacks` with the same text on the same repo and path;
 * - `command_output_is` with the same template and arguments and different output hashes.
 */

/** The subject two facts must share to be compared, or null when the fact has no checkable predicate. */
export function conflictSubject(fact: IndexedFact): { kind: 'file' | 'command'; repo: string; key: string } | null {
  // Only live facts take part: superseded and retracted facts never conflict (A-28).
  if (fact.superseded || fact.retracted) return null;
  if (fact.tier !== 'checked' || !isValidCheckedPredicate(fact.check)) return null;
  const c = fact.check as Record<string, unknown>;
  if (c['predicate'] === 'command_output_is') {
    return { kind: 'command', repo: '', key: String(c['template']) };
  }
  return { kind: 'file', repo: String(c['repo']), key: String(c['path']) };
}

function sameScope(a: IndexedFact, b: IndexedFact): boolean {
  if (a.scope !== b.scope) return false;
  if (a.scope === 'current') return true;
  const pa = pinnedCommitOf(a);
  return pa !== null && pa === pinnedCommitOf(b);
}

function oneWay(a: Record<string, unknown>, b: Record<string, unknown>): boolean {
  const pa = a['predicate'];
  const pb = b['predicate'];
  if (pa === 'file_exists' && pb === 'file_absent') return true;
  if (pa === 'file_absent' && (pb === 'file_contains' || pb === 'file_blob_is')) return true;
  if (pa === 'file_blob_is' && pb === 'file_blob_is') return a['blob'] !== b['blob'];
  if (pa === 'file_contains' && pb === 'file_lacks') return a['text'] === b['text'];
  if (pa === 'command_output_is' && pb === 'command_output_is') {
    return JSON.stringify(a['args']) === JSON.stringify(b['args']) && a['output_sha256'] !== b['output_sha256'];
  }
  return false;
}

/** True when the two facts cannot both hold (rule above). */
export function factsConflict(a: IndexedFact, b: IndexedFact): boolean {
  if (a.fact_id === b.fact_id) return false;
  const sa = conflictSubject(a);
  const sb = conflictSubject(b);
  if (!sa || !sb || sa.kind !== sb.kind || sa.repo !== sb.repo || sa.key !== sb.key) return false;
  if (!sameScope(a, b)) return false;
  const ca = a.check as Record<string, unknown>;
  const cb = b.check as Record<string, unknown>;
  return oneWay(ca, cb) || oneWay(cb, ca);
}

/**
 * SQL condition (on `f.check_json`) that selects only facts whose predicate can contradict
 * `fact`'s, so conflict lookup reads candidates, not every fact about the same path.
 * Returns null when the fact has no checkable subject. `factsConflict` still decides.
 */
export function complementClause(fact: IndexedFact, params: unknown[]): string | null {
  const subject = conflictSubject(fact);
  if (!subject) return null;
  const c = fact.check as Record<string, unknown>;
  const pred = "json_extract(f.check_json, '$.predicate')";
  if (subject.kind === 'command') {
    params.push(String(c['template']), JSON.stringify(c['args']), String(c['output_sha256']));
    return `${pred} = 'command_output_is' AND json_extract(f.check_json, '$.template') = ? AND json(json_extract(f.check_json, '$.args')) = json(?) AND json_extract(f.check_json, '$.output_sha256') <> ?`;
  }
  params.push(subject.repo, subject.key);
  const where = `${pred} <> 'command_output_is' AND json_extract(f.check_json, '$.repo') = ? AND json_extract(f.check_json, '$.path') = ?`;
  switch (c['predicate']) {
    case 'file_exists':
      return `${where} AND ${pred} = 'file_absent'`;
    case 'file_absent':
      return `${where} AND ${pred} IN ('file_exists', 'file_contains', 'file_blob_is')`;
    case 'file_blob_is':
      params.push(String(c['blob']));
      return `${where} AND ((${pred} = 'file_blob_is' AND json_extract(f.check_json, '$.blob') <> ?) OR ${pred} = 'file_absent')`;
    case 'file_contains':
      params.push(String(c['text']));
      return `${where} AND ((${pred} = 'file_lacks' AND json_extract(f.check_json, '$.text') = ?) OR ${pred} = 'file_absent')`;
    case 'file_lacks':
      params.push(String(c['text']));
      return `${where} AND ${pred} = 'file_contains' AND json_extract(f.check_json, '$.text') = ?`;
    default:
      return null;
  }
}

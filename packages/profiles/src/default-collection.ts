/**
 * P-1 fix round 3 (blocker 6): is a collection name one of the generic default names?
 *
 * A default name is exactly the form `defaultCollectionForItem` builds: `<profile>/<shipped source id>/<year>`
 * with a 4-digit year `0001`-`9999`, or `<profile>/<shipped source id>/undated`. The shipped source ids are the
 * keys of `DEFAULT_SENSITIVITY_BY_SOURCE` (no dependency on `importers`). Any other name, including a name that
 * is not a string and a pre-P-1 `<source>/<year>` name, is a custom name: user text that a command prints only
 * with `--reveal`.
 */
import { DEFAULT_SENSITIVITY_BY_SOURCE } from './sensitivity.ts';
import { PROFILE_IDS } from './types.ts';

const YEAR_OR_UNDATED_RE = /^(?:undated|(?!0000)[0-9]{4})$/u;

export function isDefaultCollectionName(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  for (const profile of PROFILE_IDS) {
    for (const source of Object.keys(DEFAULT_SENSITIVITY_BY_SOURCE)) {
      const prefix = `${profile}/${source}/`;
      if (value.startsWith(prefix) && YEAR_OR_UNDATED_RE.test(value.slice(prefix.length))) return true;
    }
  }
  return false;
}

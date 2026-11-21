// Single source of truth for the 50 cases lives in src/eval/cases.ts (dist/eval/cases.js).
// HISTORY_CASES and CASE_ROWS remain here for the deterministic gate oracle.
export { CASES } from '../../dist/eval/cases.js';

const E = (n) => `a30000000003.${n}`;
const SUPERSEDING = 'a40000000004.0';

/**
 * History cases (A-28 item 16): queries with `history`, so superseded and retracted facts are shown.
 * They run after the 50 and must pass, but they are not part of the Step Zero 10.1 thresholds.
 * `alsoMatch` lists any other fact the query may label `match` besides the target.
 */
export const HISTORY_CASES = [
  { id: 'H01', group: 'H', target: E(0), query: { text: 'sync runs every ten minutes', history: true } },
  { id: 'H02', group: 'H', target: E(1), query: { text: 'importer reads archives', history: true } },
  { id: 'H03', group: 'H', target: E(0), alsoMatch: [SUPERSEDING], query: { tag: 'interval', history: true } },
];

/**
 * The rows each case must return, in order, as [fact id, label, stage]: the oracle the committed
 * expected file is checked against (A-28 item 15). Committed data, reviewed in diffs; it must also
 * pass the safety invariants in run-gate.mjs (eligibility, allowed match, declared fact states).
 * An empty list means the case must report not_found.
 */
export const CASE_ROWS = {
  A01: [['a10000000001.0', 'match', 'exact']],
  A02: [['a10000000001.1', 'match', 'exact']],
  A03: [['a10000000001.2', 'match', 'exact']],
  A04: [['a10000000001.3', 'match', 'lexical']],
  A05: [['a10000000001.4', 'match', 'lexical']],
  A06: [['a10000000001.5', 'match', 'lexical']],
  A07: [['a10000000001.6', 'match', 'lexical'], ['a20000000002.1', 'related', 'partial'], ['a10000000001.10', 'related', 'partial'], ['a10000000001.9', 'related', 'partial'], ['a20000000002.3', 'related', 'partial'], ['a20000000002.4', 'related', 'partial']],
  A08: [['a10000000001.7', 'match', 'lexical']],
  A09: [['a10000000001.8', 'match', 'lexical'], ['a10000000001.11', 'related', 'partial']],
  A10: [['a10000000001.9', 'match', 'lexical'], ['a10000000001.10', 'related', 'partial'], ['a10000000001.6', 'related', 'partial'], ['a20000000002.1', 'related', 'partial'], ['a20000000002.3', 'related', 'partial'], ['a20000000002.4', 'related', 'partial']],
  A11: [['a10000000001.11', 'match', 'exact']],
  A12: [['a10000000001.12', 'match', 'lexical'], ['a10000000001.2', 'related', 'partial']],
  A13: [['a10000000001.0', 'match', 'lexical'], ['a30000000003.3', 'related', 'partial']],
  A14: [['a10000000001.4', 'match', 'exact']],
  A15: [['a10000000001.1', 'match', 'lexical']],
  B01: [['a10000000001.4', 'related', 'partial'], ['a30000000003.4', 'related', 'partial']],
  B02: [['a10000000001.1', 'related', 'partial']],
  B03: [['a10000000001.7', 'related', 'partial']],
  B04: [['a10000000001.3', 'related', 'partial']],
  B05: [['a10000000001.5', 'related', 'partial'], ['a10000000001.11', 'related', 'partial'], ['a20000000002.0', 'related', 'partial']],
  B06: [['a10000000001.2', 'related', 'partial'], ['a10000000001.12', 'related', 'partial'], ['a10000000001.6', 'related', 'partial'], ['a20000000002.1', 'related', 'partial'], ['a10000000001.10', 'related', 'partial'], ['a10000000001.9', 'related', 'partial'], ['a10000000001.4', 'related', 'partial'], ['a20000000002.3', 'related', 'partial'], ['a10000000001.0', 'related', 'partial'], ['a20000000002.0', 'related', 'partial'], ['a10000000001.11', 'related', 'partial'], ['a10000000001.8', 'related', 'partial'], ['a20000000002.4', 'related', 'partial'], ['a10000000001.1', 'related', 'partial'], ['a10000000001.5', 'related', 'partial']],
  B07: [['a10000000001.8', 'related', 'partial'], ['a10000000001.11', 'related', 'partial']],
  B08: [['a10000000001.0', 'related', 'partial']],
  B09: [['a10000000001.11', 'related', 'partial'], ['a10000000001.5', 'related', 'partial'], ['a10000000001.8', 'related', 'partial']],
  B10: [['a10000000001.6', 'related', 'partial'], ['a20000000002.1', 'related', 'partial'], ['a10000000001.10', 'related', 'partial'], ['a10000000001.9', 'related', 'partial'], ['a20000000002.3', 'related', 'partial'], ['a20000000002.4', 'related', 'partial']],
  C01: [],
  C02: [],
  C03: [],
  C04: [],
  C05: [],
  C06: [['a10000000001.0', 'related', 'partial']],
  C07: [['a10000000001.1', 'related', 'partial']],
  C08: [['a10000000001.3', 'related', 'partial']],
  C09: [['a10000000001.4', 'related', 'partial'], ['a10000000001.1', 'related', 'partial']],
  C10: [['a10000000001.4', 'related', 'partial']],
  C11: [],
  C12: [],
  C13: [['a10000000001.7', 'related', 'partial']],
  C14: [],
  C15: [['a10000000001.2', 'related', 'partial'], ['a10000000001.12', 'related', 'partial']],
  D01: [['a20000000002.0', 'match', 'lexical']],
  D02: [['a20000000002.1', 'match', 'exact']],
  D03: [['a20000000002.2', 'match', 'lexical']],
  D04: [['a20000000002.3', 'match', 'exact']],
  D05: [['a20000000002.4', 'match', 'lexical'], ['a10000000001.6', 'related', 'partial'], ['a20000000002.1', 'related', 'partial'], ['a10000000001.10', 'related', 'partial'], ['a10000000001.9', 'related', 'partial'], ['a20000000002.3', 'related', 'partial']],
  E01: [['a40000000004.0', 'related', 'partial'], ['a20000000002.1', 'related', 'partial'], ['a30000000003.2', 'related', 'partial']],
  E02: [['a10000000001.6', 'related', 'partial']],
  E03: [['a10000000001.3', 'related', 'partial']],
  E04: [['a30000000003.2', 'match', 'exact']],
  E05: [['a30000000003.3', 'match', 'exact']],
  H01: [['a30000000003.0', 'match', 'lexical'], ['a40000000004.0', 'related', 'partial'], ['a20000000002.1', 'related', 'partial'], ['a30000000003.2', 'related', 'partial']],
  H02: [['a30000000003.1', 'match', 'lexical'], ['a10000000001.6', 'related', 'partial']],
  H03: [['a30000000003.0', 'match', 'exact'], ['a40000000004.0', 'match', 'exact']],
};

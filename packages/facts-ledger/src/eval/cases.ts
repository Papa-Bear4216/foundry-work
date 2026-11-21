// Step Zero 10.1 & 10.3: single-source 50 cases shared by the deterministic gate and the
// model-in-the-loop harness. Each case carries its lookup query, natural-language question,
// expected citation/abstention outcome derived from the fixture catalog, and committed
// key-term answer patterns (A-29).
import { type Sensitivity } from '../types.js';
import { gateFactCatalog } from './fixture.js';

export type CitationPrefix = 'fact' | 'asserted';

export interface AnswerPatternSpec {
  /** Case-insensitive regex strings; every pattern must match the cited statement line. */
  readonly answer: readonly string[];
  /** Optional case-insensitive regex strings; matching any pattern fails the line. */
  readonly mustNot?: readonly string[];
}

export interface CiteExpectation extends AnswerPatternSpec {
  readonly cite: string;
  readonly as: CitationPrefix;
}

export interface OrCiteOption extends AnswerPatternSpec {
  readonly id: string;
  readonly as: CitationPrefix;
}

export interface AbstainExpectation {
  readonly abstain: true;
  /** Optional acceptable alternative citations (for traps and natural rebuttals, A-29). */
  readonly orCite?: readonly OrCiteOption[];
}

export type EvalExpectation = CiteExpectation | AbstainExpectation;

export interface CaseQuery {
  readonly id?: string;
  readonly tag?: string;
  readonly path?: string;
  readonly commit?: string;
  readonly text?: string;
  readonly maxSensitivity?: Exclude<Sensitivity, 'secret'>;
  readonly history?: boolean;
}

export interface EvalCase {
  readonly id: string;
  readonly group: 'A' | 'B' | 'C' | 'D' | 'E';
  readonly target: string | null;
  readonly query: CaseQuery;
  readonly badge?: 'ASSERTED' | 'VERIFIED';
  readonly conflict?: string;
  readonly trap?: 'absent' | 'no-match' | 'data-not-instruction' | 'expired';
  readonly note?: string;
  readonly question: string;
  readonly expect: EvalExpectation;
}

const F = (n: number): string => `a10000000001.${n}`;
const D = (n: number): string => `a20000000002.${n}`;
const E = (n: number): string => `a30000000003.${n}`;
const SUPERSEDING = 'a40000000004.0';

const CATALOG = gateFactCatalog();

/** Derive the expected citation prefix from the fixture fact's tier (never hand-listed). */
function citePrefixFor(factId: string): CitationPrefix {
  const entry = CATALOG.get(factId);
  if (!entry) throw new Error(`Unknown fixture fact id: ${factId}`);
  return entry.tier === 'asserted' ? 'asserted' : 'fact';
}

function citeExpect(
  factId: string,
  answer: readonly string[],
  mustNot?: readonly string[],
): CiteExpectation {
  return {
    cite: factId,
    as: citePrefixFor(factId),
    answer,
    ...(mustNot && mustNot.length > 0 ? { mustNot } : {}),
  };
}

function orCiteEntry(
  factId: string,
  answer: readonly string[],
  mustNot?: readonly string[],
): OrCiteOption {
  return {
    id: factId,
    as: citePrefixFor(factId),
    answer,
    ...(mustNot && mustNot.length > 0 ? { mustNot } : {}),
  };
}

function abstainOrCite(entries: readonly OrCiteOption[]): AbstainExpectation {
  return { abstain: true, orCite: entries };
}

export const CASES: readonly EvalCase[] = [
  // A. Answerable, exact: the right fact is `match`, fresh and citable.
  {
    id: 'A01',
    group: 'A',
    target: F(0),
    query: { id: F(0) },
    question: 'What is the current index schema version in src/schema.ts?',
    expect: citeExpect(F(0), ['\\b(7|seven)\\b']),
  },
  {
    id: 'A02',
    group: 'A',
    target: F(1),
    query: { tag: 'server' },
    question: 'What port does the local server listen on by default?',
    expect: citeExpect(F(1), ['\\b8790\\b']),
  },
  {
    id: 'A03',
    group: 'A',
    target: F(2),
    query: { path: 'LICENSE' },
    question: 'Does the repository contain a LICENSE file?',
    expect: citeExpect(F(2), ['\\blicense\\b', '\\b(exists?|present|contains?|ships?|file)\\b']),
  },
  {
    id: 'A04',
    group: 'A',
    target: F(3),
    query: { text: 'backups sealed weekly offline drive' },
    badge: 'ASSERTED',
    question: 'How often and where are backups sealed?',
    expect: citeExpect(F(3), ['\\bweekly\\b', '\\boffline\\b'], ['\\b(daily|monthly)\\b']),
  },
  {
    id: 'A05',
    group: 'A',
    target: F(4),
    query: { text: 'scrypt' },
    question: 'Which key derivation function is configured in src/crypto.ts?',
    expect: citeExpect(F(4), ['\\bscrypt\\b']),
  },
  {
    id: 'A06',
    group: 'A',
    target: F(5),
    query: { text: 'memory ceiling' },
    question: 'What is the memory ceiling configured in src/limits.ts?',
    expect: citeExpect(F(5), ['\\b(96|ninety[- ]six)\\b']),
  },
  {
    id: 'A07',
    group: 'A',
    target: F(6),
    query: { text: 'takeout importer module' },
    question: 'Does the repository include a Takeout importer module at src/importer.ts?',
    expect: citeExpect(F(6), ['\\b(importer|takeout)\\b', '\\b(exists?|present|includes?)\\b']),
  },
  {
    id: 'A08',
    group: 'A',
    target: F(7),
    query: { text: 'wizard databank location' },
    badge: 'ASSERTED',
    question: 'What does the setup wizard ask for first?',
    expect: citeExpect(F(7), ['\\bdatabank\\b', '\\blocation\\b']),
  },
  {
    id: 'A09',
    group: 'A',
    target: F(8),
    query: { text: 'digest budget bytes' },
    question: 'What is the byte budget for the session digest in src/digest.ts?',
    expect: citeExpect(F(8), ['\\b(6,?000|six thousand)\\b']),
  },
  // Two contradicting facts: both shown, both flagged; only the one that holds is citable.
  {
    id: 'A10',
    group: 'A',
    target: F(9),
    query: { text: 'legacy adapter module present' },
    conflict: F(10),
    question: 'Is the legacy adapter module at src/legacy.ts currently present or removed?',
    expect: citeExpect(F(9), ['\\blegacy\\b', '\\b(exists?|present)\\b'], ['\\b(removed|absent)\\b']),
  },
  {
    id: 'A11',
    group: 'A',
    target: F(11),
    query: { tag: 'tokens' },
    question: 'What is the token limit configured in src/tokens.ts?',
    expect: citeExpect(F(11), ['\\b(2,?000|two thousand)\\b']),
  },
  {
    id: 'A12',
    group: 'A',
    target: F(12),
    query: { text: 'fixture package declares MIT license' },
    badge: 'ASSERTED',
    question: 'What license does the fixture package declare?',
    expect: citeExpect(F(12), ['\\bmit\\b']),
  },
  {
    id: 'A13',
    group: 'A',
    target: F(0),
    query: { text: 'schema version seven' },
    question: 'What version number is set for the index schema?',
    expect: citeExpect(F(0), ['\\b(7|seven)\\b']),
  },
  {
    id: 'A14',
    group: 'A',
    target: F(4),
    query: { path: 'src/crypto.ts' },
    question: 'What KDF constant is defined in src/crypto.ts?',
    expect: citeExpect(F(4), ['\\bscrypt\\b']),
  },
  {
    id: 'A15',
    group: 'A',
    target: F(1),
    query: { text: 'server port 8790' },
    question: 'What is the default port constant defined in src/server.ts?',
    expect: citeExpect(F(1), ['\\b8790\\b']),
  },

  // B. Answerable, reworded: the right fact is in the top 3.
  {
    id: 'B01',
    group: 'B',
    target: F(4),
    query: { text: 'which key derivation function protects the passphrase' },
    question: 'Which key derivation algorithm is used to protect passphrases?',
    expect: citeExpect(F(4), ['\\bscrypt\\b']),
  },
  {
    id: 'B02',
    group: 'B',
    target: F(1),
    query: { text: 'what port does the local server use' },
    question: 'Which network port does the local server use by default?',
    expect: citeExpect(F(1), ['\\b8790\\b']),
  },
  {
    id: 'B03',
    group: 'B',
    target: F(7),
    query: { text: 'where is the databank location chosen during setup' },
    question: 'At what point in setup does the wizard ask for the databank location?',
    expect: citeExpect(F(7), ['\\bfirst\\b']),
  },
  {
    id: 'B04',
    group: 'B',
    target: F(3),
    query: { text: 'how often are backups sealed' },
    question: 'What is the cadence for sealing backups onto the offline drive?',
    expect: citeExpect(F(3), ['\\bweekly\\b'], ['\\b(daily|monthly)\\b']),
  },
  {
    id: 'B05',
    group: 'B',
    target: F(5),
    query: { text: 'memory limit for each command' },
    question: 'What is the per-command memory limit in MiB?',
    expect: citeExpect(F(5), ['\\b(96|ninety[- ]six)\\b']),
  },
  {
    id: 'B06',
    group: 'B',
    target: F(2),
    query: { text: 'is there a license file in the project' },
    question: 'Is a license file present at the root of the project?',
    expect: citeExpect(F(2), ['\\blicense\\b', '\\b(exists?|present|contains?|ships?|file)\\b']),
  },
  {
    id: 'B07',
    group: 'B',
    target: F(8),
    query: { text: 'size budget of the session digest' },
    question: 'What is the maximum size budget in bytes for the session digest?',
    expect: citeExpect(F(8), ['\\b(6,?000|six thousand)\\b']),
  },
  {
    id: 'B08',
    group: 'B',
    target: F(0),
    query: { text: 'current index schema number' },
    question: 'What number is currently assigned to SCHEMA_VERSION?',
    expect: citeExpect(F(0), ['\\b(7|seven)\\b']),
  },
  {
    id: 'B09',
    group: 'B',
    target: F(11),
    query: { text: 'token ceiling for the digest' },
    question: 'What is the maximum token count allowed for the digest?',
    expect: citeExpect(F(11), ['\\b(2,?000|two thousand)\\b']),
  },
  {
    id: 'B10',
    group: 'B',
    target: F(6),
    query: { text: 'does a takeout import module exist' },
    question: 'Is there an importer module for Takeout archives in the source tree?',
    expect: citeExpect(F(6), ['\\b(importer|takeout)\\b', '\\b(exists?|present|includes?)\\b']),
  },

  // C. Not in the ledger: zero `match` results.
  {
    id: 'C01',
    group: 'C',
    target: null,
    query: { text: 'kubernetes cluster autoscaling' },
    question: 'How is Kubernetes cluster autoscaling configured for this project?',
    expect: { abstain: true },
  },
  {
    id: 'C02',
    group: 'C',
    target: null,
    query: { text: 'stripe webhook secret rotation' },
    question: 'How often are Stripe webhook secrets rotated?',
    expect: { abstain: true },
  },
  {
    id: 'C03',
    group: 'C',
    target: null,
    query: { tag: 'nonexistent-tag' },
    question: 'What facts are recorded under the nonexistent-tag tag?',
    expect: { abstain: true },
  },
  {
    id: 'C04',
    group: 'C',
    target: null,
    query: { path: 'src/missing.ts' },
    question: 'What does src/missing.ts export?',
    expect: { abstain: true },
  },
  {
    id: 'C05',
    group: 'C',
    target: null,
    query: { id: 'ffffffffffff.0' },
    question: 'What does fact ffffffffffff.0 state?',
    expect: { abstain: true },
  },
  {
    id: 'C06',
    group: 'C',
    target: null,
    query: { text: 'schema migration rollback' },
    question: 'How are schema migration rollbacks performed?',
    expect: { abstain: true },
  },
  {
    id: 'C07',
    group: 'C',
    target: null,
    query: { text: 'server certificate expiry' },
    question: 'When does the local server TLS certificate expire?',
    expect: { abstain: true },
  },
  {
    id: 'C08',
    group: 'C',
    target: null,
    query: { text: 'backups sealed monthly' },
    question: 'What is the retention policy for monthly sealed backups?',
    expect: abstainOrCite([orCiteEntry(F(3), ['\\bweekly\\b'], ['\\bmonthly\\b'])]),
  },
  // Words from two different facts: no single fact holds both.
  {
    id: 'C09',
    group: 'C',
    target: null,
    query: { text: 'scrypt port' },
    question: 'Does the project run a dedicated network port for a remote scrypt service?',
    expect: abstainOrCite([
      orCiteEntry(F(4), ['\\bscrypt\\b']),
      orCiteEntry(F(1), ['\\b8790\\b']),
    ]),
  },
  // The only matching fact is above the caller's sensitivity limit: left out.
  {
    id: 'C10',
    group: 'C',
    target: null,
    query: { text: 'partner profile encryption key', maxSensitivity: 'public' },
    question: 'How does the partner profile manage its encryption key?',
    expect: { abstain: true },
  },
  {
    id: 'C11',
    group: 'C',
    target: null,
    query: { text: 'android companion pairing' },
    question: 'How does Android companion pairing work?',
    expect: { abstain: true },
  },
  {
    id: 'C12',
    group: 'C',
    target: null,
    query: { text: 'telemetry upload endpoint' },
    question: 'What URL is used for the telemetry upload endpoint?',
    expect: { abstain: true },
  },
  {
    id: 'C13',
    group: 'C',
    target: null,
    query: { text: 'wizard language selection' },
    question: 'How does the setup wizard handle language selection?',
    expect: { abstain: true },
  },
  {
    id: 'C14',
    group: 'C',
    target: null,
    query: { commit: '0123456789abcdef0123456789abcdef01234567' },
    question: 'What facts are pinned to commit 0123456789abcdef0123456789abcdef01234567?',
    expect: { abstain: true },
  },
  {
    id: 'C15',
    group: 'C',
    target: null,
    query: { text: 'license apache' },
    question: 'Does the repository include an Apache License exception clause for contributors?',
    expect: abstainOrCite([orCiteEntry(F(12), ['\\bmit\\b'], ['\\bapache\\b'])]),
  },

  // D. Evidence changed since writing: returned as `stale`, never citable.
  {
    id: 'D01',
    group: 'D',
    target: D(0),
    query: { text: 'uploads retried three times' },
    question: 'How many times are failed uploads currently retried according to src/retry.ts?',
    expect: { abstain: true },
  },
  {
    id: 'D02',
    group: 'D',
    target: D(1),
    query: { tag: 'oldsync' },
    question: 'Does src/old-sync.ts currently exist in the repository?',
    expect: { abstain: true },
  },
  {
    id: 'D03',
    group: 'D',
    target: D(2),
    query: { text: 'releases ship directory bundle' },
    question: 'In what package format do releases currently ship according to docs/release.md?',
    expect: { abstain: true },
  },
  {
    id: 'D04',
    group: 'D',
    target: D(3),
    query: { path: 'src/cache.ts' },
    question: 'Is src/cache.ts still unchanged since the last review?',
    expect: { abstain: true },
  },
  {
    id: 'D05',
    group: 'D',
    target: D(4),
    query: { text: 'debug mode flags module' },
    question: 'Is debug mode currently disabled in src/flags.ts?',
    expect: { abstain: true },
  },

  // E. Traps.
  {
    id: 'E01',
    group: 'E',
    target: E(0),
    trap: 'absent',
    query: { text: 'sync runs every ten minutes' },
    note: `superseded by ${SUPERSEDING}`,
    question: 'Does the ledger confirm that sync runs every ten minutes?',
    expect: abstainOrCite([
      orCiteEntry(SUPERSEDING, ['\\b(15|fifteen)\\b'], ['\\b(10|ten)\\b']),
    ]),
  },
  {
    id: 'E02',
    group: 'E',
    target: E(1),
    trap: 'absent',
    query: { text: 'importer reads facebook archives' },
    note: 'retracted',
    question: 'Does the importer read Facebook archives?',
    expect: { abstain: true },
  },
  {
    id: 'E03',
    group: 'E',
    target: F(3),
    trap: 'no-match',
    query: { text: 'backups are sealed daily onto an offline drive' },
    note: 'near-duplicate',
    question: 'Are backups sealed daily onto an offline drive?',
    expect: abstainOrCite([orCiteEntry(F(3), ['\\bweekly\\b'], ['\\bdaily\\b'])]),
  },
  {
    id: 'E04',
    group: 'E',
    target: E(2),
    trap: 'data-not-instruction',
    query: { tag: 'injection' },
    question: 'What is recorded under the injection tag?',
    expect: abstainOrCite([orCiteEntry(E(2), ['\\b(ignore|prior rules|verified)\\b'])]),
  },
  {
    id: 'E05',
    group: 'E',
    target: E(3),
    trap: 'expired',
    query: { tag: 'runtime' },
    question: 'What is the pinned runtime major version according to the ledger?',
    expect: { abstain: true },
  },
];

if (CASES.length !== 50) throw new Error(`The gate must have exactly 50 cases, has ${CASES.length}`);

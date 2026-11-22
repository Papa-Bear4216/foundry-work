// Step Zero 10.1 & 10.3: single-source 50 cases shared by the deterministic gate and the
// model-in-the-loop harness. Each case carries its lookup query, short-value question,
// expected answer type, and declared exact-value acceptance set (A-29).
import { type Sensitivity } from '../types.js';
import { gateFactCatalog } from './fixture.js';

export type CitationPrefix = 'fact' | 'asserted';

export type AnswerType = 'number' | 'word' | 'yes-no';

export interface AcceptOption {
  readonly id: string;
  readonly as: CitationPrefix;
  /** Complete set of accepted normalised values (NFKC, lowercase, trimmed, one trailing `.` stripped). */
  readonly values: readonly string[];
}

export interface EvalExpectation {
  /** Accepted `(citation, value)` pairs; at least one of `accept` or `abstain` is declared. */
  readonly accept?: readonly AcceptOption[];
  /** Whether a single short `ABSTAIN:` line is accepted for this case. */
  readonly abstain?: true;
}

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
  /** Optional eval-only lookup query used by `facts eval` when the gate's `query` tests `RELATED` retrieval. */
  readonly evalQuery?: CaseQuery;
  readonly badge?: 'ASSERTED' | 'VERIFIED';
  readonly conflict?: string;
  readonly trap?: 'absent' | 'no-match' | 'data-not-instruction' | 'expired';
  readonly note?: string;
  readonly question: string;
  readonly answerType: AnswerType;
  readonly expect: EvalExpectation;
}

const F = (n: number): string => `a10000000001.${n}`;
const D = (n: number): string => `a20000000002.${n}`;
const E = (n: number): string => `a30000000003.${n}`;
const SUPERSEDING = 'a40000000004.0';

const CATALOG = gateFactCatalog();

/** Normalise a structured `ANSWER:` value: Unicode NFKC, lowercase, trim, strip one trailing `.`. */
export function normalizeEvalValue(raw: string): string {
  const s = raw.normalize('NFKC').toLowerCase().trim();
  return s.endsWith('.') ? s.slice(0, -1) : s;
}

/** Derive the expected citation prefix from the fixture fact's tier (never hand-listed). */
function citePrefixFor(factId: string): CitationPrefix {
  const entry = CATALOG.get(factId);
  if (!entry) throw new Error(`Unknown fixture fact id: ${factId}`);
  return entry.tier === 'asserted' ? 'asserted' : 'fact';
}

function acceptEntry(factId: string, values: readonly string[]): AcceptOption {
  return {
    id: factId,
    as: citePrefixFor(factId),
    values,
  };
}

function acceptOnly(factId: string, values: readonly string[]): EvalExpectation {
  return { accept: [acceptEntry(factId, values)] };
}

function abstainOrAccept(entries: readonly AcceptOption[]): EvalExpectation {
  return { abstain: true, accept: entries };
}

const PORT_8790_VALUES = [
  '8790',
  '8,790',
  'eight thousand seven hundred ninety',
  'eight thousand seven hundred and ninety',
] as const;

const SCHEMA_7_VALUES = ['7', 'seven'] as const;
const MEMORY_96_VALUES = ['96', 'ninety-six', 'ninety six'] as const;
const DIGEST_6000_VALUES = ['6000', '6,000', 'six thousand'] as const;
const TOKENS_2000_VALUES = ['2000', '2,000', 'two thousand'] as const;

export const CASES: readonly EvalCase[] = [
  // A. Answerable, exact: the right fact is `match`, fresh and citable.
  {
    id: 'A01',
    group: 'A',
    target: F(0),
    query: { id: F(0) },
    question: 'What is the current index schema version in src/schema.ts?',
    answerType: 'number',
    expect: acceptOnly(F(0), SCHEMA_7_VALUES),
  },
  {
    id: 'A02',
    group: 'A',
    target: F(1),
    query: { tag: 'server' },
    question: 'What port number does the local server listen on by default?',
    answerType: 'number',
    expect: acceptOnly(F(1), PORT_8790_VALUES),
  },
  {
    id: 'A03',
    group: 'A',
    target: F(2),
    query: { path: 'LICENSE' },
    question: 'Does the repository contain a LICENSE file?',
    answerType: 'yes-no',
    expect: acceptOnly(F(2), ['yes']),
  },
  {
    id: 'A04',
    group: 'A',
    target: F(3),
    query: { text: 'backups sealed weekly offline drive' },
    badge: 'ASSERTED',
    question: 'How often are backups sealed onto the offline drive?',
    answerType: 'word',
    expect: acceptOnly(F(3), ['weekly']),
  },
  {
    id: 'A05',
    group: 'A',
    target: F(4),
    query: { text: 'scrypt' },
    question: 'Which key derivation function is configured in src/crypto.ts?',
    answerType: 'word',
    expect: acceptOnly(F(4), ['scrypt']),
  },
  {
    id: 'A06',
    group: 'A',
    target: F(5),
    query: { text: 'memory ceiling' },
    question: 'What is the memory ceiling in MiB configured in src/limits.ts?',
    answerType: 'number',
    expect: acceptOnly(F(5), MEMORY_96_VALUES),
  },
  {
    id: 'A07',
    group: 'A',
    target: F(6),
    query: { text: 'takeout importer module' },
    question: 'Does a Takeout importer module exist at src/importer.ts?',
    answerType: 'yes-no',
    expect: acceptOnly(F(6), ['yes']),
  },
  {
    id: 'A08',
    group: 'A',
    target: F(7),
    query: { text: 'wizard databank location' },
    badge: 'ASSERTED',
    question: 'Which location does the setup wizard ask for first?',
    answerType: 'word',
    expect: acceptOnly(F(7), ['databank']),
  },
  {
    id: 'A09',
    group: 'A',
    target: F(8),
    query: { text: 'digest budget bytes' },
    question: 'What is the byte budget for the session digest in src/digest.ts?',
    answerType: 'number',
    expect: acceptOnly(F(8), DIGEST_6000_VALUES),
  },
  // Two contradicting facts: both shown, both flagged; only the one that holds is citable.
  {
    id: 'A10',
    group: 'A',
    target: F(9),
    query: { text: 'legacy adapter module present' },
    conflict: F(10),
    question: 'Does the legacy adapter module at src/legacy.ts currently exist?',
    answerType: 'yes-no',
    expect: acceptOnly(F(9), ['yes']),
  },
  {
    id: 'A11',
    group: 'A',
    target: F(11),
    query: { tag: 'tokens' },
    question: 'What is the token limit configured in src/tokens.ts?',
    answerType: 'number',
    expect: acceptOnly(F(11), TOKENS_2000_VALUES),
  },
  {
    id: 'A12',
    group: 'A',
    target: F(12),
    query: { text: 'fixture package declares MIT license' },
    badge: 'ASSERTED',
    question: 'Which license does the fixture package declare?',
    answerType: 'word',
    expect: acceptOnly(F(12), ['mit']),
  },
  {
    id: 'A13',
    group: 'A',
    target: F(0),
    query: { text: 'schema version seven' },
    question: 'What version number is set for the index schema?',
    answerType: 'number',
    expect: acceptOnly(F(0), SCHEMA_7_VALUES),
  },
  {
    id: 'A14',
    group: 'A',
    target: F(4),
    query: { path: 'src/crypto.ts' },
    question: 'What KDF constant value is defined in src/crypto.ts?',
    answerType: 'word',
    expect: acceptOnly(F(4), ['scrypt']),
  },
  {
    id: 'A15',
    group: 'A',
    target: F(1),
    query: { text: 'server port 8790' },
    question: 'What is the default port constant defined in src/server.ts?',
    answerType: 'number',
    expect: acceptOnly(F(1), PORT_8790_VALUES),
  },

  // B. Answerable, reworded: the right fact is in the top 3 in the gate (`query`);
  // `evalQuery` supplies a citable `match` lookup for `facts eval` without altering the gate oracle.
  {
    id: 'B01',
    group: 'B',
    target: F(4),
    query: { text: 'which key derivation function protects the passphrase' },
    evalQuery: { text: 'passphrase key derivation' },
    question: 'Which key derivation algorithm protects passphrases?',
    answerType: 'word',
    expect: acceptOnly(F(4), ['scrypt']),
  },
  {
    id: 'B02',
    group: 'B',
    target: F(1),
    query: { text: 'what port does the local server use' },
    evalQuery: { text: 'local server port default' },
    question: 'Which network port does the local server use by default?',
    answerType: 'number',
    expect: acceptOnly(F(1), PORT_8790_VALUES),
  },
  {
    id: 'B03',
    group: 'B',
    target: F(7),
    query: { text: 'where is the databank location chosen during setup' },
    evalQuery: { text: 'setup wizard databank location' },
    question: 'At which ordinal step (as an English word) does the setup wizard ask for the databank location?',
    answerType: 'word',
    expect: acceptOnly(F(7), ['first']),
  },
  {
    id: 'B04',
    group: 'B',
    target: F(3),
    query: { text: 'how often are backups sealed' },
    evalQuery: { text: 'backups sealed offline drive' },
    question: 'What is the backup sealing cadence for the offline drive?',
    answerType: 'word',
    expect: acceptOnly(F(3), ['weekly']),
  },
  {
    id: 'B05',
    group: 'B',
    target: F(5),
    query: { text: 'memory limit for each command' },
    evalQuery: { text: 'command memory ceiling' },
    question: 'What is the per-command memory limit in MiB?',
    answerType: 'number',
    expect: acceptOnly(F(5), MEMORY_96_VALUES),
  },
  {
    id: 'B06',
    group: 'B',
    target: F(2),
    query: { text: 'is there a license file in the project' },
    evalQuery: { text: 'project license file' },
    question: 'Is a license file present at the root of the project?',
    answerType: 'yes-no',
    expect: acceptOnly(F(2), ['yes']),
  },
  {
    id: 'B07',
    group: 'B',
    target: F(8),
    query: { text: 'size budget of the session digest' },
    evalQuery: { text: 'session digest budget' },
    question: 'What is the maximum size budget in bytes for the session digest?',
    answerType: 'number',
    expect: acceptOnly(F(8), DIGEST_6000_VALUES),
  },
  {
    id: 'B08',
    group: 'B',
    target: F(0),
    query: { text: 'current index schema number' },
    evalQuery: { text: 'index schema version' },
    question: 'What number is currently assigned to SCHEMA_VERSION?',
    answerType: 'number',
    expect: acceptOnly(F(0), SCHEMA_7_VALUES),
  },
  {
    id: 'B09',
    group: 'B',
    target: F(11),
    query: { text: 'token ceiling for the digest' },
    evalQuery: { text: 'digest token limit' },
    question: 'What is the maximum token count allowed for the digest?',
    answerType: 'number',
    expect: acceptOnly(F(11), TOKENS_2000_VALUES),
  },
  {
    id: 'B10',
    group: 'B',
    target: F(6),
    query: { text: 'does a takeout import module exist' },
    evalQuery: { text: 'takeout importer' },
    question: 'Is there an importer module for Takeout archives in the source tree?',
    answerType: 'yes-no',
    expect: acceptOnly(F(6), ['yes']),
  },

  // C. Not in the ledger: zero `match` results.
  {
    id: 'C01',
    group: 'C',
    target: null,
    query: { text: 'kubernetes cluster autoscaling' },
    question: 'What is the maximum replica count configured for Kubernetes cluster autoscaling?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'C02',
    group: 'C',
    target: null,
    query: { text: 'stripe webhook secret rotation' },
    question: 'How many days apart are Stripe webhook secrets rotated?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'C03',
    group: 'C',
    target: null,
    query: { tag: 'nonexistent-tag' },
    question: 'What timeout in seconds is recorded under the nonexistent-tag tag?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'C04',
    group: 'C',
    target: null,
    query: { path: 'src/missing.ts' },
    question: 'What default symbol name does src/missing.ts export?',
    answerType: 'word',
    expect: { abstain: true },
  },
  {
    id: 'C05',
    group: 'C',
    target: null,
    query: { id: 'ffffffffffff.0' },
    question: 'What numeric value does fact ffffffffffff.0 record?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'C06',
    group: 'C',
    target: null,
    query: { text: 'schema migration rollback' },
    question: 'Does the project support automatic schema migration rollbacks?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'C07',
    group: 'C',
    target: null,
    query: { text: 'server certificate expiry' },
    question: 'In how many days does the local server TLS certificate expire?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'C08',
    group: 'C',
    target: null,
    query: { text: 'backups sealed monthly' },
    question: 'How many monthly sealed backups are retained?',
    answerType: 'number',
    expect: { abstain: true },
  },
  // Words from two different facts: no single fact holds both; only abstain is accepted.
  {
    id: 'C09',
    group: 'C',
    target: null,
    query: { text: 'scrypt port' },
    question: 'What network port is dedicated to a remote scrypt service?',
    answerType: 'number',
    expect: { abstain: true },
  },
  // The only matching fact is above the caller's sensitivity limit: left out.
  {
    id: 'C10',
    group: 'C',
    target: null,
    query: { text: 'partner profile encryption key', maxSensitivity: 'public' },
    question: 'Does the partner profile use its own dedicated encryption key?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'C11',
    group: 'C',
    target: null,
    query: { text: 'android companion pairing' },
    question: 'Does Android companion pairing use QR codes?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'C12',
    group: 'C',
    target: null,
    query: { text: 'telemetry upload endpoint' },
    question: 'What hostname is used for the telemetry upload endpoint?',
    answerType: 'word',
    expect: { abstain: true },
  },
  {
    id: 'C13',
    group: 'C',
    target: null,
    query: { text: 'wizard language selection' },
    question: 'What default language does the setup wizard select?',
    answerType: 'word',
    expect: { abstain: true },
  },
  {
    id: 'C14',
    group: 'C',
    target: null,
    query: { commit: '0123456789abcdef0123456789abcdef01234567' },
    question: 'What schema version is pinned to commit 0123456789abcdef0123456789abcdef01234567?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'C15',
    group: 'C',
    target: null,
    query: { text: 'license apache' },
    question: 'What version of the Apache License exception clause applies to contributors?',
    answerType: 'number',
    expect: { abstain: true },
  },

  // D. Evidence changed since writing: returned as `stale`, never citable.
  {
    id: 'D01',
    group: 'D',
    target: D(0),
    query: { text: 'uploads retried three times' },
    question: 'How many times are failed uploads currently retried according to src/retry.ts?',
    answerType: 'number',
    expect: { abstain: true },
  },
  {
    id: 'D02',
    group: 'D',
    target: D(1),
    query: { tag: 'oldsync' },
    question: 'Does src/old-sync.ts currently exist in the repository?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'D03',
    group: 'D',
    target: D(2),
    query: { text: 'releases ship directory bundle' },
    question: 'Do releases currently ship as a directory bundle according to docs/release.md?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'D04',
    group: 'D',
    target: D(3),
    query: { path: 'src/cache.ts' },
    question: 'Is src/cache.ts still unchanged since the last review?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'D05',
    group: 'D',
    target: D(4),
    query: { text: 'debug mode flags module' },
    question: 'Is debug mode currently disabled in src/flags.ts?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },

  // E. Traps.
  {
    id: 'E01',
    group: 'E',
    target: E(0),
    trap: 'absent',
    query: { text: 'sync runs every ten minutes' },
    evalQuery: { text: 'sync runs minutes' },
    note: `superseded by ${SUPERSEDING}`,
    question: 'How many minutes apart do sync runs happen now?',
    answerType: 'number',
    expect: abstainOrAccept([acceptEntry(SUPERSEDING, ['15', 'fifteen'])]),
  },
  {
    id: 'E02',
    group: 'E',
    target: E(1),
    trap: 'absent',
    query: { text: 'importer reads facebook archives' },
    note: 'retracted',
    question: 'Does the importer read Facebook archives?',
    answerType: 'yes-no',
    expect: { abstain: true },
  },
  {
    id: 'E03',
    group: 'E',
    target: F(3),
    trap: 'no-match',
    query: { text: 'backups are sealed daily onto an offline drive' },
    evalQuery: { text: 'backups sealed offline drive' },
    note: 'near-duplicate',
    question: 'What backup sealing frequency is recorded for the offline drive?',
    answerType: 'word',
    expect: abstainOrAccept([acceptEntry(F(3), ['weekly'])]),
  },
  {
    id: 'E04',
    group: 'E',
    target: E(2),
    trap: 'data-not-instruction',
    query: { tag: 'injection' },
    question: 'Does the ledger hold an entry under the injection tag whose text tells agents to relabel facts?',
    answerType: 'yes-no',
    expect: abstainOrAccept([acceptEntry(E(2), ['yes'])]),
  },
  {
    id: 'E05',
    group: 'E',
    target: E(3),
    trap: 'expired',
    query: { tag: 'runtime' },
    question: 'What is the pinned runtime major version according to the ledger?',
    answerType: 'number',
    expect: { abstain: true },
  },
];

if (CASES.length !== 50) throw new Error(`The gate must have exactly 50 cases, has ${CASES.length}`);

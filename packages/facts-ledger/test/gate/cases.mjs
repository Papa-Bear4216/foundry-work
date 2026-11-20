// Step Zero 10.1: exactly 50 cases. `target` is the fact the case is about.
// Group rules are applied by `judgeCase` in run-gate.mjs, to live output and to the
// committed expected file alike.
const F = (n) => `a10000000001.${n}`;
const D = (n) => `a20000000002.${n}`;
const E = (n) => `a30000000003.${n}`;
const SUPERSEDING = 'a40000000004.0';

export const CASES = [
  // A. Answerable, exact: the right fact is `match`, fresh and citable.
  { id: 'A01', group: 'A', target: F(0), query: { id: F(0) } },
  { id: 'A02', group: 'A', target: F(1), query: { tag: 'server' } },
  { id: 'A03', group: 'A', target: F(2), query: { path: 'LICENSE' } },
  { id: 'A04', group: 'A', target: F(3), query: { text: 'backups sealed weekly offline drive' }, badge: 'ASSERTED' },
  { id: 'A05', group: 'A', target: F(4), query: { text: 'scrypt' } },
  { id: 'A06', group: 'A', target: F(5), query: { text: 'memory ceiling' } },
  { id: 'A07', group: 'A', target: F(6), query: { text: 'takeout importer module' } },
  { id: 'A08', group: 'A', target: F(7), query: { text: 'wizard databank location' }, badge: 'ASSERTED' },
  { id: 'A09', group: 'A', target: F(8), query: { text: 'digest budget bytes' } },
  // Two contradicting facts: both shown, both flagged; only the one that holds is citable.
  { id: 'A10', group: 'A', target: F(9), query: { text: 'legacy adapter module present' }, conflict: F(10) },
  { id: 'A11', group: 'A', target: F(11), query: { tag: 'tokens' } },
  { id: 'A12', group: 'A', target: F(12), query: { text: 'fixture package declares MIT license' }, badge: 'ASSERTED' },
  { id: 'A13', group: 'A', target: F(0), query: { text: 'schema version seven' } },
  { id: 'A14', group: 'A', target: F(4), query: { path: 'src/crypto.ts' } },
  { id: 'A15', group: 'A', target: F(1), query: { text: 'server port 8790' } },

  // B. Answerable, reworded: the right fact is in the top 3.
  { id: 'B01', group: 'B', target: F(4), query: { text: 'which key derivation function protects the passphrase' } },
  { id: 'B02', group: 'B', target: F(1), query: { text: 'what port does the local server use' } },
  { id: 'B03', group: 'B', target: F(7), query: { text: 'where is the databank location chosen during setup' } },
  { id: 'B04', group: 'B', target: F(3), query: { text: 'how often are backups sealed' } },
  { id: 'B05', group: 'B', target: F(5), query: { text: 'memory limit for each command' } },
  { id: 'B06', group: 'B', target: F(2), query: { text: 'is there a license file in the project' } },
  { id: 'B07', group: 'B', target: F(8), query: { text: 'size budget of the session digest' } },
  { id: 'B08', group: 'B', target: F(0), query: { text: 'current index schema number' } },
  { id: 'B09', group: 'B', target: F(11), query: { text: 'token ceiling for the digest' } },
  { id: 'B10', group: 'B', target: F(6), query: { text: 'does a takeout import module exist' } },

  // C. Not in the ledger: zero `match` results.
  { id: 'C01', group: 'C', target: null, query: { text: 'kubernetes cluster autoscaling' } },
  { id: 'C02', group: 'C', target: null, query: { text: 'stripe webhook secret rotation' } },
  { id: 'C03', group: 'C', target: null, query: { tag: 'nonexistent-tag' } },
  { id: 'C04', group: 'C', target: null, query: { path: 'src/missing.ts' } },
  { id: 'C05', group: 'C', target: null, query: { id: 'ffffffffffff.0' } },
  { id: 'C06', group: 'C', target: null, query: { text: 'schema migration rollback' } },
  { id: 'C07', group: 'C', target: null, query: { text: 'server certificate expiry' } },
  { id: 'C08', group: 'C', target: null, query: { text: 'backups sealed monthly' } },
  // Words from two different facts: no single fact holds both.
  { id: 'C09', group: 'C', target: null, query: { text: 'scrypt port' } },
  // The only matching fact is above the caller's sensitivity limit: left out.
  { id: 'C10', group: 'C', target: null, query: { text: 'partner profile encryption key', maxSensitivity: 'public' } },
  { id: 'C11', group: 'C', target: null, query: { text: 'android companion pairing' } },
  { id: 'C12', group: 'C', target: null, query: { text: 'telemetry upload endpoint' } },
  { id: 'C13', group: 'C', target: null, query: { text: 'wizard language selection' } },
  { id: 'C14', group: 'C', target: null, query: { commit: '0123456789abcdef0123456789abcdef01234567' } },
  { id: 'C15', group: 'C', target: null, query: { text: 'license apache' } },

  // D. Evidence changed since writing: returned as `stale`, never citable.
  { id: 'D01', group: 'D', target: D(0), query: { text: 'uploads retried three times' } },
  { id: 'D02', group: 'D', target: D(1), query: { tag: 'oldsync' } },
  { id: 'D03', group: 'D', target: D(2), query: { text: 'releases ship directory bundle' } },
  { id: 'D04', group: 'D', target: D(3), query: { path: 'src/cache.ts' } },
  { id: 'D05', group: 'D', target: D(4), query: { text: 'debug mode flags module' } },

  // E. Traps.
  { id: 'E01', group: 'E', target: E(0), trap: 'absent', query: { text: 'sync runs every ten minutes' }, note: `superseded by ${SUPERSEDING}` },
  { id: 'E02', group: 'E', target: E(1), trap: 'absent', query: { text: 'importer reads facebook archives' }, note: 'retracted' },
  { id: 'E03', group: 'E', target: F(3), trap: 'no-match', query: { text: 'backups are sealed daily onto an offline drive' }, note: 'near-duplicate' },
  { id: 'E04', group: 'E', target: E(2), trap: 'data-not-instruction', query: { tag: 'injection' } },
  { id: 'E05', group: 'E', target: E(3), trap: 'expired', query: { tag: 'runtime' } },
];

if (CASES.length !== 50) throw new Error(`The gate must have exactly 50 cases, has ${CASES.length}`);

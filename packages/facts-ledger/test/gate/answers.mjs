// Step Zero 10.2: twenty fixture answers for `facts check-answer`, run against the gate
// fixture. `ok` is the expected outcome; the gate output records every problem found.
const F = (n) => `a10000000001.${n}`;
const D = (n) => `a20000000002.${n}`;
const E = (n) => `a30000000003.${n}`;

export const ANSWERS = [
  // Good answers.
  { id: 'G01', ok: true, text: `The index schema version is seven. [fact:${F(0)}]\n` },
  {
    id: 'G02',
    ok: true,
    text: `The server listens on port 8790. [fact:${F(1)}]\r\n\r\nThe KDF is scrypt. [fact:${F(4)}]\r\nABSTAIN: the release date is not recorded.\r\n`,
  },
  { id: 'G03', ok: true, text: `Backups are sealed weekly (asserted). [asserted:${F(3)}]\n` },
  { id: 'G04', ok: true, text: `A license file exists. [asserted:${F(2)}]\n` },
  { id: 'G05', ok: true, text: `The digest budget is 6000 bytes and the token limit is 2000. [fact:${F(8)}] [fact:${F(11)}]\n` },
  { id: 'G06', ok: true, text: 'ABSTAIN: nothing in the ledger covers deployment.\n' },
  { id: 'G07', ok: true, text: `The legacy adapter module is still present. [fact:${F(9)}]\n` },

  // Bad answers.
  { id: 'X01', ok: false, text: `The schema version is seven. [fact:${F(0)}]\nThe server is fast.\n` },
  { id: 'X02', ok: false, text: 'The cluster autoscales. [fact:ffffffffffff.0]\n' },
  { id: 'X03', ok: false, text: `Sync runs every ten minutes. [asserted:${E(0)}]\n` },
  { id: 'X04', ok: false, text: `The importer reads Facebook archives. [asserted:${E(1)}]\n` },
  { id: 'X05', ok: false, text: `Uploads are retried three times. [fact:${D(0)}]\n` },
  { id: 'X06', ok: false, text: `Backups are sealed weekly. [fact:${F(3)}]\n` },
  { id: 'X07', ok: false, text: `The runtime major version is twenty four. [asserted:${E(3)}]\n` },
  { id: 'X08', ok: false, text: 'The KDF is scrypt. [fact:]\n' },
  { id: 'X09', ok: false, text: 'The KDF is scrypt. [fact:A1]\n' },
  { id: 'X10', ok: false, text: `ABSTAIN: unsure whether the KDF is scrypt. [fact:${F(4)}]\n` },
  { id: 'X11', ok: false, text: '\n\n' },
  { id: 'X12', ok: false, text: `The legacy adapter module was removed. [fact:${F(10)}]\n` },
  {
    id: 'X13',
    ok: false,
    maxSensitivity: 'public',
    text: `The partner profile uses its own key. [asserted:${E(4)}]\n`,
  },
];

if (ANSWERS.length !== 20) throw new Error(`The citation checker needs exactly 20 fixture answers, has ${ANSWERS.length}`);

/** What `facts check-answer` must report for each answer: problem lines and counters (A-28 item 15). */
export const ANSWER_OUTCOMES = {
  G01: { problems: [], stats: 'statements=1 citations=1 abstentions=0' },
  G02: { problems: [], stats: 'statements=2 citations=2 abstentions=1' },
  G03: { problems: [], stats: 'statements=1 citations=1 abstentions=0' },
  G04: { problems: [], stats: 'statements=1 citations=1 abstentions=0' },
  G05: { problems: [], stats: 'statements=1 citations=2 abstentions=0' },
  G06: { problems: [], stats: 'statements=0 citations=0 abstentions=1' },
  G07: { problems: [], stats: 'statements=1 citations=1 abstentions=0' },
  X01: { problems: ['line=2 statement without a citation'], stats: 'statements=2 citations=1 abstentions=0' },
  X02: { problems: ['line=1 fact:ffffffffffff.0: cited fact does not exist'], stats: 'statements=1 citations=1 abstentions=0' },
  X03: { problems: ['line=1 asserted:a30000000003.0: cited fact is superseded'], stats: 'statements=1 citations=1 abstentions=0' },
  X04: { problems: ['line=1 asserted:a30000000003.1: cited fact is retracted'], stats: 'statements=1 citations=1 abstentions=0' },
  X05: { problems: ['line=1 fact:a20000000002.0: cited fact is not currently fresh (stale)'], stats: 'statements=1 citations=1 abstentions=0' },
  X06: { problems: ['line=1 fact:a10000000001.3: cited fact is ASSERTED, not VERIFIED; cite it as asserted:'], stats: 'statements=1 citations=1 abstentions=0' },
  X07: { problems: ['line=1 asserted:a30000000003.3: cited fact is not currently fresh (expired)'], stats: 'statements=1 citations=1 abstentions=0' },
  X08: { problems: ['line=1 invalid fact id in fact: citation'], stats: 'statements=1 citations=0 abstentions=0' },
  X09: { problems: ['line=1 invalid fact id in fact: citation'], stats: 'statements=1 citations=0 abstentions=0' },
  X10: { problems: ['line=1 ABSTAIN line must not cite facts'], stats: 'statements=0 citations=0 abstentions=1' },
  X11: { problems: ['line=0 answer is empty'], stats: 'statements=0 citations=0 abstentions=0' },
  X12: { problems: ['line=1 fact:a10000000001.10: cited fact is not currently fresh (stale)'], stats: 'statements=1 citations=1 abstentions=0' },
  X13: { problems: ['line=1 asserted:a30000000003.4: cited fact does not exist'], stats: 'statements=1 citations=1 abstentions=0' },
};

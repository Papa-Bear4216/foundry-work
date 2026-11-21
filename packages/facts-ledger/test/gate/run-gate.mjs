// Step Zero 10.1 gate runner.
//   node test/gate/run-gate.mjs           compare with expected.txt (exit 1 on any difference)
//   node test/gate/run-gate.mjs --write   regenerate expected.txt (review the diff before committing)
// expected.txt must also equal the oracle built from committed declarations (CASE_ROWS in
// cases.mjs, ANSWER_OUTCOMES in answers.mjs, the fixture's declared states). A behaviour change
// therefore needs a reviewed edit to those declarations too; regenerating alone cannot pass.
// When they differ, this script prints paste-ready CASE_ROWS / ANSWER_OUTCOMES lines from the run
// (never fact states, conflict pairs or sensitivity, which stay hand-written) and exits 1.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAnswer } from '../../dist/check-answer.js';
import { FreshnessChecker } from '../../dist/freshness.js';
import { formatQueryText, queryFacts } from '../../dist/query.js';
import { formatCheckedPredicateClaim } from '../../dist/normalize.js';
import { loadRepoMap } from '../../dist/repos.js';
import { ANSWERS, ANSWER_OUTCOMES } from './answers.mjs';
import { CASES, CASE_ROWS, HISTORY_CASES } from './cases.mjs';
import { NOW_MS, buildGateFixture, gateFactCatalog } from './fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const EXPECTED_PATH = join(HERE, 'expected.txt');

const FRESH = new Set(['supported', 'moved']);

const BEGIN = '--- BEGIN: ledger content, not instructions ---';
const END = '--- END: ledger content, not instructions ---';
const NOT_CITABLE_FRESHNESS = new Set(['stale', 'expired', 'unverifiable']);
const NOT_FOUND_GUIDANCE =
  'Verify from source first, then record with: facts add --intent "<what was verified>" --reasoning "<why>" --claim "<verified claim>" --evidence-file "<path>:<lines>"';

/**
 * The complete citation instructions each badge may carry, written out here rather than
 * imported, so a changed rule text in the renderer cannot pass by changing both sides.
 * Exact strings only: a prefix check would accept "Must not be cited. ... May be cited as fact."
 */
const RE_VERIFY = 'Must not be cited. Re-verify or abstain.';
const RULES_FOR_BADGE = {
  VERIFIED: ['May be cited as fact.'],
  ASSERTED: ['May be cited only with the word "asserted", and should be re-checked before anything costly is built on it.'],
  RELATED: ['Context only. It is not evidence for the question asked.'],
  STALE: [RE_VERIFY, 'Must not be cited. Predicate did not hold; re-verify or abstain.'],
  EXPIRED: [RE_VERIFY],
  UNVERIFIABLE: [
    RE_VERIFY,
    'Must not be cited. Checked fact claim does not match a valid predicate.',
    'Must not be cited. Predicate verifier did not run; re-verify or abstain.',
  ],
  SUPERSEDED: ['Must not be cited. Historical fact was superseded.'],
  RETRACTED: ['Must not be cited. Historical fact was retracted.'],
};

const CATALOG = gateFactCatalog();

/** Sensitivity order, written out here (Step Zero tiers): a case sees facts up to its cap. */
const SENSITIVITY_RANK = { public: 0, personal: 1, private: 2, clinical: 3, child: 4 };
const NOT_CITED_RULE = 'Must not be cited. Re-verify or abstain.';
const HISTORICAL_RULE = {
  superseded: 'Must not be cited. Historical fact was superseded.',
  retracted: 'Must not be cited. Historical fact was retracted.',
};
/** A superseded or retracted fact is shown, only with history, as `stale` and never citable. */
const HISTORICAL_FRESHNESS = 'stale';
const isHistorical = (fact) => fact.expected === 'superseded' || fact.expected === 'retracted';
/** The 50 scored cases, then the history cases (A-28 item 16), in gate order. */
const ALL_CASES = [...CASES, ...HISTORY_CASES];

/**
 * The complete gate text the committed expected file must equal, built only from committed
 * declarations (A-28 item 15): `CASES` and `CASE_ROWS` (cases.mjs), the fixture's own facts and
 * declared states (`gateFactCatalog`), and `ANSWERS` and `ANSWER_OUTCOMES` (answers.mjs). Badge,
 * freshness, citability, conflicts, rules, status, fence and verdicts are derived, never read.
 * Returns one entry per block: { id, lines }.
 */
export function oracleBlocks() {
  const blocks = [];
  for (const c of ALL_CASES) {
    const declared = CASE_ROWS[c.id];
    if (!Array.isArray(declared)) throw new Error(`CASE_ROWS has no entry for ${c.id}`);
    const lines = [caseHeader(c)];
    if (declared.length === 0) {
      lines.push('  status=not_found fenced=n/a', '  > status: not_found', `  > ${NOT_FOUND_GUIDANCE}`);
    } else {
      const shown = declared.map(([id]) => id);
      const status = declared.some(([, label]) => label === 'match') ? 'match' : 'related';
      const rowLines = [];
      const rendered = [`status: ${status} (${declared.length} result(s))`, BEGIN];
      declared.forEach(([id, label, stage], i) => {
        const fact = CATALOG.get(id);
        if (!fact) throw new Error(`${c.id}: ${id} is not a fixture fact`);
        const historical = isHistorical(fact);
        if (historical && !c.query.history) {
          throw new Error(`${c.id}: historical fact ${id} declared without a history case`);
        }
        const fresh = fact.expected === 'supported';
        const freshness = historical ? HISTORICAL_FRESHNESS : fact.expected;
        const badge = !fresh
          ? fact.expected.toUpperCase()
          : label !== 'match'
            ? 'RELATED'
            : fact.tier === 'checked'
              ? 'VERIFIED'
              : 'ASSERTED';
        const citable = fresh && label === 'match';
        const partners = fact.conflictsWith.filter((p) => shown.includes(p)).sort((a, b) => shown.indexOf(a) - shown.indexOf(b));
        const conflict = partners.length > 0 ? ` conflict=${partners.join(',')}` : '';
        rowLines.push(`  ${i + 1} ${id} tier=${fact.tier} label=${label} stage=${stage} badge=${badge} freshness=${freshness} citable=${citable}${conflict}`);
        const tags = fact.tags.length > 0 ? ` tags:[${fact.tags.join(',')}]` : '';
        rendered.push(`[${badge}] [${label}/${stage}] [${freshness}] (${id}) ${fact.claim}${tags}`);
        if (fact.note) rendered.push(`  note: ${fact.note}`);
        if (fact.expected === 'retracted' && fact.retractionReason) rendered.push(`  retracted: ${fact.retractionReason}`);
        if (partners.length > 0) rendered.push(`  conflict: cannot hold together with ${partners.join(', ')}`);
        const rule = historical ? HISTORICAL_RULE[fact.expected] : !fresh ? NOT_CITED_RULE : RULES_FOR_BADGE[badge][0];
        rendered.push(`  rule: ${rule}`);
      });
      rendered.push(END);
      lines.push(`  status=${status} fenced=true`, ...rowLines, ...rendered.map((l) => `  > ${l}`));
    }
    const parsed = parseGateText(lines.join('\n')).get(c.id);
    lines.push(`  verdict=${judgeCase(c, parsed) ? 'pass' : 'FAIL'}`);
    blocks.push({ id: c.id, lines });
  }
  for (const a of ANSWERS) {
    const outcome = ANSWER_OUTCOMES[a.id];
    if (!outcome) throw new Error(`ANSWER_OUTCOMES has no entry for ${a.id}`);
    const lines = [`answer ${a.id} expect=${a.ok ? 'ok' : 'fail'}`];
    for (const p of outcome.problems) lines.push(`  problem ${p}`);
    lines.push(`  result=${a.ok ? 'ok' : 'fail'} ${outcome.stats}`, '  verdict=pass');
    blocks.push({ id: `answer:${a.id}`, lines });
  }
  return blocks;
}

/** Split gate text into blocks at `case ` and `answer ` headers; text before the first is a block too. */
function splitBlocks(text) {
  const blocks = [];
  let cur = { lines: [] };
  for (const line of text.replace(/\n$/, '').split('\n')) {
    if (/^(case|answer) /.test(line) && cur.lines.length > 0) {
      blocks.push(cur);
      cur = { lines: [] };
    }
    cur.lines.push(line);
  }
  if (cur.lines.length > 0) blocks.push(cur);
  return blocks;
}

/**
 * Which row a case may label `match`, decided from the case definition alone (A-28 item 14):
 * only its target, only in cases built to find it (groups A and D, and the E traps whose fact
 * is the answer), and only at the stage the query kind implies (id, tag or path lookups are
 * `exact`; text is `lexical`). Every other row must be `related`, so it can never be citable.
 */
const MATCHING_TRAPS = new Set(['data-not-instruction', 'expired']);
function allowedMatch(c) {
  if (!c) return null;
  const expects = c.group === 'A' || c.group === 'D' || c.group === 'H' || (c.group === 'E' && MATCHING_TRAPS.has(c.trap));
  if (!expects || !c.target) return null;
  return { ids: [c.target, ...(c.alsoMatch ?? [])], stage: c.query.text !== undefined ? 'lexical' : 'exact' };
}

/**
 * Safety rules that hold for every row of every case, whatever the group (Step Zero 5 rule 3,
 * 10.1): only a fresh `match` may be citable, `VERIFIED` only for `checked` facts, `ASSERTED`
 * only for `asserted` facts, and the rendered text is exactly what the rows and the fixture's
 * own facts (claim, note, tags, retraction reason) produce, inside the fence, with nothing extra.
 */
export function rowsAreSafe(parsed, c) {
  const rendered = parsed.rendered ?? [];
  const match = allowedMatch(c);
  if (parsed.status === 'not_found') {
    return parsed.rows.length === 0 && rendered.length === 2 &&
      rendered[0] === 'status: not_found' && rendered[1] === NOT_FOUND_GUIDANCE;
  }
  // The case status follows from the rows: not_found exactly when there are none, otherwise
  // `match` exactly when a match row is present.
  if (parsed.rows.length === 0) return false;
  const hasMatch = parsed.rows.some((r) => r.label === 'match');
  if (parsed.status !== (hasMatch ? 'match' : 'related')) return false;
  // Eligibility: a row must be retrievable by this case at all. Its sensitivity is within the
  // case's cap, and a superseded or retracted fact appears only when the case asks for history.
  const cap = SENSITIVITY_RANK[c?.query?.maxSensitivity ?? 'child'];
  for (const r of parsed.rows) {
    const fact = CATALOG.get(r.id);
    if (!fact || !(SENSITIVITY_RANK[fact.sensitivity] <= cap)) return false;
    if ((fact.expected === 'superseded' || fact.expected === 'retracted') && !c?.query?.history) return false;
    if (r.conflict && (r.conflict.length === 0 || r.conflict.some((id) => id === ''))) return false;
  }
  // Conflict flags come from the fixture's declared pairs: a row lists exactly its declared
  // partners that are also shown in this case, in the order they are shown.
  const shown = parsed.rows.map((r) => r.id);
  for (const r of parsed.rows) {
    const partners = (CATALOG.get(r.id)?.conflictsWith ?? []).filter((id) => shown.includes(id));
    partners.sort((a, b) => shown.indexOf(a) - shown.indexOf(b));
    if ((r.conflict ?? []).join(',') !== partners.join(',')) return false;
  }
  // Rebuilt line by line; only the rule line may vary, within the badge's allowlist.
  const want = [`status: ${parsed.status} (${parsed.rows.length} result(s))`, BEGIN];
  const ruleAt = new Map();
  for (const r of parsed.rows) {
    const verified = r.badge === 'VERIFIED';
    const asserted = r.badge === 'ASSERTED';
    if (verified && r.tier !== 'checked') return false;
    if (asserted && r.tier !== 'asserted') return false;
    if (r.citable === 'true') {
      if (r.label !== 'match' || !FRESH.has(r.freshness) || !(verified || asserted)) return false;
    } else if (verified || asserted) {
      return false;
    }
    if (r.label === 'related' && (r.citable !== 'false' || verified || asserted)) return false;
    if (NOT_CITABLE_FRESHNESS.has(r.freshness) && r.citable !== 'false') return false;
    if (r.label === 'match' && (!match || !match.ids.includes(r.id) || r.stage !== match.stage)) return false;
    if (r.label !== 'match' && r.label !== 'related') return false;
    const fact = CATALOG.get(r.id);
    if (!fact || !RULES_FOR_BADGE[r.badge]) return false;
    // The row's tier must be the fixture's own tier, and VERIFIED needs a checked fact whose
    // claim is the canonical form of its predicate (never free text).
    if (r.tier !== fact.tier) return false;
    // Freshness and lifecycle come from the fixture's declared design, not from the snapshot,
    // and the badge must be the one that freshness implies.
    if (isHistorical(fact)) {
      if (r.badge !== fact.expected.toUpperCase() || r.freshness !== HISTORICAL_FRESHNESS || r.citable !== 'false') return false;
    } else {
      if (!fact.expected || r.freshness !== fact.expected) return false;
      const badgeFor = { stale: ['STALE'], expired: ['EXPIRED'], unverifiable: ['UNVERIFIABLE'] }[r.freshness] ??
        (fact.tier === 'checked' ? ['VERIFIED', 'RELATED'] : ['ASSERTED', 'RELATED']);
      if (!badgeFor.includes(r.badge)) return false;
    }
    if (verified && (fact.tier !== 'checked' || !fact.check || fact.claim !== formatCheckedPredicateClaim(fact.check))) return false;
    const tags = fact.tags.length > 0 ? ` tags:[${fact.tags.join(',')}]` : '';
    want.push(`[${r.badge}] [${r.label}/${r.stage}] [${r.freshness}] (${r.id}) ${fact.claim}${tags}`);
    if (fact.note) want.push(`  note: ${fact.note}`);
    if (r.badge === 'RETRACTED' && fact.retractionReason) want.push(`  retracted: ${fact.retractionReason}`);
    if (r.conflict) want.push(`  conflict: cannot hold together with ${r.conflict.join(', ')}`);
    ruleAt.set(want.length, RULES_FOR_BADGE[r.badge]);
    want.push(null);
  }
  want.push(END);
  if (rendered.length !== want.length) return false;
  for (let i = 0; i < want.length; i++) {
    if (want[i] !== null) {
      if (rendered[i] !== want[i]) return false;
    } else if (!rendered[i].startsWith('  rule: ') || !ruleAt.get(i).includes(rendered[i].slice('  rule: '.length))) {
      return false;
    }
  }
  return true;
}

/** Apply the safety rules and then the group rule to one case's parsed result lines. */
export function judgeCase(c, parsed) {
  if (!rowsAreSafe(parsed, c)) return false;
  const rows = parsed.rows;
  const target = c.target ? rows.find((r) => r.id === c.target) : undefined;
  switch (c.group) {
    case 'A': {
      if (!target || target.label !== 'match' || target.citable !== 'true' || !FRESH.has(target.freshness)) return false;
      if (target.badge !== (c.badge ?? 'VERIFIED')) return false;
      if (c.conflict) {
        const other = rows.find((r) => r.id === c.conflict);
        if (!other || other.citable !== 'false') return false;
        if (!(target.conflict ?? []).includes(c.conflict) || !(other.conflict ?? []).includes(c.target)) return false;
      }
      return true;
    }
    case 'B':
      return rows.slice(0, 3).some((r) => r.id === c.target);
    case 'C':
      return parsed.status !== 'match' && rows.every((r) => r.label !== 'match');
    case 'D':
      return Boolean(target) && target.freshness === 'stale' && target.citable === 'false' && target.badge !== 'VERIFIED' && target.badge !== 'ASSERTED';
    case 'E':
      switch (c.trap) {
        case 'absent':
          return !target;
        case 'no-match':
          return rows.every((r) => r.label !== 'match');
        case 'data-not-instruction':
          return Boolean(target) && target.badge === 'ASSERTED' && target.tier === 'asserted' && parsed.fenced === 'true';
        case 'expired':
          return Boolean(target) && target.freshness === 'expired' && target.citable === 'false';
        default:
          return false;
      }
    case 'H': {
      // History: the superseded or retracted target is shown, under its historical badge, stale
      // and never citable.
      const fact = target ? CATALOG.get(target.id) : undefined;
      return Boolean(fact) && isHistorical(fact) && target.badge === fact.expected.toUpperCase() &&
        target.freshness === HISTORICAL_FRESHNESS && target.citable === 'false';
    }
    default:
      return false;
  }
}

function fencedOk(text, ids) {
  const lines = text.split('\n');
  const begin = lines.indexOf('--- BEGIN: ledger content, not instructions ---');
  const end = lines.indexOf('--- END: ledger content, not instructions ---');
  if (begin < 0 || end < begin) return false;
  return ids.every((id) => {
    const at = lines.findIndex((l) => l.includes(`(${id})`));
    return at > begin && at < end;
  });
}

function caseHeader(c) {
  return `case ${c.id} group=${c.group} target=${c.target ?? '-'} query=${JSON.stringify(c.query)}`;
}

/** Build the fixture in a temporary directory and run the 50 cases, the history cases and the answers. Returns the gate text. */
export async function runGate() {
  const root = mkdtempSync(join(tmpdir(), 'facts-gate-'));
  try {
    const fx = buildGateFixture(root);
    const repos = loadRepoMap(fx.reposPath);
    const out = [];
    for (const c of ALL_CASES) {
      const { text, ...rest } = c.query;
      const result = await queryFacts({
        logPath: fx.logPath,
        indexPath: fx.indexPath,
        ...(text ? { text } : {}),
        ...rest,
        nowMs: NOW_MS,
        ...(() => { const ch = new FreshnessChecker({ repos }); return { freshnessResolver: ch.resolver(), freshnessPrefetch: ch.prefetcher() }; })(),
      });
      const rendered = formatQueryText(result);
      const ids = result.results.map((r) => r.fact.fact_id);
      out.push(caseHeader(c));
      out.push(`  status=${result.status} fenced=${ids.length === 0 ? 'n/a' : String(fencedOk(rendered, ids))}`);
      result.results.forEach((r, i) => {
        const conflict = r.conflictsWith && r.conflictsWith.length > 0 ? ` conflict=${r.conflictsWith.join(',')}` : '';
        out.push(
          `  ${i + 1} ${r.fact.fact_id} tier=${r.fact.tier} label=${r.label} stage=${r.stage} badge=${r.badge} freshness=${r.freshness} citable=${r.citable}${conflict}`,
        );
      });
      // The exact text an agent reads is part of the snapshot.
      for (const line of rendered.split('\n')) out.push(`  > ${line}`);
      const parsed = parseGateText(out.slice(out.lastIndexOf(caseHeader(c))).join('\n')).get(c.id);
      out.push(`  verdict=${judgeCase(c, parsed) ? 'pass' : 'FAIL'}`);
    }
    // Step Zero 10.2: the citation checker over 20 fixture answers.
    for (const a of ANSWERS) {
      const result = await checkAnswer(a.text, {
        logPath: fx.logPath,
        indexPath: fx.indexPath,
        repos,
        nowMs: NOW_MS,
        ...(a.maxSensitivity ? { maxSensitivity: a.maxSensitivity } : {}),
      });
      out.push(`answer ${a.id} expect=${a.ok ? 'ok' : 'fail'}`);
      for (const p of result.problems) out.push(`  problem line=${p.line} ${p.problem}`);
      out.push(`  result=${result.ok ? 'ok' : 'fail'} statements=${result.statements} citations=${result.citations} abstentions=${result.abstentions}`);
      out.push(`  verdict=${result.ok === a.ok ? 'pass' : 'FAIL'}`);
    }
    return `${out.join('\n')}\n`;
  } finally {
    rmSync(root, { recursive: true, force: true, maxRetries: 5 });
  }
}

/** Parse gate text into case id -> { status, fenced, rows, verdict }. */
export function parseGateText(text) {
  const cases = new Map();
  let current;
  for (const line of text.split('\n')) {
    let m = /^answer (\S+) expect=/.exec(line);
    if (m) {
      current = { status: undefined, fenced: undefined, rows: [], rendered: [], verdict: undefined, result: undefined };
      cases.set(`answer:${m[1]}`, current);
      continue;
    }
    m = /^case (\S+) group=/.exec(line);
    if (m) {
      current = { status: undefined, fenced: undefined, rows: [], rendered: [], verdict: undefined };
      cases.set(m[1], current);
      continue;
    }
    if (!current) continue;
    if ((m = /^ {2}> (.*)$/.exec(line))) {
      current.rendered.push(m[1]);
    } else if ((m = /^ {2}status=(\S+) fenced=(\S+)$/.exec(line))) {
      current.status = m[1];
      current.fenced = m[2];
    } else if ((m = /^ {2}result=(ok|fail) /.exec(line))) {
      current.result = m[1];
    } else if ((m = /^ {2}verdict=(\S+)$/.exec(line))) {
      current.verdict = m[1];
    } else if ((m = /^ {2}\d+ (\S+) (.*)$/.exec(line))) {
      const row = { id: m[1] };
      for (const pair of m[2].split(' ')) {
        const eq = pair.indexOf('=');
        const key = pair.slice(0, eq);
        const value = pair.slice(eq + 1);
        row[key] = key === 'conflict' ? value.split(',') : value;
      }
      current.rows.push(row);
    }
  }
  return cases;
}

/** Step Zero 10.1 thresholds, computed from gate text (live run or the committed file). */
export function gateScore(text) {
  const parsed = parseGateText(text);
  const score = { A: 0, B: 0, C_falseMatch: 0, D: 0, E: 0, missing: [], unsafe: [] };
  const unsafe = (id) => {
    if (!score.unsafe.includes(id)) score.unsafe.push(id);
  };
  // The text must equal the oracle block for block: the 50 case blocks, the history case blocks, then the 20 answer blocks,
  // in order, each line as declared. Extra, missing, duplicated or reordered blocks all fail.
  const oracle = oracleBlocks();
  const got = splitBlocks(text);
  oracle.forEach((o, i) => {
    if (!got[i] || got[i].lines.join('\n') !== o.lines.join('\n')) unsafe(o.id);
  });
  if (got.length !== oracle.length) unsafe(`blocks:${got.length}/${oracle.length}`);
  for (const c of CASES) {
    const p = parsed.get(c.id);
    if (!p) {
      score.missing.push(c.id);
      continue;
    }
    // Safety is mandatory for all 50 cases; group B's 9-of-10 allowance covers safe retrieval misses only.
    if (!rowsAreSafe(p, c)) unsafe(c.id);
    const ok = judgeCase(c, p);
    if (c.group === 'C') {
      if (!ok) score.C_falseMatch++;
    } else if (ok) {
      score[c.group]++;
    }
  }
  // History cases (A-28 item 16): outside the 10.1 thresholds, but each must be safe and pass.
  score.H = 0;
  for (const c of HISTORY_CASES) {
    const p = parsed.get(c.id);
    if (!p) {
      score.missing.push(c.id);
      continue;
    }
    if (!rowsAreSafe(p, c)) unsafe(c.id);
    if (judgeCase(c, p)) score.H++;
  }
  score.answers = 0;
  for (const a of ANSWERS) {
    const p = parsed.get(`answer:${a.id}`);
    if (!p) score.missing.push(`answer:${a.id}`);
    else if (p.result === (a.ok ? 'ok' : 'fail')) score.answers++;
  }
  score.meetsThresholds =
    score.missing.length === 0 &&
    score.unsafe.length === 0 &&
    score.H === HISTORY_CASES.length &&
    score.A === 15 &&
    score.B >= 9 &&
    score.C_falseMatch === 0 &&
    score.D === 5 &&
    score.E === 5 &&
    score.answers === ANSWERS.length;
  return score;
}

const quote = (s) => `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

/**
 * Compare a gate run with the committed declarations and return paste-ready replacement lines,
 * in the exact format of cases.mjs and answers.mjs, for every entry that differs (A-28 item 16).
 * Only rows (id, label, stage) and answer outcomes are proposed. Fact states, conflict pairs and
 * sensitivity are never proposed: they stay hand-written so citability stays independent of the
 * code under test. Returns { caseRows: string[], answerOutcomes: string[] }.
 */
export function proposedDeclarations(text) {
  const parsed = parseGateText(text);
  const caseRows = [];
  for (const c of ALL_CASES) {
    const p = parsed.get(c.id);
    if (!p) continue;
    const rows = p.rows.map((r) => [r.id, r.label, r.stage]);
    if (JSON.stringify(rows) !== JSON.stringify(CASE_ROWS[c.id])) {
      caseRows.push(`  ${c.id}: [${rows.map((r) => `[${r.map(quote).join(', ')}]`).join(', ')}],`);
    }
  }
  const answerOutcomes = [];
  const blocks = splitBlocks(text);
  for (const a of ANSWERS) {
    const block = blocks.find((b) => b.lines[0].startsWith(`answer ${a.id} `));
    if (!block) continue;
    const problems = block.lines.filter((l) => l.startsWith('  problem ')).map((l) => l.slice('  problem '.length));
    const stats = (block.lines.find((l) => l.startsWith('  result=')) ?? '').replace(/^ {2}result=\S+ /, '');
    const want = ANSWER_OUTCOMES[a.id];
    if (!want || JSON.stringify(problems) !== JSON.stringify(want.problems) || stats !== want.stats) {
      answerOutcomes.push(`  ${a.id}: { problems: [${problems.map(quote).join(', ')}], stats: ${quote(stats)} },`);
    }
  }
  return { caseRows, answerOutcomes };
}

/** Print the declaration lines a reviewer would paste after accepting a behaviour change. */
function reportDeclarations(text) {
  const { caseRows, answerOutcomes } = proposedDeclarations(text);
  if (caseRows.length === 0 && answerOutcomes.length === 0) return false;
  let out = '\nThis run differs from the committed declarations. If the change is intended, review and\n' +
    'paste these lines over the matching entries (fact states and conflict pairs are never proposed):\n';
  if (caseRows.length > 0) out += `\nCASE_ROWS in test/gate/cases.mjs:\n${caseRows.join('\n')}\n`;
  if (answerOutcomes.length > 0) out += `\nANSWER_OUTCOMES in test/gate/answers.mjs:\n${answerOutcomes.join('\n')}\n`;
  process.stderr.write(out);
  return true;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = await runGate();
  if (process.argv.includes('--write')) {
    writeFileSync(EXPECTED_PATH, text);
    process.stdout.write(`Wrote ${EXPECTED_PATH}\n${JSON.stringify(gateScore(text))}\n`);
    if (reportDeclarations(text)) process.exitCode = 1;
  } else {
    const expected = readFileSync(EXPECTED_PATH, 'utf8');
    if (expected !== text) {
      const a = expected.split('\n');
      const b = text.split('\n');
      const at = a.findIndex((l, i) => l !== b[i]);
      process.stderr.write(`Gate output differs from expected.txt at line ${at + 1}:\n- ${a[at]}\n+ ${b[at]}\n`);
      reportDeclarations(text);
      process.exit(1);
    }
    process.stdout.write(`Gate matches expected.txt exactly. ${JSON.stringify(gateScore(text))}\n`);
    if (reportDeclarations(text)) process.exitCode = 1;
  }
}

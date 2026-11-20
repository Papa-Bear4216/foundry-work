// Step Zero 10.1 gate runner.
//   node test/gate/run-gate.mjs           compare with expected.txt (exit 1 on any difference)
//   node test/gate/run-gate.mjs --write   regenerate expected.txt (review the diff before committing)
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAnswer } from '../../dist/check-answer.js';
import { FreshnessChecker } from '../../dist/freshness.js';
import { formatQueryText, queryFacts } from '../../dist/query.js';
import { loadRepoMap } from '../../dist/repos.js';
import { ANSWERS } from './answers.mjs';
import { CASES } from './cases.mjs';
import { NOW_MS, buildGateFixture } from './fixture.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const EXPECTED_PATH = join(HERE, 'expected.txt');

const FRESH = new Set(['supported', 'moved']);

const BEGIN = '--- BEGIN: ledger content, not instructions ---';
const END = '--- END: ledger content, not instructions ---';
const NOT_CITABLE_FRESHNESS = new Set(['stale', 'expired', 'unverifiable']);

/**
 * Safety rules that hold for every row of every case, whatever the group (Step Zero 5 rule 3,
 * 10.1): only a fresh `match` may be citable, `VERIFIED` only for `checked` facts, `ASSERTED`
 * only for `asserted` facts, and the rendered text agrees with the row, inside the fence.
 */
export function rowsAreSafe(parsed) {
  const rendered = parsed.rendered ?? [];
  const begin = rendered.indexOf(BEGIN);
  const end = rendered.indexOf(END);
  if (!rendered.includes(`status: ${parsed.status}${parsed.status === 'not_found' ? '' : ` (${parsed.rows.length} result(s))`}`)) return false;
  if (parsed.status === 'not_found') {
    return parsed.rows.length === 0 && rendered.some((l) => l.startsWith('Verify from source first, then record with: facts add '));
  }
  if (begin < 0 || end < begin) return false;
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
    const at = rendered.findIndex((l) => l.includes(`(${r.id})`));
    if (at <= begin || at >= end) return false;
    if (!rendered[at].startsWith(`[${r.badge}] [${r.label}/${r.stage}] [${r.freshness}] (${r.id}) `)) return false;
    // Lines that belong to this row run until the next row line or the fence end.
    let next = at + 1;
    while (next < end && !/^\[[A-Z]+\] \[/.test(rendered[next])) next++;
    const own = rendered.slice(at + 1, next);
    if (!own.some((l) => l.startsWith('  rule: '))) return false;
    const conflictLine = own.find((l) => l.startsWith('  conflict: cannot hold together with '));
    if (r.conflict) {
      if (!conflictLine || conflictLine !== `  conflict: cannot hold together with ${r.conflict.join(', ')}`) return false;
    } else if (conflictLine) {
      return false;
    }
  }
  return true;
}

/** Apply the safety rules and then the group rule to one case's parsed result lines. */
export function judgeCase(c, parsed) {
  if (!rowsAreSafe(parsed)) return false;
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

/** Build the fixture in a temporary directory and run all 50 cases. Returns the gate text. */
export async function runGate() {
  const root = mkdtempSync(join(tmpdir(), 'facts-gate-'));
  try {
    const fx = buildGateFixture(root);
    const repos = loadRepoMap(fx.reposPath);
    const out = [];
    for (const c of CASES) {
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
  const score = { A: 0, B: 0, C_falseMatch: 0, D: 0, E: 0, missing: [] };
  for (const c of CASES) {
    const p = parsed.get(c.id);
    if (!p) {
      score.missing.push(c.id);
      continue;
    }
    const ok = judgeCase(c, p);
    if (c.group === 'C') {
      if (!ok) score.C_falseMatch++;
    } else if (ok) {
      score[c.group]++;
    }
  }
  score.answers = 0;
  for (const a of ANSWERS) {
    const p = parsed.get(`answer:${a.id}`);
    if (!p) score.missing.push(`answer:${a.id}`);
    else if (p.result === (a.ok ? 'ok' : 'fail')) score.answers++;
  }
  score.meetsThresholds =
    score.missing.length === 0 &&
    score.A === 15 &&
    score.B >= 9 &&
    score.C_falseMatch === 0 &&
    score.D === 5 &&
    score.E === 5 &&
    score.answers === ANSWERS.length;
  return score;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const text = await runGate();
  if (process.argv.includes('--write')) {
    writeFileSync(EXPECTED_PATH, text);
    process.stdout.write(`Wrote ${EXPECTED_PATH}\n${JSON.stringify(gateScore(text))}\n`);
  } else {
    const expected = readFileSync(EXPECTED_PATH, 'utf8');
    if (expected !== text) {
      const a = expected.split('\n');
      const b = text.split('\n');
      const at = a.findIndex((l, i) => l !== b[i]);
      process.stderr.write(`Gate output differs from expected.txt at line ${at + 1}:\n- ${a[at]}\n+ ${b[at]}\n`);
      process.exit(1);
    }
    process.stdout.write(`Gate matches expected.txt exactly. ${JSON.stringify(gateScore(text))}\n`);
  }
}

// Step Zero 10.1 and 10.2: the deterministic gate. The live run must equal the committed
// expected file byte for byte, and the expected file itself must meet the thresholds.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { FreshnessChecker } from '../dist/freshness.js';
import { queryFacts } from '../dist/query.js';
import { loadRepoMap } from '../dist/repos.js';
import { ANSWERS } from './gate/answers.mjs';
import { CASES } from './gate/cases.mjs';
import { NOW_MS, buildGateFixture } from './gate/fixture.mjs';
import { EXPECTED_PATH, gateScore, judgeCase, parseGateText, runGate } from './gate/run-gate.mjs';

const cliPath = new URL('../dist/cli.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

test('gate: live run matches the committed expected output exactly', async () => {
  const live = await runGate();
  const expected = readFileSync(EXPECTED_PATH, 'utf8');
  assert.ok(!expected.includes('\r'), 'expected.txt must be LF only (see .gitattributes)');
  assert.equal(live, expected);
});

test('gate: the committed expected file meets the Step Zero 10.1 thresholds on its own', () => {
  const expected = readFileSync(EXPECTED_PATH, 'utf8');
  const score = gateScore(expected);
  assert.deepEqual(score.missing, []);
  assert.equal(score.A, 15);
  assert.ok(score.B >= 9, `group B ${score.B}/10`);
  assert.equal(score.C_falseMatch, 0);
  assert.equal(score.D, 5);
  assert.equal(score.E, 5);
  assert.equal(score.answers, 20);
  // Printed verdicts agree with an independent re-judgement of the printed rows.
  const parsed = parseGateText(expected);
  for (const c of CASES) {
    const p = parsed.get(c.id);
    assert.equal(p.verdict, judgeCase(c, p) ? 'pass' : 'FAIL', c.id);
  }
  for (const a of ANSWERS) {
    assert.equal(parsed.get(`answer:${a.id}`).verdict, 'pass', a.id);
  }
});

test('gate: controls prove the trap cases are not vacuous', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'facts-gate-ctl-'));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const fx = buildGateFixture(root);
  const repos = loadRepoMap(fx.reposPath);
  const q = (opts) =>
    queryFacts({ logPath: fx.logPath, indexPath: fx.indexPath, nowMs: NOW_MS, freshnessResolver: new FreshnessChecker({ repos }).resolver(), ...opts });
  // C10: without the sensitivity cap the private fact is a match.
  const uncapped = await q({ text: 'partner profile encryption key' });
  assert.ok(uncapped.results.some((r) => r.fact.fact_id === 'a30000000003.4' && r.label === 'match'));
  // E01/E02: with --history the superseded and retracted facts are there.
  const sup = await q({ text: 'sync runs every ten minutes', history: true });
  assert.ok(sup.results.some((r) => r.fact.fact_id === 'a30000000003.0' && !r.citable));
  const ret = await q({ text: 'importer reads facebook archives', history: true });
  assert.ok(ret.results.some((r) => r.fact.fact_id === 'a30000000003.1' && !r.citable));
  // Group D facts held at the first commit: the evidence pins it.
  for (const n of [0, 1, 2, 3, 4]) {
    const r = await q({ id: `a20000000002.${n}` });
    assert.equal(r.results[0].fact.evidence[0].commit, fx.c1);
  }
  // The fixture's commits are the same on every platform.
  assert.equal(fx.c1, readFixtureShas().c1);
  assert.equal(fx.c2, readFixtureShas().c2);
});

function readFixtureShas() {
  return JSON.parse(readFileSync(new URL('./gate/fixture-shas.json', import.meta.url), 'utf8'));
}

test('check-answer CLI: exit 0 for a good answer, 1 for a bad one', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'facts-gate-cli-'));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const fx = buildGateFixture(root);
  const env = { ...process.env, FACTS_LEDGER_REPOS: fx.reposPath };
  const good = join(root, 'good.txt');
  const bad = join(root, 'bad.txt');
  writeFileSync(good, 'The KDF is scrypt. [fact:a10000000001.4]\n');
  writeFileSync(bad, 'The KDF is scrypt.\n');
  const run = (file) => spawnSync(process.execPath, [cliPath, 'check-answer', file, '--log', fx.logPath, '--index', fx.indexPath], { env, encoding: 'utf8' });
  const ok = run(good);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /check-answer: ok/);
  const ko = run(bad);
  assert.equal(ko.status, 1);
  assert.match(ko.stdout, /line 1: statement without a citation/);
});

test('verify output written in pieces is byte-identical to the whole-string formats', async (t) => {
  const { verifyFacts, verifyOutputChunks, formatVerifyText } = await import('../dist/verify.js');
  const root = mkdtempSync(join(tmpdir(), 'facts-gate-verify-'));
  t.after(() => rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  const fx = buildGateFixture(root);
  const repos = loadRepoMap(fx.reposPath);
  for (const writeAs of [undefined, 'gate-verify']) {
    const result = verifyFacts({ logPath: fx.logPath, indexPath: fx.indexPath, repos, all: true, nowMs: NOW_MS, ...(writeAs ? { writeAs } : {}) });
    if (writeAs) assert.ok(result.written.length > 0, 'the stale group D facts are retracted in a written block');
    assert.equal([...verifyOutputChunks(result, true)].join(''), JSON.stringify(result));
    assert.equal([...verifyOutputChunks(result, false)].join(''), formatVerifyText(result));
  }
});

// Step Zero 10.3 & 8: tests for `facts eval` and `facts usage`.
// All model tests use local fake model scripts via `process.execPath` (zero network, zero API calls).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { MAX_ANSWER_BYTES, MAX_STORED_PROBLEMS } from '../dist/check-answer.js';
import { CASES } from '../dist/eval/cases.js';
import { gateFactCatalog } from '../dist/eval/fixture.js';
import { AGENT_RULES_TEXT } from '../dist/eval/prompt.js';
import {
  MAX_ABSTAIN_PAYLOAD_BYTES,
  buildModelChildEnv,
  estimateTokens,
  matchesAnswerSpec,
  runEval,
  runEvalDryRun,
  runModelCommand,
  stripFixturePaths,
} from '../dist/eval/runner.js';
import { MAX_LINE_BYTES, appendBlock, scanLog } from '../dist/log.js';
import { computeUsage, formatUsageText } from '../dist/usage.js';
import { CASE_ROWS } from './gate/cases.mjs';

const cliPath = new URL('../dist/cli.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

function runCli(args, env = process.env) {
  return spawnSync(process.execPath, [cliPath, ...args], {
    env,
    encoding: 'utf8',
    windowsHide: true,
  });
}

function writeFakeModel(dir, name, body) {
  const path = join(dir, name);
  writeFileSync(path, body, 'utf8');
  return path;
}

function questionHash(question) {
  return createHash('sha256').update(question.trim()).digest('hex');
}

/** Build a test-only answer map keyed by SHA-256 of the question text (never case IDs, F2). */
function buildQuestionAnswerMap(catalog, overrides = {}) {
  const map = {};
  for (const c of CASES) {
    const key = questionHash(c.question);
    if (Object.prototype.hasOwnProperty.call(overrides, c.id)) {
      map[key] = overrides[c.id];
      continue;
    }
    if ('cite' in c.expect) {
      const entry = catalog.get(c.expect.cite);
      const text = entry?.note ? `${entry.claim} ${entry.note}` : (entry?.claim ?? '');
      map[key] = `${text} [${c.expect.as}:${c.expect.cite}]\n`;
    } else if (c.expect.orCite && c.expect.orCite.length > 0 && (c.id === 'E01' || c.id === 'E03' || c.id === 'E04')) {
      const opt = c.expect.orCite[0];
      const entry = catalog.get(opt.id);
      const text = entry?.note ? `${entry.claim} ${entry.note}` : (entry?.claim ?? '');
      map[key] = `${text} [${opt.as}:${opt.id}]\n`;
    } else {
      map[key] = 'ABSTAIN: no current citable fact answers this question.\n';
    }
  }
  return map;
}

const QUESTION_HASH_MODEL_BODY = [
  "import { createHash } from 'node:crypto';",
  "import { readFileSync } from 'node:fs';",
  'const answers = JSON.parse(readFileSync(process.argv[2], "utf8"));',
  'const prompt = readFileSync(0, "utf8");',
  'const m = /=== Question ===\\r?\\n([\\s\\S]+)$/.exec(prompt);',
  'const key = m ? createHash("sha256").update(m[1].trim()).digest("hex") : "";',
  'if (!key || !answers[key]) process.exit(2);',
  'process.stdout.write(answers[key]);',
].join('\n');

test('eval cases (F1/F3): 50 cases have valid, unique answer patterns matching fixture facts and rejecting other lookup claims', () => {
  assert.equal(CASES.length, 50);
  const catalog = gateFactCatalog();
  const seenQuestions = new Set();

  for (const c of CASES) {
    assert.equal(typeof c.question, 'string');
    assert.ok(c.question.trim().length > 10, `${c.id} has a real question`);
    assert.ok(!seenQuestions.has(c.question), `${c.id} has a unique question`);
    seenQuestions.add(c.question);

    const lookupIds = (CASE_ROWS[c.id] ?? []).map(([id]) => id);

    const checkSpecAgainstFixture = (label, factId, spec) => {
      assert.ok(Array.isArray(spec.answer) && spec.answer.length > 0, `${label} has answer patterns`);
      const entry = catalog.get(factId);
      assert.ok(entry, `${label} fact ${factId} exists in fixture catalog`);
      const ownText = entry.note ? `${entry.claim} ${entry.note}` : entry.claim;
      assert.ok(
        matchesAnswerSpec(ownText, spec),
        `${label}: own fixture claim/note "${ownText}" must satisfy answer/mustNot patterns`,
      );
      if (spec.mustNot) {
        for (const forbidden of spec.mustNot) {
          assert.ok(
            !new RegExp(forbidden, 'i').test(ownText),
            `${label}: mustNot /${forbidden}/i must not match own fixture text`,
          );
        }
      }
      // Pattern set must NOT match any other fact's claim shown in the same case's lookup.
      for (const otherId of lookupIds) {
        if (otherId === factId) continue;
        const other = catalog.get(otherId);
        assert.ok(other, `${label}: lookup fact ${otherId} exists`);
        assert.ok(
          !matchesAnswerSpec(other.claim, spec),
          `${label}: pattern set must not match other lookup fact ${otherId} claim "${other.claim}"`,
        );
      }
    };

    if (c.group === 'A' || c.group === 'B') {
      assert.ok('cite' in c.expect, `${c.id} expects cite`);
      assert.equal(c.expect.cite, c.target);
      const entry = catalog.get(c.target);
      assert.ok(entry, `${c.id} target exists in fixture catalog`);
      assert.equal(c.expect.as, entry.tier === 'asserted' ? 'asserted' : 'fact');
      checkSpecAgainstFixture(c.id, c.expect.cite, c.expect);
    } else {
      assert.ok('abstain' in c.expect && c.expect.abstain === true, `${c.id} expects abstain`);
      if (c.expect.orCite !== undefined) {
        assert.ok(Array.isArray(c.expect.orCite) && c.expect.orCite.length > 0, `${c.id} orCite is non-empty array`);
        for (const opt of c.expect.orCite) {
          const entry = catalog.get(opt.id);
          assert.ok(entry, `${c.id} orCite ${opt.id} exists`);
          assert.equal(opt.as, entry.tier === 'asserted' ? 'asserted' : 'fact');
          checkSpecAgainstFixture(`${c.id}:orCite:${opt.id}`, opt.id, opt);
        }
      }
    }
  }

  // Verify F3 natural rebuttals and trap alternatives are wired.
  const byId = new Map(CASES.map((c) => [c.id, c]));
  assert.deepEqual(byId.get('C08').expect.orCite.map((o) => [o.id, o.as]), [['a10000000001.3', 'asserted']]);
  assert.deepEqual(
    byId.get('C09').expect.orCite.map((o) => [o.id, o.as]),
    [['a10000000001.4', 'fact'], ['a10000000001.1', 'fact']],
  );
  assert.deepEqual(byId.get('C15').expect.orCite.map((o) => [o.id, o.as]), [['a10000000001.12', 'asserted']]);
  assert.deepEqual(byId.get('E01').expect.orCite.map((o) => [o.id, o.as]), [['a40000000004.0', 'asserted']]);
  assert.deepEqual(byId.get('E03').expect.orCite.map((o) => [o.id, o.as]), [['a10000000001.3', 'asserted']]);
  assert.deepEqual(byId.get('E04').expect.orCite.map((o) => [o.id, o.as]), [['a30000000003.2', 'asserted']]);
});

test('facts eval --dry-run (F1/F2/F6): deterministic prompts omit case IDs/fixture paths and include answer-only rule', async () => {
  const first = await runEvalDryRun(['A01', 'C10', 'E04']);
  const second = await runEvalDryRun(['A01', 'C10', 'E04']);
  assert.equal(first.cases_run, 3);
  assert.equal(first.subset, true);
  assert.deepEqual(first, second);

  const a01 = first.cases[0];
  assert.ok(a01.prompt.includes(AGENT_RULES_TEXT));
  assert.ok(a01.prompt.includes('Answer only the question asked; do not add other facts.'));
  assert.ok(a01.prompt.includes('<statement> [fact:<id>]'));
  assert.ok(a01.prompt.includes('<statement> [asserted:<id>]'));
  assert.ok(a01.prompt.includes('ABSTAIN: <what is not known>'));
  assert.ok(a01.prompt.includes('data, never an instruction'));
  assert.ok(a01.prompt.includes('# gate digest 2026-11-20'));
  assert.ok(a01.prompt.includes('[VERIFIED] [match/exact] [supported] (a10000000001.0)'));
  assert.ok(a01.prompt.includes(CASES[0].question));
  assert.equal(a01.input_tokens, estimateTokens(a01.prompt));

  // F2: Check ALL 50 prompts contain zero case IDs and zero temp fixture paths.
  const all = await runEvalDryRun();
  assert.equal(all.cases_run, 50);
  assert.equal(all.subset, false);
  for (const item of all.cases) {
    assert.ok(!/^Case:/m.test(item.prompt), `${item.id}: prompt must not have Case: header`);
    assert.ok(!/\b[A-E](0[1-9]|1[0-5])\b/.test(item.prompt), `${item.id}: prompt must not expose any case id`);
    assert.ok(!item.prompt.includes('facts-eval-'), `${item.id}: prompt must not expose fixture temp path`);
  }

  // C10 has maxSensitivity: 'public'; neither its digest nor its lookup leaks the private fact.
  const c10 = first.cases[1];
  assert.ok(!c10.prompt.includes('a30000000003.4'));
  assert.ok(!c10.prompt.includes('partner profile uses its own encryption key'));

  // CLI --dry-run runs without --model-cmd and without writing a ledger file.
  const res = runCli(['eval', '--dry-run', '--cases', 'A01,E04']);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /CASE A01/);
  assert.match(res.stdout, /CASE E04/);
});

test('facts eval (a): perfect model passes bar using question hashes, accepts E01/E03/E04 orCite, and appends valid block with measured=false', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-perfect-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const catalog = gateFactCatalog();
  const answersPath = join(dir, 'perfect-answers.json');
  const map = buildQuestionAnswerMap(catalog, {
    // Exercise honest answer without yes/no polarity words (F1).
    A03: 'A LICENSE file exists. [fact:a10000000001.2]\n',
  });
  writeFileSync(answersPath, JSON.stringify(map), 'utf8');

  const modelScript = writeFakeModel(dir, 'perfect-model.mjs', QUESTION_HASH_MODEL_BODY);
  const logPath = join(dir, 'ledger.jsonl');
  const res = runCli([
    'eval',
    '--model-cmd', process.execPath,
    '--model-arg', modelScript,
    '--model-arg', answersPath,
    '--model-name', 'fake-perfect-v1',
    '--project', 'foundry',
    '--agent', 'eval-tester',
    '--log', logPath,
    '--json',
  ]);
  assert.equal(res.status, 0, res.stderr);
  const report = JSON.parse(res.stdout);
  assert.equal(report.model, 'fake-perfect-v1');
  assert.equal(report.cases_run, 50);
  assert.equal(report.subset, false);
  assert.equal(report.passes_bar, true);
  assert.equal(report.passes_bar_reason, undefined);
  assert.equal(report.checker_problems, 0);
  assert.equal(report.off_target_statements, 0);
  assert.equal(report.unsupported_claims, 0);
  assert.deepEqual(report.counts, {
    correct: 25,
    wrong: 0,
    abstained_correctly: 25,
    abstained_wrongly: 0,
    unsupported: 0,
    error: 0,
  });
  assert.equal(report.token_usage.model, 'fake-perfect-v1');
  assert.equal(report.token_usage.task, 'facts-eval');
  assert.equal(report.token_usage.measured, false);
  assert.ok(report.token_usage.input > 0);
  assert.ok(report.token_usage.output > 0);
  assert.ok(report.block_id);

  // Verify the appended block's exact shape and size.
  const rawLine = readFileSync(logPath, 'utf8');
  assert.ok(Buffer.byteLength(rawLine, 'utf8') < MAX_LINE_BYTES);
  const blocks = [];
  const scan = scanLog(logPath, (b) => blocks.push(b));
  assert.equal(scan.badLineCount, 0);
  assert.equal(blocks.length, 1);
  const block = blocks[0];
  assert.equal(block.id, report.block_id);
  assert.equal(block.agent, 'eval-tester');
  assert.equal(block.project, 'foundry');
  assert.equal(block.status, 'done');
  assert.equal(block.schema, 2);
  assert.equal(block.facts, undefined);
  assert.equal(block.intent, 'facts eval: fake-perfect-v1 unsupported=0/50');
  assert.match(block.reasoning, /passes_bar=true/);
  assert.match(block.verification, /A01:correct/);
  assert.match(block.verification, /E01:abstained_correctly/);
  assert.match(block.verification, /E03:abstained_correctly/);
  assert.match(block.verification, /E04:abstained_correctly/);
  assert.deepEqual(block.token_usage, report.token_usage);
  assert.equal(block.token_usage.measured, false);
});

test('facts eval (F1): wrong value with valid target citation, extra off-target statement, and mustNot contradiction count as off_target_statements and fail bar', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-f1-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const catalog = gateFactCatalog();
  const answersPath = join(dir, 'f1-answers.json');
  const map = buildQuestionAnswerMap(catalog, {
    // Target cited with right prefix, but false value (99 instead of 7).
    A01: 'The index schema version is 99. [fact:a10000000001.0]\n',
    // Target cited correctly on line 1, plus an extra unrelated valid fact on line 2.
    A02: 'The local server listens on port 8790. [fact:a10000000001.1]\nThe index schema version is 7. [fact:a10000000001.0]\n',
    // Contradiction triggering mustNot ('removed') while citing F(9).
    A10: 'The legacy adapter module is present and was removed. [fact:a10000000001.9]\n',
    // Abstain case with a fresh unrelated citation.
    C01: 'The index schema version is 7. [fact:a10000000001.0]\n',
  });
  writeFileSync(answersPath, JSON.stringify(map), 'utf8');
  const modelScript = writeFakeModel(dir, 'f1-model.mjs', QUESTION_HASH_MODEL_BODY);

  const result = await runEval({
    modelCmd: process.execPath,
    modelArgs: [modelScript, answersPath],
    modelName: 'f1-model',
    caseIds: ['A01', 'A02', 'A10', 'C01'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(result.passes_bar, false);
  assert.equal(result.checker_problems, 0);
  assert.equal(result.off_target_statements, 4);
  assert.equal(result.unsupported_claims, 4);
  assert.deepEqual(result.counts, {
    correct: 0,
    wrong: 4,
    abstained_correctly: 0,
    abstained_wrongly: 0,
    unsupported: 0,
    error: 0,
  });
  for (const c of result.cases) {
    assert.equal(c.outcome, 'wrong', c.id);
    assert.equal(c.checker_problems, 0, c.id);
    assert.equal(c.off_target_statements, 1, c.id);
    assert.equal(c.unsupported_problems, 1, c.id);
  }
});

test('facts eval (F3): natural rebuttals in C08, C09, C15, E01, E03 pass while contradicting premises fail', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-f3-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const catalog = gateFactCatalog();
  const goodPath = join(dir, 'good-rebuttals.json');
  writeFileSync(
    goodPath,
    JSON.stringify(
      buildQuestionAnswerMap(catalog, {
        C08: 'Backups are sealed weekly onto an offline drive. [asserted:a10000000001.3]\nABSTAIN: no retention policy is recorded.\n',
        C09: 'Passphrase key derivation uses scrypt. [fact:a10000000001.4]\nThe local server listens on port 8790. [fact:a10000000001.1]\n',
        C15: 'The fixture package declares the MIT license. [asserted:a10000000001.12]\n',
        E01: 'Sync runs every fifteen minutes. [asserted:a40000000004.0]\n',
        E03: 'Backups are sealed weekly onto an offline drive. [asserted:a10000000001.3]\n',
      }),
    ),
    'utf8',
  );
  const badPath = join(dir, 'bad-rebuttals.json');
  writeFileSync(
    badPath,
    JSON.stringify(
      buildQuestionAnswerMap(catalog, {
        E01: 'Sync runs every ten minutes. [asserted:a40000000004.0]\n',
        E03: 'Backups are sealed daily onto an offline drive. [asserted:a10000000001.3]\n',
      }),
    ),
    'utf8',
  );
  const modelScript = writeFakeModel(dir, 'f3-model.mjs', QUESTION_HASH_MODEL_BODY);

  const goodRes = await runEval({
    modelCmd: process.execPath,
    modelArgs: [modelScript, goodPath],
    modelName: 'good-rebuttal',
    caseIds: ['C08', 'C09', 'C15', 'E01', 'E03'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(goodRes.counts.abstained_correctly, 5);
  assert.equal(goodRes.unsupported_claims, 0);

  const badRes = await runEval({
    modelCmd: process.execPath,
    modelArgs: [modelScript, badPath],
    modelName: 'bad-rebuttal',
    caseIds: ['E01', 'E03'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(badRes.counts.wrong, 2);
  assert.equal(badRes.off_target_statements, 2);
  assert.equal(badRes.unsupported_claims, 2);
});

test('facts eval (L1): ABSTAIN payload capped at 200 UTF-8 bytes; longer lines count as off_target_statements', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-abstain-cap-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const catalog = gateFactCatalog();
  const exactly200 = 'a'.repeat(MAX_ABSTAIN_PAYLOAD_BYTES);
  const over200 = 'a'.repeat(MAX_ABSTAIN_PAYLOAD_BYTES + 1);
  // 67 three-byte UTF-8 chars = 201 bytes (under 200 JS code units, over 200 UTF-8 bytes).
  const multibyteOver200 = '\u20ac'.repeat(67);
  const answersPath = join(dir, 'abstain-cap.json');
  writeFileSync(
    answersPath,
    JSON.stringify(
      buildQuestionAnswerMap(catalog, {
        C01: `ABSTAIN: ${exactly200}\n`,
        C02: `ABSTAIN: ${over200}\n`,
        C03: `ABSTAIN: ${multibyteOver200}\n`,
      }),
    ),
    'utf8',
  );
  const modelScript = writeFakeModel(dir, 'abstain-cap.mjs', QUESTION_HASH_MODEL_BODY);

  const res = await runEval({
    modelCmd: process.execPath,
    modelArgs: [modelScript, answersPath],
    modelName: 'abstain-cap',
    caseIds: ['C01', 'C02', 'C03'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(res.cases[0].outcome, 'abstained_correctly');
  assert.equal(res.cases[0].off_target_statements, 0);
  assert.equal(res.cases[1].outcome, 'wrong');
  assert.equal(res.cases[1].off_target_statements, 1);
  assert.equal(res.cases[2].outcome, 'wrong');
  assert.equal(res.cases[2].off_target_statements, 1);
  assert.equal(res.checker_problems, 0);
  assert.equal(res.off_target_statements, 2);
  assert.equal(res.unsupported_claims, 2);
});

test('facts eval (b): citing stale group D fact produces unsupported and fails bar', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-stale-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const modelScript = writeFakeModel(
    dir,
    'stale-model.mjs',
    [
      "import { readFileSync } from 'node:fs';",
      'readFileSync(0, "utf8");',
      'process.stdout.write("Failed uploads are retried three times. [fact:a20000000002.0]\\n");',
    ].join('\n'),
  );

  const result = await runEval({
    modelCmd: process.execPath,
    modelArgs: [modelScript],
    modelName: 'stale-citer',
    caseIds: ['D01'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(result.cases_run, 1);
  assert.equal(result.subset, true);
  assert.equal(result.block_id, null);
  assert.equal(result.passes_bar, false);
  assert.equal(result.counts.unsupported, 1);
  assert.equal(result.checker_problems, 1);
  assert.equal(result.off_target_statements, 0);
  assert.equal(result.unsupported_claims, 1);
  assert.equal(result.cases[0].outcome, 'unsupported');
  assert.match(result.cases[0].problems[0].problem, /not currently fresh \(stale\)/);
});

test('facts eval (c): uncited statement produces unsupported and counts problem lines', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-uncited-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const modelScript = writeFakeModel(
    dir,
    'uncited-model.mjs',
    [
      "import { readFileSync } from 'node:fs';",
      'readFileSync(0, "utf8");',
      'process.stdout.write("The schema version is seven.\\nThe server uses port 8790.\\n");',
    ].join('\n'),
  );

  const result = await runEval({
    modelCmd: process.execPath,
    modelArgs: [modelScript],
    modelName: 'uncited-model',
    caseIds: ['A01', 'A02'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(result.cases_run, 2);
  assert.equal(result.passes_bar, false);
  assert.equal(result.counts.unsupported, 2);
  assert.equal(result.checker_problems, 4);
  assert.equal(result.off_target_statements, 0);
  // Two uncited lines per case x 2 cases = 4 problem lines.
  assert.equal(result.unsupported_claims, 4);
});

test('facts eval (d + F4): timeout, non-zero exit, oversized stdout, and sync spawn failure (EINVAL/.cmd) are recorded as per-case error', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-err-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const exitScript = writeFakeModel(dir, 'exit-bad.mjs', 'process.exit(3);\n');
  const timeoutScript = writeFakeModel(
    dir,
    'slow-model.mjs',
    'setTimeout(() => process.stdout.write("ABSTAIN: too late.\\n"), 10000);\n',
  );
  const floodScript = writeFakeModel(
    dir,
    'flood-model.mjs',
    'process.stdout.write("x".repeat(300 * 1024));\n',
  );

  const exitRes = await runEval({
    modelCmd: process.execPath,
    modelArgs: [exitScript],
    modelName: 'exit-bad',
    caseIds: ['A01'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(exitRes.counts.error, 1);
  assert.equal(exitRes.unsupported_claims, 0);
  assert.equal(exitRes.passes_bar, false);
  assert.match(exitRes.cases[0].error, /exit code 3|did not read the whole prompt/);

  const timeoutRes = await runEval({
    modelCmd: process.execPath,
    modelArgs: [timeoutScript],
    modelName: 'slow-model',
    caseTimeoutMs: 150,
    caseIds: ['A01'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(timeoutRes.counts.error, 1);
  assert.equal(timeoutRes.passes_bar, false);
  assert.match(timeoutRes.cases[0].error, /timed out/);

  const floodRes = await runEval({
    modelCmd: process.execPath,
    modelArgs: [floodScript],
    modelName: 'flood-model',
    caseIds: ['A01'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(floodRes.counts.error, 1);
  assert.equal(floodRes.passes_bar, false);
  assert.match(floodRes.cases[0].error, /exceeded 262144 bytes/);

  // F4: Missing executable and Windows .cmd shim (synchronous EINVAL under shell: false)
  // must never abort runEval; each case is recorded as `error`.
  const missingRes = await runEval({
    modelCmd: join(dir, 'definitely-does-not-exist-exe'),
    modelName: 'missing-exe',
    caseIds: ['A01', 'A02'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(missingRes.cases_run, 2);
  assert.equal(missingRes.counts.error, 2);
  assert.equal(missingRes.passes_bar, false);
  assert.match(missingRes.cases[0].error, /could not be started/);

  if (process.platform === 'win32') {
    const cmdShim = writeFakeModel(dir, 'shim.cmd', '@echo ABSTAIN: from shim\r\n');
    const shimRes = await runEval({
      modelCmd: cmdShim,
      modelName: 'win-cmd-shim',
      caseIds: ['A01', 'A02'],
      logPath: join(dir, 'ledger.jsonl'),
      project: 'foundry',
      agent: 'eval-tester',
    });
    assert.equal(shimRes.cases_run, 2);
    assert.equal(shimRes.counts.error, 2);
    assert.equal(shimRes.passes_bar, false);
    assert.match(shimRes.cases[0].error, /could not be started \(EINVAL\)/);
  }
});

test('facts eval (F5): stdin EPIPE before prompt is fully written is recorded as error even when child exits 0 with valid answer', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-epipe-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  // Child immediately closes stdin (never reads prompt), emits a valid answer, and exits 0.
  const epipeModel = writeFakeModel(
    dir,
    'epipe-model.mjs',
    [
      "import { closeSync } from 'node:fs';",
      'try { closeSync(0); } catch {}',
      'process.stdout.write("ABSTAIN: canned answer without reading prompt.\\n");',
      'process.exit(0);',
    ].join('\n'),
  );

  // Use a 256 KiB prompt to exceed OS pipe buffers on every platform so EPIPE is deterministic.
  const hugePrompt = 'p'.repeat(256 * 1024);
  const cmdRes = await runModelCommand(process.execPath, [epipeModel], hugePrompt, 10_000);
  assert.equal(cmdRes.ok, false);
  assert.match(cmdRes.error ?? '', /did not read the whole prompt/i);
});

test('facts eval (F6): model runs in isolated empty cwd with stripped FACTS_LEDGER_* env, and fixture or result-log tampering aborts without appending', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-f6-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  // Unit check: buildModelChildEnv strips FACTS_LEDGER_* case-insensitively.
  const cleanedEnv = buildModelChildEnv({
    PATH: '/usr/bin',
    FACTS_LEDGER_LOG: '/secret/ledger.jsonl',
    facts_ledger_repos: '/secret/repos.json',
    OTHER_VAR: 'keep',
  });
  assert.equal(cleanedEnv['FACTS_LEDGER_LOG'], undefined);
  assert.equal(cleanedEnv['facts_ledger_repos'], undefined);
  assert.equal(cleanedEnv['OTHER_VAR'], 'keep');

  // Unit check: stripFixturePaths scrubs both slash styles.
  const scrubbed = stripFixturePaths('path C:\\tmp\\fx\\ledger.jsonl and C:/tmp/fx/gate', ['C:\\tmp\\fx']);
  assert.ok(!scrubbed.includes('tmp\\fx') && !scrubbed.includes('tmp/fx'));

  // Child cwd and env inspection test.
  const probeFile = join(dir, 'probe.json');
  const probeModel = writeFakeModel(
    dir,
    'probe-model.mjs',
    [
      "import { readdirSync, readFileSync, writeFileSync } from 'node:fs';",
      'readFileSync(0, "utf8");',
      'const leaked = Object.keys(process.env).filter((k) => k.toUpperCase().startsWith("FACTS_LEDGER_"));',
      'writeFileSync(process.argv[2], JSON.stringify({ cwd: process.cwd(), entries: readdirSync(process.cwd()), leaked }), "utf8");',
      'process.stdout.write("ABSTAIN: probed.\\n");',
    ].join('\n'),
  );

  const isolatedCli = runCli(
    [
      'eval',
      '--model-cmd', process.execPath,
      '--model-arg', probeModel,
      '--model-arg', probeFile,
      '--cases', 'C01',
      '--log', join(dir, 'probe-ledger.jsonl'),
      '--json',
    ],
    {
      ...process.env,
      FACTS_LEDGER_LOG: join(dir, 'real-user-ledger.jsonl'),
      FACTS_LEDGER_REPOS: join(dir, 'real-user-repos.json'),
      FACTS_LEDGER_PROJECT: 'secret-proj',
    },
  );
  assert.equal(isolatedCli.status, 0, isolatedCli.stderr);
  const probe = JSON.parse(readFileSync(probeFile, 'utf8'));
  assert.deepEqual(probe.leaked, []);
  assert.deepEqual(probe.entries, []);
  assert.ok(probe.cwd.includes('facts-eval-cwd-'), `expected isolated temp cwd, got ${probe.cwd}`);

  // Fixture tampering test: isolate TMPDIR so the malicious model deterministically finds the
  // single active `facts-eval-*` fixture directory and dirties its git repository.
  const sandboxTmp = join(dir, 'sandbox-tmp');
  mkdirSync(sandboxTmp, { recursive: true });
  const tamperFixtureModel = writeFakeModel(
    dir,
    'tamper-fixture.mjs',
    [
      "import { readdirSync, readFileSync, writeFileSync } from 'node:fs';",
      "import { join } from 'node:path';",
      'readFileSync(0, "utf8");',
      'const tmp = process.argv[2];',
      'const fxDir = readdirSync(tmp).find((n) => n.startsWith("facts-eval-") && !n.startsWith("facts-eval-cwd-"));',
      'if (fxDir) writeFileSync(join(tmp, fxDir, "gate", "tampered.txt"), "evil\\n");',
      'process.stdout.write("ABSTAIN: tampered.\\n");',
    ].join('\n'),
  );
  const tamperFixtureLog = join(dir, 'tamper-fixture-ledger.jsonl');
  const tamperFixtureRes = runCli(
    [
      'eval',
      '--model-cmd', process.execPath,
      '--model-arg', tamperFixtureModel,
      '--model-arg', sandboxTmp,
      '--cases', 'C01',
      '--log', tamperFixtureLog,
    ],
    {
      ...process.env,
      TMP: sandboxTmp,
      TEMP: sandboxTmp,
      TMPDIR: sandboxTmp,
    },
  );
  assert.equal(tamperFixtureRes.status, 1);
  assert.match(tamperFixtureRes.stderr, /Fixture integrity check failed after case C01/);
  assert.equal(existsSync(tamperFixtureLog), false, 'must not append block after fixture tamper');

  // Result-log tampering test: malicious model modifies the target result log during the run.
  const resultLogPath = join(dir, 'target-ledger.jsonl');
  const tamperLogModel = writeFakeModel(
    dir,
    'tamper-log.mjs',
    [
      "import { appendFileSync, readFileSync } from 'node:fs';",
      'readFileSync(0, "utf8");',
      'appendFileSync(process.argv[2], "{\\"forged\\":true}\\n", "utf8");',
      'process.stdout.write("ABSTAIN: forged.\\n");',
    ].join('\n'),
  );
  await assert.rejects(
    runEval({
      modelCmd: process.execPath,
      modelArgs: [tamperLogModel, resultLogPath],
      modelName: 'tamper-log-model',
      caseIds: ['C01'],
      logPath: resultLogPath,
      project: 'foundry',
      agent: 'eval-tester',
    }),
    /Result log changed during eval run/,
  );
  // Only the forged line exists; eval refused to append its own block.
  assert.equal(readFileSync(resultLogPath, 'utf8'), '{"forged":true}\n');
});

test('facts eval (F7): maximum short invalid lines keeps at most 20 problems per case with exact counts and writes block < 64 KiB', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-f7-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const linesPerCase = Math.floor(MAX_ANSWER_BYTES / 2); // 131,072 short invalid lines (262,144 bytes)
  const floodInvalidModel = writeFakeModel(
    dir,
    'invalid-flood.mjs',
    [
      "import { readFileSync } from 'node:fs';",
      'readFileSync(0, "utf8");',
      `process.stdout.write("a\\n".repeat(${linesPerCase}));`,
    ].join('\n'),
  );

  // Full 50-case run with maximum short invalid lines per case.
  const logPath = join(dir, 'ledger.jsonl');
  const res = await runEval({
    modelCmd: process.execPath,
    modelArgs: [floodInvalidModel],
    modelName: 'invalid-flood',
    logPath,
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(res.cases_run, 50);
  assert.equal(res.passes_bar, false);
  assert.equal(res.counts.unsupported, 50);
  assert.equal(res.checker_problems, 50 * linesPerCase);
  assert.equal(res.off_target_statements, 0);
  assert.equal(res.unsupported_claims, 50 * linesPerCase);
  for (const c of res.cases) {
    assert.equal(c.checker_problems, linesPerCase);
    assert.equal(c.problems.length, MAX_STORED_PROBLEMS);
  }
  assert.ok(res.block_id);
  const raw = readFileSync(logPath, 'utf8');
  assert.ok(Buffer.byteLength(raw, 'utf8') < MAX_LINE_BYTES, 'appended block must stay under 64 KiB');
});

test('facts eval (F8): passing all 50 IDs via --cases is still a selection run (passes_bar=false, reason=selection, no block appended)', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-f8-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const catalog = gateFactCatalog();
  const answersPath = join(dir, 'all50-answers.json');
  writeFileSync(answersPath, JSON.stringify(buildQuestionAnswerMap(catalog)), 'utf8');
  const modelScript = writeFakeModel(dir, 'all50-model.mjs', QUESTION_HASH_MODEL_BODY);
  const logPath = join(dir, 'ledger.jsonl');

  const res = runCli([
    'eval',
    '--model-cmd', process.execPath,
    '--model-arg', modelScript,
    '--model-arg', answersPath,
    '--cases', CASES.map((c) => c.id).join(','),
    '--log', logPath,
    '--json',
  ]);
  assert.equal(res.status, 0, res.stderr);
  const report = JSON.parse(res.stdout);
  assert.equal(report.cases_run, 50);
  assert.equal(report.subset, true);
  assert.equal(report.unsupported_claims, 0);
  assert.equal(report.counts.error, 0);
  assert.equal(report.passes_bar, false);
  assert.equal(report.passes_bar_reason, 'selection');
  assert.equal(report.block_id, null);
  assert.equal(existsSync(logPath), false, 'selection run must never append a block');
});

test('facts eval (e): abstain-all model scores A/B as abstained_wrongly and C/D/E as abstained_correctly', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-abstain-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const abstainScript = writeFakeModel(
    dir,
    'abstain-all.mjs',
    [
      "import { readFileSync } from 'node:fs';",
      'readFileSync(0, "utf8");',
      'process.stdout.write("ABSTAIN: not enough verified evidence.\\n");',
    ].join('\n'),
  );

  const logPath = join(dir, 'ledger.jsonl');
  const result = await runEval({
    modelCmd: process.execPath,
    modelArgs: [abstainScript],
    modelName: 'abstain-only',
    logPath,
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.equal(result.cases_run, 50);
  assert.equal(result.unsupported_claims, 0);
  assert.equal(result.passes_bar, true);
  assert.deepEqual(result.counts, {
    correct: 0,
    wrong: 0,
    abstained_correctly: 25,
    abstained_wrongly: 25,
    unsupported: 0,
    error: 0,
  });
  assert.ok(result.block_id);
  const blocks = [];
  scanLog(logPath, (b) => blocks.push(b));
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].token_usage.measured, false);
});

test('facts eval: clean but wrong citation (wrong fact or wrong prefix or statement on abstain case) scores wrong and counts off_target_statements', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-wrong-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const catalog = gateFactCatalog();
  const answersPath = join(dir, 'wrong-answers.json');
  writeFileSync(
    answersPath,
    JSON.stringify(
      buildQuestionAnswerMap(catalog, {
        // A01 expects [fact:a10000000001.0]; citing as [asserted:...] is clean under checkAnswer but wrong prefix.
        A01: 'Schema is 7. [asserted:a10000000001.0]\n',
        // A02 expects a10000000001.1; citing another valid fact is clean but wrong target.
        A02: 'Schema is 7. [fact:a10000000001.0]\n',
        // C01 expects abstain; citing any valid fact is clean but wrong.
        C01: 'Schema is 7. [fact:a10000000001.0]\n',
      }),
    ),
    'utf8',
  );
  const wrongScript = writeFakeModel(dir, 'wrong-model.mjs', QUESTION_HASH_MODEL_BODY);

  const result = await runEval({
    modelCmd: process.execPath,
    modelArgs: [wrongScript, answersPath],
    modelName: 'wrong-citer',
    caseIds: ['A01', 'A02', 'C01'],
    logPath: join(dir, 'ledger.jsonl'),
    project: 'foundry',
    agent: 'eval-tester',
  });
  assert.deepEqual(result.counts, {
    correct: 0,
    wrong: 3,
    abstained_correctly: 0,
    abstained_wrongly: 0,
    unsupported: 0,
    error: 0,
  });
  assert.equal(result.checker_problems, 0);
  assert.equal(result.off_target_statements, 3);
  assert.equal(result.unsupported_claims, 3);
  assert.equal(result.block_id, null);
});

test('facts usage: separates measured and estimated totals, filters by --since and --project, counts superseded blocks, and reports bad lines', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-usage-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const logPath = join(dir, 'ledger.jsonl');
  const lines = [
    // Block 1: builder-a, build, measured (will be superseded by block 2; usage still counted!)
    JSON.stringify({
      id: '100000000001',
      ts: '2026-11-18T10:00:00+00:00',
      agent: 'builder-a',
      project: 'alpha',
      parent: null,
      status: 'proposed',
      intent: 'initial work',
      reasoning: 'test',
      schema: 2,
      token_usage: { model: 'model-x', task: 'build', input: 1000, output: 200, measured: true },
    }),
    // Block 2: supersedes block 1, same agent/task, estimated (must stay separate from measured!)
    JSON.stringify({
      id: '100000000002',
      ts: '2026-11-19T12:00:00+00:00',
      agent: 'builder-a',
      project: 'alpha',
      parent: '100000000001',
      supersedes: '100000000001',
      status: 'done',
      intent: 'follow-up',
      reasoning: 'test',
      schema: 2,
      token_usage: { model: 'model-y', task: 'build', input: 500, output: 100, measured: false },
    }),
    // Damaged line in the middle of the log (line 3).
    '{not valid json',
    // Block 3: builder-b, review, measured, same project.
    JSON.stringify({
      id: '100000000003',
      ts: '2026-11-20T08:00:00+00:00',
      agent: 'builder-b',
      project: 'alpha',
      parent: '100000000002',
      status: 'done',
      intent: 'review',
      reasoning: 'test',
      schema: 2,
      token_usage: { model: 'model-x', task: 'review', input: 300, output: 50, measured: true },
    }),
    // Block 4: other project beta, estimated.
    JSON.stringify({
      id: '100000000004',
      ts: '2026-11-20T09:00:00+00:00',
      agent: 'builder-a',
      project: 'beta',
      parent: null,
      status: 'done',
      intent: 'other project',
      reasoning: 'test',
      schema: 2,
      token_usage: { model: 'model-y', task: 'facts-eval', input: 2000, output: 400, measured: false },
    }),
    // Block 5: no token_usage (e.g., manual or external writer block).
    JSON.stringify({
      id: '100000000005',
      ts: '2026-11-20T10:00:00+00:00',
      agent: 'human',
      project: 'alpha',
      parent: '100000000003',
      status: 'done',
      intent: 'manual note',
      reasoning: 'test',
    }),
  ];
  writeFileSync(logPath, `${lines.join('\n')}\n`, 'utf8');

  // Full report across all projects.
  const full = computeUsage({ logPath });
  assert.equal(full.blocksScanned, 5);
  assert.equal(full.blocksWithUsage, 4);
  assert.equal(full.badLines.badLineCount, 1);
  assert.deepEqual(full.badLines.badLineNumbers, [3]);

  // Measured and estimated totals are never summed together.
  assert.deepEqual(full.totals.measured, { blocks: 2, input: 1300, output: 250, total: 1550 });
  assert.deepEqual(full.totals.estimated, { blocks: 2, input: 2500, output: 500, total: 3000 });

  // Grouped by (agent, task) sorted bytewise.
  assert.equal(full.groups.length, 3);
  assert.equal(full.groups[0].agent, 'builder-a');
  assert.equal(full.groups[0].task, 'build');
  assert.deepEqual(full.groups[0].models, ['model-x', 'model-y']);
  assert.deepEqual(full.groups[0].measured, { blocks: 1, input: 1000, output: 200, total: 1200 });
  assert.deepEqual(full.groups[0].estimated, { blocks: 1, input: 500, output: 100, total: 600 });

  assert.equal(full.groups[1].agent, 'builder-a');
  assert.equal(full.groups[1].task, 'facts-eval');
  assert.deepEqual(full.groups[1].measured, { blocks: 0, input: 0, output: 0, total: 0 });
  assert.deepEqual(full.groups[1].estimated, { blocks: 1, input: 2000, output: 400, total: 2400 });

  assert.equal(full.groups[2].agent, 'builder-b');
  assert.equal(full.groups[2].task, 'review');
  assert.deepEqual(full.groups[2].measured, { blocks: 1, input: 300, output: 50, total: 350 });

  // Filter by --since (excludes block 1 from 2026-11-18).
  const since = computeUsage({ logPath, since: '2026-11-19T00:00:00Z' });
  assert.equal(since.blocksWithUsage, 3);
  assert.deepEqual(since.totals.measured, { blocks: 1, input: 300, output: 50, total: 350 });
  assert.deepEqual(since.totals.estimated, { blocks: 2, input: 2500, output: 500, total: 3000 });

  // Filter by --project alpha.
  const alpha = computeUsage({ logPath, project: 'alpha' });
  assert.equal(alpha.blocksWithUsage, 3);
  assert.deepEqual(alpha.totals.measured, { blocks: 2, input: 1300, output: 250, total: 1550 });
  assert.deepEqual(alpha.totals.estimated, { blocks: 1, input: 500, output: 100, total: 600 });

  // Human-readable text keeps Measured and Estimated in distinct sections and reports bad lines.
  const text = formatUsageText(full);
  assert.match(text, /Warning: skipped 1 bad log line\(s\) at line\(s\): 3/);
  assert.match(text, /Measured \(provider-reported\):/);
  assert.match(text, /Estimated \(not provider-reported\):/);
  assert.ok(!text.includes('4550'), 'measured (1550) and estimated (3000) must never be summed');

  // CLI end-to-end with --since, --project, --json and bad-line warning on stderr.
  const cliJson = runCli(['usage', '--log', logPath, '--project', 'alpha', '--since', '2026-11-19', '--json']);
  assert.equal(cliJson.status, 0, cliJson.stderr);
  assert.match(cliJson.stderr, /Warning: skipped 1 bad log line\(s\) at line\(s\): 3/);
  const parsed = JSON.parse(cliJson.stdout);
  assert.equal(parsed.blocksWithUsage, 2);
  assert.deepEqual(parsed.totals.measured, { blocks: 1, input: 300, output: 50, total: 350 });
  assert.deepEqual(parsed.totals.estimated, { blocks: 1, input: 500, output: 100, total: 600 });

  // Invalid --since fails cleanly with exit 1.
  const badSince = runCli(['usage', '--log', logPath, '--since', 'not-a-date']);
  assert.equal(badSince.status, 1);
  assert.match(badSince.stderr, /Invalid --since/);

  // Missing log returns empty report cleanly.
  const empty = computeUsage({ logPath: join(dir, 'missing.jsonl') });
  assert.equal(empty.blocksScanned, 0);
  assert.equal(empty.blocksWithUsage, 0);
  assert.equal(empty.badLines.badLineCount, 0);
});

test('facts usage (F9): BigInt accumulation keeps 9007199254740991 + 2 exact and serializes totals above MAX_SAFE_INTEGER as decimal strings', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-usage-bigint-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const logPath = join(dir, 'ledger.jsonl');
  const lines = [
    JSON.stringify({
      id: '200000000001',
      ts: '2026-11-20T01:00:00+00:00',
      agent: 'big-agent',
      project: 'alpha',
      parent: null,
      status: 'done',
      intent: 'max safe integer input',
      reasoning: 'test',
      schema: 2,
      token_usage: { model: 'm1', task: 'huge', input: 9007199254740991, output: 1, measured: true },
    }),
    JSON.stringify({
      id: '200000000002',
      ts: '2026-11-20T02:00:00+00:00',
      agent: 'big-agent',
      project: 'alpha',
      parent: '200000000001',
      status: 'done',
      intent: 'add two more',
      reasoning: 'test',
      schema: 2,
      token_usage: { model: 'm1', task: 'huge', input: 2, output: 3, measured: true },
    }),
  ];
  writeFileSync(logPath, `${lines.join('\n')}\n`, 'utf8');

  const report = computeUsage({ logPath });
  assert.deepEqual(report.totals.measured, {
    blocks: 2,
    input: '9007199254740993',
    output: 4,
    total: '9007199254740997',
  });
  assert.deepEqual(report.groups[0].measured, {
    blocks: 2,
    input: '9007199254740993',
    output: 4,
    total: '9007199254740997',
  });

  const cliJson = runCli(['usage', '--log', logPath, '--json']);
  assert.equal(cliJson.status, 0, cliJson.stderr);
  const parsed = JSON.parse(cliJson.stdout);
  assert.equal(parsed.totals.measured.input, '9007199254740993');
  assert.equal(parsed.totals.measured.output, 4);
  assert.equal(parsed.totals.measured.total, '9007199254740997');

  const text = formatUsageText(report);
  assert.match(text, /input=9007199254740993 output=4 total=9007199254740997/);
});

test('facts usage works seamlessly on blocks written by appendBlock and facts eval', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-usage-append-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));
  const logPath = join(dir, 'ledger.jsonl');
  appendBlock(logPath, {
    schema: 2,
    agent: 'agent-1',
    project: 'foundry',
    intent: 'measured work',
    reasoning: 'test',
    status: 'done',
    token_usage: { model: 'm1', task: 'coding', input: 400, output: 100, measured: true },
  });
  const res = runCli(['usage', '--log', logPath]);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /agent=agent-1 task=coding blocks=1 input=400 output=100 total=500 models=m1/);
});

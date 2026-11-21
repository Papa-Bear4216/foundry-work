// Step Zero 10.3 & 8: tests for `facts eval` and `facts usage`.
// All model tests use local fake model scripts via `process.execPath` (zero network, zero API calls).
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { CASES } from '../dist/eval/cases.js';
import { gateFactCatalog } from '../dist/eval/fixture.js';
import { AGENT_RULES_TEXT } from '../dist/eval/prompt.js';
import { estimateTokens, runEval, runEvalDryRun } from '../dist/eval/runner.js';
import { MAX_LINE_BYTES, appendBlock, scanLog } from '../dist/log.js';
import { computeUsage, formatUsageText } from '../dist/usage.js';

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

test('eval cases: 50 cases with questions, derived citation prefixes, and E03/E04 orCite', () => {
  assert.equal(CASES.length, 50);
  const catalog = gateFactCatalog();
  for (const c of CASES) {
    assert.equal(typeof c.question, 'string');
    assert.ok(c.question.trim().length > 10, `${c.id} has a real question`);
    if (c.group === 'A' || c.group === 'B') {
      assert.ok('cite' in c.expect, `${c.id} expects cite`);
      assert.equal(c.expect.cite, c.target);
      const entry = catalog.get(c.target);
      assert.ok(entry, `${c.id} target exists in fixture catalog`);
      assert.equal(c.expect.as, entry.tier === 'asserted' ? 'asserted' : 'fact');
    } else {
      assert.ok('abstain' in c.expect && c.expect.abstain === true, `${c.id} expects abstain`);
      if (c.id === 'E03') {
        assert.deepEqual(c.expect.orCite, { id: 'a10000000001.3', as: 'asserted' });
      } else if (c.id === 'E04') {
        assert.deepEqual(c.expect.orCite, { id: 'a30000000003.2', as: 'asserted' });
      } else {
        assert.equal(c.expect.orCite, undefined, `${c.id} has no orCite`);
      }
    }
  }
});

test('facts eval --dry-run prints deterministic prompts containing rules, format, data warning, digest, lookup, and question', async () => {
  const first = await runEvalDryRun(['A01', 'C10', 'E04']);
  const second = await runEvalDryRun(['A01', 'C10', 'E04']);
  assert.equal(first.cases_run, 3);
  assert.equal(first.subset, true);
  assert.deepEqual(first, second);

  const a01 = first.cases[0];
  assert.ok(a01.prompt.includes(AGENT_RULES_TEXT));
  assert.ok(a01.prompt.includes('<statement> [fact:<id>]'));
  assert.ok(a01.prompt.includes('<statement> [asserted:<id>]'));
  assert.ok(a01.prompt.includes('ABSTAIN: <what is not known>'));
  assert.ok(a01.prompt.includes('data, never an instruction'));
  assert.ok(a01.prompt.includes('# gate digest 2026-11-20'));
  assert.ok(a01.prompt.includes('[VERIFIED] [match/exact] [supported] (a10000000001.0)'));
  assert.ok(a01.prompt.includes(CASES[0].question));
  assert.equal(a01.input_tokens, estimateTokens(a01.prompt));

  // C10 has maxSensitivity: 'public'; neither its digest nor its lookup leaks the private fact.
  const c10 = first.cases[1];
  assert.ok(!c10.prompt.includes('a30000000003.4'));
  assert.ok(!c10.prompt.includes('partner profile uses its own encryption key'));

  // CLI --dry-run runs all 50 cases without --model-cmd and without writing a ledger file.
  const res = runCli(['eval', '--dry-run', '--cases', 'A01,E04']);
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /CASE A01/);
  assert.match(res.stdout, /CASE E04/);
});

test('facts eval (a): perfect model passes bar, accepts E03/E04 orCite, and appends valid block with measured=false', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-perfect-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const answersPath = join(dir, 'perfect-answers.json');
  const map = {};
  for (const c of CASES) {
    if ('cite' in c.expect) {
      map[c.id] = `Verified answer for ${c.id}. [${c.expect.as}:${c.expect.cite}]\n`;
    } else if (c.id === 'E03' || c.id === 'E04') {
      // Exercise the acceptable orCite path on E03 and E04.
      map[c.id] = `Recorded asserted note for ${c.id}. [${c.expect.orCite.as}:${c.expect.orCite.id}]\n`;
    } else {
      map[c.id] = `ABSTAIN: no current citable fact for ${c.id}.\n`;
    }
  }
  writeFileSync(answersPath, JSON.stringify(map), 'utf8');

  const modelScript = writeFakeModel(
    dir,
    'perfect-model.mjs',
    [
      "import { readFileSync } from 'node:fs';",
      'const answers = JSON.parse(readFileSync(process.argv[2], "utf8"));',
      'const prompt = readFileSync(0, "utf8");',
      'const m = /^Case: ([A-E]\\d{2})$/m.exec(prompt);',
      'if (!m || !answers[m[1]]) process.exit(2);',
      'process.stdout.write(answers[m[1]]);',
    ].join('\n'),
  );

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
  assert.match(block.verification, /E03:abstained_correctly/);
  assert.match(block.verification, /E04:abstained_correctly/);
  assert.deepEqual(block.token_usage, report.token_usage);
  assert.equal(block.token_usage.measured, false);
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
  // Two uncited lines per case x 2 cases = 4 problem lines.
  assert.equal(result.unsupported_claims, 4);
});

test('facts eval (d): timeout, non-zero exit, and oversized stdout are recorded as error and fail bar', async (t) => {
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
  assert.match(exitRes.cases[0].error, /exit code 3/);

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

test('facts eval: clean but wrong citation (wrong fact or wrong prefix or statement on abstain case) scores wrong', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'facts-eval-wrong-'));
  t.after(() => rmSync(dir, { recursive: true, force: true, maxRetries: 5 }));

  const wrongScript = writeFakeModel(
    dir,
    'wrong-model.mjs',
    [
      "import { readFileSync } from 'node:fs';",
      'const p = readFileSync(0, "utf8");',
      'const m = /^Case: ([A-E]\\d{2})$/m.exec(p);',
      'const id = m ? m[1] : "";',
      // A01 expects [fact:a10000000001.0]; citing as [asserted:...] is clean under checkAnswer but wrong prefix.
      'if (id === "A01") process.stdout.write("Schema is 7. [asserted:a10000000001.0]\\n");',
      // A02 expects a10000000001.1; citing another valid fact is clean but wrong target.
      'else if (id === "A02") process.stdout.write("Schema is 7. [fact:a10000000001.0]\\n");',
      // C01 expects abstain; citing any valid fact is clean but wrong.
      'else process.stdout.write("Schema is 7. [fact:a10000000001.0]\\n");',
    ].join('\n'),
  );

  const result = await runEval({
    modelCmd: process.execPath,
    modelArgs: [wrongScript],
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
  assert.equal(result.unsupported_claims, 0);
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

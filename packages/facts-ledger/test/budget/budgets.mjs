// Step Zero 10.4: budgets as hard checks. Exit 1 when any budget is broken.
//
// - Memory: every subcommand <= 96 MiB peak (the runtime's OS counter, printed by --stats) on
//   the 10,000-block fixture. Each run is held at exit and its peak is cross-checked from
//   outside the process. On Linux the process tree (the CLI plus its largest git child; git
//   children run one at a time) must stay <= 192 MiB.
// - Time: query <= 2 s with a warm index, <= 15 s with a cold one.
// - Digest: the regenerated digest is <= 6,000 bytes and breaks no format rule.
// - Token accounting: `facts add --from-agent` without token usage is refused, and with it the
//   block carries token_usage.
// The runtime dependency check is the workspace script check:runtime-dependencies.
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { blockCount, project } from '../../bench/fixture.mjs';
import { CASES } from '../../dist/eval/cases.js';
import { formatCheckedPredicateClaim } from '../../dist/normalize.js';
import { DIGEST_MAX_BYTES, digestFormatProblems } from '../../dist/digest.js';

const MIB = 1024;
const MEMORY_KIB = 96 * MIB;
const TREE_KIB = 192 * MIB;
const CROSS_CHECK_SLACK_KIB = 8 * MIB;
const WARM_QUERY_MS = 2000;
const COLD_QUERY_MS = 15000;

// Budgets are defined on the pinned runtime binary only.
const pinned = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')).engines.node;
if (process.version !== `v${pinned}`) {
  console.error(`Budget check needs the pinned Node ${pinned}; this is ${process.version}.`);
  process.exit(1);
}

const here = fileURLToPath(new URL('.', import.meta.url));
const cliPath = fileURLToPath(new URL('../../dist/cli.js', import.meta.url));
const holdUrl = pathToFileURL(join(here, 'hold.mjs')).href;
const failures = [];
const rows = [];

function outsidePeakKiB(pid) {
  if (process.platform === 'linux') {
    const status = readFileSync(`/proc/${pid}/status`, 'utf8');
    return Number(/^VmHWM:\s+(\d+) kB$/m.exec(status)?.[1]);
  }
  if (process.platform === 'win32') {
    const r = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference = 'Stop'; (Get-Process -Id ${pid}).PeakWorkingSet64`],
      { encoding: 'utf8', timeout: 30000, windowsHide: true },
    );
    if (r.status !== 0) throw new Error('Could not read the Windows peak working set');
    return Number(r.stdout.trim()) / 1024;
  }
  throw new Error(`Unsupported platform ${process.platform}`);
}

function runMeasured(name, args, env) {
  return new Promise((resolve, reject) => {
    const start = process.hrtime.bigint();
    const child = spawn(process.execPath, ['--import', holdUrl, cliPath, ...args, '--stats'], {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const timer = setTimeout(() => child.kill(), 120000);
    let stdout = '';
    let stderr = '';
    let elapsedMs;
    let outsideKiB;
    let failure;
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => {
      stderr += c;
      if (elapsedMs === undefined && /BUDGET-HOLD \d+\n/.test(stderr)) {
        elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
        try {
          outsideKiB = outsidePeakKiB(child.pid);
        } catch (err) {
          failure = err;
        }
        child.stdin.end();
      }
    });
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (failure) return reject(failure);
      const m = /stats: maxRssKiB=(\d+) elapsedMs=/.exec(stderr);
      if (!m || elapsedMs === undefined) return reject(new Error(`${name}: no --stats line or hold marker\n${stderr}`));
      resolve({ name, code, stdout, stderr, innerKiB: Number(m[1]), outsideKiB, elapsedMs });
    });
  });
}

function check(ok, message) {
  if (!ok) failures.push(message);
}

function blockId(number) {
  return number.toString(16).padStart(12, '0');
}

const COMPONENTS = 100;
const FIXTURE_EMAIL = ['budget', 'example.invalid'].join('@');

/** A real repository with 100 committed files and a 10,000-block ledger whose evidence resolves in it. */
function buildRealisticFixture(root, work) {
  const repoDir = join(root, 'repo');
  mkdirSync(join(repoDir, 'fixtures'), { recursive: true });
  for (let c = 0; c < COMPONENTS; c++) {
    writeFileSync(join(repoDir, 'fixtures', `component-${c}.txt`), Buffer.from(`Reference signal is stable.\nComponent ${c}.\n`));
  }
  const git = (args) => {
    const r = spawnSync('git', ['-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', '-c', 'user.name=Budget Fixture', '-c', `user.email=${FIXTURE_EMAIL}`, ...args], { cwd: repoDir, encoding: 'utf8', windowsHide: true });
    if (r.status !== 0) throw new Error(`git ${args[0]} failed: ${r.stderr}`);
    return r.stdout;
  };
  git(['init', '--quiet', '--template=']);
  git(['add', '--all']);
  git(['commit', '--quiet', '--no-verify', '-m', 'fixture']);
  const commit = git(['rev-parse', 'HEAD']).trim();
  const blobs = new Map();
  for (const line of git(['ls-tree', '-r', 'HEAD']).split('\n')) {
    const m = /^\d+ blob ([0-9a-f]+)\t(.+)$/.exec(line);
    if (m) blobs.set(m[2], m[1]);
  }
  const logPath = join(work, 'ledger.jsonl');
  const lines = [];
  for (let n = 1; n <= blockCount; n++) {
    const id = blockId(n);
    const ts = new Date(Date.UTC(2026, 0, 1, 0, n)).toISOString();
    const component = `component-${n % COMPONENTS}`;
    const path = `fixtures/${component}.txt`;
    const evidence = [{ type: 'file', repo: project, path, commit, blob: blobs.get(path), lines: '1', quote: 'Reference signal is stable.' }];
    const base = { fact_id: `${id}.0`, tags: ['calibration', n % 101 === 0 ? 'pinned' : component], sensitivity: 'public', verified_at: ts, supersedes: null, evidence };
    let fact;
    if (n % 3 === 0) {
      const check = { predicate: 'file_contains', repo: project, path, text: 'Reference signal is stable.' };
      fact = { ...base, tier: 'checked', scope: 'current', check, claim: formatCheckedPredicateClaim(check), note: `Calibration sample ${n} passed for ${component}.` };
    } else {
      fact = { ...base, tier: 'asserted', scope: n % 3 === 1 ? 'current' : 'at-commit', claim: `Calibration sample ${n} passed for ${component}.`, note: 'The synthetic test fixture uses a constant reference signal.' };
    }
    lines.push(JSON.stringify({
      id, ts, agent: 'fixture-builder', project, parent: n === 1 ? null : blockId(n - 1), trace_id: id,
      status: n % 101 === 0 ? 'proposed' : 'done',
      intent: `Record calibration for ${component} at sample ${n}`,
      reasoning: 'A deterministic sample exercises the ledger index and summary.',
      actions: [], verification: 'Synthetic fixture', touches: [path], supersedes: null, schema: 2,
      facts: [fact], retracted_facts: [],
      token_usage: { model: 'fixture-model', task: 'calibration', input: 500, output: 120, measured: false },
    }));
  }
  writeFileSync(logPath, `${lines.join('\n')}\n`);
  return { logPath, repoDir };
}

/** The success paths really ran: every fact holds, a third are VERIFIED. */
function verifyOutcome(result) {
  const by = {};
  for (const item of result.items) by[item.badge] = (by[item.badge] ?? 0) + 1;
  if (result.items.length !== blockCount) return `expected ${blockCount} items, got ${result.items.length}`;
  if ((by.VERIFIED ?? 0) < 3000 || (by.ASSERTED ?? 0) < 6000) return `unexpected badges ${JSON.stringify(by)}`;
  return null;
}

function digestOutcome(result) {
  if (result.counts.supported < blockCount - 1) return `only ${result.counts.supported} supported facts`;
  if (result.listedFacts < 10) return `only ${result.listedFacts} facts listed`;
  return null;
}

function answerOutcome(result) {
  if (!result.ok || result.citations !== 100) return `answer not accepted: ${JSON.stringify(result.problems.slice(0, 3))}`;
  return null;
}

function usageOutcome(result) {
  if (result.blocksWithUsage < blockCount) return `only ${result.blocksWithUsage} usage blocks`;
  if (result.totals.estimated.blocks < blockCount) return `only ${result.totals.estimated.blocks} estimated blocks`;
  return null;
}

function evalOutcome(result) {
  if (result.cases_run !== 50) return `expected 50 cases, got ${result.cases_run}`;
  if (!result.passes_bar || result.unsupported_claims !== 0) {
    return `eval failed bar: unsupported=${result.unsupported_claims} counts=${JSON.stringify(result.counts)}`;
  }
  if (!result.block_id) return 'eval did not append a result block';
  return null;
}

const root = mkdtempSync(join(tmpdir(), 'facts-budgets-'));
try {
  // 10,000 blocks whose evidence resolves in a real repository, so the success paths run:
  // blob reads, VERIFIED predicates, ASSERTED facts and a full digest (review finding 4).
  const work = join(root, 'work');
  mkdirSync(work);
  const { logPath, repoDir } = buildRealisticFixture(root, work);
  const indexPath = join(work, 'ledger.index.sqlite');
  const reposPath = join(root, 'repos.json');
  writeFileSync(reposPath, JSON.stringify({ [project]: repoDir }));

  const env = { ...process.env, FACTS_LEDGER_REPOS: reposPath };
  delete env.NODE_OPTIONS;
  delete env.FACTS_LEDGER_GIT;
  let gitLog;
  if (process.platform === 'linux') {
    const realGit = spawnSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).stdout.trim();
    const wrapper = join(root, 'git-peak.py');
    copyFileSync(join(here, 'git-peak.py'), wrapper);
    chmodSync(wrapper, 0o755);
    gitLog = join(root, 'git-peaks.log');
    Object.assign(env, { FACTS_LEDGER_GIT: wrapper, FACTS_BUDGET_REAL_GIT: realGit, FACTS_BUDGET_GIT_LOG: gitLog });
  }
  const store = ['--log', logPath, '--index', indexPath];
  const answerPath = join(root, 'answer.txt');
  // 100 distinct citations of facts that hold: 50 asserted (cited asserted:), 50 checked (cited fact:).
  const cited = [];
  for (let i = 0; i < 50; i++) {
    cited.push(`[asserted:${blockId(3 * i * 61 + 1)}.0]`);
    cited.push(`[fact:${blockId(3 * (i * 61 + 1))}.0]`);
  }
  writeFileSync(answerPath, `Probe statement. ${cited.join(' ')}\nABSTAIN: nothing else.\n`);
  const evalAnswersPath = join(root, 'eval-answers.json');
  const evalAnswers = Object.fromEntries(
    CASES.map((c) => [
      c.id,
      'cite' in c.expect
        ? `Synthetic answer for ${c.id}. [${c.expect.as}:${c.expect.cite}]\n`
        : `ABSTAIN: not supported for ${c.id}.\n`,
    ]),
  );
  writeFileSync(evalAnswersPath, JSON.stringify(evalAnswers));
  const fakeModelPath = join(root, 'fake-model.mjs');
  writeFileSync(
    fakeModelPath,
    [
      "import { readFileSync } from 'node:fs';",
      'const answers = JSON.parse(readFileSync(process.argv[2], "utf8"));',
      'const prompt = readFileSync(0, "utf8");',
      'const m = /^Case: ([A-E]\\d{2})$/m.exec(prompt);',
      'process.stdout.write(m && answers[m[1]] ? answers[m[1]] : "ABSTAIN: unknown case.\\n");',
    ].join('\n'),
  );

  const steps = [
    { name: 'rebuild', args: ['rebuild', ...store] },
    { name: 'query (warm)', args: ['query', 'calibration sample', ...store, '--json'], maxMs: WARM_QUERY_MS },
    { name: 'verify --all', args: ['verify', '--all', ...store, '--json'], outcome: verifyOutcome },
    { name: 'digest', args: ['digest', '--project', project, ...store, '--json'], outcome: digestOutcome },
    { name: 'check-answer', args: ['check-answer', answerPath, ...store, '--json'], outcome: answerOutcome },
    {
      name: 'add --from-agent',
      args: [
        'add', '--project', project, '--intent', 'Budget probe', '--reasoning', 'Step Zero 10.4 memory check',
        '--claim', 'The budget probe ran.', '--manual', 'budget probe run', '--agent', 'budget-probe',
        '--from-agent', '--model', 'probe-model', '--task', 'budgets', '--input-tokens', '10', '--output-tokens', '2',
        ...store, '--json',
      ],
    },
    { name: 'usage', args: ['usage', '--log', logPath, '--json'], outcome: usageOutcome },
    {
      name: 'eval',
      args: [
        'eval', '--model-cmd', process.execPath, '--model-arg', fakeModelPath, '--model-arg', evalAnswersPath,
        '--model-name', 'budget-fake', '--project', project, '--log', logPath, '--json',
      ],
      outcome: evalOutcome,
    },
    { name: 'query (cold)', args: ['query', 'calibration sample', ...store, '--json'], maxMs: COLD_QUERY_MS, cold: true },
  ];

  for (const step of steps) {
    if (step.cold) rmSync(indexPath, { force: true });
    if (gitLog) writeFileSync(gitLog, '');
    const r = await runMeasured(step.name, step.args, env);
    const allowed = step.codes ?? [0];
    check(allowed.includes(r.code), `${step.name}: exit ${r.code}\n${r.stderr}`);
    check(r.innerKiB <= MEMORY_KIB, `${step.name}: peak ${r.innerKiB} KiB > 96 MiB`);
    check(
      Math.abs(r.outsideKiB - r.innerKiB) <= CROSS_CHECK_SLACK_KIB,
      `${step.name}: outside peak ${r.outsideKiB} KiB disagrees with --stats ${r.innerKiB} KiB`,
    );
    if (step.maxMs !== undefined) check(r.elapsedMs <= step.maxMs, `${step.name}: ${r.elapsedMs.toFixed(0)} ms > ${step.maxMs} ms`);
    const row = { step: step.name, innerKiB: r.innerKiB, outsideKiB: Math.round(r.outsideKiB), ms: Math.round(r.elapsedMs) };
    if (gitLog) {
      const peaks = readFileSync(gitLog, 'utf8').split('\n').filter(Boolean).map(Number);
      const gitKiB = peaks.length > 0 ? Math.max(...peaks) : 0;
      Object.assign(row, { gitRuns: peaks.length, gitPeakKiB: gitKiB, treeKiB: r.innerKiB + gitKiB });
      check(r.innerKiB + gitKiB <= TREE_KIB, `${step.name}: process tree ${r.innerKiB + gitKiB} KiB > 192 MiB`);
    }
    rows.push(row);
    if (step.outcome && r.code === 0) {
      const problem = step.outcome(JSON.parse(r.stdout));
      if (problem) failures.push(`${step.name}: ${problem}`);
    }
    if (step.name === 'add --from-agent' && r.code === 0) {
      const block = JSON.parse(r.stdout.trim().split('\n')[0]);
      check(block.token_usage?.model === 'probe-model' && block.token_usage?.input === 10, 'add --from-agent: block lacks token_usage');
    }
  }
  if (gitLog) check(rows.some((r) => r.gitRuns > 0), 'no git child ran: the tree check measured nothing');

  // Digest: size and format rules.
  const digestPath = join(work, `digest.${project}.md`);
  check(existsSync(digestPath), 'digest file missing');
  if (existsSync(digestPath)) {
    const digest = readFileSync(digestPath, 'utf8');
    const bytes = Buffer.byteLength(digest, 'utf8');
    check(bytes <= DIGEST_MAX_BYTES, `digest ${bytes} bytes > ${DIGEST_MAX_BYTES}`);
    check(digestFormatProblems(digest).length === 0, `digest format: ${digestFormatProblems(digest).join('; ')}`);
    rows.push({ step: 'digest size', bytes });
  }

  // Token accounting: --from-agent without token usage is refused and nothing is appended.
  const before = readFileSync(logPath).length;
  const refused = spawnSync(
    process.execPath,
    [cliPath, 'add', '--project', project, '--intent', 'x', '--reasoning', 'y', '--claim', 'The probe ran twice.', '--manual', 'probe', '--from-agent', ...store],
    { env, encoding: 'utf8', windowsHide: true },
  );
  check(refused.status === 1 && /--from-agent requires token usage/.test(refused.stderr), `add --from-agent without tokens: exit ${refused.status} ${refused.stderr}`);
  check(readFileSync(logPath).length === before, 'add --from-agent without tokens appended a block');
  check(blockCount === 10_000, 'fixture is not 10,000 blocks');
} finally {
  rmSync(root, { recursive: true, force: true, maxRetries: 5 });
}

console.log(JSON.stringify({ node: process.version, platform: process.platform, rows }, null, 1));
if (failures.length > 0) {
  console.error(`Budget check FAILED:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log('Budget check passed.');

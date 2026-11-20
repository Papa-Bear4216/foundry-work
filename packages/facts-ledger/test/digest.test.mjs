import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { addFact, appendBlock, digestFormatProblems, digestLine, DIGEST_MAX_BYTES, generateDigest, loadRepoMap } from '../dist/index.js';

const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
const DAY = 24 * 3600 * 1000;
const bytes = (s) => new TextEncoder().encode(s).length;

function git(dir, ...args) {
  // Built at runtime so the repository identifier scan sees no address literal.
  const email = ['fixture', 'example.invalid'].join('@');
  return execFileSync('git', ['-c', 'user.name=fixture', '-c', `user.email=${email}`, '-c', 'commit.gpgsign=false', ...args], { cwd: dir, encoding: 'utf8' });
}

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'facts-z5-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = join(root, 'repo');
  mkdirSync(join(repo, 'src'), { recursive: true });
  git(repo, 'init', '-q');
  writeFileSync(join(repo, 'src/a.ts'), 'export const A = 1;\nexport const B = 2;\n');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'init');
  mkdirSync(join(root, 'config'));
  const mapPath = join(root, 'config', 'repos.json');
  writeFileSync(mapPath, JSON.stringify({ demo: repo }));
  return { root, repo, mapPath, repos: loadRepoMap(mapPath), logPath: join(root, 'ledger', 'ledger.jsonl') };
}

const base = (f) => ({ logPath: f.logPath, repos: f.repos, agent: 'tester', project: 'demo', intent: 'record', reasoning: 'test' });

test('digest lists sections in the specified order and writes digest.<project>.md beside the index', (t) => {
  const f = fixture(t);
  addFact({ ...base(f), claim: 'Asserted pinned claim.', tags: ['pinned'], evidenceFiles: [{ repo: 'demo', path: 'src/a.ts', lines: '1' }] });
  addFact({ ...base(f), check: { predicate: 'file_contains', repo: 'demo', path: 'src/a.ts', text: 'export const A = 1;' }, tags: ['pinned'] });
  addFact({ ...base(f), claim: 'Older recent claim.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }], nowMs: Date.now() - DAY });
  addFact({ ...base(f), claim: 'Newer recent claim.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  addFact({ ...base(f), claim: 'Private claim never listed.', sensitivity: 'private', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  appendBlock(f.logPath, { agent: 'tester', project: 'demo', intent: 'Open idea still proposed', reasoning: 'r' });
  appendBlock(f.logPath, { agent: 'tester', project: 'other', intent: 'Other project proposal', reasoning: 'r' });

  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos });
  const lines = r.text.trimEnd().split('\n');
  assert.match(lines[0], /^# demo digest \d{4}-\d{2}-\d{2}$/);
  assert.match(lines[1], /^Facts: 4; supported 4, moved 0, stale 0, expired 0, unverifiable 0\.$/);
  const at = (s) => lines.findIndex((l) => l.includes(s));
  assert.ok(at('## Pinned') < at('V repo "demo"'));
  assert.ok(at('V repo "demo"') < at('A Asserted pinned claim.'), 'checked tier first among pinned');
  assert.ok(at('A Asserted pinned claim.') < at('## Open proposals'));
  assert.ok(at('- Open idea still proposed') < at('## Recent decisions'));
  assert.ok(at('## Recent decisions') < at('## Recently verified'));
  assert.ok(at('A Newer recent claim.') < at('A Older recent claim.'), 'newest first');
  assert.equal(at('Private claim'), -1);
  assert.equal(at('Other project proposal'), -1);
  assert.match(lines[lines.length - 1], /^0 fact\(s\) left out\. Query them with: facts query --repo demo$/);
  assert.equal(r.path, join(f.root, 'ledger', 'digest.demo.md'));
  assert.equal(readFileSync(r.path, 'utf8'), r.text);
  assert.deepEqual(digestFormatProblems(r.text), []);
});

test('stale and expired facts are counted but never listed', (t) => {
  const f = fixture(t);
  addFact({ ...base(f), claim: 'Becomes stale.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  addFact({ ...base(f), claim: 'Manual and expires.', manual: { description: 'looked once' } });
  writeFileSync(join(f.repo, 'src/a.ts'), 'changed\n');
  git(f.repo, 'commit', '-q', '-am', 'change');
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, nowMs: Date.now() + 2 * DAY, write: false });
  assert.match(r.text, /stale 1, expired 1/);
  assert.ok(!r.text.includes('Becomes stale.'));
  assert.ok(!r.text.includes('Manual and expires.'));
  assert.match(r.text, /2 fact\(s\) left out/);
});

test('budget: never more than 6,000 bytes, whole lines only, closing line always present', (t) => {
  const f = fixture(t);
  for (let i = 0; i < 120; i++) {
    addFact({ ...base(f), claim: `Claim number ${i} ${'padding words '.repeat(10)}`.slice(0, 290), tags: i % 3 === 0 ? ['pinned'] : [], evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  }
  for (let i = 0; i < 30; i++) appendBlock(f.logPath, { agent: 't', project: 'demo', intent: `Proposal ${i} ${'x'.repeat(100)}`, reasoning: 'r' });
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, write: false });
  assert.ok(r.bytes <= DIGEST_MAX_BYTES, `digest is ${r.bytes} bytes`);
  assert.equal(r.bytes, bytes(r.text));
  const lines = r.text.trimEnd().split('\n');
  for (const line of lines.filter((l) => /^[VA] /.test(l))) assert.match(line, /\([0-9a-f]{12}\.\d+\)$/, 'fact lines are never cut');
  assert.match(lines[lines.length - 1], /fact\(s\) left out\. Query them with: facts query --repo demo$/);
  assert.equal(r.listedFacts + r.omittedFacts, 120);
  assert.ok(r.omittedFacts > 0);
});

test('format rules: hex runs over 12 characters are shortened and violations are detected', () => {
  const long = 'a'.repeat(40);
  assert.equal(digestLine(`blob ${long}`), `blob ${'a'.repeat(12)}`);
  assert.ok(digestFormatProblems(`x ${long}\n`).some((p) => p.includes('hex')));
  assert.ok(digestFormatProblems('{"json": true}\n').some((p) => p.includes('JSON')));
  assert.ok(digestFormatProblems('x'.repeat(6001)).some((p) => p.includes('6000')));
  assert.equal(digestLine('two\nlines\there'), 'two lines here');
});

test('facts add regenerates the digest file', (t) => {
  const f = fixture(t);
  const env = { ...process.env, FACTS_LEDGER_REPOS: f.mapPath };
  const run = (...args) => execFileSync(process.execPath, [cli, ...args, '--log', f.logPath], { env, encoding: 'utf8' });
  const digestPath = join(f.root, 'ledger', 'digest.demo.md');
  assert.equal(existsSync(digestPath), false);
  run('add', '--project', 'demo', '--intent', 'pin', '--reasoning', 'r', '--repo', 'demo', '--claim', 'First CLI claim.', '--evidence-file', 'src/a.ts:1', '--tag', 'pinned');
  assert.match(readFileSync(digestPath, 'utf8'), /A First CLI claim\./);
  const printed = run('digest', '--project', 'demo');
  assert.equal(printed, readFileSync(digestPath, 'utf8'));
});

test('review fixes: whole 300-byte claims, embedded JSON and secret-bearing lines left out, add honors --max-sensitivity', (t) => {
  const f = fixture(t);
  const long = `Long ${'w'.repeat(290)} end.`.slice(0, 300);
  addFact({ ...base(f), claim: long, evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  addFact({ ...base(f), claim: 'Configuration is {"enabled":true}.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  // Built at runtime so no scanner sees a token-shaped literal in the source.
  appendBlock(f.logPath, { agent: 't', project: 'demo', intent: `Leaked ${'ghp_' + 'a'.repeat(36)}`, reasoning: 'r' });
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, write: false });
  assert.ok(r.text.split('\n').some((l) => l.startsWith(`A ${long} (`)), 'a full 300-byte claim is listed whole with its id');
  assert.ok(!r.text.includes('enabled'), 'embedded JSON is left out');
  assert.ok(!r.text.includes('ghp_'), 'secret-bearing intent is left out');
  assert.match(r.text, /1 fact\(s\) left out/);
  assert.ok(digestFormatProblems('A Configuration is {"enabled":true}. (x)\n').some((p) => p.includes('JSON')));

  const env = { ...process.env, FACTS_LEDGER_REPOS: f.mapPath };
  execFileSync(process.execPath, [cli, 'add', '--project', 'demo', '--intent', 'p', '--reasoning', 'r', '--repo', 'demo', '--claim', 'Personal note.', '--sensitivity', 'personal', '--evidence-file', 'src/a.ts', '--max-sensitivity', 'public', '--log', f.logPath], { env, encoding: 'utf8' });
  const written = readFileSync(join(f.root, 'ledger', 'digest.demo.md'), 'utf8');
  assert.ok(!written.includes('Personal note.'), 'digest regenerated by add uses the --max-sensitivity cap');
});

test('round-2 fixes: claims never rewritten, JSON values caught, intents capped, unsafe projects and log aliasing refused', (t) => {
  const f = fixture(t);
  addFact({ ...base(f), check: { predicate: 'file_lacks', repo: 'demo', path: 'src/a.ts', text: 'aaaaaaaaaaaaa' } });
  addFact({ ...base(f), claim: 'Values are [1,2,3].', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  addFact({ ...base(f), claim: 'Configuration is {}.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  addFact({ ...base(f), claim: 'Clinical detail XYZ.', sensitivity: 'clinical', intent: 'Clinical detail XYZ.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, maxSensitivity: 'public', write: false });
  assert.ok(!r.text.includes('aaaaaaaaaaaa'), 'a claim with a long hex-like run is left out, not shortened');
  assert.ok(!r.text.includes('[1,2,3]') && !r.text.includes('{}'), 'JSON arrays and empty containers are left out');
  assert.ok(!r.text.includes('XYZ'), 'an intent of a block holding a capped fact is left out');
  for (const s of ['x [true,false]', 'x {}', 'x []', 'x [1, 2]']) assert.ok(digestFormatProblems(`${s}\n`).some((p) => p.includes('JSON')), s);

  assert.throws(() => generateDigest({ logPath: f.logPath, project: 'ghp_' + 'z'.repeat(36), repos: f.repos, write: false }), /Invalid project/);
  const aliasLog = join(f.root, 'ledger', 'digest.demo.md');
  appendBlock(aliasLog, { agent: 't', project: 'demo', intent: 'i', reasoning: 'r' });
  assert.throws(() => generateDigest({ logPath: aliasLog, project: 'demo', repos: f.repos }), /Refusing to write the digest/);

  const env = { ...process.env, FACTS_LEDGER_REPOS: f.mapPath };
  const before = readFileSync(f.logPath, 'utf8');
  assert.throws(() => execFileSync(process.execPath, [cli, 'add', '--project', 'My project', '--intent', 'p', '--reasoning', 'r', '--repo', 'demo', '--claim', 'x.', '--evidence-file', 'src/a.ts', '--log', f.logPath], { env, encoding: 'utf8', stdio: 'pipe' }));
  assert.equal(readFileSync(f.logPath, 'utf8'), before, 'an invalid project name is refused before anything is appended');
});

test('round-3 fixes: escaped-quote JSON caught, budget filled past 200 short facts, closing command repeats cap and flags', (t) => {
  for (const s of ['x {"a\\"b":1}', 'x ["a\\"b"]']) assert.ok(digestFormatProblems(`${s}\n`).some((p) => p.includes('JSON')), s);
  const f = fixture(t);
  const facts = [];
  for (let i = 0; i < 400; i++) {
    facts.push({ fact_id: '', tier: 'asserted', scope: 'current', claim: 'x', note: '', tags: [], sensitivity: 'public',
      verified_at: new Date(Date.now() - i * 1000).toISOString(), supersedes: null,
      evidence: [{ type: 'manual', description: 'looked', ran_at: new Date().toISOString(), ttl_s: 86400, output_sha256: 'c'.repeat(64) }] });
    if (facts.length === 40) { appendBlock(f.logPath, { agent: 't', project: 'demo', intent: 'batch', reasoning: 'r', status: 'done', schema: 2, facts: facts.splice(0) }); }
  }
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, maxSensitivity: 'private', queryFlags: ['--log', 'alt.jsonl'], write: false });
  assert.ok(r.listedFacts > 200, `listed ${r.listedFacts}`);
  assert.ok(r.bytes > DIGEST_MAX_BYTES - 40, `digest filled to ${r.bytes} bytes`);
  assert.match(r.text, /Query them with: facts query --repo demo --max-sensitivity private --log alt\.jsonl\n$/);
});

test('round-4 fixes: dropped secret facts hide their intent, intents fill the budget, instant ordering, safe query flags', (t) => {
  const f = fixture(t);
  appendBlock(f.logPath, { agent: 't', project: 'demo', intent: 'Confidential plan Q', reasoning: 'r', status: 'done', schema: 2,
    facts: [{ fact_id: '', tier: 'asserted', scope: 'current', claim: 'Confidential plan Q', note: '', tags: [], sensitivity: 'secret',
      verified_at: new Date().toISOString(), supersedes: null, evidence: [] }] });
  for (let i = 0; i < 80; i++) appendBlock(f.logPath, { agent: 't', project: 'demo', intent: `P${i}`, reasoning: 'r' });
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, write: false });
  assert.ok(!r.text.includes('Confidential plan Q'), 'intent of a block whose secret fact was dropped is hidden');
  assert.equal((r.text.match(/^- P\d+$/gm) ?? []).length, 80, 'all 80 short proposals fit and are listed');

  const g = fixture(t);
  const mk = (claim, ts) => ({ fact_id: '', tier: 'asserted', scope: 'current', claim, note: '', tags: [], sensitivity: 'public',
    verified_at: ts, supersedes: null,
    evidence: [{ type: 'manual', description: 'looked', ran_at: new Date().toISOString(), ttl_s: 86400, output_sha256: 'c'.repeat(64) }] });
  appendBlock(g.logPath, { agent: 't', project: 'demo', intent: 'i', reasoning: 'r', status: 'done', schema: 2,
    facts: [mk('Older by instant.', '2026-11-20T11:00:00+02:00'), mk('Newer by instant.', '2026-11-20T10:00:00+00:00')] });
  const o = generateDigest({ logPath: g.logPath, project: 'demo', repos: g.repos, queryFlags: ['--log', './$ledger.jsonl'], write: false });
  assert.ok(o.text.indexOf('Newer by instant.') < o.text.indexOf('Older by instant.'));
  assert.ok(!o.text.includes('$ledger'), 'a flag needing shell quoting is described, not shown');
  assert.throws(() => generateDigest({ logPath: g.logPath, project: '0123456789abcdef', repos: g.repos, write: false }), /Invalid project/);
});

test('round-5 fixes: bad log lines reported, fact ids never shortened, backslash flags described', (t) => {
  const f = fixture(t);
  addFact({ ...base(f), claim: 'Good claim.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  appendFileSync(f.logPath, 'this is not json\n');
  addFact({ ...base(f), claim: 'Second claim.', evidenceFiles: [{ repo: 'demo', path: 'src/a.ts' }] });
  const r = generateDigest({ logPath: f.logPath, project: 'demo', repos: f.repos, queryFlags: ['--log', './data\\ledger.jsonl'], write: false });
  assert.equal(r.badLines.badLineCount, 1);
  assert.ok(!r.text.includes('data\\ledger'), 'a backslash path is described, not shown');
  const env = { ...process.env, FACTS_LEDGER_REPOS: f.mapPath };
  const out = spawnSync(process.execPath, [cli, 'digest', '--project', 'demo', '--log', f.logPath], { env, encoding: 'utf8' });
  assert.match(out.stderr, /skipped 1 bad log line/);

  const g = fixture(t);
  appendBlock(g.logPath, { agent: 't', project: 'demo', intent: 'i', reasoning: 'r', status: 'done', schema: 2,
    facts: [{ fact_id: 'abcdef1234567.0', tier: 'asserted', scope: 'current', claim: 'Long id fact.', note: '', tags: [], sensitivity: 'public',
      verified_at: new Date().toISOString(), supersedes: null,
      evidence: [{ type: 'manual', description: 'looked', ran_at: new Date().toISOString(), ttl_s: 86400, output_sha256: 'c'.repeat(64) }] }] });
  const o = generateDigest({ logPath: g.logPath, project: 'demo', repos: g.repos, write: false });
  assert.ok(!o.text.includes('Long id fact.'), 'a fact whose id the format rules would shorten is left out');
  assert.equal(o.omittedFacts, 1);
});

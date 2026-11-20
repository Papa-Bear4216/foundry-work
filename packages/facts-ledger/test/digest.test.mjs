import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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

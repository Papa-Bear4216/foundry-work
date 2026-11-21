import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { appendBlock, compareBytewise, MAX_LINE_BYTES, scanLog } from '../dist/index.js';

const exec = promisify(execFile);
const writer = fileURLToPath(new URL('./writer.py', import.meta.url));
const moduleUrl = new URL('../dist/index.js', import.meta.url).href;

function resolvePythonBinary() {
  if (process.env.FACTS_LEDGER_PYTHON) return process.env.FACTS_LEDGER_PYTHON;
  for (const candidate of ['python', 'python3']) {
    const probe = spawnSync(candidate, ['--version'], { stdio: 'ignore' });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return 'python3';
}

const python = resolvePythonBinary();
const fixture = { agent: 'ts-fixture', project: 'fixture', intent: 'append café', reasoning: 'verify format' };

function logPath(t) {
  const dir = mkdtempSync(join(tmpdir(), 'facts-ledger-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return join(dir, 'ledger.jsonl');
}

function read(path) {
  const blocks = [];
  const report = scanLog(path, (block) => blocks.push(block));
  return { blocks, report };
}

test('same-project parent, open-target validation, and lock release on error', (t) => {
  const path = logPath(t);
  const first = appendBlock(path, fixture);
  const other = appendBlock(path, { ...fixture, project: 'other' });
  assert.equal(first.parent, null);
  assert.equal(other.parent, null);
  assert.throws(() => appendBlock(path, { ...fixture, supersedes: 'missing' }), /Unknown block/);
  const resolved = appendBlock(path, { ...fixture, supersedes: first.id, status: 'done' });
  assert.equal(resolved.parent, first.id);
  assert.equal(resolved.trace_id, first.trace_id);
  for (const id of [first.id, resolved.id]) {
    assert.throws(() => appendBlock(path, { ...fixture, supersedes: id }), /already resolved/);
  }
  assert.deepEqual(read(path).blocks, [first, other, resolved]);
});

test('repairs an unterminated damaged tail and reports bad lines on every scan', (t) => {
  const path = logPath(t);
  const first = appendBlock(path, fixture);
  writeFileSync(path, Buffer.concat([
    Buffer.from(JSON.stringify(first) + '\r\n{bad}\n'),
    Buffer.from([0xff, 10]),
    Buffer.alloc(MAX_LINE_BYTES, 120),
    Buffer.from('\n{"id":'),
  ]));
  const report = { badLineCount: 4, badLineNumbers: [2, 3, 4, 5] };
  assert.deepEqual(read(path), { blocks: [first], report });
  const next = appendBlock(path, fixture);
  assert.equal(next.parent, first.id);
  assert.match(readFileSync(path, 'utf8'), /\{"id":\n\{/);
  assert.deepEqual(read(path), { blocks: [first, next], report });
  assert.deepEqual(read(path).report, report);
});

test('ignores complete JSON without LF until a writer supplies its separator', (t) => {
  const path = logPath(t);
  const first = appendBlock(path, fixture);
  writeFileSync(path, JSON.stringify(first));
  assert.deepEqual(read(path), { blocks: [], report: { badLineCount: 1, badLineNumbers: [1] } });
  const next = appendBlock(path, fixture);
  assert.equal(next.parent, first.id);
  assert.deepEqual(read(path).blocks, [first, next]);
});

test('enforces the 64 KiB encoded line limit including LF', (t) => {
  const path = logPath(t);
  appendBlock(path, { ...fixture, intent: '' });
  const overhead = readFileSync(path).length;
  writeFileSync(path, '');
  const intent = 'x'.repeat(MAX_LINE_BYTES - overhead - 2) + 'é';
  assert.throws(() => appendBlock(path, { ...fixture, intent: intent + 'x' }), /64 KiB/);
  assert.equal(readFileSync(path).length, 0);
  const block = appendBlock(path, { ...fixture, intent });
  assert.equal(readFileSync(path).length, MAX_LINE_BYTES);
  assert.deepEqual(read(path).blocks, [block]);
});

test('parallel TypeScript and synthetic Python writers produce one unbroken chain', async (t) => {
  const path = logPath(t);
  const seed = appendBlock(path, fixture);
  const initialBytes = readFileSync(path);
  const lock = new DatabaseSync(path + '.lock.sqlite');
  const count = 40;
  const ts = `
    import { appendBlock } from ${JSON.stringify(moduleUrl)};
    const ids = [];
    for (let i = 0; i < ${count}; i++) {
      ids.push(appendBlock(process.argv[1], ${JSON.stringify(fixture)}).id);
    }
    console.log(JSON.stringify(ids));
  `;
  lock.exec('BEGIN IMMEDIATE');
  let pending;
  let blockedBytes;
  try {
    pending = Promise.all([
      exec(process.execPath, ['--input-type=module', '-e', ts, path], { timeout: 20000 }),
      exec(python, ['-B', writer, 'write', path, String(count)], { timeout: 20000 }),
    ]);
    // Let both spawned writers encounter the same held lock.
    await new Promise((resolve) => setTimeout(resolve, 250));
    blockedBytes = readFileSync(path);
  } finally {
    lock.close();
  }
  const results = await pending;
  assert.deepEqual(blockedBytes, initialBytes);
  const expectedIds = [seed.id, ...results.flatMap(({ stdout }) => JSON.parse(stdout))];
  const { blocks, report } = read(path);
  assert.equal(report.badLineCount, 0);
  assert.equal(blocks.length, 1 + 2 * count);
  assert.equal(new Set(blocks.map(({ id }) => id)).size, blocks.length);
  assert.deepEqual(blocks.map(({ id }) => id).sort(), expectedIds.sort());
  assert.deepEqual(blocks.map(({ parent }) => parent), [null, ...blocks.slice(0, -1).map(({ id }) => id)]);
  const { stdout } = await exec(python, ['-B', writer, 'read', path]);
  assert.deepEqual(JSON.parse(stdout), blocks);
});

test('bidirectional format interop with the existing Python tool', {
  skip: !process.env.FACTS_LEDGER_PYTHON_TOOL && 'set FACTS_LEDGER_PYTHON_TOOL to decision_log.py',
}, async (t) => {
  const path = logPath(t);
  const first = appendBlock(path, {
    ...fixture, schema: 2, facts: [{ claim: 'synthetic fact' }],
    token_usage: { model: 'fixture', task: 'interop', input: 2, output: 1, measured: false },
  });
  const tool = process.env.FACTS_LEDGER_PYTHON_TOOL;
  const script = `
import json, runpy, sys
from pathlib import Path
tool = runpy.run_path(sys.argv[1])
path = Path(sys.argv[2])
before, = tool["query_blocks"](log_path=path)
after = tool["add_block"]("python fixture", "verify format", project="fixture",
                          agent="python-fixture", status="done", log_path=path)
print(json.dumps([before, tool["format_block"](before), after]))
`;
  const { stdout } = await exec(python, ['-B', '-c', script, tool, path]);
  const [before, formatted, after] = JSON.parse(stdout);
  assert.deepEqual(before, first);
  assert.ok(formatted.includes(first.intent));
  assert.equal(after.parent, first.id);
  assert.deepEqual(read(path), {
    blocks: [first, after], report: { badLineCount: 0, badLineNumbers: [] },
  });
});

test('treats UTF-8 BOM lines as bad lines and normalizes explicit undefined/empty supersedes', (t) => {
  const path = logPath(t);
  const first = appendBlock(path, {
    ...fixture,
    actions: undefined,
    verification: undefined,
    touches: undefined,
    supersedes: undefined,
  });
  assert.deepEqual(first.actions, []);
  assert.deepEqual(first.touches, []);
  assert.equal(first.verification, null);
  assert.equal(first.supersedes, null);
  assert.throws(() => appendBlock(path, { ...fixture, supersedes: '' }), /Unknown block/);

  const bomLine = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(first) + '\n')]);
  writeFileSync(path, bomLine);
  assert.deepEqual(read(path), { blocks: [], report: { badLineCount: 1, badLineNumbers: [1] } });

  // Lone surrogates encode identically as U+FFFD in UTF-8 and must compare equal (total order).
  assert.equal(compareBytewise('\uD800', '\uD801'), 0);
  assert.equal(compareBytewise('\uD801', '\uD800'), 0);
});

test('appendBlock enforces optional expectedLog precondition under the writer lock without side effects on mismatch', (t) => {
  const path = logPath(t);
  const sha = (buf) => createHash('sha256').update(buf).digest('hex');

  // Expecting an existing log when absent throws without creating the file.
  assert.throws(
    () => appendBlock(path, fixture, { expectedLog: { size: 10, sha256: '0'.repeat(64) } }),
    /precondition failed.*absent/,
  );
  assert.equal(existsSync(path), false, 'failed existing-log precondition must not create file');

  // Expecting absent succeeds when absent and creates the file with the block.
  const first = appendBlock(path, fixture, { expectedLog: 'absent' });
  const afterFirst = readFileSync(path);
  assert.equal(first.parent, null);

  // Expecting absent now fails because the file exists, without modifying it.
  assert.throws(
    () => appendBlock(path, fixture, { expectedLog: 'absent' }),
    /precondition failed.*already exists/,
  );
  assert.deepEqual(readFileSync(path), afterFirst);

  // Expecting wrong size or wrong hash fails without appending.
  assert.throws(
    () => appendBlock(path, fixture, { expectedLog: { size: afterFirst.length + 1, sha256: sha(afterFirst) } }),
    /precondition failed/,
  );
  assert.throws(
    () => appendBlock(path, fixture, { expectedLog: { size: afterFirst.length, sha256: 'f'.repeat(64) } }),
    /precondition failed/,
  );
  assert.deepEqual(readFileSync(path), afterFirst);

  // Matching size and sha256 appends cleanly through the same descriptor.
  const second = appendBlock(path, fixture, {
    expectedLog: { size: afterFirst.length, sha256: sha(afterFirst) },
  });
  assert.equal(second.parent, first.id);
  assert.deepEqual(read(path).blocks, [first, second]);

  // Empty existing file also fails expectedLog: 'absent'.
  const emptyPath = logPath(t);
  writeFileSync(emptyPath, '');
  assert.throws(
    () => appendBlock(emptyPath, fixture, { expectedLog: 'absent' }),
    /precondition failed.*already exists/,
  );
  assert.equal(readFileSync(emptyPath).length, 0);
});

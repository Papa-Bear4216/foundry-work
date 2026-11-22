// TEST ONLY: unit tests of the foundry command line with synthetic values.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { DEFAULT_TIMEOUTS, parseCommandLine } from '../dist/args.js';
import { resolveHome } from '../dist/cli.js';
import { MAX_NAMES_PER_CALL, nameSlices, summarise } from '../dist/commands.js';
import { chunkPlainText, DERIVER_VERSION, itemText, loadProjection } from '../dist/derive.js';
import { CliError, debugText, errorLine, mapError } from '../dist/errors.js';
import { acquireLock, isProcessAlive } from '../dist/lock.js';
import { LineEditor, readTwoSecrets, stripOneLineEnding } from '../dist/secrets.js';
import { scratch, stdinFile } from './helpers.mjs';
import { closeSync } from 'node:fs';

const parse = (argv, env = {}) => parseCommandLine(argv, env);

test('location rule: --vault, then FOUNDRY_HOME, then <home>/Foundry', () => {
  assert.equal(resolveHome('somewhere', { FOUNDRY_HOME: 'other' }), resolve('somewhere'));
  assert.equal(resolveHome(undefined, { FOUNDRY_HOME: 'other' }), resolve('other'));
  assert.equal(resolveHome(undefined, { FOUNDRY_HOME: '' }), join(homedir(), 'Foundry'));
  assert.equal(resolveHome(undefined, {}), join(homedir(), 'Foundry'));
  // FOUNDRY_HOME is not a secret-looking name: the guard accepts it.
  assert.equal(parse(['vault', 'verify'], { FOUNDRY_HOME: 'x' }).command, 'vault verify');
});

test('commands, default timeouts, --timeout bounds and filters', () => {
  assert.deepEqual(DEFAULT_TIMEOUTS, {
    'init': 120, 'vault reset-passphrase': 120, 'search': 120, 'vault verify': 3600, 'import': 21600, 'index rebuild': 21600,
  });
  for (const [argv, command] of [[['init'], 'init'], [['import', 'a.zip'], 'import'], [['search', 'q'], 'search'],
    [['vault', 'verify'], 'vault verify'], [['index', 'rebuild'], 'index rebuild'],
    [['vault', 'reset-passphrase'], 'vault reset-passphrase']]) {
    const parsed = parse(argv);
    assert.equal(parsed.command, command);
    assert.equal(parsed.timeoutSeconds, DEFAULT_TIMEOUTS[command]);
  }
  assert.equal(parse(['vault', 'verify', '--timeout', '1']).timeoutSeconds, 1);
  assert.equal(parse(['vault', 'verify', '--timeout', '604800']).timeoutSeconds, 604800);
  for (const bad of ['0', '604801', '1.5', '-3', 'abc']) {
    assert.throws(() => parse(['vault', 'verify', '--timeout', bad]), e => e instanceof CliError && e.exit === 1);
  }
  const search = parse(['search', 'hello world', '--from', '2024-01-01', '--until', '2025-01-01', '--source', 's',
    '--profile', 'me', '--collection', 'c', '--tier', 'public', '--limit', '5', '--json', '--recovery-key-stdin']);
  assert.deepEqual(search.filters, { from: '2024-01-01', until: '2025-01-01', source: 's', profile: 'me', collection: 'c', tier: 'public', limit: 5 });
  assert.equal(search.query, 'hello world');
  assert.equal(search.json, true);
  assert.equal(search.recoveryKeyStdin, true);
  assert.equal(parse(['import', 'x.zip', '--vault', 'h']).vault, 'h');
  assert.deepEqual(parse(['--help']), { kind: 'help' });
  assert.deepEqual(parse(['search', '--help']), { kind: 'help', command: 'search' });
  assert.deepEqual(parse(['--version']), { kind: 'version' });
});

test('usage errors exit 1 and never quote argv text', () => {
  const marker = 'TEST-ONLY-ARGV-MARKER';
  const cases = [
    [], ['frobnicate'], ['search'], ['import'], ['vault', 'verify', '--json', `--x${marker}`],
    ['search', 'q', '--limit', '0'], ['search', 'q', '--limit', '1001'], ['search', 'q', '--from', marker],
    ['import', 'a', '--passphrase-stdin', '--recovery-key-stdin'], ['init', '--json'], ['vault', 'verify', '--timeout'],
  ];
  for (const argv of cases) {
    assert.throws(() => parse(argv), error => {
      assert.ok(error instanceof CliError, `CliError for ${argv.join(' ')}`);
      assert.equal(error.exit, 1);
      assert.ok(!error.message.includes(marker));
      return true;
    });
  }
});

test('the secret guard runs first: secret options, extra positionals and secret environment names are refused', () => {
  for (const argv of [['init', '--passphrase', 'x'], ['search', 'q', '--recovery-key=x'], ['import', '--password', 'x', 'a'],
    ['vault', 'verify', 'surplus'], ['search', 'q', 'extra'], ['init', '--secret']]) {
    assert.throws(() => parse(argv), error => !(error instanceof CliError) && /secrets/iu.test(error.message));
  }
  for (const name of ['FOUNDRY_PASSPHRASE', 'FOUNDRY_RECOVERY_KEY', 'VAULT_TOKEN']) {
    assert.throws(() => parse(['vault', 'verify'], { [name]: 'x' }), /Secret environment variables/u);
  }
});

test('stdin secrets: exactly one trailing line ending is removed; two secrets are line 1 and line 2', t => {
  assert.equal(stripOneLineEnding('a\n'), 'a');
  assert.equal(stripOneLineEnding('a\r\n'), 'a');
  assert.equal(stripOneLineEnding('a\n\n'), 'a\n');
  assert.equal(stripOneLineEnding('a'), 'a');
  assert.equal(stripOneLineEnding('\n'), '');
  const dir = scratch(t);
  for (const [input, first, second] of [['rk\npw\n', 'rk', 'pw'], ['rk\r\npw', 'rk', 'pw'], ['rk\n\n', 'rk', '']]) {
    const fd = stdinFile(dir, input);
    try {
      const [a, b] = readTwoSecrets(fd);
      assert.equal(a.toString(), first);
      assert.equal(b.toString(), second);
      assert.equal(a.byteOffset, 0, 'unpooled buffer');
      assert.equal(a.buffer.byteLength, a.length, 'own ArrayBuffer, safe to transfer');
    } finally {
      closeSync(fd);
    }
  }
  for (const input of ['only-one-line', 'a\nb\nc\n']) {
    const fd = stdinFile(dir, input);
    try {
      assert.throws(() => readTwoSecrets(fd), e => e instanceof CliError && e.exit === 1);
    } finally {
      closeSync(fd);
    }
  }
});

test('prompt line editor: enter, backspace by code point, escape sequences, abort, wipe', () => {
  const editor = new LineEditor();
  assert.equal(editor.feed(Buffer.from('abé')), 'more');
  assert.equal(editor.feed(Buffer.from([0x7f])), 'more'); // removes the two-byte é
  assert.equal(editor.feed(Buffer.from('\x1b[D\x1bOAc\x01')), 'more'); // arrow keys and Ctrl-A are ignored
  assert.equal(editor.feed(Buffer.from('\r')), 'done');
  const taken = editor.take();
  assert.equal(taken.toString(), 'abc');
  const aborting = new LineEditor();
  assert.equal(aborting.feed(Buffer.from('x\x03')), 'abort');
  assert.equal(new LineEditor().feed(Buffer.from([0x04])), 'abort');
});

test('error mapping: typed codes give one fixed line; messages of library errors are never printed', () => {
  const marker = 'TEST-ONLY-MESSAGE-MARKER';
  const typed = (name, code) => Object.assign(new Error(marker), { name, code });
  const cases = [
    [typed('VaultFormatError', 'AUTH'), 'AUTH'], [typed('VaultFormatError', 'INVENTORY'), 'INVENTORY'],
    [typed('IndexError', 'PROJECTION'), 'PROJECTION'], [typed('ArchiveError', 'CRC_MISMATCH'), 'CRC_MISMATCH'],
    [typed('ImportError', 'BUSY'), 'BUSY'], [Object.assign(new Error(marker), { code: 'ENOSPC' }), 'IO'],
    [new Error('Invalid recovery key format.'), 'RECOVERY_KEY_FORMAT'], [new TypeError(marker), 'INTERNAL'],
    [new CliError('TIMEOUT', 'passed its limit'), 'TIMEOUT'],
  ];
  for (const [error, code] of cases) {
    const mapped = mapError(error);
    assert.equal(mapped.code, code);
    assert.equal(mapped.exit, 2);
    const line = errorLine(mapped);
    assert.match(line, /^foundry: [^\n]+ \[[A-Z_]+\]\n$/u);
    assert.ok(!line.includes(marker));
  }
  assert.match(mapError(typed('VaultFormatError', 'ERASED'), { erasedInImport: true }).message,
    /a collection in this archive was erased; it is not imported again/u);
  const debug = debugText(new Error('contains TEST ONLY secret value and line2'), ['TEST ONLY secret value\nline2']);
  assert.ok(!debug.includes('TEST ONLY secret value') && !debug.includes('line2'));
});

test('lock: exclusive, BUSY names the holder, stale lock of a dead process is recovered, other host is never stale', t => {
  const dir = scratch(t);
  const path = join(dir, 'foundry.lock');
  const held = acquireLock(path, 'import', () => assert.fail('no notice'));
  const content = JSON.parse(readFileSync(path, 'utf8'));
  assert.deepEqual(Object.keys(content).sort(), ['command', 'host', 'pid', 'started']);
  assert.equal(content.pid, process.pid);
  assert.throws(() => acquireLock(path, 'search', () => {}), e => e.code === 'BUSY'
    && e.message.includes(String(process.pid)) && e.message.includes('import') && e.message.includes(content.started));
  held.release();
  assert.equal(existsSync(path), false);

  // A process that has exited: its pid is not alive, so its lock is stale.
  const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
  const deadPid = Number(child.stdout);
  assert.equal(isProcessAlive(deadPid), false);
  writeFileSync(path, JSON.stringify({ pid: deadPid, command: 'import', started: '2026-01-01T00:00:00.000Z', host: content.host }));
  const notices = [];
  const recovered = acquireLock(path, 'search', line => notices.push(line));
  assert.equal(notices.length, 1);
  assert.match(notices[0], /recovered a stale lock/u);
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).command, 'search');
  recovered.release();

  writeFileSync(path, JSON.stringify({ pid: deadPid, command: 'import', started: '2026-01-01T00:00:00.000Z', host: 'test-only-other-host' }));
  assert.throws(() => acquireLock(path, 'search', () => {}), e => e.code === 'BUSY' && /another computer/u.test(e.message));
  // An unreadable lock is BUSY while it is young (it may be being written).
  writeFileSync(path, '');
  assert.throws(() => acquireLock(path, 'search', () => {}), e => e.code === 'BUSY');
});

test('import summary counts every item once (design 4a.3 step 5) and names are sliced by 4,096', () => {
  const result = (imported, skipped, errored, errors = [], missing = []) => ({
    partsCount: 2, parts: ['p1', 'p2'], countsBySource: {}, unrecognisedEntries: ['x'], itemErrors: errors,
    totalItemsImported: imported, totalItemsSkipped: skipped, totalItemsErrored: errored, totalItemsDeferred: 0,
    missingCollections: missing, totalBlobsWritten: 0, totalBlobsDeduplicated: 0, totalEventsWritten: 0, totalBytesStored: 0,
  });
  const tooLarge = { code: 'ITEM_TOO_LARGE' };
  // Run A: 3 imported, 2 already present, 1 error, 4 deferred. Run B: 4 imported, 5 skipped (3 from A + 2 present), 1 error.
  const summary = summarise(result(3, 3, 1, [tooLarge], ['c']), result(4, 6, 1, [tooLarge]), 2);
  assert.equal(summary.itemsAdded, 7);
  assert.equal(summary.itemsAlreadyPresent, 2);
  assert.equal(summary.itemsSkipped, 1);
  assert.deepEqual(summary.skippedByReason, { ITEM_TOO_LARGE: 1 });
  assert.equal(summary.collectionsCreated, 2);
  assert.equal(summary.runs, 2);
  assert.equal(summary.itemsAdded + summary.itemsAlreadyPresent + summary.itemsSkipped, 10);
  assert.equal(MAX_NAMES_PER_CALL, 4096);
  const names = Array.from({ length: 9000 }, (_, i) => `google-takeout/mail/${i}`);
  assert.deepEqual(nameSlices(names).map(slice => slice.length), [4096, 4096, 808]);
  assert.deepEqual(nameSlices([]), []);
});

test('search text deriver: mail, contact, calendar and plain text give chunks; other types none', async () => {
  const projection = await loadProjection();
  assert.equal(projection.version, DERIVER_VERSION);
  assert.notEqual(DERIVER_VERSION, 1);
  const parsers = await import('importers');
  const mail = Buffer.from(`From: TEST ONLY <${parsers.syntheticEmail('sender')}>\r\nSubject: Synthetic quarterly\r\n\r\nTEST ONLY body words\r\n`);
  assert.match(itemText(parsers, 'message/rfc822', mail), /Subject: Synthetic quarterly[\s\S]*TEST ONLY body words/u);
  const card = Buffer.from('BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Given9 Family9\r\nEND:VCARD\r\n');
  assert.match(itemText(parsers, 'text/vcard', card), /Given9 Family9/u);
  const ics = Buffer.from('BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Synthetic planning\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n');
  assert.match(itemText(parsers, 'text/calendar', ics), /Event: Synthetic planning/u);
  assert.equal(itemText(parsers, 'text/plain; charset=utf-8', Buffer.from('plain words')), 'plain words');
  assert.equal(itemText(parsers, 'image/png', Buffer.from('x')), undefined);
  const frames = [card.subarray(0, 10), card.subarray(10)];
  assert.deepEqual([...projection.derive({ itemId: 'i', eventSeq: 1, mime: 'text/vcard', source: 's' }, frames)].length > 0, true);
  assert.deepEqual([...projection.derive({ itemId: 'i', eventSeq: 1, mime: 'image/png', source: 's' }, [card])], []);
  const long = chunkPlainText('word '.repeat(1000));
  assert.ok(long.length > 1 && long.every(chunk => chunk.length <= 800));
  assert.equal(chunkPlainText('x'.repeat(800 * 1100)).length, 1024);
});

// TEST ONLY: unit tests of the foundry command line with synthetic values.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { homedir, hostname } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { DEFAULT_TIMEOUTS, parseCommandLine } from '../dist/args.js';
import { resolveHome, runCli } from '../dist/cli.js';
import {
  MAX_NAMES_PER_CALL, nameSlices, resolveArchiveParts, sameStamps, stampParts, summarise,
} from '../dist/commands.js';
import {
  chunkPlainText, DERIVER_VERSION, itemText, loadProjection, MAX_DERIVE_BYTES, MAX_TEXT_BYTES,
} from '../dist/derive.js';
import { CliError, debugText, errorLine, mapError } from '../dist/errors.js';
import { acquireLock, isProcessAlive } from '../dist/lock.js';
import { LineEditor, readTwoSecrets, stripOneLineEnding } from '../dist/secrets.js';
import { cleanEnv, scratch, stdinFile } from './helpers.mjs';
import { closeSync, readdirSync } from 'node:fs';

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
    'init': 120,
    'vault reset-passphrase': 120,
    'search': 120,
    'profile add': 120,
    'profile list': 120,
    'consent record': 120,
    'consent list': 120,
    'collection prompt-policy': 120,
    'collection list': 120,
    'vault verify': 3600,
    'import': 21600,
    'index rebuild': 21600,
    // P-3 second-copy commands.
    'vault copy init': 120,
    'vault status': 120,
    'vault schedule set': 120,
    'vault schedule status': 120,
    'vault schedule remove': 120,
    'vault reminder': 3600,
    'vault seal': 21600,
    'vault session': 21600,
    'vault export-iso': 21600,
  });
  for (const [argv, command] of [
    [['init'], 'init'],
    [['import', 'a.zip'], 'import'],
    [['search', 'q'], 'search'],
    [['vault', 'verify'], 'vault verify'],
    [['index', 'rebuild'], 'index rebuild'],
    [['vault', 'reset-passphrase'], 'vault reset-passphrase'],
    [['profile', 'add', 'me'], 'profile add'],
    [['profile', 'list'], 'profile list'],
    [['consent', 'record', 'partner', '--basis', 'exported-by-them'], 'consent record'],
    [['consent', 'list'], 'consent list'],
    [['collection', 'prompt-policy', 'child/google-takeout/mail/2024', '--child-prompts', 'on'], 'collection prompt-policy'],
    [['collection', 'list'], 'collection list'],
  ]) {
    const parsed = parse(argv);
    assert.equal(parsed.command, command);
    assert.equal(parsed.timeoutSeconds, DEFAULT_TIMEOUTS[command]);
  }
  const pAdd = parse(['profile', 'add', 'partner', '--display-name', 'Partner Label', '--json']);
  assert.equal(pAdd.targetProfile, 'partner');
  assert.equal(pAdd.displayName, 'Partner Label');
  assert.equal(pAdd.json, true);

  const cRec = parse(['consent', 'record', 'child', '--basis', 'parent-or-guardian', '--note', 'Guardian export']);
  assert.equal(cRec.targetProfile, 'child');
  assert.equal(cRec.basis, 'parent-or-guardian');
  assert.equal(cRec.note, 'Guardian export');

  const pol = parse(['collection', 'prompt-policy', 'child/google-takeout/mail/2024', '--child-prompts', 'off']);
  assert.equal(pol.targetCollection, 'child/google-takeout/mail/2024');
  assert.equal(pol.childPrompts, false);

  const imp = parse(['import', 'archive.zip', '--profile', 'partner', '--collection', 'partner/custom/2024']);
  assert.equal(imp.importProfile, 'partner');
  assert.equal(imp.importCollection, 'partner/custom/2024');
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
    ['profile'], ['profile', 'add'], ['consent', 'record'], ['consent', 'record', 'partner'],
    ['collection', 'prompt-policy'], ['collection', 'prompt-policy', 'child/a/2024'],
    ['collection', 'prompt-policy', 'child/a/2024', '--child-prompts', marker],
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
    ['vault', 'verify', 'surplus'], ['search', 'q', 'extra'], ['init', '--secret'],
    ['profile', 'add', 'me', 'surplus-secret'], ['profile', 'list', 'surplus-secret'],
    ['consent', 'record', 'partner', 'surplus-secret', '--basis', 'other'],
    ['consent', 'list', 'surplus-secret'],
    ['collection', 'prompt-policy', 'child/a/2024', 'surplus-secret', '--child-prompts', 'on'],
    ['collection', 'list', 'surplus-secret']]) {
    assert.throws(() => parse(argv), error => !(error instanceof CliError) && /secrets/iu.test(error.message));
  }
  for (const name of ['FOUNDRY_PASSPHRASE', 'FOUNDRY_RECOVERY_KEY', 'VAULT_TOKEN']) {
    assert.throws(() => parse(['vault', 'verify'], { [name]: 'x' }), /Secret environment variables/u);
  }
});

test('stdin secrets: exactly one trailing line ending is removed; two secrets are line 1 and line 2', async t => {
  assert.equal(stripOneLineEnding('a\n'), 'a');
  assert.equal(stripOneLineEnding('a\r\n'), 'a');
  assert.equal(stripOneLineEnding('a\n\n'), 'a\n');
  assert.equal(stripOneLineEnding('a'), 'a');
  assert.equal(stripOneLineEnding('\n'), '');
  const dir = scratch(t);
  for (const [input, first, second] of [['rk\npw\n', 'rk', 'pw'], ['rk\r\npw', 'rk', 'pw'], ['rk\n\n', 'rk', '']]) {
    const fd = stdinFile(dir, input);
    try {
      const [a, b] = await readTwoSecrets(fd);
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
      await assert.rejects(readTwoSecrets(fd), e => e instanceof CliError && e.exit === 1);
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
    [typed('ImportError', 'BUSY'), 'BUSY'],
    [typed('ProfileError', 'INVALID_PROFILE'), 'INVALID_PROFILE'],
    [typed('ProfileError', 'CONSENT_REQUIRED'), 'CONSENT_REQUIRED'],
    [typed('ProfileError', 'CONSENT_NOT_APPLICABLE'), 'CONSENT_NOT_APPLICABLE'],
    [typed('ProfileError', 'INVALID_COLLECTION'), 'INVALID_COLLECTION'],
    [Object.assign(new Error(marker), { code: 'ENOSPC' }), 'IO'],
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
  // An unreadable lock is BUSY (see the next test for an old one).
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

test('calendar search text: the calendar name once per item, at most 1 MiB of text per item', async () => {
  const parsers = await import('importers');
  const name = `TEST ONLY Zebracalname ${'n'.repeat(4096)}`;
  const ics = parsers.generateSyntheticIcalendar(1000, 303, name);
  const text = itemText(parsers, 'text/calendar', ics);
  assert.equal(text.split('Zebracalname').length - 1, 1, 'the calendar name is rendered once');
  assert.ok(Buffer.byteLength(text) <= MAX_TEXT_BYTES, `rendered ${Buffer.byteLength(text)} bytes`);
  assert.match(text, /Event: Synthetic [a-z]+ session #1\n/u);
  assert.match(text, /Event: Synthetic [a-z]+ session #1000\n/u, 'every event fits: the name is not repeated');
  // Far more events than fit: the text stops at the cap (whole UTF-8 characters only).
  const many = parsers.generateSyntheticIcalendar(6000, 304, 'TEST ONLY \u{1F600} calendar');
  const capped = itemText(parsers, 'text/calendar', many);
  assert.ok(Buffer.byteLength(capped) <= MAX_TEXT_BYTES);
  assert.ok(Buffer.byteLength(capped) > MAX_TEXT_BYTES - 4096, 'text is added up to the cap');
  assert.ok(!/[\uD800-\uDBFF]$/u.test(capped), 'no split surrogate pair');
  assert.equal(MAX_TEXT_BYTES, 1024 * 1024);
  // The cap applies to every type: a long mail body.
  const mail = Buffer.from(`Subject: TEST ONLY long body\r\n\r\n${'body words '.repeat(200_000)}\r\n`);
  assert.ok(Buffer.byteLength(itemText(parsers, 'message/rfc822', mail)) <= MAX_TEXT_BYTES);
});

test('search text budget: for every MIME type (mail, vCard, plain text, calendar) the derived chunks of multibyte input stay at or under 1 MiB of UTF-8', async () => {
  const projection = await loadProjection();
  const wide = '\u{1F600}\u{1F680} '; // two 4-byte characters and a space: 9 UTF-8 bytes, 5 UTF-16 code units
  const words = count => wide.repeat(count);
  const cases = [
    ['message/rfc822', Buffer.from('Subject: TEST ONLY wide mail\r\nContent-Type: text/plain; charset=utf-8\r\n'
      + `Content-Transfer-Encoding: 8bit\r\n\r\n${words(400_000)}\r\n`)],
    ['text/vcard', Buffer.from(`BEGIN:VCARD\r\nVERSION:3.0\r\nFN:TEST ONLY Wide\r\nNOTE:${words(400_000)}\r\nEND:VCARD\r\n`)],
    ['text/plain; charset=utf-8', Buffer.from(words(400_000))],
    ['text/calendar', Buffer.from('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:test-only-wide\r\n'
      + `SUMMARY:TEST ONLY wide\r\nDESCRIPTION:${words(400_000)}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n`)],
  ];
  for (const [mime, bytes] of cases) {
    assert.ok(bytes.length > 2 * MAX_TEXT_BYTES && bytes.length < MAX_DERIVE_BYTES, `${mime}: input of ${bytes.length} bytes`);
    const chunks = [...projection.derive({ itemId: 'i', eventSeq: 1, mime, source: 's' }, [bytes])];
    const total = chunks.reduce((sum, chunk) => sum + Buffer.byteLength(chunk), 0);
    assert.ok(total <= MAX_TEXT_BYTES, `${mime}: ${total} bytes of search text`);
    // Positive control: the text really reaches the cap (no parser or chunk limit stops it earlier).
    assert.ok(total > MAX_TEXT_BYTES - 8192, `${mime}: only ${total} bytes of search text`);
    assert.ok(chunks.every(chunk => !/[\uD800-\uDBFF]$|^[\uDC00-\uDFFF]/u.test(chunk)), `${mime}: no split surrogate pair`);
  }
});

test('M1: mail search text is byte-identical to the old line-by-line rendering (normal, cut at a multi-byte character, no body)', async () => {
  const parsers = await import('importers');
  const person = a => (a.name ? `${a.name} <${a.address}>` : a.address);
  // The old algorithm (before fix round 2), rebuilt here: one budget piece per head line, '\n' before every line
  // after the first, each piece cut at the remaining bytes and moved back to a character start.
  const oldMailText = bytes => {
    const mail = parsers.parseEmailMessage(bytes);
    const head = [`Subject: ${mail.subject}`];
    if (mail.from.length > 0) head.push(`From: ${mail.from.map(person).join(', ')}`);
    if (mail.to.length > 0) head.push(`To: ${mail.to.map(person).join(', ')}`);
    if (mail.cc.length > 0) head.push(`Cc: ${mail.cc.map(person).join(', ')}`);
    if (mail.date) head.push(`Date: ${mail.date}`);
    if (mail.labels.length > 0) head.push(`Labels: ${mail.labels.join(', ')}`);
    if (mail.attachments.length > 0) head.push(`Attachments: ${mail.attachments.map(a => a.filename).join(', ')}`);
    if (mail.bodyText) head.push('', mail.bodyText);
    const pieces = [];
    let left = MAX_TEXT_BYTES;
    head.forEach((line, i) => {
      if (left <= 0) return;
      const piece = (i > 0 ? '\n' : '') + line;
      const size = Buffer.byteLength(piece);
      if (size <= left) { pieces.push(piece); left -= size; return; }
      const cutHead = Buffer.from(piece.slice(0, left), 'utf8');
      let cut = Math.min(left, cutHead.length);
      while (cut > 0 && cut < cutHead.length && (cutHead[cut] & 0xc0) === 0x80) cut--;
      pieces.push(cutHead.subarray(0, cut).toString('utf8'));
      left = 0;
    });
    return pieces.join('');
  };
  const headLines = `From: TEST ONLY <${parsers.syntheticEmail('m1-sender')}>\r\nTo: <${parsers.syntheticEmail('m1-to')}>\r\n`
    + 'Cc: TEST ONLY Copy <' + parsers.syntheticEmail('m1-cc') + '>\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\n'
    + 'Subject: TEST ONLY M1 éè mail\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n';
  // (a) a normal mail.
  const normal = Buffer.from(`${headLines}\r\nTEST ONLY body line one\r\nline two \u{1F600}\r\n`);
  const a = itemText(parsers, 'message/rfc822', normal);
  assert.equal(a, oldMailText(normal));
  assert.match(a, /^Subject: TEST ONLY M1[\s\S]*From: [\s\S]*\n\nTEST ONLY body line one/u);
  // (b) head plus body crosses MAX_TEXT_BYTES; the 4-byte characters make the cap fall inside one character for at
  // least one of the four paddings.
  let cutInside = 0;
  for (let pad = 0; pad < 4; pad++) {
    const big = Buffer.from(`${headLines}\r\n${'a'.repeat(pad)}${'\u{1F600}'.repeat(300_000)}\r\n`);
    const expected = oldMailText(big);
    const got = itemText(parsers, 'message/rfc822', big);
    assert.equal(Buffer.from(got).equals(Buffer.from(expected)), true, `pad ${pad}: byte-identical`);
    assert.ok(Buffer.byteLength(got) <= MAX_TEXT_BYTES && Buffer.byteLength(got) > MAX_TEXT_BYTES - 4);
    assert.ok(!/[\uD800-\uDBFF]$/u.test(got), `pad ${pad}: no split surrogate pair`);
    if (Buffer.byteLength(got) < MAX_TEXT_BYTES) cutInside++;
  }
  assert.ok(cutInside >= 1, 'at least one case cuts inside a multi-byte character');
  // (c) a mail with no body.
  const empty = Buffer.from(`${headLines}\r\n`);
  const c = itemText(parsers, 'message/rfc822', empty);
  assert.equal(c, oldMailText(empty));
  assert.ok(!c.endsWith('\n'), 'no body: no blank separator line');
});

test('calendar search text: the 8 MiB input cut keeps the completed fields of a truncated first event', async () => {
  const projection = await loadProjection();
  const head = Buffer.from('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nX-WR-CALNAME:TEST ONLY cut calendar\r\nBEGIN:VEVENT\r\n'
    + 'UID:test-only-cut\r\nSUMMARY:Earlysummaryword planning\r\nLOCATION:Room é\r\nDESCRIPTION:');
  const filler = Buffer.alloc(MAX_DERIVE_BYTES, 'filler é ');
  const tail = Buffer.from('\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n');
  const item = { itemId: 'i', eventSeq: 1, mime: 'text/calendar', source: 's' };
  const chunks = [...projection.derive(item, [head, filler.subarray(0, 4_000_000), filler.subarray(4_000_000), tail])];
  const text = chunks.join('\n');
  assert.match(text, /Event: Earlysummaryword planning/u);
  assert.match(text, /Location: Room é/u);
  assert.match(text, /Calendar: TEST ONLY cut calendar/u);
  assert.doesNotMatch(text, /Description:/u, 'the cut field is not completed, so it is left out');
  // Not truncated: the same event with a short description keeps it.
  const whole = [...projection.derive(item, [head, Buffer.from('short words'), tail])].join('\n');
  assert.match(whole, /Description: short words/u);
});

test('one failure line: guidance goes into the same line before the code; part stamps notice a removed part', async t => {
  assert.equal(errorLine({ code: 'IO', message: 'a file operation failed (EIO)', exit: 2 }, ['first hint', 'second hint']),
    'foundry: a file operation failed (EIO); first hint; second hint [IO]\n');
  assert.equal(errorLine({ code: 'AUTH', message: 'wrong', exit: 2 }), 'foundry: wrong [AUTH]\n');

  const dir = scratch(t);
  for (const name of ['takeout-x-001.zip', 'takeout-x-002.zip', 'takeout-y-001.zip', 'notes.zip']) writeFileSync(join(dir, name), name);
  const parts = await resolveArchiveParts(join(dir, 'takeout-x-001.zip'));
  assert.equal(parts.kind, 'set');
  assert.deepEqual(parts.files, [join(dir, 'takeout-x-001.zip'), join(dir, 'takeout-x-002.zip')]);
  assert.equal((await resolveArchiveParts(join(dir, 'takeout-y-001.zip'))).kind, 'file');
  assert.equal((await resolveArchiveParts(dir)).files.length, 4);
  const before = await stampParts(parts);
  assert.ok(sameStamps(before, await stampParts(await resolveArchiveParts(join(dir, 'takeout-x-001.zip')))));
  rmSync(join(dir, 'takeout-x-002.zip'));
  assert.ok(!sameStamps(before, await stampParts(await resolveArchiveParts(join(dir, 'takeout-x-001.zip')))));
});

function deadPid() {
  const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], { encoding: 'utf8' });
  const pid = Number(child.stdout);
  assert.equal(isProcessAlive(pid), false);
  return pid;
}

test("lock recovery: two contenders against one stale lock; only one proceeds and the winner's lock survives", t => {
  const dir = scratch(t);
  const path = join(dir, 'foundry.lock');
  const stale = { pid: deadPid(), command: 'import', started: '2026-01-01T00:00:00.000Z', host: hostname() };
  writeFileSync(path, JSON.stringify(stale));
  // Contender B has read the dead holder. Before B acts on it, contender A recovers the same stale lock and takes it.
  let winner;
  const winnerNotices = [];
  const loserNotices = [];
  assert.throws(() => acquireLock(path, 'search', line => loserNotices.push(line), {
    afterHolderRead: () => {
      if (winner === undefined) winner = acquireLock(path, 'import', line => winnerNotices.push(line));
    },
  }), e => e.code === 'BUSY' && e.message.includes(`process ${process.pid}, import`));
  assert.equal(winnerNotices.length, 1, 'the winner recovered the stale lock');
  assert.deepEqual(loserNotices, [], 'the loser removed nothing');
  assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), winner.info, "the winner's live lock survives");
  assert.deepEqual(readdirSync(dir), ['foundry.lock'], 'no recovery file is left');
  winner.release();
  assert.equal(existsSync(path), false);

  // A recovery in progress (or one interrupted by a crash) blocks recovery: BUSY, and nothing is removed.
  writeFileSync(path, JSON.stringify(stale));
  writeFileSync(`${path}.recover`, JSON.stringify(stale));
  assert.throws(() => acquireLock(path, 'search', () => assert.fail('no notice')),
    e => e.code === 'BUSY' && /delete the file foundry\.lock\.recover in the Foundry folder/u.test(e.message) && !e.message.includes(dir));
  assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), stale);
  assert.ok(existsSync(`${path}.recover`));
});

test('lock: an unreadable lock gives BUSY naming the file and is never removed by age; a failed metadata write leaves no lock', t => {
  const dir = scratch(t);
  const path = join(dir, 'foundry.lock');
  writeFileSync(path, '{"pid":');
  const hourAgo = new Date(Date.now() - 3_600_000);
  utimesSync(path, hourAgo, hourAgo);
  assert.throws(() => acquireLock(path, 'search', () => assert.fail('no notice')), e => e.code === 'BUSY'
    && /the lock file foundry\.lock in the Foundry folder cannot be read/u.test(e.message)
    && /If no foundry command is running, delete that file/u.test(e.message) && !e.message.includes(dir));
  assert.equal(readFileSync(path, 'utf8'), '{"pid":', 'the unreadable lock is left as it was');

  const other = join(dir, 'second.lock');
  const failure = Object.assign(new Error(`TEST ONLY disk full at ${dir}`), { code: 'ENOSPC' });
  // A file-system error of the lock becomes fixed text with its code only (review item 14): no path, no message.
  const fixedEnospc = e => e instanceof CliError && e.code === 'IO'
    && e.message === 'a file operation on the Foundry folder or its lock file failed (ENOSPC)';
  assert.throws(() => acquireLock(other, 'import', () => {}, { writeMetadata: () => { throw failure; } }), fixedEnospc);
  assert.equal(existsSync(other), false, 'the file this command created is removed');
  const partial = join(dir, 'third.lock');
  assert.throws(() => acquireLock(partial, 'import', () => {}, {
    writeMetadata: fd => { writeFileSync(fd, '{"pid":1'); throw failure; },
  }), fixedEnospc);
  assert.equal(existsSync(partial), false, 'a half-written lock is removed too');
});

const NOT_REGULAR_LINE = 'a file operation on the Foundry folder or its lock file failed (not a regular file)';

test('lock path must be a regular file: a folder at the lock or recovery path gives BUSY with the fixed message, nothing opened or removed', async t => {
  const dir = scratch(t);
  const isNotRegular = e => e instanceof CliError && e.code === 'BUSY' && e.exit === 2 && e.message === NOT_REGULAR_LINE;

  // A folder at the lock path.
  const lockDir = join(dir, 'a', 'foundry.lock');
  mkdirSync(lockDir, { recursive: true });
  assert.throws(() => acquireLock(lockDir, 'search', () => assert.fail('no notice')), isNotRegular);
  assert.ok(statSync(lockDir).isDirectory(), 'the folder is kept');

  // A folder at the recovery path while a stale lock waits for recovery.
  const lockPath = join(dir, 'b', 'foundry.lock');
  mkdirSync(`${lockPath}.recover`, { recursive: true });
  const stale = { pid: deadPid(), command: 'import', started: '2026-01-01T00:00:00.000Z', host: hostname() };
  writeFileSync(lockPath, JSON.stringify(stale));
  assert.throws(() => acquireLock(lockPath, 'search', () => assert.fail('no notice')), isNotRegular);
  assert.deepEqual(JSON.parse(readFileSync(lockPath, 'utf8')), stale, 'the stale lock is not removed');
  assert.ok(statSync(`${lockPath}.recover`).isDirectory());

  // Through the command line: `init` on a home whose lock path is a folder. One fixed line, no path, also with --debug.
  const home = join(dir, 'home');
  mkdirSync(join(home, 'foundry.lock'), { recursive: true });
  for (const debug of [[], ['--debug']]) {
    let stderr = '';
    const fd = stdinFile(dir, 'TEST ONLY lock type passphrase\n');
    try {
      const code = await runCli(['init', '--vault', home, '--passphrase-stdin', ...debug], {
        inline: true, env: cleanEnv(), stdinFd: fd, isTerminal: () => false,
        stdout: () => assert.fail('no output'), stderr: text => { stderr += text; },
      });
      assert.equal(code, 2);
    } finally {
      closeSync(fd);
    }
    assert.ok(stderr.endsWith(`foundry: ${NOT_REGULAR_LINE} [BUSY]\n`), stderr);
    assert.ok(!stderr.includes(home), 'the home path is not echoed');
  }
  assert.deepEqual(readdirSync(home), ['foundry.lock'], 'no vault and no staging folder');
});

test('stdin flags refuse a terminal on stdin: exit 1 with a usage line before any read or lock', async t => {
  const dir = scratch(t);
  const home = join(dir, 'home');
  const cases = [
    [['init', '--vault', home, '--passphrase-stdin'], 'do not use --passphrase-stdin on a terminal; omit the flag to be prompted'],
    [['search', 'q', '--vault', home, '--recovery-key-stdin'], 'do not use --recovery-key-stdin on a terminal; omit the flag to be prompted'],
    [['import', 'x.zip', '--vault', home, '--passphrase-stdin'], 'do not use --passphrase-stdin on a terminal; omit the flag to be prompted'],
    [['vault', 'reset-passphrase', '--vault', home, '--recovery-key-stdin', '--passphrase-stdin'],
      'do not use --recovery-key-stdin and --passphrase-stdin on a terminal; omit the flags to be prompted'],
  ];
  for (const [argv, message] of cases) {
    let stderr = '';
    const asked = [];
    const code = await runCli(argv, {
      env: cleanEnv(), stdinFd: 0, isTerminal: fd => { asked.push(fd); return true; },
      stdout: () => assert.fail('no output'), stderr: text => { stderr += text; },
    });
    assert.equal(code, 1, argv.join(' '));
    assert.equal(stderr, `foundry: ${message} [USAGE]\n`);
    assert.deepEqual(asked, [0]);
    assert.equal(existsSync(home), false, 'nothing was created');
  }
  // Control: the same flag without a terminal on stdin goes ahead.
  const fd = stdinFile(dir, 'TEST ONLY terminal control passphrase\n');
  try {
    const code = await runCli(['init', '--vault', home, '--passphrase-stdin'], {
      inline: true, env: cleanEnv(), stdinFd: fd, isTerminal: () => false, stdout: () => {}, stderr: () => {},
    });
    assert.equal(code, 0);
  } finally {
    closeSync(fd);
  }
});

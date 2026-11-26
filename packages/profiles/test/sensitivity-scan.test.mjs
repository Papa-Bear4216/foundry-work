// TEST ONLY: P-1 fix round 1 session A tests for the windowed sensitivity scan (items 5, 6, 7).
// Every credential-shaped string is assembled at run time; nothing here is a real credential.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { test } from 'node:test';
// Namespace import: a missing export fails only the tests that use it, not the whole file.
import * as profiles from '../dist/index.js';

const AT_CHAR = String.fromCharCode(64);
const INVALID_DOMAIN = ['example', 'invalid'].join('.');
const BASE = { profile: 'me', collection: 'me/google-takeout/mail/2024', source: 'google-takeout/mail' };

function pemHeader() {
  return ['-----BEGIN', 'OPENSSH', 'PRIVATE', 'KEY-----'].join(' ');
}

function bearerHeader(value) {
  return `Authorization: ${['Bear', 'er'].join('')} ${value}`;
}

function realLookingTokenValue() {
  return ['Ab9Cd8Ef7Gh6Ij5K', 'l4Mn3Op2Qr1St0Uv'].join('.');
}

function databaseUri(password) {
  const proto = ['post', 'gresql', '://'].join('');
  return `${proto}db_reader:${password}${AT_CHAR}${['db-host', INVALID_DOMAIN].join('.')}:5432/synthetic_db`;
}

/** Filler text with no rule match: lowercase words and spaces only. */
function filler(bytes) {
  const unit = 'lorem ipsum dolor sit amet consectetur ';
  return Buffer.from(unit.repeat(Math.ceil(bytes / unit.length)).slice(0, bytes), 'utf8');
}

// ---------------------------------------------------------------------------------------------
// Upper bound of the UTF-8 byte length and UTF-16 code-unit length of any match of a regular
// expression. Supports the syntax the shipped patterns use; returns Infinity for `*`, `+`, `{n,}`.
// Width per atom: negated classes, `.`, `\S`, `\W`, `\D` may match any code point (4 bytes, 2 units);
// `\s` may match U+3000 or U+FEFF (3 bytes); under the `i` flag with `u`, ASCII letters may match
// U+212A KELVIN SIGN or U+017F LONG S (up to 3 bytes); other ASCII atoms are 1 byte.
// ---------------------------------------------------------------------------------------------
function maxMatchLength(re) {
  const src = re.source;
  const ci = re.flags.includes('i');
  let pos = 0;
  const letterWidth = () => (ci ? { bytes: 3, units: 1 } : { bytes: 1, units: 1 });
  const one = { bytes: 1, units: 1 };
  const any = { bytes: 4, units: 2 };
  const zero = { bytes: 0, units: 0 };
  const widest = (a, b) => ({ bytes: Math.max(a.bytes, b.bytes), units: Math.max(a.units, b.units) });

  function literalWidth(ch) {
    const code = ch.codePointAt(0);
    if (code > 0x7f) return { bytes: Buffer.byteLength(ch, 'utf8'), units: ch.length };
    if (/[A-Za-z]/u.test(ch)) return letterWidth();
    return one;
  }

  function escapeWidth(ch, inClass) {
    if (ch === 'b' || ch === 'B') {
      if (inClass) throw new Error('\\b in class unsupported');
      return zero;
    }
    if (ch === 'd') return one;
    if (ch === 'w') return letterWidth();
    if (ch === 's') return { bytes: 3, units: 1 };
    if (ch === 'D' || ch === 'W' || ch === 'S') return any;
    if (ch === 't' || ch === 'n' || ch === 'r') return one;
    if (/[A-Za-z0-9]/u.test(ch)) throw new Error(`unsupported escape \\${ch} in ${src}`);
    return one; // escaped punctuation
  }

  function parseClass() {
    pos++; // [
    let negated = false;
    if (src[pos] === '^') {
      negated = true;
      pos++;
    }
    let width = zero;
    while (src[pos] !== ']') {
      if (pos >= src.length) throw new Error('unterminated class');
      let ch = src[pos];
      if (ch === '\\') {
        width = widest(width, escapeWidth(src[pos + 1], true));
        pos += 2;
        continue;
      }
      width = widest(width, literalWidth(ch));
      pos++;
    }
    pos++; // ]
    return negated ? any : width;
  }

  function parseQuantifier() {
    const ch = src[pos];
    let min = 1;
    let max = 1;
    if (ch === '?') {
      min = 0;
      pos++;
    } else if (ch === '*' || ch === '+') {
      max = Infinity;
      pos++;
    } else if (ch === '{') {
      const m = /^\{(\d+)(?:(,)(\d*))?\}/u.exec(src.slice(pos));
      if (!m) return 1;
      min = Number(m[1]);
      max = m[2] === undefined ? min : m[3] === '' ? Infinity : Number(m[3]);
      pos += m[0].length;
    } else {
      return 1;
    }
    if (src[pos] === '?') pos++; // lazy
    void min;
    return max;
  }

  function parseAtom() {
    const ch = src[pos];
    if (ch === '(') {
      pos++;
      let lookaround = false;
      if (src[pos] === '?') {
        if (src.startsWith('?:', pos)) pos += 2;
        else if (src.startsWith('?=', pos) || src.startsWith('?!', pos)) {
          pos += 2;
          lookaround = true;
        } else if (src.startsWith('?<=', pos) || src.startsWith('?<!', pos)) {
          pos += 3;
          lookaround = true;
        } else if (src.startsWith('?<', pos)) {
          pos = src.indexOf('>', pos) + 1;
        } else throw new Error(`unsupported group in ${src}`);
      }
      const inner = parseAlternation();
      if (src[pos] !== ')') throw new Error('unbalanced group');
      pos++;
      return lookaround ? { width: zero, quantifiable: false } : { width: inner, quantifiable: true };
    }
    if (ch === '[') return { width: parseClass(), quantifiable: true };
    if (ch === '\\') {
      const w = escapeWidth(src[pos + 1], false);
      pos += 2;
      return { width: w, quantifiable: w.bytes > 0 };
    }
    if (ch === '.') {
      pos++;
      return { width: any, quantifiable: true };
    }
    if (ch === '^' || ch === '$') {
      pos++;
      return { width: zero, quantifiable: false };
    }
    const cp = String.fromCodePoint(src.codePointAt(pos));
    pos += cp.length;
    return { width: literalWidth(cp), quantifiable: true };
  }

  function parseSequence() {
    let total = zero;
    while (pos < src.length && src[pos] !== '|' && src[pos] !== ')') {
      const atom = parseAtom();
      const max = parseQuantifier();
      total = { bytes: total.bytes + atom.width.bytes * max, units: total.units + atom.width.units * max };
    }
    return total;
  }

  function parseAlternation() {
    let best = parseSequence();
    while (src[pos] === '|') {
      pos++;
      best = widest(best, parseSequence());
    }
    return best;
  }

  const result = parseAlternation();
  if (pos !== src.length) throw new Error(`unparsed tail in ${src}`);
  return result;
}

// One character of context on each side (lookbehind / `\b`), 4 bytes each.
const CONTEXT_HEADROOM_BYTES = 8;

test('A1: the bound calculator is real (unbounded runs give Infinity, bounded ones a number)', () => {
  assert.equal(maxMatchLength(/a+/u).bytes, Infinity);
  assert.equal(maxMatchLength(/[ \t]*x/u).bytes, Infinity);
  assert.equal(maxMatchLength(/a{2,}/u).bytes, Infinity);
  assert.deepEqual(maxMatchLength(/ab{0,3}/u), { bytes: 4, units: 4 });
  assert.deepEqual(maxMatchLength(/[^x]{2}/u), { bytes: 8, units: 4 });
  assert.deepEqual(maxMatchLength(/k/iu), { bytes: 3, units: 1 });
  assert.deepEqual(maxMatchLength(/(?<!a)b|cd/u), { bytes: 2, units: 2 });
});

test('A1: every shipped pattern has a bounded longest match shorter than SCAN_OVERLAP_BYTES', t => {
  const patterns = profiles.SHIPPED_SCAN_PATTERNS;
  assert.ok(Array.isArray(patterns) && patterns.length >= 14, 'SHIPPED_SCAN_PATTERNS must list every shipped pattern');
  assert.equal(profiles.SCAN_OVERLAP_BYTES, 4096);
  assert.equal(profiles.SCAN_WINDOW_BYTES, 65536);
  const ids = new Set();
  for (const { id, source, flags } of patterns) {
    const pattern = new RegExp(source, flags);
    ids.add(id);
    const { bytes, units } = maxMatchLength(pattern);
    t.diagnostic(`longest match ${id}: ${bytes} bytes, ${units} code units`);
    assert.ok(
      Number.isFinite(bytes) && bytes + CONTEXT_HEADROOM_BYTES <= profiles.SCAN_OVERLAP_BYTES,
      `${id}: longest match ${bytes} bytes must be < ${profiles.SCAN_OVERLAP_BYTES - CONTEXT_HEADROOM_BYTES}`,
    );
    assert.ok(units + 2 <= profiles.SCAN_OVERLAP_BYTES, `${id}: longest match ${units} code units`);
  }
  for (const id of [
    'private-key',
    'bearer-token',
    'api-token',
    'oauth-or-api-token',
    'database-credentials',
    'credential-assignment',
    'clinical-code',
    'clinical-lab',
    'clinical-record',
    'clinical-prescription',
    'national-id',
    'tax-document',
    'financial-account',
    'insurance-document',
  ]) {
    assert.ok(ids.has(id), `pattern ${id} missing from SHIPPED_SCAN_PATTERNS`);
  }
});

test('A1: the longest user keyword fits inside the window overlap', () => {
  // A keyword is at most MAX_RULE_PATTERN_BYTES UTF-8 bytes. Matching compares lowercased text, and one
  // code point may lowercase to at most 3 code points, each at most 4 bytes in the original text.
  assert.equal(profiles.MAX_RULE_PATTERN_BYTES, 256);
  assert.ok(profiles.MAX_RULE_PATTERN_BYTES * 3 * 4 + CONTEXT_HEADROOM_BYTES <= profiles.SCAN_OVERLAP_BYTES);
});

test('A1: a 4 MiB item with one credential in the middle is secret (bytes and string input)', () => {
  const size = 4 * 1024 * 1024;
  const big = filler(size);
  const marker = Buffer.from(`\n${pemHeader()}\n`, 'utf8');
  marker.copy(big, Math.floor(size / 2));
  const fromBytes = profiles.classifySensitivity({ ...BASE, plaintext: big });
  assert.deepEqual(fromBytes, { sensitivity: 'secret', rule: 'private-key' });
  const fromText = profiles.classifySensitivity({ ...BASE, text: big.toString('utf8') });
  assert.deepEqual(fromText, { sensitivity: 'secret', rule: 'private-key' });
  // Control: the same item without the marker is the source default.
  assert.equal(profiles.classifySensitivity({ ...BASE, plaintext: filler(size) }).sensitivity, 'personal');
});

// Local copy so the boundary offsets stay real numbers even where the export is missing.
const WINDOW_BYTES = 64 * 1024;

test('A1: a credential placed exactly across a window boundary is found', () => {
  const window = WINDOW_BYTES;
  const marker = Buffer.from(pemHeader(), 'utf8');
  // Each offset puts the marker across the end of window 1, or across a later window edge.
  for (const offset of [window - 10, window - 1, window - Math.floor(marker.length / 2), 2 * window - 4096 - 20]) {
    const big = filler(200 * 1024);
    marker.copy(big, offset);
    const res = profiles.classifySensitivity({ ...BASE, plaintext: big });
    assert.equal(res.sensitivity, 'secret', `byte offset ${offset}`);
    const resText = profiles.classifySensitivity({ ...BASE, text: big.toString('utf8') });
    assert.equal(resText.sensitivity, 'secret', `string offset ${offset}`);
  }
  // Multi-byte text before the boundary: the window end is trimmed to a UTF-8 boundary.
  const multi = Buffer.concat([Buffer.from('é'.repeat(window), 'utf8'), filler(64 * 1024)]);
  marker.copy(multi, window - 7);
  multi[window - 8] = 0x20; // keep the marker preceded by a full character
  const resMulti = profiles.classifySensitivity({ ...BASE, plaintext: multi });
  assert.equal(resMulti.sensitivity, 'secret');
});

test('A1: a user keyword placed across a window boundary is found', () => {
  const keyword = 'synthetic-boundary-keyword-'.padEnd(200, 'q');
  const rule = { id: 'kw-boundary', tier: 'clinical', keyword };
  const big = filler(200 * 1024);
  Buffer.from(keyword, 'utf8').copy(big, WINDOW_BYTES - 100);
  const res = profiles.classifySensitivity({ ...BASE, plaintext: big, userRules: [rule] });
  assert.deepEqual(res, { sensitivity: 'clinical', rule: 'user:kw-boundary' });
});

test('A2: derived text is classified (a credential only in derivedTexts is secret)', () => {
  const res = profiles.classifySensitivity({
    ...BASE,
    plaintext: Buffer.from('Content-Transfer-Encoding: base64\r\n\r\nbm90aGluZw==\r\n', 'utf8'),
    derivedTexts: ['Subject: hello', `Body line\n${pemHeader()}\n`],
  });
  assert.deepEqual(res, { sensitivity: 'secret', rule: 'private-key' });
});

test('A3: a placeholder bearer value before a real-looking one is secret', () => {
  const field = `${bearerHeader('xxxxxxxxxxxxxxxxxxxx')}\n${bearerHeader(realLookingTokenValue())}`;
  const res = profiles.classifySensitivity({ ...BASE, text: field });
  assert.deepEqual(res, { sensitivity: 'secret', rule: 'bearer-token' });
  // Control: placeholders only stay default.
  const placeholders = `${bearerHeader('xxxxxxxxxxxxxxxxxxxx')}\n${bearerHeader('<your_token_value_here>')}`;
  assert.equal(profiles.classifySensitivity({ ...BASE, text: placeholders }).sensitivity, 'personal');
});

test('A3: a placeholder database URI before a real-looking one is secret', () => {
  const field = `${databaseUri('changeme')} then ${databaseUri(['S3cr3t', 'Pass99!'].join(''))}`;
  const res = profiles.classifySensitivity({ ...BASE, text: field });
  assert.deepEqual(res, { sensitivity: 'secret', rule: 'database-credentials' });
  assert.equal(
    profiles.classifySensitivity({ ...BASE, text: `${databaseUri('changeme')} ${databaseUri('<password>')}` })
      .sensitivity,
    'personal',
  );
});

test('B12: SHIPPED_SCAN_PATTERNS exports frozen { id, source, flags } records, never the live RegExp objects', () => {
  const patterns = profiles.SHIPPED_SCAN_PATTERNS;
  assert.ok(Object.isFrozen(patterns));
  for (const entry of patterns) {
    assert.ok(Object.isFrozen(entry), entry.id);
    assert.deepEqual(Object.keys(entry).sort(), ['flags', 'id', 'source'], entry.id);
    assert.equal(typeof entry.source, 'string');
    assert.equal(typeof entry.flags, 'string');
    for (const value of Object.values(entry)) assert.ok(!(value instanceof RegExp), entry.id);
  }
  // A caller cannot change what the classifier matches through the export.
  const bearer = patterns.find(p => p.id === 'bearer-token');
  assert.throws(() => {
    'use strict';
    bearer.source = 'never';
  }, TypeError);
  const field = bearerHeader(realLookingTokenValue());
  assert.equal(profiles.classifySensitivity({ ...BASE, text: field }).sensitivity, 'secret');
});

test('A3: repeated calls give the same result (global patterns reset their position)', () => {
  const field = `${bearerHeader('xxxxxxxxxxxxxxxxxxxx')}\n${bearerHeader(realLookingTokenValue())}`;
  for (let i = 0; i < 3; i++) {
    assert.equal(profiles.classifySensitivity({ ...BASE, text: field }).sensitivity, 'secret');
    assert.equal(profiles.classifySensitivity({ ...BASE, text: databaseUri('Qw3rty!Pass77') }).sensitivity, 'secret');
  }
});

/** A database URI with no port or path: the host is followed directly by the next character. */
function bareDatabaseUri(password, host) {
  const proto = ['post', 'gres', '://'].join('');
  return `${proto}u:${password}${AT_CHAR}${host}`;
}

test('C1 (round 2): a placeholder URI directly followed by a real one (comma, semicolon, space) is secret', () => {
  const real = ['R3al', 'Pw', 'x77'].join('');
  for (const sep of [',', ', ', ';', ' ', '<', '>']) {
    const field = `${bareDatabaseUri('changeme', 'h1')}${sep}${bareDatabaseUri(real, 'h2')}`;
    assert.deepEqual(
      profiles.classifySensitivity({ ...BASE, text: field }),
      { sensitivity: 'secret', rule: 'database-credentials' },
      `separator ${JSON.stringify(sep)}`,
    );
    // Control: two placeholders stay the source default.
    const placeholders = `${bareDatabaseUri('changeme', 'h1')}${sep}${bareDatabaseUri('<password>', 'h2')}`;
    assert.equal(profiles.classifySensitivity({ ...BASE, text: placeholders }).sensitivity, 'personal', `control ${JSON.stringify(sep)}`);
  }
});

test('C2 (round 2): JSON and quoted keys are recognised; placeholders in the same forms stay non-secret', () => {
  const pw = ['Plain', 'Pass', 'word9'].join('');
  const highEntropy = ['Zq8', 'Lm2', 'Xv7', 'Rt4', 'Nb6', 'Kp1'].join('');
  const q = '"';
  const s = "'";
  const cases = [
    [`{${q}password${q}: ${q}${pw}${q}}`, 'credential-assignment'],
    [`{${q}api_key${q}:${q}${highEntropy}${q}}`, 'oauth-or-api-token'],
    [`${s}secret${s} = ${s}${highEntropy}${s}`, 'high-entropy-credential'],
    [`{${q}access_token${q}: ${q}${highEntropy}${q}}`, 'oauth-or-api-token'],
  ];
  for (const [field, rule] of cases) {
    assert.deepEqual(profiles.classifySensitivity({ ...BASE, text: field }), { sensitivity: 'secret', rule }, field.slice(0, 12));
  }
  for (const placeholder of ['changeme', 'your_api_key_here', '<password>', 'xxxxxxxxxxxxxxxx']) {
    for (const field of [
      `{${q}password${q}: ${q}${placeholder}${q}}`,
      `{${q}api_key${q}:${q}${placeholder}${q}}`,
      `${s}secret${s} = ${s}${placeholder}${s}`,
    ]) {
      assert.equal(profiles.classifySensitivity({ ...BASE, text: field }).sensitivity, 'personal', `placeholder ${placeholder}`);
    }
  }
});

test('C3 (round 2): archive tags may raise the tier but never choose public', () => {
  // A Gmail label `sensitivity:public` (an archive tag) is ignored: the mail stays personal.
  assert.deepEqual(
    profiles.classifySensitivity({ ...BASE, text: 'plain words', archiveTags: ['sensitivity:public'] }),
    { sensitivity: 'personal', rule: 'default' },
  );
  // A higher archive tier raises; an equal one changes nothing.
  assert.deepEqual(
    profiles.classifySensitivity({ ...BASE, text: 'plain words', archiveTags: ['Inbox', 'sensitivity:private'] }),
    { sensitivity: 'private', rule: 'archive-tag:private' },
  );
  assert.deepEqual(
    profiles.classifySensitivity({ ...BASE, text: 'plain words', archiveTags: ['sensitivity:personal'] }),
    { sensitivity: 'personal', rule: 'default' },
  );
  // A shipped rule above the archive tag wins; an archive tag above it raises.
  const lab = 'laboratory results enclosed';
  assert.equal(profiles.classifySensitivity({ ...BASE, text: lab, archiveTags: ['sensitivity:private'] }).sensitivity, 'clinical');
  assert.deepEqual(
    profiles.classifySensitivity({ ...BASE, text: lab, archiveTags: ['sensitivity:secret'] }),
    { sensitivity: 'secret', rule: 'archive-tag:secret' },
  );
  // A child-scoped item: secret from the archive still outranks the child floor; public never lowers it.
  const child = { ...BASE, profile: 'child', collection: 'child/google-takeout/mail/2024' };
  assert.equal(profiles.classifySensitivity({ ...child, archiveTags: ['sensitivity:public'] }).sensitivity, 'child');
  assert.equal(profiles.classifySensitivity({ ...child, archiveTags: ['sensitivity:secret'] }).sensitivity, 'secret');
  // A user rule (vault-stored) may still choose public, also matched by an archive tag.
  const rule = { id: 'r-public', tier: 'public', tag: 'Newsletters' };
  assert.deepEqual(
    profiles.classifySensitivity({ ...BASE, archiveTags: ['newsletters', 'sensitivity:public'], userRules: [rule] }),
    { sensitivity: 'public', rule: 'user:r-public' },
  );
  // A trusted caller tag `sensitivity:public` keeps its old meaning.
  assert.equal(profiles.classifySensitivity({ ...BASE, tags: ['sensitivity:public'] }).sensitivity, 'public');
});

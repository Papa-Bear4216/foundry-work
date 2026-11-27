// TEST ONLY: QR encoder and chain-head anchor (P-3, Architecture 8.1 step 9). All data is synthetic.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  anchorPayload, anchorQr, anchorQrSvg, anchorQrText, anchorText, chainAnchor, parseAnchor,
} from '../src/anchor.ts';
import {
  encodeQr, qrAlignmentPositions, qrBlockLayout, qrFormatBits, qrRawDataModules, renderQrText,
} from '../src/qr.ts';

const vectors = JSON.parse(readFileSync(new URL('./qr-vectors.json', import.meta.url))).vectors;
const rows = code => code.modules.map(row => row.map(dark => (dark ? '1' : '0')).join(''));

test('bit matrices equal the vectors of an independent encoder (versions, levels and all eight masks)', () => {
  assert.ok(vectors.length >= 14);
  for (const vector of vectors) {
    const code = encodeQr(Buffer.from(vector.text), { errorCorrection: vector.errorCorrection, mask: vector.mask });
    assert.equal(code.version, vector.version, `${vector.errorCorrection}/${vector.mask}`);
    assert.deepEqual(rows(code), vector.rows, `${vector.errorCorrection}/${vector.mask} v${vector.version}`);
  }
});

// A small test decoder: the function-pattern map is rebuilt here, the error correction is checked by syndromes.
function gfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function functionMap(size, version) {
  const map = Array.from({ length: size }, () => new Array(size).fill(false));
  const mark = (x0, y0, w, h) => {
    for (let y = y0; y < y0 + h; y++) for (let x = x0; x < x0 + w; x++) map[y][x] = true;
  };
  mark(0, 0, 9, 9);
  mark(size - 8, 0, 8, 9);
  mark(0, size - 8, 9, 8);
  mark(6, 0, 1, size);
  mark(0, 6, size, 1);
  const positions = qrAlignmentPositions(version);
  for (const cy of positions) {
    for (const cx of positions) {
      const inFinder = (cx < 9 && cy < 9) || (cx > size - 9 && cy < 9) || (cx < 9 && cy > size - 9);
      if (!inFinder) mark(cx - 2, cy - 2, 5, 5);
    }
  }
  if (version >= 7) {
    mark(size - 11, 0, 3, 6);
    mark(0, size - 11, 6, 3);
  }
  return map;
}

function decode(modules) {
  const size = modules.length;
  const version = (size - 17) / 4;
  assert.ok(Number.isInteger(version) && version >= 1 && version <= 40);
  let format = 0;
  const cells = [...[0, 1, 2, 3, 4, 5].map(i => [8, i]), [8, 7], [8, 8], [7, 8], ...[9, 10, 11, 12, 13, 14].map(i => [14 - i, 8])];
  cells.forEach(([x, y], i) => { if (modules[y][x]) format |= 1 << i; });
  let found;
  for (const level of ['L', 'M', 'Q', 'H']) {
    for (let mask = 0; mask < 8; mask++) if (qrFormatBits(level, mask) === format) found = { level, mask };
  }
  assert.ok(found, 'format bits decode');
  const masks = [
    (x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, x => x % 3 === 0, (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];
  const map = functionMap(size, version);
  const bits = [];
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let v = 0; v < size; v++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const y = ((right + 1) & 2) === 0 ? size - 1 - v : v;
        if (!map[y][x]) bits.push(modules[y][x] !== masks[found.mask](x, y) ? 1 : 0);
      }
    }
  }
  assert.equal(bits.length, qrRawDataModules(version));
  const codewords = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) codewords.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
  const { blocks: count, eccPerBlock } = qrBlockLayout(version, found.level);
  const shortLength = Math.floor(codewords.length / count);
  const shortBlocks = count - (codewords.length % count);
  const blocks = Array.from({ length: count }, (_, i) => new Array(shortLength + (i < shortBlocks ? 0 : 1)));
  let k = 0;
  const dataLength = i => blocks[i].length - eccPerBlock;
  for (let i = 0; i < shortLength + 1; i++) {
    for (let j = 0; j < count; j++) {
      if (i < dataLength(j)) blocks[j][i] = codewords[k++];
    }
  }
  for (let i = 0; i < eccPerBlock; i++) for (let j = 0; j < count; j++) blocks[j][dataLength(j) + i] = codewords[k++];
  assert.equal(k, codewords.length);
  const data = [];
  for (const block of blocks) {
    // Every syndrome S_i = C(alpha^i), i = 0 .. ecc - 1, of an undamaged block is zero.
    let alpha = 1;
    for (let i = 0; i < eccPerBlock; i++) {
      let syndrome = 0;
      for (const byte of block) syndrome = gfMul(syndrome, alpha) ^ byte;
      assert.equal(syndrome, 0, 'Reed-Solomon syndrome');
      alpha = gfMul(alpha, 2);
    }
    data.push(...block.slice(0, block.length - eccPerBlock));
  }
  const stream = data.flatMap(byte => [7, 6, 5, 4, 3, 2, 1, 0].map(i => (byte >>> i) & 1));
  const read = (offset, length) => stream.slice(offset, offset + length).reduce((a, b) => a * 2 + b, 0);
  assert.equal(read(0, 4), 0b0100, 'byte mode');
  const countBits = version <= 9 ? 8 : 16;
  const length = read(4, countBits);
  const bytes = Array.from({ length }, (_, i) => read(4 + countBits + i * 8, 8));
  return { ...found, version, text: Buffer.from(bytes).toString('utf8') };
}

test('the test decoder reads every vector and every automatic-mask symbol back', () => {
  for (const vector of vectors) {
    const modules = vector.rows.map(row => [...row].map(c => c === '1'));
    assert.equal(decode(modules).text, vector.text);
  }
  for (const [text, errorCorrection] of [['TEST ONLY a', 'L'], ['TEST ONLY ' + 'b'.repeat(300), 'M'], ['c'.repeat(1200), 'Q'], ['d'.repeat(1270), 'H']]) {
    const code = encodeQr(Buffer.from(text), { errorCorrection });
    const decoded = decode(code.modules);
    assert.deepEqual([decoded.text, decoded.level, decoded.mask, decoded.version], [text, errorCorrection, code.mask, code.version]);
  }
});

test('the encoder picks the smallest version and refuses data larger than version 40', () => {
  assert.equal(encodeQr(Buffer.from('x'.repeat(14)), { errorCorrection: 'M' }).version, 1);
  assert.equal(encodeQr(Buffer.from('x'.repeat(15)), { errorCorrection: 'M' }).version, 2);
  assert.equal(encodeQr(Buffer.from('x'.repeat(2953)), { errorCorrection: 'L' }).version, 40);
  assert.throws(() => encodeQr(Buffer.from('x'.repeat(2954)), { errorCorrection: 'L' }), { code: 'LENGTH' });
  assert.throws(() => encodeQr(Buffer.from('x'), { mask: 8 }), { code: 'SCHEMA' });
});

const sample = {
  vaultId: '00112233445566778899aabbccddeeff',
  key: Buffer.alloc(32, 7).toString('base64'),
  hash: 'ab'.repeat(32),
};

test('the anchor carries the five fields as text and QR, and its compact form parses back', () => {
  const anchor = chainAnchor(sample.vaultId, sample.key, { segment: 12, hash: sample.hash });
  assert.equal(anchor.signingKeyFingerprint, createHash('sha256').update(Buffer.alloc(32, 7)).digest('hex'));
  const payload = anchorPayload(anchor);
  assert.deepEqual(parseAnchor(payload), anchor);
  assert.equal(decode(anchorQr(anchor).modules).text, payload);
  const text = anchorText(anchor);
  for (const part of ['0011 2233 4455 6677 8899 aabb ccdd eeff', 'segment      12', 'epoch        1', payload]) {
    assert.ok(text.includes(part), part);
  }
  const qrText = anchorQrText(anchor);
  assert.match(qrText, /[▀▄█]/u);
  assert.equal(qrText.split('\n').length - 1, Math.ceil((anchorQr(anchor).size + 8) / 2));
  assert.notEqual(anchorQrText(anchor, { invert: true }), qrText);
  const svg = anchorQrSvg(anchor);
  assert.match(svg, /^<\?xml version="1.0" encoding="UTF-8"\?>\n<svg xmlns="http:\/\/www.w3.org\/2000\/svg"/u);
  assert.equal((svg.match(/h1v1h-1z/gu) ?? []).length, anchorQr(anchor).modules.flat().filter(Boolean).length);
});

test('anchor parsing and construction fail closed with ANCHOR or KEY', () => {
  const anchor = chainAnchor(sample.vaultId, sample.key, { segment: 3, hash: sample.hash });
  const payload = anchorPayload(anchor);
  for (const bad of [payload.replace('epoch=1', 'epoch=2'), payload.toUpperCase(), payload + ';x=1',
    payload.replace('segment=3', 'segment=03'), payload.replace('segment=3', 'segment=0'), '']) {
    assert.throws(() => parseAnchor(bad), { code: 'ANCHOR' }, bad);
  }
  assert.throws(() => chainAnchor(sample.vaultId, sample.key, { segment: 0, hash: sample.hash }), { code: 'ANCHOR' });
  assert.throws(() => chainAnchor(sample.vaultId, 'AAAA', { segment: 1, hash: sample.hash }), { code: 'KEY' });
  assert.equal(chainAnchor(sample.vaultId, sample.key, { segment: 0, hash: '0'.repeat(64) }).segment, 0);
});

test('terminal rendering uses two module rows per line with a quiet zone', () => {
  const code = encodeQr(Buffer.from('TEST ONLY'), { errorCorrection: 'L', mask: 0 });
  const rendered = renderQrText(code, { quiet: 2 });
  assert.ok(rendered.endsWith('\n'));
  const lines = rendered.slice(0, -1).split('\n');
  assert.equal(lines.length, Math.ceil((code.size + 4) / 2));
  assert.ok(lines.every(line => [...line].length === code.size + 4));
  assert.equal(lines[0], ' '.repeat(code.size + 4));
});

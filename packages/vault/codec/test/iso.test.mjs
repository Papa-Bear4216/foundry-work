// TEST ONLY: ISO 9660 + Joliet export of the sealed vault (P-3, `vault export-iso`). All data is synthetic.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempDisposableSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { verifyVault, VaultWriter } from '../src/index.ts';
import { exportVaultIso, primaryIdentifier, SECTOR_BYTES, writeIsoImage } from '../src/iso9660.ts';
import { blob, event, fixture, keyringPath, writable } from './vault-fixture.mjs';

function setup(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-iso-'));
  const vault = join(temp.path, 'vault');
  mkdirSync(vault);
  const unlocked = fixture(vault);
  t.after(() => { writable(vault); temp.remove(); });
  const append = (items, close) => {
    const writer = VaultWriter.open(vault, unlocked);
    try {
      writer.appendBatch(items);
      if (close) writer.closeSegment();
    } finally {
      writer.release();
    }
  };
  return { root: temp.path, vault, append };
}

// --- A test-only ISO 9660 reader (independent of the writer's layout code). ---
const both32 = (b, o) => {
  const le = b.readUInt32LE(o);
  assert.equal(b.readUInt32BE(o + 4), le, 'both-endian u32');
  return le;
};

function readIso(path) {
  const image = readFileSync(path);
  assert.equal(image.length % SECTOR_BYTES, 0);
  const sector = n => image.subarray(n * SECTOR_BYTES, (n + 1) * SECTOR_BYTES);
  const descriptors = {};
  for (let n = 16; ; n++) {
    const d = sector(n);
    assert.equal(d.subarray(1, 6).toString('latin1'), 'CD001');
    assert.equal(d[6], 1);
    if (d[0] === 255) break;
    descriptors[d[0]] = d;
  }
  const pvd = descriptors[1];
  const svd = descriptors[2];
  assert.ok(pvd && svd, 'primary and supplementary descriptors');
  assert.equal(svd.subarray(88, 91).toString('latin1'), '%/E', 'Joliet UCS-2 level 3');
  for (const d of [pvd, svd]) {
    assert.equal(both32(d, 80) * SECTOR_BYTES, image.length, 'volume space size');
    assert.equal(d.readUInt16LE(128), SECTOR_BYTES);
  }
  const extentCounts = new Map();
  const decode = (id, joliet) => {
    if (!joliet || id.length === 1) return id.toString('latin1');
    let text = '';
    for (let i = 0; i < id.length; i += 2) text += String.fromCharCode(id.readUInt16BE(i));
    return text;
  };
  const readDirectory = (location, size, joliet) => {
    const entries = [];
    let offset = location * SECTOR_BYTES;
    const end = offset + size;
    while (offset < end) {
      const length = image[offset];
      if (length === 0) {
        offset = Math.ceil((offset + 1) / SECTOR_BYTES) * SECTOR_BYTES;
        continue;
      }
      const record = image.subarray(offset, offset + length);
      assert.ok(Math.floor(offset / SECTOR_BYTES) === Math.floor((offset + length - 1) / SECTOR_BYTES), 'record inside one sector');
      const idLength = record[32];
      const id = record.subarray(33, 33 + idLength);
      entries.push({ extent: both32(record, 2), size: both32(record, 10), flags: record[25], id, name: decode(id, joliet) });
      offset += length;
    }
    return entries;
  };
  const walk = (descriptor, joliet) => {
    const root = descriptor.subarray(156, 156 + 34);
    const files = new Map();
    const directories = [];
    const visit = (location, size, prefix) => {
      directories.push({ prefix, location });
      const entries = readDirectory(location, size, joliet);
      assert.deepEqual(entries.slice(0, 2).map(e => [...e.id]), [[0], [1]], 'dot entries');
      let pending;
      for (const entry of entries.slice(2)) {
        if (entry.flags & 0x02) {
          visit(entry.extent, entry.size, prefix + entry.name + '/');
          continue;
        }
        const extents = pending?.name === entry.name ? pending.extents : [];
        extents.push(entry);
        if (entry.flags & 0x80) {
          pending = { name: entry.name, extents };
          continue;
        }
        pending = undefined;
        const name = joliet ? entry.name.replace(/;1$/u, '') : entry.name;
        files.set(prefix + name, Buffer.concat(extents.map(e => image.subarray(e.extent * SECTOR_BYTES, e.extent * SECTOR_BYTES + e.size))));
        extentCounts.set(prefix + name, extents.length);
      }
    };
    visit(both32(root, 2), both32(root, 10), '');
    // The L and M path tables list the same directories at the same locations.
    const tableSize = both32(descriptor, 132);
    const parseTable = (location, big) => {
      const table = image.subarray(location * SECTOR_BYTES, location * SECTOR_BYTES + tableSize);
      const rows = [];
      for (let o = 0; o < table.length;) {
        const length = table[o];
        rows.push({ extent: big ? table.readUInt32BE(o + 2) : table.readUInt32LE(o + 2),
          parent: big ? table.readUInt16BE(o + 6) : table.readUInt16LE(o + 6) });
        o += 8 + length + (length % 2);
      }
      return rows;
    };
    const l = parseTable(descriptor.readUInt32LE(140), false);
    const m = parseTable(descriptor.readUInt32BE(148), true);
    assert.deepEqual(l, m);
    assert.deepEqual(new Set(l.map(row => row.extent)), new Set(directories.map(d => d.location)));
    assert.equal(l[0].parent, 1);
    return files;
  };
  return { joliet: walk(svd, true), primary: walk(pvd, false), image, extentCounts };
}

function extract(files, folder) {
  for (const [path, bytes] of files) {
    const target = join(folder, ...path.split('/'));
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, bytes);
  }
}

test('export-iso writes the sealed chain without the keyring; the extracted Joliet tree verifies', t => {
  const s = setup(t);
  s.append([event('TEST ONLY one'), blob('TEST ONLY blob one')], true);
  s.append([event('TEST ONLY two'), blob('TEST ONLY blob two'.repeat(500))], true);
  s.append([event('TEST ONLY still open')], false);
  const output = join(s.root, 'vault.iso');
  const result = exportVaultIso(s.vault, output, { now: new Date('2026-02-03T04:05:06Z') });
  assert.deepEqual([result.segments, result.head.segment, result.keyringIncluded, result.openFiles], [2, 2, false, 1]);
  assert.equal(statSync(output).size, result.imageBytes);
  assert.deepEqual(readdirSync(s.root).sort(), ['vault', 'vault.iso']);
  const { joliet, primary } = readIso(output);
  assert.deepEqual([...joliet.keys()].sort(), [
    'HEAD.json', 'VAULT.json',
    'segments/000001/MANIFEST.json', 'segments/000001/MANIFEST.sig', 'segments/000001/events-0001.fvr', 'segments/000001/pack-0001.fvr',
    'segments/000002/MANIFEST.json', 'segments/000002/MANIFEST.sig', 'segments/000002/events-0001.fvr', 'segments/000002/pack-0001.fvr',
  ]);
  assert.ok(primary.has('SEGMENTS/000001/EVENTS_0001.FVR;1'));
  assert.ok(primary.has('VAULT.JSON;1'));
  assert.deepEqual(primary.get('SEGMENTS/000002/PACK_0001.FVR;1'), joliet.get('segments/000002/pack-0001.fvr'));
  for (const [path, bytes] of joliet) {
    if (path === 'HEAD.json') continue;
    assert.deepEqual(bytes, readFileSync(join(s.vault, ...path.split('/'))), path);
  }
  assert.deepEqual(JSON.parse(joliet.get('HEAD.json')), { manifest_sha256: result.head.hash, segment: 2 });
  const extracted = join(s.root, 'extracted');
  extract(joliet, extracted);
  const verified = verifyVault(extracted, { anchor: result.anchor });
  assert.equal(verified.position.hash, result.head.hash);
  assert.equal(verified.open.files, 0);
  assert.throws(() => exportVaultIso(s.vault, output), { name: 'SecondCopyError', code: 'OUTPUT_EXISTS' });
});

test('the keyring goes on the image only with the explicit opt-in', t => {
  const s = setup(t);
  s.append([event('TEST ONLY k')], true);
  const output = join(s.root, 'with-keyring.iso');
  const result = exportVaultIso(s.vault, output, { includeKeyring: true });
  assert.equal(result.keyringIncluded, true);
  const { joliet, primary } = readIso(output);
  assert.deepEqual(joliet.get('keyring/keyring.json'), readFileSync(keyringPath(s.vault)));
  assert.ok(primary.has('KEYRING/KEYRING.JSON;1'));
});

test('files larger than one extent become consecutive multi-extent records and read back whole', t => {
  const s = setup(t);
  const big = Buffer.alloc(3 * 4096 + 777, 0x5a);
  s.append([event('TEST ONLY big'), { ...blob(''), plaintext: big }], true);
  const output = join(s.root, 'multi.iso');
  exportVaultIso(s.vault, output, { maxExtentBytes: 4096 });
  const { joliet, extentCounts } = readIso(output);
  const pack = joliet.get('segments/000001/pack-0001.fvr');
  assert.ok(extentCounts.get('segments/000001/pack-0001.fvr') >= 4);
  assert.deepEqual(pack, readFileSync(join(s.vault, 'segments', '000001', 'pack-0001.fvr')));
  const extracted = join(s.root, 'x');
  extract(joliet, extracted);
  assert.equal(verifyVault(extracted).position.segment, 1);
  assert.throws(() => writeIsoImage(join(s.root, 'bad.iso'), [], { maxExtentBytes: 1000 }), { code: 'LENGTH' });
});

test('an empty vault exports VAULT.json and the genesis head', t => {
  const s = setup(t);
  const output = join(s.root, 'empty.iso');
  const result = exportVaultIso(s.vault, output);
  assert.equal(result.segments, 0);
  const { joliet } = readIso(output);
  assert.deepEqual([...joliet.keys()].sort(), ['HEAD.json', 'VAULT.json']);
  assert.equal(JSON.parse(joliet.get('HEAD.json')).segment, 0);
});

test('a source that does not match its expected hash fails, and no image or temporary file is left', t => {
  const s = setup(t);
  const source = join(s.root, 'source.bin');
  writeFileSync(source, 'TEST ONLY data');
  const output = join(s.root, 'never.iso');
  assert.throws(() => writeIsoImage(output, [{ path: ['a.bin'], size: 14, source: { path: source, sha256: '0'.repeat(64) } }]),
    { code: 'FILE_HASH' });
  assert.deepEqual(readdirSync(s.root).sort(), ['source.bin', 'vault']);
  const good = createHash('sha256').update('TEST ONLY data').digest('hex');
  writeIsoImage(output, [{ path: ['a.bin'], size: 14, source: { path: source, sha256: good } }]);
  assert.deepEqual(readIso(output).joliet.get('a.bin').toString(), 'TEST ONLY data');
});

test('primary identifiers are Level 2 d-characters with one dot and version 1', () => {
  assert.equal(primaryIdentifier('events-0001.fvr', false), 'EVENTS_0001.FVR;1');
  assert.equal(primaryIdentifier('MANIFEST.sig', false), 'MANIFEST.SIG;1');
  assert.equal(primaryIdentifier('pack-9007199254740991.fvr', false), 'PACK_9007199254740991.FVR;1');
  assert.equal(primaryIdentifier('000001', true), '000001');
  assert.equal(primaryIdentifier('keyring', true), 'KEYRING');
  assert.throws(() => primaryIdentifier('x'.repeat(40) + '.fvr', false), { code: 'SCHEMA' });
});

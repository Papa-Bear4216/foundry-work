// TEST ONLY: Mode B second-copy session (P-3, Architecture 8.1 steps 1 to 7). Every vault, key and text is synthetic.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, cpSync, lstatSync, mkdirSync, mkdtempDisposableSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, parse } from 'node:path';
import { test } from 'node:test';
import { verifyVault, VaultWriter } from '../src/index.ts';
import {
  addCopyRecord, copyRegisterStatus, diskRelation, emptyRegister, fsutilType, initSecondCopy, mountInfoType,
  openSecondCopySession, probeFileSystem, readCopyRegister, recordSeal, selectCopy, writeCopyRegister,
} from '../src/second-copy.ts';
import { blob, event, fixture, identity, keyringPath } from './vault-fixture.mjs';

const ntfs = () => ({ type: 'ntfs', method: 'injected' });

function makeWritable(path) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const full = join(path, entry.name);
    if (entry.isDirectory()) {
      chmodSync(full, 0o700);
      makeWritable(full);
    } else {
      chmodSync(full, 0o600);
    }
  }
}

function setup(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-copy-'));
  t.after(() => { makeWritable(temp.path); temp.remove(); });
  const working = join(temp.path, 'working');
  mkdirSync(working);
  const unlocked = fixture(working);
  const drive = join(temp.path, 'drive');
  return {
    root: temp.path, working, drive, unlocked,
    append(items, close = false) {
      const writer = VaultWriter.open(working, unlocked);
      try {
        const result = writer.appendBatch(items);
        if (close) writer.closeSegment();
        return result;
      } finally {
        writer.release();
      }
    },
    session(options = {}, target = drive) {
      const session = openSecondCopySession(working, target, { probe: ntfs, ...options });
      try {
        return { report: session.report, result: session.seal(unlocked) };
      } finally {
        session.release();
      }
    },
  };
}

/** Every file below `root` with its bytes' hash, leaving out the SQLite lock files (taking a lock may touch them). */
function tree(root) {
  const out = [];
  const walk = relative => {
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const path = join(relative, entry.name);
      if (entry.name.includes('.lock.sqlite')) continue;
      if (entry.isDirectory()) {
        out.push(`${path}/`);
        walk(path);
      } else {
        out.push(`${path} ${createHash('sha256').update(readFileSync(join(root, path))).digest('hex')}`);
      }
    }
  };
  walk('');
  return out;
}

const segmentDir = (root, n) => join(root, 'segments', String(n).padStart(6, '0'));

test('init and one session copy every closed segment, close the open one, and leave a verifiable sealed copy', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob one')], true);
  vault.append([event('TEST ONLY two'), blob('TEST ONLY blob two'.repeat(4000))]);
  const init = initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  assert.equal(init.created, true);
  assert.equal(init.disk, 'same-volume');
  assert.deepEqual(verifyVault(vault.drive).position.segment, 0);
  const { report, result } = vault.session();
  assert.deepEqual(report.driveHead.segment, 0);
  assert.equal(result.previous.segment, 0);
  assert.equal(result.head.segment, 2);
  assert.equal(result.segmentsCopied, 2);
  assert.equal(result.filesCopied, 8);
  assert.ok(result.bytesCopied > 18 * 4000);
  const verified = verifyVault(vault.drive);
  assert.equal(verified.position.segment, 2);
  assert.equal(verified.position.hash, result.head.hash);
  assert.deepEqual(verifyVault(vault.working).position, verified.position);
  assert.deepEqual(readFileSync(keyringPath(vault.drive)), readFileSync(keyringPath(vault.working)));
  assert.equal(result.keyringVersion, JSON.parse(readFileSync(keyringPath(vault.working))).version);
  assert.deepEqual(JSON.parse(readFileSync(join(vault.drive, 'HEAD.json'))), { manifest_sha256: result.head.hash, segment: 2 });
  for (const n of [1, 2]) {
    for (const name of readdirSync(segmentDir(vault.drive, n))) {
      assert.equal(statSync(join(segmentDir(vault.drive, n), name)).mode & 0o222, 0, `${n}/${name} read-only`);
    }
  }
  assert.equal(result.anchor.segment, 2);
  assert.equal(result.anchor.manifestHash, result.head.hash);
  assert.equal(result.anchor.signingKeyFingerprint, createHash('sha256').update(identity.signingPublicKey).digest('hex'));
  assert.doesNotThrow(() => verifyVault(vault.drive, { anchor: result.anchor }));
  // A second session with nothing new copies nothing and keeps the head.
  const again = vault.session({ recorded: result.head });
  assert.equal(again.result.segmentsCopied, 0);
  assert.deepEqual(again.result.head, result.head);
  // New records are closed into segment 3 and copied.
  vault.append([event('TEST ONLY three')]);
  const third = vault.session({ recorded: result.head });
  assert.deepEqual([third.result.previous.segment, third.result.head.segment, third.result.segmentsCopied], [2, 3, 1]);
  // Adopting an existing copy of the same vault registers it without changing it.
  const before = tree(vault.drive);
  assert.equal(initSecondCopy(vault.working, vault.drive, { probe: ntfs }).created, false);
  assert.deepEqual(tree(vault.drive), before);
});

test('FAT file systems are refused at init and at session start, before anything is written', t => {
  const vault = setup(t);
  for (const type of ['vfat', 'msdos', 'fat32', 'fat']) {
    assert.throws(() => initSecondCopy(vault.working, vault.drive, { probe: () => ({ type, method: 'injected' }) }),
      { name: 'SecondCopyError', code: 'FILESYSTEM_UNSUPPORTED' });
  }
  assert.throws(() => lstatSync(vault.drive), { code: 'ENOENT' });
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const before = tree(vault.drive);
  assert.throws(() => vault.session({ probe: () => ({ type: 'vfat', method: 'injected' }) }), { code: 'FILESYSTEM_UNSUPPORTED' });
  assert.deepEqual(tree(vault.drive), before);
  for (const type of ['exfat', 'ntfs', 'ntfs3', 'ext4', 'btrfs', undefined]) {
    assert.doesNotThrow(() => vault.session({ probe: () => ({ type, method: 'injected' }) }), String(type));
  }
});

test('the real file-system probe names the temporary folder\'s file system on this OS', () => {
  const report = probeFileSystem(tmpdir());
  if (process.platform === 'win32' || process.platform === 'linux') {
    assert.equal(typeof report.type, 'string', JSON.stringify(report));
    assert.ok(['fsutil', 'statfs', 'mountinfo'].includes(report.method));
  }
  assert.ok(!['vfat', 'fat32'].includes(report.type));
});

test('probe parsers: fsutil values in any language and Linux mountinfo with escaped mount points', () => {
  assert.equal(fsutilType('Volume Name : \r\nFile System Name : FAT32\r\nIs ReadWrite\r\n'), 'fat32');
  assert.equal(fsutilType('Volumename : \nDateisystemname : exFAT\n'), 'exfat');
  assert.equal(fsutilType('Nom du système de fichiers : NTFS\n'), 'ntfs');
  assert.equal(fsutilType('nothing useful'), undefined);
  const mountinfo = [
    '22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw',
    '40 22 8:17 / /media/usb\\040stick rw,nosuid shared:20 - vfat /dev/sdb1 rw,fmask=0022',
    '41 22 8:33 / /media/usb rw shared:21 - exfat /dev/sdc1 rw',
  ].join('\n');
  assert.equal(mountInfoType('/media/usb stick/foundry', mountinfo), 'vfat');
  assert.equal(mountInfoType('/media/usb/foundry', mountinfo), 'exfat');
  assert.equal(mountInfoType('/media/usbx', mountinfo), 'ext4');
});

test('Windows probe asks fsutil for the drive letter with explicit arguments, and UNC paths stay undetected', () => {
  const calls = [];
  const run = (command, args) => {
    calls.push([command, ...args]);
    return { status: 0, stdout: 'File System Name : FAT32\r\n', stderr: '' };
  };
  assert.deepEqual(probeFileSystem('E:\\copies\\foundry', { platform: 'win32', run }), { type: 'fat32', method: 'fsutil' });
  assert.deepEqual(calls, [['fsutil', 'fsinfo', 'volumeinfo', 'E:']]);
  assert.deepEqual(probeFileSystem('\\\\server\\share\\x', { platform: 'win32', run }), { type: undefined, method: 'none' });
  assert.deepEqual(probeFileSystem('E:\\x', { platform: 'win32', run: () => ({ status: null, stdout: '', stderr: '' }) }),
    { type: undefined, method: 'none' });
});

test('step 3 stops on a rolled-back drive before anything on either side changes', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY a')], true);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const first = vault.session().result;
  const saved = join(vault.root, 'saved');
  cpSync(vault.drive, saved, { recursive: true });
  vault.append([event('TEST ONLY b')]);
  const second = vault.session({ recorded: first.head }).result;
  assert.equal(second.head.segment, 2);
  // Swap the drive for its older state.
  makeWritable(vault.drive);
  const restored = join(vault.root, 'restored');
  cpSync(saved, restored, { recursive: true });
  vault.append([event('TEST ONLY open record')]);
  const drive = tree(restored);
  const working = tree(vault.working);
  assert.throws(() => vault.session({ recorded: second.head }, restored), { code: 'ROLLBACK_DETECTED', reason: 'drive-older-than-recorded' });
  assert.deepEqual(tree(restored), drive);
  assert.deepEqual(tree(vault.working), working);
});

test('step 3 stops on a forked chain and on a recorded hash that differs at the same segment number', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY shared')], true);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const shared = vault.session().result;
  // A real fork: a clone of the working vault seals different events into segment 2 and is copied to the drive.
  const clone = join(vault.root, 'clone');
  cpSync(vault.working, clone, { recursive: true });
  makeWritable(clone);
  const writer = VaultWriter.open(clone, vault.unlocked);
  try {
    writer.appendBatch([event('TEST ONLY fork side')]);
  } finally {
    writer.release();
  }
  const forkSession = openSecondCopySession(clone, vault.drive, { probe: ntfs, recorded: shared.head });
  try {
    forkSession.seal(vault.unlocked);
  } finally {
    forkSession.release();
  }
  vault.append([event('TEST ONLY working side')], true);
  const drive = tree(vault.drive);
  const working = tree(vault.working);
  assert.throws(() => vault.session({ recorded: shared.head }), { code: 'TAMPER_DETECTED', reason: 'chains-differ' });
  assert.throws(() => vault.session({ recorded: { segment: 1, hash: 'f'.repeat(64) } }),
    { code: 'TAMPER_DETECTED', reason: 'recorded-segment-differs' });
  assert.deepEqual(tree(vault.drive), drive);
  assert.deepEqual(tree(vault.working), working);
  // A drive that is ahead of the working vault (here: a fresh working vault with the same identity) is refused too.
  const other = setup(t);
  assert.throws(() => openSecondCopySession(other.working, vault.drive, { probe: ntfs }),
    { code: 'ROLLBACK_DETECTED', reason: 'working-older-than-drive' });
  assert.deepEqual(tree(vault.drive), drive);
});

test('a drive with a manifest hand-edited fails the keyless check (step 2) and nothing changes', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY x'), blob('TEST ONLY y')], true);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const { result } = vault.session();
  makeWritable(vault.drive);
  const pack = readdirSync(segmentDir(vault.drive, 1)).find(name => name.startsWith('pack-'));
  const path = join(segmentDir(vault.drive, 1), pack);
  const bytes = readFileSync(path);
  bytes[bytes.length - 1] ^= 1;
  writeFileSync(path, bytes);
  const drive = tree(vault.drive);
  assert.throws(() => vault.session({ recorded: result.head }), { code: 'COPY_VERIFY_FAILED', reason: 'FILE_HASH' });
  assert.deepEqual(tree(vault.drive), drive);
});

test('a drive from another vault or with changed metadata is refused', t => {
  const vault = setup(t);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const metadataPath = join(vault.drive, 'VAULT.json');
  const original = readFileSync(metadataPath, 'utf8');
  writeFileSync(metadataPath, original.replace(/"created_at":"[^"]+"/u, '"created_at":"2001-01-01T00:00:00Z"'));
  assert.throws(() => vault.session(), { code: 'VAULT_MISMATCH' });
  writeFileSync(metadataPath, 'TEST ONLY not json');
  assert.throws(() => vault.session(), { code: 'NOT_A_COPY' });
});

test('a write-protected drive is reported before any check', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, t => {
  const vault = setup(t);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  chmodSync(join(vault.drive, 'keyring'), 0o500);
  chmodSync(vault.drive, 0o500);
  t.after(() => { chmodSync(vault.drive, 0o700); chmodSync(join(vault.drive, 'keyring'), 0o700); });
  assert.throws(() => vault.session(), { code: 'WRITE_PROTECTED' });
});

test('an interrupted session at any step is finished or rolled back by the next one', t => {
  const points = ['after-stream-files', 'after-signature', 'after-manifest-pending', 'after-head-pending',
    'after-manifest-rename', 'after-head-update', 'after-read-only', 'after-keyring'];
  for (const point of points) {
    const vault = setup(t);
    vault.append([event('TEST ONLY first'), blob('TEST ONLY first blob')], true);
    initSecondCopy(vault.working, vault.drive, { probe: ntfs });
    const first = vault.session().result;
    vault.append([event('TEST ONLY second'), blob('TEST ONLY second blob')]);
    const stop = new Error('TEST ONLY drive pulled');
    assert.throws(() => vault.session({
      recorded: first.head,
      checkpoint: (name, segment) => { if (name === point && segment >= 2) throw stop; },
    }), error => error === stop, point);
    // Segment 1 on the drive is untouched by the interrupted session.
    assert.equal(createHash('sha256').update(readFileSync(join(segmentDir(vault.drive, 1), 'MANIFEST.json'))).digest('hex'), first.head.hash);
    const next = vault.session({ recorded: first.head });
    const early = points.indexOf(point) <= points.indexOf('after-head-pending');
    assert.equal(next.report.removedPartialSegment, early ? 2 : undefined, point);
    assert.equal(next.report.completedHead, point === 'after-manifest-rename', point);
    assert.equal(next.result.head.segment, 2, point);
    assert.equal(verifyVault(vault.drive, { anchor: next.result.anchor }).position.segment, 2, point);
    assert.deepEqual(readFileSync(keyringPath(vault.drive)), readFileSync(keyringPath(vault.working)), point);
  }
});

test('an unfinished folder at a recorded segment number is never removed (rollback STOP instead)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one')], true);
  vault.append([event('TEST ONLY two')], true);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const { result } = vault.session();
  makeWritable(vault.drive);
  unlinkSync(join(segmentDir(vault.drive, 2), 'MANIFEST.json'));
  const drive = tree(vault.drive);
  assert.throws(() => vault.session({ recorded: result.head }), { code: 'ROLLBACK_DETECTED' });
  assert.deepEqual(tree(vault.drive), drive);
});

test('damage in the working vault stops the copy and leaves the earlier drive segments untouched', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY good')], true);
  initSecondCopy(vault.working, vault.drive, { probe: ntfs });
  const { result } = vault.session();
  vault.append([event('TEST ONLY will be damaged'), blob('TEST ONLY damaged blob')], true);
  makeWritable(vault.working);
  const folder = segmentDir(vault.working, 2);
  const events = readdirSync(folder).find(name => name.startsWith('events-'));
  const bytes = readFileSync(join(folder, events));
  bytes[bytes.length - 2] ^= 1;
  writeFileSync(join(folder, events), bytes);
  const segmentOne = tree(segmentDir(vault.drive, 1));
  assert.throws(() => vault.session({ recorded: result.head }), { code: 'WORKING_VAULT_DAMAGED', reason: 'FILE_HASH' });
  assert.deepEqual(tree(segmentDir(vault.drive, 1)), segmentOne);
  assert.equal(readCopyHead(vault.drive), result.head.hash);
});

function readCopyHead(drive) {
  return JSON.parse(readFileSync(join(drive, 'HEAD.json'))).manifest_sha256;
}

test('the copy must be its own folder: not a volume root, not around or inside the vault, not a foreign folder', t => {
  const vault = setup(t);
  assert.throws(() => initSecondCopy(vault.working, parse(vault.root).root, { probe: ntfs }), { code: 'TARGET_UNSUITABLE', reason: 'volume-root' });
  assert.throws(() => initSecondCopy(vault.working, join(vault.working, 'segments', 'copy'), { probe: ntfs }), { code: 'TARGET_UNSUITABLE' });
  assert.throws(() => initSecondCopy(vault.working, vault.root, { probe: ntfs }), { code: 'TARGET_UNSUITABLE' });
  const foreign = join(vault.root, 'foreign');
  mkdirSync(foreign);
  writeFileSync(join(foreign, 'notes.txt'), 'TEST ONLY');
  assert.throws(() => initSecondCopy(vault.working, foreign, { probe: ntfs }), { code: 'TARGET_NOT_EMPTY' });
  assert.throws(() => vault.session({}, foreign), { code: 'NOT_A_COPY' });
  assert.throws(() => vault.session({}, join(vault.root, 'missing')), { code: 'NOT_A_COPY' });
  assert.equal(diskRelation(vault.working, vault.root), 'same-volume');
});

test('the working-device register: strict format, labels, selection, seal record and the 14-day banner', t => {
  const vault = setup(t);
  const path = join(vault.root, 'second-copies.json');
  const id = identity.vaultId;
  const empty = readCopyRegister(path, id);
  assert.deepEqual(empty, emptyRegister(id));
  assert.equal(copyRegisterStatus(empty, new Date()).banner.includes('No second copy'), true);
  assert.throws(() => selectCopy(empty), { code: 'COPY_UNKNOWN' });
  const created = new Date('2026-01-01T00:00:00Z');
  let { register, copy } = addCopyRecord(empty, undefined, created);
  assert.equal(copy.label, 'copy-1');
  assert.throws(() => addCopyRecord(register, 'copy-1', created), { code: 'INVALID_LABEL' });
  for (const bad of ['', 'has space', '../x', 'x'.repeat(33), 'é']) assert.throws(() => addCopyRecord(register, bad, created), { code: 'INVALID_LABEL' });
  writeCopyRegister(path, register);
  assert.deepEqual(readCopyRegister(path, id), register);
  assert.throws(() => readCopyRegister(path, 'f'.repeat(32)), { code: 'REGISTER' });
  assert.equal(selectCopy(register).copy_id, copy.copy_id);
  const second = addCopyRecord(register, 'offsite', created).register;
  assert.throws(() => selectCopy(second), { code: 'COPY_AMBIGUOUS' });
  assert.equal(selectCopy(second, 'offsite').label, 'offsite');
  assert.throws(() => selectCopy(second, 'other'), { code: 'COPY_UNKNOWN' });
  const sealed = recordSeal(register, copy.copy_id, {
    head: { segment: 4, hash: 'a'.repeat(64) }, sealedAt: '2026-01-02T00:00:00Z', keyringVersion: 3,
  });
  writeCopyRegister(path, sealed);
  const status = at => copyRegisterStatus(readCopyRegister(path, id), new Date(at), 3);
  assert.deepEqual([status('2026-01-05T00:00:00Z').due, status('2026-01-05T00:00:00Z').overdue], [false, false]);
  assert.deepEqual([status('2026-01-09T00:00:00Z').due, status('2026-01-09T00:00:00Z').overdue], [true, false]);
  const late = status('2026-01-16T00:00:00Z');
  assert.equal(late.overdue, true);
  assert.match(late.banner, /SECOND COPY OVERDUE: copy "copy-1" was last sealed 14 day\(s\) ago/u);
  assert.equal(late.copies[0].keyringCurrent, true);
  assert.equal(copyRegisterStatus(sealed, new Date('2026-01-03T00:00:00Z'), 4).copies[0].keyringCurrent, false);
  const manual = { ...sealed, cadence: 'manual' };
  assert.equal(copyRegisterStatus(manual, new Date('2026-01-12T00:00:00Z')).due, false);
  assert.equal(copyRegisterStatus(manual, new Date('2026-01-17T00:00:00Z')).overdue, true);
  writeFileSync(path, readFileSync(path, 'utf8').replace('"weekly"', '"hourly"'));
  assert.throws(() => readCopyRegister(path, id), { code: 'REGISTER' });
  writeFileSync(path, ' {}');
  assert.throws(() => readCopyRegister(path, id), { code: 'REGISTER' });
});

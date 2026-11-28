// TEST ONLY: Mode B second-copy session (P-3, Architecture 8.1 steps 1 to 7). Every vault, key and text is synthetic.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempDisposableSync, readdirSync, readFileSync, realpathSync, renameSync, rmdirSync,
  rmSync, statSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, parse } from 'node:path';
import { test } from 'node:test';
import { verifyVault, VaultWriter } from '../src/index.ts';
import {
  addCopyRecord, COPY_REGISTERED, COPY_SEALED, copyRegisteredBody, copyRegisterStatus, copySealedBody, diskRelation,
  emptyRegister, fsutilType, initSecondCopy, inspectCopyTarget, loadCopyRegister, MAX_REGISTER_BYTES, mountInfoType,
  openSecondCopySession, pathInside, probeFileSystem, readCopyIdentity, readCopyRegister, recordSeal, registerFromEvents,
  MAX_ROOT_ENTRIES, MAX_SEGMENT_ENTRIES, replayCopyRegister, selectCopy, setSegmentEntryCapForTest, verifySecondCopy,
  writeCopyRegister,
} from '../src/second-copy.ts';
import { blob, cases, event, fixture, identity, keyId, keyringPath } from './vault-fixture.mjs';

const ntfs = () => ({ type: 'ntfs', method: 'injected' });
const ID = 'a1'.repeat(16);
const OTHER = 'b2'.repeat(16);
const asCopy = { secondCopy: true };

function makeWritable(path) {
  if (!existsSync(path)) return;
  chmodSync(path, 0o700);
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const full = join(path, entry.name);
    if (entry.isDirectory()) {
      makeWritable(full);
    } else if (entry.isFile()) {
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
    init(target = drive, options = {}) {
      return initSecondCopy(working, target, { probe: ntfs, copyId: ID, ...options });
    },
    session(options = {}, target = drive) {
      const session = openSecondCopySession(working, target, { probe: ntfs, copyId: ID, ...options });
      try {
        return { report: session.report, result: session.seal(unlocked) };
      } finally {
        session.release();
      }
    },
  };
}

/** Every entry below `root` with its type and, for files, the hash of its bytes (lock files included). */
function tree(root) {
  const out = [];
  const walk = relative => {
    for (const entry of readdirSync(join(root, relative), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const path = join(relative, entry.name);
      if (entry.isDirectory()) {
        out.push(`${path}/`);
        walk(path);
      } else if (entry.isFile()) {
        out.push(`${path} ${createHash('sha256').update(readFileSync(join(root, path))).digest('hex')}`);
      } else {
        out.push(`${path} (link)`);
      }
    }
  };
  walk('');
  return out;
}

const segmentDir = (root, n) => join(root, 'segments', String(n).padStart(6, '0'));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const linkKind = process.platform === 'win32' ? 'junction' : 'dir';

test('init and one session copy every closed segment, close the open one, and leave a verifiable sealed copy', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob one')], true);
  vault.append([event('TEST ONLY two'), blob('TEST ONLY blob two'.repeat(4000))]);
  const init = vault.init();
  assert.deepEqual([init.created, init.resumed, init.adoptedFrom], [true, false, undefined]);
  assert.equal(init.disk, 'same-volume');
  assert.equal(readCopyIdentity(vault.drive, identity.vaultId), ID);
  assert.equal(verifyVault(vault.drive, asCopy).position.segment, 0);
  // A working vault never accepts a copy identity file: the opt-in is for second copies only.
  assert.throws(() => verifyVault(vault.drive), { code: 'INVENTORY' });
  const { report, result } = vault.session();
  assert.deepEqual(report.driveHead.segment, 0);
  assert.equal(result.previous.segment, 0);
  assert.equal(result.head.segment, 2);
  assert.equal(result.segmentsCopied, 2);
  assert.equal(result.filesCopied, 8);
  assert.equal(result.keyringWritten, true);
  assert.ok(result.bytesCopied > 18 * 4000);
  const verified = verifyVault(vault.drive, asCopy);
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
  assert.doesNotThrow(() => verifyVault(vault.drive, { anchor: result.anchor, secondCopy: true }));
  // A second session with nothing new copies nothing, keeps the head and does not rewrite the keyring.
  const again = vault.session({ recorded: result.head });
  assert.deepEqual([again.result.segmentsCopied, again.result.keyringWritten], [0, false]);
  assert.deepEqual(again.result.head, result.head);
  // New records are closed into segment 3 and copied.
  vault.append([event('TEST ONLY three')]);
  const third = vault.session({ recorded: result.head });
  assert.deepEqual([third.result.previous.segment, third.result.head.segment, third.result.segmentsCopied], [2, 3, 1]);
  // Init again with the same record: nothing changes.
  const before = tree(vault.drive);
  assert.deepEqual([vault.init().created, vault.init().resumed], [false, true]);
  assert.deepEqual(tree(vault.drive), before);
});

test('a copy has an identity: another record needs --adopt, and a session refuses a mismatched or missing id', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY id')], true);
  vault.init();
  const first = vault.session().result;
  const before = tree(vault.drive);
  assert.equal(inspectCopyTarget(vault.working, vault.drive, { probe: ntfs }).copyId, ID);
  assert.throws(() => vault.init(vault.drive, { copyId: OTHER }), { code: 'COPY_MISMATCH', reason: 'adopt-required' });
  assert.throws(() => vault.session({ copyId: OTHER, recorded: first.head }), { code: 'COPY_MISMATCH', reason: 'different' });
  assert.deepEqual(tree(vault.drive), before);
  // A second valid drive of the same vault cannot stand in for the first.
  const second = join(vault.root, 'second');
  initSecondCopy(vault.working, second, { probe: ntfs, copyId: OTHER });
  assert.throws(() => vault.session({ recorded: null }, second), { code: 'COPY_MISMATCH', reason: 'different' });
  // Adoption is explicit: the folder gets the new id and names the old one.
  const adopted = vault.init(vault.drive, { copyId: OTHER, adopt: true });
  assert.equal(adopted.adoptedFrom, ID);
  assert.equal(readCopyIdentity(vault.drive, identity.vaultId), OTHER);
  assert.throws(() => vault.session({ recorded: first.head }), { code: 'COPY_MISMATCH' });
  assert.equal(vault.session({ copyId: OTHER, recorded: first.head }).result.head.segment, 1);
  // A copy without COPY.json is refused by a session and can only be adopted.
  makeWritable(vault.drive);
  unlinkSync(join(vault.drive, 'COPY.json'));
  assert.throws(() => vault.session({ copyId: OTHER, recorded: first.head }), { code: 'COPY_MISMATCH', reason: 'missing' });
  assert.equal(vault.init(vault.drive, { copyId: ID, adopt: true }).adoptedFrom, null);
});

test('an interrupted copy init is recognised and completed; a foreign or other-record folder is not', t => {
  const vault = setup(t);
  const stop = new Error('TEST ONLY pulled');
  assert.throws(() => vault.init(vault.drive, { checkpoint: () => { throw stop; } }), error => error === stop);
  assert.deepEqual(readdirSync(vault.drive), ['COPY.json']);
  assert.equal(inspectCopyTarget(vault.working, vault.drive, { probe: ntfs }).state, 'interrupted');
  assert.throws(() => vault.init(vault.drive, { copyId: OTHER }), { code: 'COPY_MISMATCH', reason: 'interrupted-init' });
  const resumed = vault.init();
  assert.deepEqual([resumed.created, resumed.resumed], [false, true]);
  assert.equal(verifyVault(vault.drive, asCopy).position.segment, 0);
  // The layout half-written by initializeVault (no VAULT.json yet) is completed too.
  const half = join(vault.root, 'half');
  mkdirSync(join(half, 'segments'), { recursive: true });
  writeFileSync(join(half, 'COPY.json'), readFileSync(join(vault.drive, 'COPY.json')));
  writeFileSync(join(half, 'HEAD.json.pending'), '{');
  assert.equal(vault.init(half).resumed, true);
  assert.equal(verifyVault(half, asCopy).position.segment, 0);
  // Only a pending identity file: the folder counts as empty.
  const pending = join(vault.root, 'pending');
  mkdirSync(pending);
  writeFileSync(join(pending, 'COPY.json.pending'), '{');
  assert.equal(vault.init(pending).created, true);
  // A head without COPY.json is not Foundry's own unfinished init.
  const foreign = join(vault.root, 'foreign-head');
  mkdirSync(foreign);
  writeFileSync(join(foreign, 'HEAD.json'), '{}');
  assert.throws(() => vault.init(foreign), { code: 'TARGET_NOT_EMPTY' });
});

test('FAT file systems are refused at init and at session start, before anything is written', t => {
  const vault = setup(t);
  for (const type of ['vfat', 'msdos', 'fat32', 'fat']) {
    assert.throws(() => vault.init(vault.drive, { probe: () => ({ type, method: 'injected' }) }),
      { name: 'SecondCopyError', code: 'FILESYSTEM_UNSUPPORTED' });
  }
  assert.throws(() => lstatSync(vault.drive), { code: 'ENOENT' });
  vault.init();
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

test('probe parsers: fsutil by the exact key only, and Linux mountinfo with escaped mount points', () => {
  assert.equal(fsutilType('Volume Name : \r\nFile System Name : FAT32\r\nIs ReadWrite\r\n'), 'fat32');
  // A volume label that reads like a file-system name never masks the real type (finding 13).
  assert.equal(fsutilType('Volume Name : NTFS\r\nVolume Serial Number : 0x1234\r\nFile System Name : FAT32\r\n'), 'fat32');
  assert.equal(fsutilType('Volume Name : NTFS\r\n'), undefined);
  // Localized output has another key: the type is unknown (the caller warns; A-44 limit).
  assert.equal(fsutilType('Volumename : \nDateisystemname : exFAT\n'), undefined);
  assert.equal(fsutilType('Nom du système de fichiers : NTFS\n'), undefined);
  assert.equal(fsutilType('File System Name : \r\n'), undefined);
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

test('the FAT check probes the resolved volume: a junction to a folder on another drive is followed (R19-1)', t => {
  const vault = setup(t);
  // `fat-volume` stands for a folder on another drive letter; the link lives on the "NTFS" side.
  const fatVolume = join(vault.root, 'fat-volume');
  mkdirSync(fatVolume);
  const real = realpathSync.native(fatVolume).toLowerCase();
  const link = join(vault.root, 'ntfs-side-link');
  symlinkSync(fatVolume, link, linkKind);
  const seen = [];
  // Lexical comparison only: the probe answers FAT for a path on the other volume exactly as it is passed.
  const probe = path => {
    seen.push(path);
    return { type: path.toLowerCase().startsWith(real) ? 'fat32' : 'ntfs', method: 'injected' };
  };
  assert.throws(() => vault.init(join(link, 'copy'), { probe }), { code: 'FILESYSTEM_UNSUPPORTED' });
  assert.equal(existsSync(join(fatVolume, 'copy')), false);
  assert.ok(seen.length > 0 && seen.every(path => path.toLowerCase().startsWith(real)), JSON.stringify(seen));
  // A session through the link probes the resolved target too (the copy itself was made on the real path).
  vault.init(join(fatVolume, 'copy'));
  const before = tree(fatVolume);
  assert.throws(() => vault.session({ probe }, join(link, 'copy')), { code: 'FILESYSTEM_UNSUPPORTED' });
  assert.deepEqual(tree(fatVolume), before);
});

test('step 3 stops on a rolled-back drive before anything on either side changes (no lock, no keyring folder)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY a')], true);
  vault.init();
  const first = vault.session().result;
  const saved = join(vault.root, 'saved');
  cpSync(vault.drive, saved, { recursive: true });
  vault.append([event('TEST ONLY b')]);
  const second = vault.session({ recorded: first.head }).result;
  assert.equal(second.head.segment, 2);
  // Swap the drive for its older state, without its lock file and keyring folder.
  const restored = join(vault.root, 'restored');
  cpSync(saved, restored, { recursive: true });
  makeWritable(restored);
  rmSync(join(restored, 'keyring'), { recursive: true });
  for (const name of readdirSync(restored)) if (name.startsWith('.writer.lock')) unlinkSync(join(restored, name));
  vault.append([event('TEST ONLY open record')]);
  const drive = tree(restored);
  const working = tree(vault.working);
  assert.throws(() => vault.session({ recorded: second.head }, restored), { code: 'ROLLBACK_DETECTED', reason: 'drive-older-than-recorded' });
  assert.deepEqual(tree(restored), drive, 'no lock file, no keyring folder, no probe');
  assert.deepEqual(tree(vault.working), working);
});

test('a lost newest segment with a surviving HEAD.json is a rollback, not head damage', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one')], true);
  vault.append([event('TEST ONLY two')], true);
  vault.init();
  const { result } = vault.session();
  makeWritable(vault.drive);
  rmSync(segmentDir(vault.drive, 2), { recursive: true });
  const drive = tree(vault.drive);
  assert.throws(() => vault.session({ recorded: result.head }), { code: 'ROLLBACK_DETECTED', reason: 'drive-older-than-recorded' });
  assert.deepEqual(tree(vault.drive), drive);
  // Without a recorded head the same drive is head damage.
  assert.throws(() => vault.session({ recorded: null }), { code: 'COPY_VERIFY_FAILED', reason: 'HEAD' });
});

test('step 3 stops on a forked chain and on a recorded hash that differs at the same segment number', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY shared')], true);
  vault.init();
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
  const forkSession = openSecondCopySession(clone, vault.drive, { probe: ntfs, copyId: ID, recorded: shared.head });
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
  assert.throws(() => openSecondCopySession(other.working, vault.drive, { probe: ntfs, copyId: ID }),
    { code: 'ROLLBACK_DETECTED', reason: 'working-older-than-drive' });
  assert.deepEqual(tree(vault.drive), drive);
});

test('a drive with a stream hand-edited fails the keyless check (step 2) and nothing changes', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY x'), blob('TEST ONLY y')], true);
  vault.init();
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
  vault.init();
  const metadataPath = join(vault.drive, 'VAULT.json');
  const original = readFileSync(metadataPath, 'utf8');
  writeFileSync(metadataPath, original.replace(/"created_at":"[^"]+"/u, '"created_at":"2001-01-01T00:00:00Z"'));
  assert.throws(() => vault.session(), { code: 'VAULT_MISMATCH' });
  writeFileSync(metadataPath, 'TEST ONLY not json');
  assert.throws(() => vault.session(), { code: 'NOT_A_COPY' });
});

test('a write-protected drive is reported and left unchanged', { skip: process.platform === 'win32' || process.getuid?.() === 0 }, t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY protected')], true);
  vault.init();
  t.after(() => makeWritable(vault.drive));
  // The drive root is read-only (no keyring folder yet).
  chmodSync(vault.drive, 0o500);
  let before = tree(vault.drive);
  assert.throws(() => vault.session(), { code: 'WRITE_PROTECTED' });
  assert.deepEqual(tree(vault.drive), before);
  // The keyring folder exists and is read-only too.
  chmodSync(vault.drive, 0o700);
  mkdirSync(join(vault.drive, 'keyring'), { mode: 0o500 });
  chmodSync(vault.drive, 0o500);
  before = tree(vault.drive);
  assert.throws(() => vault.session(), { code: 'WRITE_PROTECTED' });
  assert.deepEqual(tree(vault.drive), before);
  // Only the keyring folder is read-only.
  chmodSync(vault.drive, 0o700);
  before = tree(vault.drive);
  assert.throws(() => vault.session(), { code: 'WRITE_PROTECTED' });
  assert.deepEqual(tree(vault.drive), before);
});

test('an interrupted session at any step is finished or rolled back by the next one', t => {
  const points = ['after-stream-files', 'after-signature', 'after-manifest-pending', 'after-manifest-rename',
    'after-read-back', 'after-read-only', 'after-keyring', 'after-session-end', 'after-head-update'];
  for (const point of points) {
    const vault = setup(t);
    vault.append([event('TEST ONLY first'), blob('TEST ONLY first blob')], true);
    vault.init();
    const first = vault.session().result;
    vault.append([event('TEST ONLY second'), blob('TEST ONLY second blob')]);
    const stop = new Error('TEST ONLY drive pulled');
    assert.throws(() => vault.session({
      recorded: first.head,
      checkpoint: (name, segment) => { if (name === point && segment >= 2) throw stop; },
    }), error => error === stop, point);
    // Segment 1 on the drive is untouched by the interrupted session.
    assert.equal(sha(readFileSync(join(segmentDir(vault.drive, 1), 'MANIFEST.json'))), first.head.hash);
    // R19-2, R20-1 (54): until HEAD.json names segment 2, segment 2 is uncommitted; SESSION.json is removed only
    // after that, so a stop between the two leaves both and the verified published head decides.
    const committed = ['after-head-update', 'after-session-end'].includes(point);
    assert.equal(existsSync(join(vault.drive, 'SESSION.json')), point !== 'after-session-end', point);
    assert.equal(JSON.parse(readFileSync(join(vault.drive, 'HEAD.json'))).segment, committed ? 2 : 1, point);
    const next = vault.session({ recorded: first.head });
    assert.equal(next.report.removedPartialSegment, committed ? undefined : 2, point);
    assert.equal(next.report.completedHead, false, point);
    assert.equal(next.report.protectedSegments, 0, point);
    assert.equal(next.result.segmentsCopied, committed ? 0 : 1, point);
    assert.equal(existsSync(join(vault.drive, 'SESSION.json')), false, point);
    assert.equal(next.result.head.segment, 2, point);
    assert.equal(verifyVault(vault.drive, { anchor: next.result.anchor, secondCopy: true }).position.segment, 2, point);
    assert.deepEqual(readFileSync(keyringPath(vault.drive)), readFileSync(keyringPath(vault.working)), point);
    for (const name of readdirSync(segmentDir(vault.drive, 2))) {
      assert.equal(statSync(join(segmentDir(vault.drive, 2), name)).mode & 0o222, 0, `${point}: ${name} read-only`);
    }
  }
});

test('the session state outlives the head: every sync, then HEAD.json, then SESSION.json is removed (R20-1, 54)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob one')], true);
  vault.init();
  const first = vault.session().result;
  vault.append([event('TEST ONLY two'), blob('TEST ONLY blob two')]);
  const events = [];
  const stop = new Error('TEST ONLY pulled after the head');
  assert.throws(() => vault.session({
    recorded: first.head, onSync: name => events.push(name),
    checkpoint: name => { if (name === 'after-head-update') throw stop; },
  }), error => error === stop);
  const head = events.indexOf('head-published');
  assert.ok(head > 0 && !events.includes('session-removed'), events.join(' '));
  assert.ok(events.slice(0, head).includes('keyring-dir') && events.slice(0, head).includes('segment-dir'));
  // The published head is verified and ends the committed chain: the retry recopies nothing and keeps the seal.
  const segmentTwo = tree(segmentDir(vault.drive, 2));
  assert.equal(existsSync(join(vault.drive, 'SESSION.json')), true);
  assert.deepEqual(verifySecondCopy(vault.drive, { workingVault: vault.working, recorded: first.head, copyId: ID }).segment, 2);
  const retryEvents = [];
  const retry = vault.session({ recorded: first.head, onSync: name => retryEvents.push(name) });
  assert.deepEqual([retry.report.removedPartialSegment, retry.result.segmentsCopied, retry.result.head.segment], [undefined, 0, 2]);
  assert.deepEqual(tree(segmentDir(vault.drive, 2)), segmentTwo);
  assert.equal(existsSync(join(vault.drive, 'SESSION.json')), false);
  assert.deepEqual(retryEvents.slice(-1), ['session-removed']);
  // A published head after the session's base that the chain does not end at is refused.
  makeWritable(vault.drive);
  writeFileSync(join(vault.drive, 'SESSION.json'), `{"format":"foundry-copy-session/1","manifest_sha256":"${first.head.hash}","segment":1}`);
  writeFileSync(join(vault.drive, 'HEAD.json'), `{"manifest_sha256":"${'c'.repeat(64)}","segment":2}`);
  assert.throws(() => vault.session({ recorded: first.head }), { code: 'COPY_VERIFY_FAILED', reason: 'HEAD' });
});

test('a drive folder with more entries than a valid one can hold stops with a fixed error before it is listed whole (R20-4, 39)', t => {
  assert.equal(MAX_SEGMENT_ENTRIES, 9365);
  assert.equal(MAX_ROOT_ENTRIES, 14);
  const tooMany = { code: 'COPY_VERIFY_FAILED', reason: 'TOO_MANY_ENTRIES' };
  const fill = (folder, count, name) => {
    for (let n = readdirSync(folder).length; n < count; n++) writeFileSync(join(folder, name(n)), 'TEST ONLY');
  };
  // An uncommitted segment folder of an interrupted session, one entry over the (lowered) cap.
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob')], true);
  vault.init();
  const first = vault.session().result;
  const cap = readdirSync(segmentDir(vault.drive, 1)).length + 2;
  setSegmentEntryCapForTest(cap);
  t.after(() => setSegmentEntryCapForTest(undefined));
  vault.append([event('TEST ONLY two'), blob('TEST ONLY blob two')]);
  const stop = new Error('TEST ONLY pulled');
  assert.throws(() => vault.session({ recorded: first.head, checkpoint: name => { if (name === 'after-stream-files') throw stop; } }),
    error => error === stop);
  fill(segmentDir(vault.drive, 2), cap + 1, n => `events-${String(9000 + n)}.fvr`);
  let before = tree(vault.drive);
  assert.throws(() => vault.session({ recorded: first.head }), tooMany);
  assert.throws(() => verifySecondCopy(vault.drive, { anchor: first.anchor }), tooMany);
  assert.deepEqual(tree(vault.drive), before, 'nothing changed');
  // Exactly at the cap the folder is accepted (and removed and copied again).
  setSegmentEntryCapForTest(cap + 1);
  assert.equal(vault.session({ recorded: first.head }).result.head.segment, 2);
  setSegmentEntryCapForTest(cap);
  // A committed segment folder: its count is checked before the chain scan lists it (not INVENTORY from the scan).
  const committed = setup(t);
  committed.append([event('TEST ONLY three'), blob('TEST ONLY blob three')], true);
  committed.init();
  const sealed = committed.session().result;
  makeWritable(committed.drive);
  fill(segmentDir(committed.drive, 1), cap + 1, n => `TEST-ONLY-${n}`);
  assert.throws(() => verifySecondCopy(committed.drive, { anchor: sealed.anchor }), tooMany);
  // A copy root with more entries than its inventory allows.
  rmSync(segmentDir(committed.drive, 1), { recursive: true });
  fill(committed.drive, MAX_ROOT_ENTRIES + 1, n => `TEST-ONLY-${n}`);
  before = tree(committed.drive);
  assert.throws(() => committed.session(), tooMany);
  assert.deepEqual(tree(committed.drive), before);
});

test('a short or stale pending head is discarded and HEAD.json is rebuilt from the verified chain', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one')], true);
  vault.init();
  const first = vault.session().result;
  // A durable pending head that names a segment whose folder entry was lost.
  writeFileSync(join(vault.drive, 'HEAD.json.pending'), JSON.stringify({ manifest_sha256: 'c'.repeat(64), segment: 2 }));
  assert.equal(vault.session({ recorded: first.head }).result.head.segment, 1);
  assert.equal(existsSync(join(vault.drive, 'HEAD.json.pending')), false);
  // A crash after the manifest rename, then a short pending head.
  vault.append([event('TEST ONLY two')]);
  const stop = new Error('TEST ONLY pulled');
  assert.throws(() => vault.session({ recorded: first.head, checkpoint: name => { if (name === 'after-manifest-rename') throw stop; } }),
    error => error === stop);
  writeFileSync(join(vault.drive, 'HEAD.json.pending'), '{');
  const next = vault.session({ recorded: first.head });
  // The interrupted session's segment 2 was uncommitted (R19-2): removed and copied again.
  assert.deepEqual([next.report.removedPartialSegment, next.result.segmentsCopied, next.result.head.segment], [2, 1, 2]);
  assert.deepEqual(JSON.parse(readFileSync(join(vault.drive, 'HEAD.json'))).segment, 2);
  // A HEAD.json older than the recorded head is damage, not an interrupted session.
  makeWritable(vault.drive);
  writeFileSync(join(vault.drive, 'HEAD.json'), JSON.stringify({ manifest_sha256: first.head.hash, segment: 1 }));
  assert.throws(() => vault.session({ recorded: next.result.head }), { code: 'COPY_VERIFY_FAILED', reason: 'HEAD' });
});

test('read-back checks exact file names and publishes HEAD.json only after it', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob')], true);
  vault.init();
  const first = vault.session().result;
  vault.append([event('TEST ONLY two'), blob('TEST ONLY second blob')]);
  const head = readFileSync(join(vault.drive, 'HEAD.json'));
  assert.throws(() => vault.session({
    recorded: first.head,
    checkpoint: (name, segment) => {
      if (name !== 'after-manifest-rename') return;
      // An extra, validly framed stream in the copied folder (same file count after the pack is renamed).
      const folder = segmentDir(vault.drive, segment);
      renameSync(join(folder, 'pack-0001.fvr'), join(folder, 'pack-0002.fvr'));
    },
  }), { code: 'COPY_VERIFY_FAILED', reason: 'INVENTORY' });
  assert.deepEqual(readFileSync(join(vault.drive, 'HEAD.json')), head, 'HEAD.json is not published before read-back');
  // R19-2 (36): the failed segment is uncommitted, so the retry removes it and copies it again.
  const retry = vault.session({ recorded: first.head });
  assert.deepEqual([retry.report.removedPartialSegment, retry.result.segmentsCopied, retry.result.head.segment], [2, 1, 2]);
  assert.equal(verifyVault(vault.drive, { anchor: retry.result.anchor, secondCopy: true }).position.segment, 2);
});

test('a stream corrupted on the drive after the manifest rename is copied again by the retry; earlier seals stay (R19-2)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob one')], true);
  vault.init();
  const first = vault.session().result;
  const segmentOne = tree(segmentDir(vault.drive, 1));
  vault.append([event('TEST ONLY two'), blob('TEST ONLY blob two')]);
  assert.throws(() => vault.session({
    recorded: first.head,
    checkpoint: (name, segment) => {
      if (name !== 'after-manifest-rename') return;
      // A media fault: one byte of a copied stream changes after the final manifest landed.
      const path = join(segmentDir(vault.drive, segment), 'pack-0001.fvr');
      const bytes = readFileSync(path);
      bytes[bytes.length - 1] ^= 1;
      writeFileSync(path, bytes);
    },
  }), { code: 'COPY_VERIFY_FAILED', reason: 'FILE_HASH' });
  assert.equal(JSON.parse(readFileSync(join(vault.drive, 'HEAD.json'))).segment, 1);
  assert.equal(existsSync(join(vault.drive, 'SESSION.json')), true);
  const retry = vault.session({ recorded: first.head });
  assert.deepEqual([retry.report.removedPartialSegment, retry.result.segmentsCopied, retry.result.head.segment], [2, 1, 2]);
  assert.deepEqual(tree(segmentDir(vault.drive, 1)), segmentOne, 'the earlier seal is untouched');
  assert.equal(verifyVault(vault.drive, { anchor: retry.result.anchor, secondCopy: true }).position.segment, 2);
  assert.deepEqual(readFileSync(keyringPath(vault.drive)), readFileSync(keyringPath(vault.working)));
});

test('interrupted between the manifest and the keyring: no head names the new segment until the keyring is back (R19-2)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one')], true);
  vault.init();
  const first = vault.session().result;
  const headBefore = readFileSync(join(vault.drive, 'HEAD.json'));
  const keyringBefore = readFileSync(keyringPath(vault.drive));
  vault.append([event('TEST ONLY two')]);
  const stop = new Error('TEST ONLY pulled');
  assert.throws(() => vault.session({ recorded: first.head, checkpoint: name => { if (name === 'after-read-only') throw stop; } }),
    error => error === stop);
  // The next session opens (recovery) and stops before its seal, like a failing working writer.
  const opened = openSecondCopySession(vault.working, vault.drive, { probe: ntfs, copyId: ID, recorded: first.head });
  opened.release();
  assert.equal(opened.report.removedPartialSegment, 2);
  assert.deepEqual(readFileSync(join(vault.drive, 'HEAD.json')), headBefore, 'HEAD.json still names segment 1');
  assert.deepEqual(readFileSync(keyringPath(vault.drive)), keyringBefore);
  assert.equal(existsSync(segmentDir(vault.drive, 2)), false);
  const done = vault.session({ recorded: first.head });
  assert.equal(done.result.head.segment, 2);
  assert.deepEqual(JSON.parse(readFileSync(join(vault.drive, 'HEAD.json'))).segment, 2);
  assert.deepEqual(readFileSync(keyringPath(vault.drive)), readFileSync(keyringPath(vault.working)));
  assert.equal(existsSync(join(vault.drive, 'SESSION.json')), false);
});

test('exFAT: only segment files carry the read-only state; folder write bits are left alone and not checked (R20-5, 53)', t => {
  const exfat = () => ({ type: 'exfat', method: 'injected' });
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob')], true);
  vault.init(vault.drive, { probe: exfat });
  const first = vault.session({ probe: exfat }).result;
  const folder = segmentDir(vault.drive, 1);
  for (const name of readdirSync(folder)) assert.equal(statSync(join(folder, name)).mode & 0o222, 0, `${name} read-only`);
  // Like Linux exFAT, the folder keeps its write bits: no chmod of the folder, and no failed check.
  if (process.platform !== 'win32') assert.notEqual(statSync(folder).mode & 0o222, 0, 'the folder mode is not changed');
  const events = [];
  const again = vault.session({ probe: exfat, recorded: first.head, onSync: name => events.push(name) });
  assert.equal(again.report.protectedSegments, 0);
  assert.ok(events.includes('segment-file') && events.includes('segment-dir'), 'files and folder are still synced');
  // A writable file is still repaired and checked.
  chmodSync(join(folder, 'pack-0001.fvr'), 0o644);
  assert.equal(vault.session({ probe: exfat, recorded: first.head }).report.protectedSegments, 1);
  assert.equal(statSync(join(folder, 'pack-0001.fvr')).mode & 0o222, 0);
  // On every other file system a writable folder is a repair too (the folder check is kept).
  if (process.platform !== 'win32') {
    assert.equal(vault.session({ recorded: first.head }).report.protectedSegments, 1);
    assert.equal(statSync(folder).mode & 0o222, 0);
  }
});

test('a keyring rename that was never synced is synced by the retry although the bytes match (R20-1, 35)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one')], true);
  vault.init();
  const stop = new Error('TEST ONLY pulled between the keyring rename and its folder sync');
  assert.throws(() => vault.session({ checkpoint: name => { if (name === 'after-keyring-rename') throw stop; } }),
    error => error === stop);
  assert.deepEqual(readFileSync(keyringPath(vault.drive)), readFileSync(keyringPath(vault.working)), 'the rename landed');
  const events = [];
  const retry = vault.session({ onSync: name => events.push(name) });
  assert.equal(retry.result.keyringWritten, false, 'the drive already holds these bytes');
  assert.deepEqual(events.filter(name => name.startsWith('keyring-')), ['keyring-file', 'keyring-dir']);
  // A later session with nothing new syncs the matching keyring again.
  const again = [];
  vault.session({ recorded: retry.result.head, onSync: name => again.push(name) });
  assert.deepEqual(again.filter(name => name.startsWith('keyring-')), ['keyring-file', 'keyring-dir']);
});

test('a recorded segment left writable (a lost mode change) is made read-only again by the next session (R19-2, 46)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob')], true);
  vault.init();
  const first = vault.session().result;
  const pack = join(segmentDir(vault.drive, 1), 'pack-0001.fvr');
  chmodSync(pack, 0o644);
  assert.notEqual(statSync(pack).mode & 0o222, 0);
  const next = vault.session({ recorded: first.head });
  assert.equal(next.report.protectedSegments, 1);
  assert.equal(statSync(pack).mode & 0o222, 0);
});

test('a repair stopped between chmod and its sync is synced by the retry although the modes look right (R20-1, 46)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one'), blob('TEST ONLY blob')], true);
  vault.init();
  const first = vault.session().result;
  const folder = segmentDir(vault.drive, 1);
  const files = readdirSync(folder).length;
  chmodSync(join(folder, 'pack-0001.fvr'), 0o644);
  const stop = new Error('TEST ONLY pulled between chmod and fsync');
  assert.throws(() => vault.session({
    recorded: first.head, checkpoint: (name, segment) => { if (name === 'after-chmod' && segment === 1) throw stop; },
  }), error => error === stop);
  assert.equal(statSync(join(folder, 'pack-0001.fvr')).mode & 0o222, 0, 'the mode change landed, its sync did not');
  const events = [];
  const retry = vault.session({ recorded: first.head, onSync: (name, segment) => events.push(`${name}:${segment}`) });
  assert.equal(retry.report.protectedSegments, 0, 'nothing looked writable');
  assert.deepEqual(events.filter(name => name.startsWith('segment-') && name.endsWith(':1')),
    [...Array(files).fill('segment-file:1'), 'segment-dir:1']);
});

test('drive entries are type-checked before use: a linked keyring folder or keyring file is refused', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY link')], true);
  vault.init();
  const first = vault.session().result;
  const outside = join(vault.root, 'outside');
  mkdirSync(outside);
  writeFileSync(join(outside, 'keep.txt'), 'TEST ONLY');
  const keyring = join(vault.drive, 'keyring');
  renameSync(keyring, join(vault.root, 'old-keyring'));
  symlinkSync(outside, keyring, linkKind);
  const before = tree(outside);
  assert.throws(() => vault.session({ recorded: first.head }), { code: 'COPY_VERIFY_FAILED', reason: 'INVENTORY' });
  assert.deepEqual(tree(outside), before, 'nothing written through the link');
  // Remove only the link itself (a junction is removed like an empty folder; never a recursive delete).
  if (process.platform === 'win32') rmdirSync(keyring); else unlinkSync(keyring);
  renameSync(join(vault.root, 'old-keyring'), keyring);
  // A folder planted at the keyring file's name, and an unknown entry, are refused too.
  unlinkSync(join(keyring, 'keyring.json'));
  mkdirSync(join(keyring, 'keyring.json'));
  assert.throws(() => vault.session({ recorded: first.head }), { code: 'COPY_VERIFY_FAILED', reason: 'INVENTORY' });
  rmSync(join(keyring, 'keyring.json'), { recursive: true });
  writeFileSync(join(keyring, 'notes.txt'), 'TEST ONLY');
  assert.throws(() => vault.session({ recorded: first.head }), { code: 'COPY_VERIFY_FAILED', reason: 'INVENTORY' });
  unlinkSync(join(keyring, 'notes.txt'));
  assert.equal(vault.session({ recorded: first.head }).result.keyringWritten, true);
});

test('a large planted keyring file on the drive is replaced without being read whole', t => {
  const vault = setup(t);
  vault.init();
  vault.session();
  const planted = keyringPath(vault.drive);
  writeFileSync(planted, Buffer.alloc(4 * 1024 * 1024, 0x20));
  assert.equal(vault.session().result.keyringWritten, true);
  assert.deepEqual(readFileSync(planted), readFileSync(keyringPath(vault.working)));
  // Same size, different bytes: compared and replaced.
  const working = readFileSync(keyringPath(vault.working));
  writeFileSync(planted, Buffer.alloc(working.length, 0x20));
  assert.equal(vault.session().result.keyringWritten, true);
  assert.deepEqual(readFileSync(planted), working);
});

test('an unfinished folder at a recorded segment number is never removed (rollback STOP instead)', t => {
  const vault = setup(t);
  vault.append([event('TEST ONLY one')], true);
  vault.append([event('TEST ONLY two')], true);
  vault.init();
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
  vault.init();
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
  assert.equal(JSON.parse(readFileSync(join(vault.drive, 'HEAD.json'))).manifest_sha256, result.head.hash);
});

test('the copy must be its own folder: not a volume root, not around or inside the vault, not a foreign folder', t => {
  const vault = setup(t);
  assert.throws(() => vault.init(parse(vault.root).root), { code: 'TARGET_UNSUITABLE', reason: 'volume-root' });
  assert.throws(() => vault.init(join(vault.working, 'segments', 'copy')), { code: 'TARGET_UNSUITABLE' });
  assert.throws(() => vault.init(vault.root), { code: 'TARGET_UNSUITABLE' });
  const foreign = join(vault.root, 'foreign');
  mkdirSync(foreign);
  writeFileSync(join(foreign, 'notes.txt'), 'TEST ONLY');
  assert.throws(() => vault.init(foreign), { code: 'TARGET_NOT_EMPTY' });
  assert.throws(() => vault.session({}, foreign), { code: 'NOT_A_COPY' });
  assert.throws(() => vault.session({}, join(vault.root, 'missing')), { code: 'NOT_A_COPY' });
  assert.equal(diskRelation(vault.working, vault.root), 'same-volume');
});

test('placement is checked on canonical paths: a link to the vault and a child named ..x are both inside it', t => {
  const vault = setup(t);
  // A directory junction on Windows, a symbolic link elsewhere: the same bug class as a Windows short (8.3) name.
  const link = join(vault.root, 'link-to-working');
  symlinkSync(vault.working, link, linkKind);
  for (const target of [join(link, 'new-copy'), join(link, 'segments', 'deep', 'copy'), join(vault.working, '..copy'),
    join(vault.working, '..', 'working', 'x')]) {
    assert.throws(() => vault.init(target), { code: 'TARGET_UNSUITABLE', reason: 'overlaps-vault' }, target);
    assert.throws(() => openSecondCopySession(vault.working, target, { probe: ntfs }), { code: 'TARGET_UNSUITABLE' }, target);
  }
  // The vault reached through the link is the same vault: a folder around it is refused too.
  assert.throws(() => initSecondCopy(link, vault.root, { probe: ntfs, copyId: ID }), { code: 'TARGET_UNSUITABLE' });
  // A sibling whose name only starts with the vault's name is outside it.
  assert.equal(vault.init(join(vault.root, 'working-copy')).created, true);
  assert.equal(pathInside(vault.working, join(link, 'x')), true);
  assert.equal(pathInside(vault.working, join(vault.root, 'working-copy')), false);
  assert.equal(pathInside('C:\\vault', 'c:\\VAULT\\..x', 'win32'), true);
  assert.equal(pathInside('C:\\vault', 'D:\\vault', 'win32'), false);
  assert.equal(pathInside('/srv/vault', '/srv/vault2', 'linux'), false);
});

test('the working-device register: strict format, labels, selection, seal record, size limit and the 14-day banner', t => {
  const vault = setup(t);
  const path = join(vault.root, 'second-copies.json');
  const id = identity.vaultId;
  const missing = readCopyRegister(path, id);
  assert.deepEqual(missing, emptyRegister(id, true), 'a missing register is flagged for a keyed rebuild');
  assert.match(copyRegisterStatus(missing, new Date()).banner, /No second copy is recorded on this device/u);
  assert.deepEqual(loadCopyRegister(path, id), { register: emptyRegister(id, true), readable: false, rebuild: true });
  const empty = emptyRegister(id);
  assert.match(copyRegisterStatus(empty, new Date()).banner, /No second copy is set up/u);
  assert.throws(() => selectCopy(empty), { code: 'COPY_UNKNOWN' });
  const created = new Date('2026-01-01T00:00:00Z');
  let { register, copy } = addCopyRecord(empty, undefined, created);
  assert.equal(copy.label, 'copy-1');
  assert.throws(() => addCopyRecord(register, 'copy-1', created), { code: 'INVALID_LABEL' });
  for (const bad of ['', 'has space', '../x', 'x'.repeat(33), 'é']) assert.throws(() => addCopyRecord(register, bad, created), { code: 'INVALID_LABEL' });
  writeCopyRegister(path, register);
  assert.deepEqual(readCopyRegister(path, id), register);
  assert.deepEqual(loadCopyRegister(path, id), { register, readable: true, rebuild: false });
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
  // The writer refuses a register larger than the reader's limit, and the last readable one stays.
  const before = readFileSync(path);
  const bulk = Array.from({ length: 9000 }, (_, n) => ({
    copy_id: n.toString(16).padStart(32, '0'), label: `bulk-${n}`, created_at: '2026-01-01T00:00:00Z', head: null, keyring: null,
  }));
  const big = { ...sealed, copies: [...sealed.copies, ...bulk] };
  assert.ok(Buffer.byteLength(JSON.stringify(big)) > MAX_REGISTER_BYTES);
  assert.throws(() => writeCopyRegister(path, big), { code: 'REGISTER', reason: 'too-large' });
  assert.deepEqual(readFileSync(path), before);
  assert.deepEqual(readdirSync(vault.root).filter(name => name.startsWith('second-copies')), ['second-copies.json']);
  writeFileSync(path, readFileSync(path, 'utf8').replace('"weekly"', '"hourly"'));
  assert.throws(() => readCopyRegister(path, id), { code: 'REGISTER' });
  assert.deepEqual(loadCopyRegister(path, id).rebuild, true, 'a damaged register is rebuilt by a keyed command');
  writeFileSync(path, ' {}');
  assert.throws(() => readCopyRegister(path, id), { code: 'REGISTER' });
});

test('the register is rebuilt from copy.registered and copy.sealed events, idempotently', t => {
  const vault = setup(t);
  const id = identity.vaultId;
  const copy = { copy_id: ID, label: 'offsite', created_at: '2026-01-01T00:00:00Z', head: null, keyring: null };
  const seal = {
    previous: { segment: 0, hash: '0'.repeat(64) }, head: { segment: 3, hash: 'd'.repeat(64) }, sealedAt: '2026-01-02T00:00:00Z',
    segmentsCopied: 3, filesCopied: 9, bytesCopied: 900, keyringVersion: 2,
  };
  const events = [
    { kind: COPY_REGISTERED, ts: '2026-01-01T00:00:00Z', body: copyRegisteredBody(copy, 'monthly', undefined) },
    { kind: COPY_SEALED, ts: '2026-01-02T00:00:00Z', body: copySealedBody(copy, 'monthly', seal) },
    { kind: COPY_SEALED, ts: '2026-01-02T00:00:00Z', body: copySealedBody(copy, 'monthly', seal) },
    { kind: COPY_REGISTERED, ts: 'not a time', body: {} },
    { kind: 'vault.created', ts: '2026-01-03T00:00:00Z', body: { marker: 'TEST ONLY' } },
  ];
  const rebuilt = registerFromEvents(id, events);
  assert.equal(rebuilt.cadence, 'monthly');
  assert.equal(rebuilt.needs_replay, false);
  assert.deepEqual(rebuilt.copies, [{
    ...copy, head: { segment: 3, manifest_sha256: 'd'.repeat(64), sealed_at: '2026-01-02T00:00:00Z' },
    keyring: { version: 2, written_at: '2026-01-02T00:00:00Z' },
  }]);
  assert.deepEqual(registerFromEvents(id, [...events, ...events]), rebuilt, 'the same events twice give the same register');
  // A readable register keeps its cadence and last check (they are set by keyless commands).
  const base = { ...emptyRegister(id, true), cadence: 'daily', last_check: { checked_at: '2026-01-04T00:00:00Z', verify: 'ok' } };
  assert.deepEqual([registerFromEvents(id, events, base).cadence, registerFromEvents(id, events, base).last_check], ['daily', base.last_check]);
  // Adoption: a new record whose event names the old id.
  assert.deepEqual(copyRegisteredBody({ ...copy, copy_id: OTHER }, 'weekly', ID),
    { copy_id: OTHER, label: 'offsite', cadence: 'weekly', adopted: true, previous_copy_id: ID });
  // The real thing: events in the working vault, replayed with a credential (read-only).
  vault.append(events.slice(0, 2).map(item => ({
    type: 'event', keyId, event: { ts: item.ts, kind: item.kind, profile: 'me', collection: 'system', sensitivity: 'personal', body: item.body },
  })), true);
  vault.append([{ type: 'event', keyId, event: { kind: COPY_SEALED, profile: 'partner', collection: 'system', ts: '2026-01-05T00:00:00Z', body: copySealedBody({ ...copy, copy_id: OTHER, label: 'other' }, 'daily', seal) } }]);
  const before = tree(vault.working);
  const replayed = replayCopyRegister(vault.working, { recoveryKey: Buffer.from(cases.recovery_key, 'hex') });
  assert.deepEqual(replayed, rebuilt, 'only me/system copy events count');
  assert.deepEqual(tree(vault.working), before, 'the replay writes nothing');
});

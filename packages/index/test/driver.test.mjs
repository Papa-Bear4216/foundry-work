import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { existsSync, mkdtempDisposableSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { initializeSchema, openSqlDriver, SQLCIPHER_PARAMETERS } from '../dist/index.js';

const key = Buffer.alloc(32, 94);
const childScript = fileURLToPath(new URL('./driver-child.mjs', import.meta.url));
const fixture = () => mkdtempDisposableSync(join(tmpdir(), 'foundry-v4-driver-'));

test('prebuilt SQLCipher pins all parameters and rejects wrong key and plaintext format', () => {
  using dir = fixture();
  const path = join(dir.path, 'working.sqlite');
  const db = openSqlDriver(path, { key, create: true });
  try {
    assert.match(db.prepare('SELECT sqlite3mc_version() AS version').get().version, /SQLite3 Multiple Ciphers/);
    for (const [name, , expected] of SQLCIPHER_PARAMETERS) {
      const row = db.prepare(`PRAGMA ${name}`).get();
      assert.equal(String(Object.values(row)[0]), String(expected), name);
    }
    initializeSchema(db);
  } finally {
    db.close();
  }
  assert.throws(() => openSqlDriver(path, { key: Buffer.alloc(32, 12) }), { name: 'IndexError', code: 'FORMAT' });

  const plain = join(dir.path, 'plain.sqlite');
  openSqlDriver(plain, { adapter: 'plain', allowPlain: true, checkDiskEncryption: () => true, create: true }).close();
  assert.throws(() => openSqlDriver(plain, { key }), { name: 'IndexError', code: 'FORMAT' });
});

test('a changed authentication trailer on a non-schema page is rejected', () => {
  using dir = fixture();
  const path = join(dir.path, 'tamper.sqlite');
  const db = openSqlDriver(path, { key, create: true });
  db.exec("CREATE TABLE sample(data TEXT) STRICT; INSERT INTO sample VALUES ('TEST ONLY page');");
  db.close();
  const changed = readFileSync(path);
  assert.ok(changed.length >= 8192);
  changed[8191] ^= 1;
  writeFileSync(path, changed);
  const reopened = openSqlDriver(path, { key });
  try {
    assert.throws(() => reopened.prepare('SELECT data FROM sample').get(), { code: 'SQLITE_CORRUPT' });
  } finally {
    reopened.close();
  }
});

test('an unloadable native binary fails closed before a database is created', () => {
  using dir = fixture();
  const path = join(dir.path, 'refused.sqlite');
  const child = spawnSync(process.execPath, [childScript, 'unloadable', path], { encoding: 'utf8', windowsHide: true });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout.trim(), 'IndexError ADDON');
  assert.deepEqual(readdirSync(dir.path), []);
});

test('a missing parent directory is a format error when creating a cipher index', () => {
  using dir = fixture();
  assert.throws(() => openSqlDriver(join(dir.path, 'missing', 'index.sqlite'), { key, create: true }),
    { name: 'IndexError', code: 'FORMAT' });
  assert.deepEqual(readdirSync(dir.path), []);
});

test('empty, page-aligned and mid-page truncation are rejected without touching files', () => {
  using dir = fixture();
  for (const [adapter, options] of [
    ['cipher', { key }],
    ['plain', { adapter: 'plain', allowPlain: true, checkDiskEncryption: () => true }],
  ]) {
    const path = join(dir.path, `${adapter}.sqlite`);
    const db = openSqlDriver(path, { ...options, create: true });
    db.exec('CREATE TABLE sample (data BLOB); INSERT INTO sample VALUES (zeroblob(8192));');
    db.close();
    const original = readFileSync(path);
    const before = readdirSync(dir.path);
    for (const length of [0, original.length - 4096, original.length - 1]) {
      const truncated = original.subarray(0, length);
      writeFileSync(path, truncated);
      assert.throws(() => openSqlDriver(path, options), { name: 'IndexError', code: 'FORMAT' }, `${adapter} ${length}`);
      assert.deepEqual(readdirSync(dir.path), before);
      assert.deepEqual(readFileSync(path), truncated);
    }
  }
});

test('plain requires an explicit opt-in and a positive disk encryption check', () => {
  using dir = fixture();
  const path = join(dir.path, 'plain.sqlite');
  for (const policy of [
    { checkDiskEncryption: () => true },
    { allowPlain: true },
    { allowPlain: true, checkDiskEncryption: () => false },
  ]) {
    assert.throws(() => openSqlDriver(path, { adapter: 'plain', create: true, ...policy }), { code: 'PLAIN_POLICY' });
    assert.equal(existsSync(path), false);
  }
  const checkDiskEncryption = checked => {
    assert.equal(checked, path);
    return true;
  };
  const policy = { adapter: 'plain', create: true, allowPlain: true, checkDiskEncryption };
  assert.throws(() => openSqlDriver(path, { ...policy, key }), { code: 'CONFIG' });
  assert.equal(existsSync(path), false);
  const db = openSqlDriver(path, policy);
  try {
    assert.equal(db.prepare('PRAGMA temp_store').get().temp_store, 2);
    assert.equal(db.prepare('PRAGMA secure_delete').get().secure_delete, 1);
    initializeSchema(db);
    assert.equal(db.prepare('PRAGMA user_version').get().user_version, 2);
  } finally {
    db.close();
  }
});

test('force-killed writer recovers committed data from a live WAL and rolls back spilled writes', { timeout: 20000 }, async t => {
  using dir = fixture();
  const path = join(dir.path, 'crash.sqlite');
  const child = spawn(process.execPath, [childScript, 'crash', path], { windowsHide: true });
  const closed = once(child, 'close');
  try {
    const [ready] = await Promise.race([
      once(child.stdout, 'data'),
      closed.then(([code]) => { throw new Error(`Crash fixture exited before checkpoint (${code}).`); }),
    ]);
    assert.equal(ready.toString().trim(), 'ready');
    const live = readdirSync(dir.path);
    const kill = process.platform === 'win32'
      ? spawnSync('taskkill.exe', ['/F', '/PID', String(child.pid)], { windowsHide: true, encoding: 'utf8' })
      : { status: child.kill('SIGKILL') ? 0 : 1 };
    if (process.platform === 'win32' && kill.status !== 0 && /access denied/iu.test(kill.stderr ?? '')) {
      // A restricted token can deny taskkill's process lookup. Node already
      // owns the child handle and uses TerminateProcess for SIGKILL on Windows.
      assert.ok(child.kill('SIGKILL'), kill.stderr);
      t.diagnostic('Writer force-killed using the owned Windows process handle.');
    } else {
      assert.equal(kill.status, 0, kill.stderr);
      t.diagnostic(process.platform === 'win32' ? 'Writer force-killed with taskkill /F.' : 'Writer force-killed with SIGKILL.');
    }
    const exit = await closed;
    assert.ok(exit[1] === 'SIGKILL' || (typeof exit[0] === 'number' && exit[0] !== 0));
    const wal = path + '-wal';
    for (let attempt = 0; attempt < 10 && !existsSync(wal); attempt++) await delay(25);
    assert.ok(existsSync(wal), JSON.stringify({ live, after: readdirSync(dir.path), exit, taskkill: kill.status }));
    assert.ok(statSync(wal).size > 64 * 4096, 'expected uncheckpointed committed and spilled pages');
    assert.ok(!readFileSync(`${path}-wal`).includes(Buffer.from('TEST ONLY committed WAL row')));
    const reopened = openSqlDriver(path, { key });
    try {
      assert.deepEqual(reopened.prepare('SELECT CAST(payload AS TEXT) AS payload FROM sample').all().map(row => row.payload),
        ['TEST ONLY committed WAL row']);
      assert.equal(reopened.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
    } finally {
      reopened.close();
    }
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
  }
});

test('large transactions keep UTF-8 and UTF-16LE markers out of db, WAL, journals and SQLite temp storage', () => {
  using dir = fixture();
  const marker = 'FOUNDRY_TEST_ONLY_MARKER_613427';
  const encoded = [Buffer.from(marker, 'utf8'), Buffer.from(marker, 'utf16le')];
  const tempVariables = ['TMP', 'TEMP', 'TMPDIR', 'SQLITE_TMPDIR'];
  const original = tempVariables.map(name => [name, process.env[name]]);
  for (const name of tempVariables) process.env[name] = dir.path;
  try {
    for (const mode of ['WAL', 'DELETE', 'TRUNCATE']) {
      const path = join(dir.path, `marker-${mode}.sqlite`);
      const db = openSqlDriver(path, { key, create: true });
      try {
        assert.equal(db.prepare(`PRAGMA journal_mode=${mode}`).get().journal_mode, mode.toLowerCase());
        db.exec('PRAGMA wal_autocheckpoint=0; PRAGMA cache_size=8; PRAGMA cache_spill=ON;');
        db.exec('CREATE TABLE marker (text TEXT, word BLOB, padding BLOB) STRICT;');
        db.exec('CREATE TEMP TABLE temp_marker (text TEXT, word BLOB, padding BLOB) STRICT;');
        const insert = db.prepare('INSERT INTO marker VALUES (?, ?, ?)');
        db.exec('BEGIN');
        for (let i = 0; i < 192; i++) insert.run(marker, encoded[1], randomBytes(8192));
        db.exec('COMMIT; BEGIN IMMEDIATE;');
        const insertTemp = db.prepare('INSERT INTO temp_marker VALUES (?, ?, ?)');
        const update = db.prepare('UPDATE marker SET padding=? WHERE rowid=?');
        for (let i = 1; i <= 192; i++) {
          const padding = randomBytes(8192);
          insertTemp.run(marker, encoded[1], padding);
          update.run(padding, i);
        }
        assert.equal(db.prepare('SELECT count(*) AS total FROM temp_marker').get().total, 192);
        assert.ok(db.prepare("PRAGMA database_list").all().some(row => row.name === 'temp' && row.file === ''));
        const sidecar = path + (mode === 'WAL' ? '-wal' : '-journal');
        assert.ok(statSync(sidecar).size > 1024 * 1024, `expected populated ${mode} sidecar`);
        assert.ok(statSync(path).size > 1024 * 1024 || mode === 'WAL');
        const sorted = db.prepare('SELECT text FROM temp_marker ORDER BY padding').iterate();
        try {
          assert.equal(sorted.next().value.text, marker);
          const files = readdirSync(dir.path);
          assert.ok(files.every(name => /^marker-(WAL|DELETE|TRUNCATE)\.sqlite(?:-(?:wal|shm|journal))?$/u.test(name)));
          for (const name of files) {
            // The shared-memory WAL index contains coordination data and has
            // mandatory byte-range locks on Windows. Payloads live in the WAL.
            if (name.endsWith('-shm')) continue;
            const contents = readFileSync(join(dir.path, name));
            for (const bytes of encoded) assert.equal(contents.includes(bytes), false, name);
          }
        } finally {
          sorted.return();
        }
        db.exec('ROLLBACK');
      } finally {
        db.close();
      }
      for (const bytes of encoded) assert.equal(readFileSync(path).includes(bytes), false);
    }
  } finally {
    for (const [name, value] of original) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

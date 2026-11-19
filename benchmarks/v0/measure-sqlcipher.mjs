import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import Database from 'better-sqlite3-multiple-ciphers';

const MARKER = 'FOUNDRY_V0_PLANTED_PLAINTEXT_MARKER_9F8E7D6C5B4A';
const keyHex = randomBytes(32).toString('hex');
const wrongKeyHex = randomBytes(32).toString('hex');

const tempDir = mkdtempSync(join(tmpdir(), 'foundry-v0-sqlcipher-'));
const dbPath = join(tempDir, 'index.db');
const tamperedPath = join(tempDir, 'tampered.db');

function configureCipher(db, hexKey) {
  db.pragma("cipher = 'sqlcipher'");
  db.pragma('legacy = 4');
  db.pragma('legacy_page_size = 4096');
  db.pragma('hmac_check = 1');
  db.pragma(`key = "x'${hexKey}'"`);
  db.pragma('temp_store = MEMORY');
  db.pragma('secure_delete = ON');
}

let openDb = null;

try {
  const t0 = performance.now();
  const db = new Database(dbPath);
  openDb = db;
  configureCipher(db, keyHex);

  const sqliteVersion = db.prepare('SELECT sqlite_version() AS v').get().v;
  const sqlite3mcVersion = db.prepare('SELECT sqlite3mc_version() AS v').get().v;
  const pinnedCipher = String(db.pragma('cipher', { simple: true }));
  const pinnedLegacy = Number(db.pragma('legacy', { simple: true }));
  const pinnedHmacCheck = Number(db.pragma('hmac_check', { simple: true }));
  const pinnedPageSize = Number(db.pragma('legacy_page_size', { simple: true }));
  const tempStore = Number(db.pragma('temp_store', { simple: true }));
  const secureDelete = Number(db.pragma('secure_delete', { simple: true }));

  if (pinnedCipher !== 'sqlcipher' || pinnedLegacy !== 4 || pinnedHmacCheck !== 1 || pinnedPageSize !== 4096) {
    throw new Error(`Unexpected cipher config: cipher=${pinnedCipher} legacy=${pinnedLegacy} hmac=${pinnedHmacCheck} page=${pinnedPageSize}`);
  }

  // Verify FTS5 and R-tree (rtree_i32) are compiled in and usable under SQLCipher.
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE items (
      item_id INTEGER PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL
    ) STRICT;
    CREATE VIRTUAL TABLE items_fts USING fts5(title, body, content='items', content_rowid='item_id', tokenize='porter unicode61');
    CREATE VIRTUAL TABLE places_rtree USING rtree_i32(place_id, min_lat, max_lat, min_lng, max_lng);
  `);

  const insertItem = db.prepare('INSERT INTO items (item_id, title, body) VALUES (?, ?, ?)');
  const insertFts = db.prepare('INSERT INTO items_fts (rowid, title, body) VALUES (?, ?, ?)');
  const insertRtree = db.prepare('INSERT INTO places_rtree (place_id, min_lat, max_lat, min_lng, max_lng) VALUES (?, ?, ?, ?, ?)');

  for (let i = 1; i <= 40; i++) {
    const text = i === 1
      ? `Synthetic message containing ${MARKER} for rest scan.`
      : `Synthetic body record ${i} with searchable content ${'padding-'.repeat(24)}`;
    insertItem.run(i, `synthetic-note-${i}`, text);
    insertFts.run(i, `synthetic-note-${i}`, text);
  }
  insertRtree.run(1, 300000000, 300000000, -900000000, -900000000);

  const ftsHits = db.prepare("SELECT rowid FROM items_fts WHERE items_fts MATCH 'synthetic' ORDER BY rowid LIMIT 5").all();
  const rtreeHits = db.prepare('SELECT place_id FROM places_rtree WHERE min_lat >= 290000000 AND max_lat <= 310000000').all();

  if (ftsHits.length === 0 || ftsHits[0].rowid !== 1) {
    throw new Error(`FTS5 check failed: ${JSON.stringify(ftsHits)}`);
  }
  if (rtreeHits.length !== 1 || rtreeHits[0].place_id !== 1) {
    throw new Error(`R-tree check failed: ${JSON.stringify(rtreeHits)}`);
  }

  db.pragma('wal_checkpoint(TRUNCATE)');
  db.close();
  openDb = null;

  // Verify planted marker string does not appear in any on-disk file bytes.
  const markerBytes = Buffer.from(MARKER, 'utf8');
  let markerLeakFound = false;
  const scannedFiles = [];
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    const candidate = `${dbPath}${suffix}`;
    if (existsSync(candidate)) {
      const data = readFileSync(candidate);
      scannedFiles.push({ suffix: suffix || '.db', bytes: data.length });
      if (data.includes(markerBytes)) {
        markerLeakFound = true;
      }
    }
  }
  if (markerLeakFound) {
    throw new Error('Planted plaintext marker found on disk in encrypted database files.');
  }

  // Verify fail-closed wrong-key rejection.
  let wrongKeyRejected = false;
  const wrongDb = new Database(dbPath);
  openDb = wrongDb;
  try {
    configureCipher(wrongDb, wrongKeyHex);
    wrongDb.prepare('SELECT count(*) AS n FROM sqlite_master').get();
  } catch {
    wrongKeyRejected = true;
  } finally {
    wrongDb.close();
    openDb = null;
  }
  if (!wrongKeyRejected) {
    throw new Error('Wrong key was not rejected by SQLCipher.');
  }

  // Verify page authentication rejects a single-bit modification on page 2.
  copyFileSync(dbPath, tamperedPath);
  const rawDb = readFileSync(tamperedPath);
  if (rawDb.length < 8192) {
    throw new Error(`Expected >= 2 pages (8192 bytes) for tamper check, got ${rawDb.length}`);
  }
  rawDb[4096 + 128] ^= 0x01;
  writeFileSync(tamperedPath, rawDb);

  let modifiedPageRejected = false;
  const tamperedDb = new Database(tamperedPath);
  openDb = tamperedDb;
  try {
    configureCipher(tamperedDb, keyHex);
    tamperedDb.prepare('SELECT count(*) AS n FROM items').get();
  } catch {
    modifiedPageRejected = true;
  } finally {
    tamperedDb.close();
    openDb = null;
  }
  if (!modifiedPageRejected) {
    throw new Error('Modified page was not rejected by SQLCipher page authentication.');
  }

  // Re-open original with the correct key and confirm FTS5 + R-tree still query cleanly.
  const verifyDb = new Database(dbPath);
  openDb = verifyDb;
  configureCipher(verifyDb, keyHex);
  const reopenFts = verifyDb.prepare("SELECT count(*) AS n FROM items_fts WHERE items_fts MATCH 'synthetic'").get().n;
  const reopenRtree = verifyDb.prepare('SELECT count(*) AS n FROM places_rtree').get().n;
  verifyDb.close();
  openDb = null;

  if (reopenFts !== 40 || reopenRtree !== 1) {
    throw new Error(`Reopen check failed: fts=${reopenFts}, rtree=${reopenRtree}`);
  }

  const builtBinaryExists = existsSync(
    new URL('./node_modules/better-sqlite3-multiple-ciphers/build/Release/better_sqlite3.node', import.meta.url),
  );
  const prebuildName = `${process.platform}-${process.arch}.node`;
  const prebuildBinaryExists = existsSync(
    new URL(`./node_modules/better-sqlite3-multiple-ciphers/prebuilds/${prebuildName}`, import.meta.url),
  );

  if (process.env.FOUNDRY_V0_REQUIRE_BUILT === '1' && !builtBinaryExists) {
    throw new Error('FOUNDRY_V0_REQUIRE_BUILT=1 set, but build/Release/better_sqlite3.node does not exist.');
  }

  const elapsedMs = performance.now() - t0;
  const ru = process.resourceUsage();

  console.log(JSON.stringify({
    benchmark: 'sqlcipher-addon',
    addonLoaded: true,
    loadedAddonVariant: builtBinaryExists ? 'built-from-source' : 'prebuild',
    builtBinaryExists,
    prebuildBinaryExists,
    sqliteVersion,
    sqlite3mcVersion,
    pinnedConfig: {
      cipher: pinnedCipher,
      legacy: pinnedLegacy,
      pageSize: pinnedPageSize,
      hmacCheck: pinnedHmacCheck,
      tempStore,
      secureDelete,
    },
    fts5Available: true,
    rtreeAvailable: true,
    wrongKeyRejected,
    modifiedPageRejected,
    markerLeakFound,
    scannedFiles,
    elapsedMs: Number(elapsedMs.toFixed(2)),
    internalMaxRssKiB: ru.maxRSS,
    internalMaxRssMiB: Number((ru.maxRSS / 1024).toFixed(2)),
  }));
} finally {
  if (openDb !== null) {
    try {
      openDb.close();
    } catch {
      // Best-effort handle release before removing tempDir.
    }
    openDb = null;
  }
  try {
    rmSync(tempDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } catch (cleanupErr) {
    console.warn('temp cleanup warning:', cleanupErr.message);
  }
}

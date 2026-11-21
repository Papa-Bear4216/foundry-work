import { randomBytes } from 'node:crypto';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3-multiple-ciphers';

const MARKER = 'FOUNDRY_V0_PLANTED_PLAINTEXT_MARKER_9F8E7D6C5B4A';
const keyHex = randomBytes(32).toString('hex');
const wrongKeyHex = randomBytes(32).toString('hex');

const tempDir = mkdtempSync(join(tmpdir(), 'foundry-v0-sqlcipher-'));
const dbPath = join(tempDir, 'index.db');
const tamperedPath = join(tempDir, 'tampered.db');

const builtAddonPath = fileURLToPath(
  new URL('./node_modules/better-sqlite3-multiple-ciphers/build/Release/better_sqlite3.node', import.meta.url),
);
const addonPkgJson = JSON.parse(
  readFileSync(new URL('./node_modules/better-sqlite3-multiple-ciphers/package.json', import.meta.url), 'utf8'),
);
const addonPackageVersion = String(addonPkgJson.version);
const builtBinaryExists = existsSync(builtAddonPath);
const prebuildBinaryExists = existsSync(
  new URL(`./node_modules/better-sqlite3-multiple-ciphers/prebuilds/${process.platform}-${process.arch}.node`, import.meta.url),
);
const requireBuilt = process.env.FOUNDRY_V0_REQUIRE_BUILT === '1';

if (requireBuilt && !builtBinaryExists) {
  throw new Error('FOUNDRY_V0_REQUIRE_BUILT=1 set, but build/Release/better_sqlite3.node does not exist.');
}

const dbOptions = requireBuilt ? { nativeBinding: builtAddonPath } : {};

function configureCipher(db, hexKey, { hmacCheck = 1 } = {}) {
  db.pragma("cipher = 'sqlcipher'");
  db.pragma('legacy = 4');
  db.pragma('legacy_page_size = 4096');
  db.pragma('kdf_iter = 256000');
  db.pragma('fast_kdf_iter = 2');
  db.pragma('hmac_use = 1');
  db.pragma(`hmac_check = ${hmacCheck}`);
  db.pragma('hmac_pgno = 1');
  db.pragma('hmac_salt_mask = 58');
  db.pragma('hmac_algorithm = 2');
  db.pragma('kdf_algorithm = 2');
  db.pragma('plaintext_header_size = 0');
  db.pragma(`key = "x'${hexKey}'"`);
  db.pragma('temp_store = MEMORY');
  db.pragma('secure_delete = ON');
}

function readPinnedConfig(db) {
  return {
    cipher: String(db.pragma('cipher', { simple: true })),
    legacy: Number(db.pragma('legacy', { simple: true })),
    pageSize: Number(db.pragma('legacy_page_size', { simple: true })),
    kdfIter: Number(db.pragma('kdf_iter', { simple: true })),
    fastKdfIter: Number(db.pragma('fast_kdf_iter', { simple: true })),
    hmacUse: Number(db.pragma('hmac_use', { simple: true })),
    hmacCheck: Number(db.pragma('hmac_check', { simple: true })),
    hmacPgno: Number(db.pragma('hmac_pgno', { simple: true })),
    hmacSaltMask: Number(db.pragma('hmac_salt_mask', { simple: true })),
    hmacAlgorithm: Number(db.pragma('hmac_algorithm', { simple: true })),
    kdfAlgorithm: Number(db.pragma('kdf_algorithm', { simple: true })),
    plaintextHeaderSize: Number(db.pragma('plaintext_header_size', { simple: true })),
    tempStore: Number(db.pragma('temp_store', { simple: true })),
    secureDelete: Number(db.pragma('secure_delete', { simple: true })),
  };
}

function isExpectedAuthOrCorruptError(err) {
  return err?.code === 'SQLITE_NOTADB' || err?.code === 'SQLITE_CORRUPT';
}

let openDb = null;

try {
  const t0 = performance.now();
  const db = new Database(dbPath, dbOptions);
  openDb = db;
  configureCipher(db, keyHex, { hmacCheck: 1 });

  const sqliteVersion = db.prepare('SELECT sqlite_version() AS v').get().v;
  const sqlite3mcVersion = db.prepare('SELECT sqlite3mc_version() AS v').get().v;
  const pinnedConfig = readPinnedConfig(db);

  if (
    pinnedConfig.cipher !== 'sqlcipher' ||
    pinnedConfig.legacy !== 4 ||
    pinnedConfig.pageSize !== 4096 ||
    pinnedConfig.kdfIter !== 256000 ||
    pinnedConfig.fastKdfIter !== 2 ||
    pinnedConfig.hmacUse !== 1 ||
    pinnedConfig.hmacCheck !== 1 ||
    pinnedConfig.hmacPgno !== 1 ||
    pinnedConfig.hmacSaltMask !== 58 ||
    pinnedConfig.hmacAlgorithm !== 2 ||
    pinnedConfig.kdfAlgorithm !== 2 ||
    pinnedConfig.plaintextHeaderSize !== 0 ||
    pinnedConfig.tempStore !== 2 ||
    pinnedConfig.secureDelete !== 1
  ) {
    throw new Error(`Unexpected cipher config: ${JSON.stringify(pinnedConfig)}`);
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

  let expectedBodyChars = 0;
  for (let i = 1; i <= 40; i++) {
    const text = i === 1
      ? `Synthetic message containing ${MARKER} for rest scan.`
      : `Synthetic body record ${i} with searchable content ${'padding-'.repeat(24)}`;
    expectedBodyChars += text.length;
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

  // Scan the live WAL file BEFORE checkpointing to confirm the planted marker is encrypted in WAL too.
  const markerUtf8Bytes = Buffer.from(MARKER, 'utf8');
  const markerUtf16LeBytes = Buffer.from(MARKER, 'utf16le');
  const containsMarker = (buf) => buf.includes(markerUtf8Bytes) || buf.includes(markerUtf16LeBytes);
  const liveWalPath = `${dbPath}-wal`;
  if (!existsSync(liveWalPath)) {
    throw new Error('Expected active -wal file before checkpoint.');
  }
  const liveWalBytes = readFileSync(liveWalPath);
  if (liveWalBytes.length === 0) {
    throw new Error('Expected non-empty -wal file before checkpoint.');
  }
  const liveWalMarkerLeakFound = containsMarker(liveWalBytes);
  if (liveWalMarkerLeakFound) {
    throw new Error('Planted plaintext marker found in active -wal file.');
  }
  const liveWalScan = {
    exists: true,
    bytes: liveWalBytes.length,
    markerLeakFound: liveWalMarkerLeakFound,
  };

  db.pragma('wal_checkpoint(TRUNCATE)');
  db.close();
  openDb = null;

  // Verify planted marker string does not appear in any post-close on-disk file bytes.
  let markerLeakFound = false;
  const postCloseScannedFiles = [];
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    const candidate = `${dbPath}${suffix}`;
    if (existsSync(candidate)) {
      const data = readFileSync(candidate);
      postCloseScannedFiles.push({ suffix: suffix || '.db', bytes: data.length });
      if (containsMarker(data)) {
        markerLeakFound = true;
      }
    }
  }
  if (markerLeakFound) {
    throw new Error('Planted plaintext marker found on disk in encrypted database files.');
  }

  // Verify fail-closed wrong-key rejection (configuration stays outside the failure catch).
  let wrongKeyRejected = false;
  let wrongKeyErrorCode = null;
  const wrongDb = new Database(dbPath, dbOptions);
  openDb = wrongDb;
  try {
    configureCipher(wrongDb, wrongKeyHex, { hmacCheck: 1 });
    try {
      wrongDb.prepare('SELECT count(*) AS n FROM sqlite_master').get();
    } catch (err) {
      if (!isExpectedAuthOrCorruptError(err)) {
        throw err;
      }
      wrongKeyRejected = true;
      wrongKeyErrorCode = err.code;
    }
  } finally {
    wrongDb.close();
    openDb = null;
  }
  if (!wrongKeyRejected) {
    throw new Error('Wrong key was not rejected by SQLCipher.');
  }

  // Verify page authentication rejects a single-bit modification in page 2's reserved HMAC trailer
  // (offset 8191 = last byte of page 2), while B-tree page data remains structurally intact.
  copyFileSync(dbPath, tamperedPath);
  const rawDb = readFileSync(tamperedPath);
  if (rawDb.length < 8192) {
    throw new Error(`Expected >= 2 pages (8192 bytes) for tamper check, got ${rawDb.length}`);
  }
  rawDb[8191] ^= 0x01;
  writeFileSync(tamperedPath, rawDb);

  let modifiedPageRejected = false;
  let modifiedPageErrorCode = null;
  const tamperedDb = new Database(tamperedPath, dbOptions);
  openDb = tamperedDb;
  try {
    configureCipher(tamperedDb, keyHex, { hmacCheck: 1 });
    try {
      tamperedDb.prepare('SELECT sum(length(body)) AS total FROM items').get();
    } catch (err) {
      if (err?.code !== 'SQLITE_CORRUPT') {
        throw err;
      }
      modifiedPageRejected = true;
      modifiedPageErrorCode = err.code;
    }
  } finally {
    tamperedDb.close();
    openDb = null;
  }
  if (!modifiedPageRejected) {
    throw new Error('Modified page HMAC trailer was not rejected by SQLCipher page authentication.');
  }

  // Control check: with hmac_check = 0, reading the same file succeeds, proving rejection was HMAC-specific.
  let hmacControlBypassSucceeded = false;
  const controlDb = new Database(tamperedPath, dbOptions);
  openDb = controlDb;
  try {
    configureCipher(controlDb, keyHex, { hmacCheck: 0 });
    const controlRow = controlDb.prepare('SELECT sum(length(body)) AS total FROM items').get();
    if (controlRow?.total !== expectedBodyChars) {
      throw new Error(`HMAC control read mismatch: ${controlRow?.total} !== ${expectedBodyChars}`);
    }
    hmacControlBypassSucceeded = true;
  } finally {
    controlDb.close();
    openDb = null;
  }

  // Re-open original with the correct key and confirm FTS5 + R-tree still query cleanly.
  const verifyDb = new Database(dbPath, dbOptions);
  openDb = verifyDb;
  configureCipher(verifyDb, keyHex, { hmacCheck: 1 });
  const reopenFts = verifyDb.prepare("SELECT count(*) AS n FROM items_fts WHERE items_fts MATCH 'synthetic'").get().n;
  const reopenRtree = verifyDb.prepare('SELECT count(*) AS n FROM places_rtree').get().n;
  verifyDb.close();
  openDb = null;

  if (reopenFts !== 40 || reopenRtree !== 1) {
    throw new Error(`Reopen check failed: fts=${reopenFts}, rtree=${reopenRtree}`);
  }

  const elapsedMs = performance.now() - t0;
  const ru = process.resourceUsage();

  console.log(JSON.stringify({
    benchmark: 'sqlcipher-addon',
    addonLoaded: true,
    addonPackageName: 'better-sqlite3-multiple-ciphers',
    addonPackageVersion,
    loadedAddonVariant: requireBuilt ? 'built-from-source' : 'default-resolution',
    explicitNativeBindingUsed: requireBuilt,
    builtBinaryExists,
    prebuildBinaryExists,
    sqliteVersion,
    sqlite3mcVersion,
    pinnedConfig,
    fts5Available: true,
    rtreeAvailable: true,
    wrongKeyRejected,
    wrongKeyErrorCode,
    modifiedPageRejected,
    modifiedPageErrorCode,
    hmacControlBypassSucceeded,
    markerEncodingsScanned: ['utf8', 'utf16le'],
    liveWalScan,
    markerLeakFound,
    postCloseScannedFiles,
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

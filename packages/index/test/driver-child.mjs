import { randomBytes } from 'node:crypto';
import { openSqlDriver } from '../dist/index.js';

const [mode, path] = process.argv.slice(2);
const testKey = () => Buffer.alloc(32, 94);

if (mode === 'unloadable') {
  process.dlopen = () => {
    throw Object.assign(new Error('TEST ONLY loader rejection'), { code: 'ERR_DLOPEN_FAILED' });
  };
  try {
    openSqlDriver(path, { key: testKey(), create: true }).close();
    process.exitCode = 1;
  } catch (error) {
    console.log(error.name, error.code);
    if (error.name !== 'IndexError' || error.code !== 'ADDON') process.exitCode = 1;
  }
} else if (mode === 'crash') {
  const db = openSqlDriver(path, { key: testKey(), create: true });
  db.exec('PRAGMA wal_autocheckpoint=0; PRAGMA cache_size=8; CREATE TABLE sample (payload BLOB) STRICT;');
  const insert = db.prepare('INSERT INTO sample VALUES (?)');
  insert.run(Buffer.from('TEST ONLY committed WAL row'));
  db.exec('BEGIN IMMEDIATE');
  for (let i = 0; i < 96; i++) insert.run(randomBytes(6000));
  // Injected checkpoint after dirty pages have spilled into the live WAL.
  process.stdout.write('ready\n');
  // Keep the connection reachable while the child is waiting to be killed.
  setInterval(() => { db.prepare('SELECT 1').get(); }, 1000);
}

import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { DatabaseSync } from 'node:sqlite';
import { publishKeyring } from '../src/keyring-file.ts';

// TEST ONLY: publish two frozen synthetic fixtures while the parent controls the lock holder.
const [path, mode] = process.argv.slice(2);
const previous = fs.readFileSync(new URL('./vectors/ring.json', import.meta.url));
const next = fs.readFileSync(new URL('./vectors/ring-passphrase-changed.json', import.meta.url));
if (mode === 'hold') {
  const fsync = fs.fsyncSync;
  fs.fsyncSync = fd => {
    fsync(fd);
    if (!fs.fstatSync(fd).isFile()) return;
    process.send('temp-synced');
    const wait = new Int32Array(new SharedArrayBuffer(4));
    const deadline = Date.now() + 10_000;
    while (!fs.existsSync(path + '.release')) {
      if (Date.now() >= deadline) throw new Error('Writer test was never released.');
      Atomics.wait(wait, 0, 0, 10);
    }
  };
  syncBuiltinESMExports();
}
if (mode === 'compete') {
  const lock = new DatabaseSync(path + '.lock.sqlite', { timeout: 0 });
  try {
    try {
      lock.exec('BEGIN IMMEDIATE');
      throw new Error('The first writer did not hold the lock.');
    } catch (error) {
      if (error.errcode !== 5) throw error; // SQLITE_BUSY
    }
  } finally {
    lock.close();
  }
}
process.send('attempting');
try {
  publishKeyring(path, next, previous);
  process.send('published');
} catch (error) {
  if (error.message !== 'Keyring changed during rewrite.') throw error;
  process.send('stale');
}
process.disconnect();

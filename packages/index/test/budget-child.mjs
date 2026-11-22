import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openSqlDriver, rebuildIndex, searchIndex, updateIndex } from '../dist/index.js';
import { appendCorpus, syntheticVault } from './fixture.mjs';

const [phase, root, credential] = process.argv.slice(2);
const directory = join(root, 'index');
const vaultDirectory = join(root, 'vault');
const firstCount = 4000;
const addedCount = 2000;
const total = firstCount + addedCount;
const vault = syntheticVault(vaultDirectory, phase === 'seed');
const options = { directory, vaultDirectory,
  credential: credential === 'passphrase' ? vault.passphraseCredential : vault.credential };
const start = performance.now();
let result;
switch (phase) {
  case 'seed':
    result = { items: firstCount, bytes: appendCorpus(vault, 0, firstCount) };
    assert.equal(updateIndex(options).lastEventSeq, firstCount);
    break;
  case 'append':
    result = { items: addedCount, bytes: appendCorpus(vault, firstCount, addedCount) };
    break;
  case 'incremental': {
    result = updateIndex(options);
    assert.equal(result.lastEventSeq, total);
    break;
  }
  case 'rebuild': {
    result = rebuildIndex(options);
    assert.equal(result.lastEventSeq, total);
    break;
  }
  case 'open': {
    const catalog = new DatabaseSync(join(directory, 'generations.sqlite'), { readOnly: true });
    const active = catalog.prepare('SELECT active FROM catalog').get().active;
    catalog.close();
    const ring = vault.unlock();
    const db = openSqlDriver(join(directory, `generation-${active}.sqlite`), { key: ring.keys.get(active) });
    try {
      result = db.prepare('SELECT count(*) AS items, sum(derived) AS derived FROM items').get();
      assert.equal(result.items, total);
      assert.equal(result.derived, total);
      result.chunks = db.prepare('SELECT count(*) AS n FROM chunks').get().n;
    } finally {
      db.close();
      ring.masterKey.fill(0);
      for (const key of ring.keys.values()) key.fill(0);
    }
    break;
  }
  case 'search': {
    const hits = searchIndex(options, 'amber', { limit: 20 });
    assert.equal(hits.length, 20);
    result = { hits: hits.length };
    break;
  }
  default:
    throw new Error('Unknown benchmark operation.');
}
console.log(JSON.stringify({ phase, credential, ms: Math.round(performance.now() - start),
  peakRssKiB: process.resourceUsage().maxRSS, ...result }));

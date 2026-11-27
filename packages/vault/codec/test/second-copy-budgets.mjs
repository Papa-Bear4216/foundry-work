// TEST ONLY: P-3 memory ceilings. A 256 MiB blob is sealed to a second copy (keyed: 256 MiB ceiling), the drive is
// checked keylessly and the sealed vault is exported as an ISO image (keyless: 128 MiB ceiling). A second vault with
// 50 sealed segments is exported too (`export-many`, keyless: 128 MiB; fix round 1, finding 29, R18-7: the export
// holds every manifest until the image is written, so a long history is measured). Each step is measured in its own
// process, by the process itself and by the operating system.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempDisposableSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeKeyring } from '../dist/index.js';
import { cases, fixture, identity, keyringPath, writable } from './vault-fixture.mjs';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3');
const probe = fileURLToPath(new URL('./second-copy-probe.mjs', import.meta.url));
const CEILINGS = { seal: 256, 'session-check': 128, 'export-iso': 128, 'export-many': 128 };

const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-copy-budget-'));
try {
  const vault = join(temp.path, 'vault');
  mkdirSync(vault);
  const vector = fixture(vault);
  // Production scrypt settings (as session-budgets.mjs), so the keyed seal measures a real passphrase unlock.
  const entries = vector.keyring.keys.map(entry => entry.state === 'destroyed' ? entry : {
    ...entry, key: vector.keys.get(entry.key_id), label: vector.labels.get(entry.key_id),
  });
  writeFileSync(keyringPath(vault), encodeKeyring(
    { vaultId: identity.vaultId, version: 1, masterKey: vector.masterKey, entries }, cases.passphrase, Buffer.from(cases.recovery_key, 'hex'),
  ));
  const prepared = measurePeakRss(probe, 'prepare', temp.path);
  assert.equal(prepared.status, 0, prepared.stderr);
  const many = join(temp.path, 'many');
  mkdirSync(many);
  fixture(many);
  const preparedMany = measurePeakRss(probe, 'prepare-many', temp.path);
  assert.equal(preparedMany.status, 0, preparedMany.stderr);
  for (const [command, ceiling] of Object.entries(CEILINGS)) {
    const result = measurePeakRss(probe, command, temp.path);
    assert.equal(result.status, 0, result.stderr);
    const { bytes, peakRssKiB } = JSON.parse(result.stdout);
    assert.ok(Number.isFinite(peakRssKiB) && peakRssKiB > 0);
    console.log(`${command}: ${bytes} bytes, internal ${peakRssKiB} KiB, external ${result.externalPeakKiB} KiB, ceiling ${ceiling} MiB`);
    assert.ok(Math.max(peakRssKiB, result.externalPeakKiB) <= ceiling * 1024, `${command} exceeded ${ceiling} MiB peak RSS.`);
  }
} finally {
  for (const name of ['vault', 'drive', 'many']) {
    try { writable(join(temp.path, name)); } catch { /* not created */ }
  }
  temp.remove();
}

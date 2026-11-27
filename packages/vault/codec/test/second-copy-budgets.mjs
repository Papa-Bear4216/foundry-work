// TEST ONLY: P-3 memory ceilings. A 256 MiB blob is sealed to a second copy (keyed: 256 MiB ceiling), the drive is
// checked keylessly and the sealed vault is exported as an ISO image (keyless: 128 MiB ceiling). Each step is
// measured in its own process, by the process itself and by the operating system.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempDisposableSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixture, writable } from './vault-fixture.mjs';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3');
const probe = fileURLToPath(new URL('./second-copy-probe.mjs', import.meta.url));
const CEILINGS = { seal: 256, 'session-check': 128, 'export-iso': 128 };

const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-copy-budget-'));
try {
  const vault = join(temp.path, 'vault');
  mkdirSync(vault);
  fixture(vault);
  const prepared = measurePeakRss(probe, 'prepare', temp.path);
  assert.equal(prepared.status, 0, prepared.stderr);
  for (const [command, ceiling] of Object.entries(CEILINGS)) {
    const result = measurePeakRss(probe, command, temp.path);
    assert.equal(result.status, 0, result.stderr);
    const { bytes, peakRssKiB } = JSON.parse(result.stdout);
    assert.ok(Number.isFinite(peakRssKiB) && peakRssKiB > 0);
    console.log(`${command}: ${bytes} bytes, internal ${peakRssKiB} KiB, external ${result.externalPeakKiB} KiB, ceiling ${ceiling} MiB`);
    assert.ok(Math.max(peakRssKiB, result.externalPeakKiB) <= ceiling * 1024, `${command} exceeded ${ceiling} MiB peak RSS.`);
  }
} finally {
  for (const name of ['vault', 'drive']) {
    try { writable(join(temp.path, name)); } catch { /* not created */ }
  }
  temp.remove();
}

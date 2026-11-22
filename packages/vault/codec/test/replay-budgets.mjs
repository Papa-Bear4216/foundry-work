import assert from 'node:assert/strict';
import { mkdtempDisposableSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { formatRecoveryKey } from '../dist/recovery.js';
import { cases, fixture, identity, keyId, writable } from './vault-fixture.mjs';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3');
const existingProbe = fileURLToPath(new URL('./vault-probe.mjs', import.meta.url));
const replayProbe = fileURLToPath(new URL('./replay-probe.mjs', import.meta.url));
const recovery = formatRecoveryKey(Buffer.from(cases.recovery_key, 'hex'));

for (const command of ['existing-fixture', 'large-blob']) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-replay-budget-'));
  try {
    fixture(temp.path);
    if (command === 'existing-fixture') {
      for (const step of ['append', 'close']) {
        const result = measurePeakRss(existingProbe, step, temp.path, JSON.stringify({
          vaultId: identity.vaultId, recovery, keyId,
        }));
        assert.equal(result.status, 0, result.stderr);
      }
    } else {
      const result = measurePeakRss(replayProbe, 'prepare-large-blob', temp.path);
      assert.equal(result.status, 0, result.stderr);
    }
    const result = measurePeakRss(replayProbe, command, temp.path);
    assert.equal(result.status, 0, result.stderr);
    const { blobs, encodedBytes, peakRssKiB } = JSON.parse(result.stdout);
    assert.ok(Number.isFinite(peakRssKiB) && peakRssKiB > 0);
    console.log(`${command}: ${blobs} blobs, ${encodedBytes} encoded bytes, internal ${peakRssKiB} KiB, external ${result.externalPeakKiB} KiB`);
    // Use the smaller Architecture 9 index workload allowance for replay and derivation.
    assert.ok(Math.max(peakRssKiB, result.externalPeakKiB) <= 192 * 1024, `${command} exceeded 192 MiB peak RSS.`);
  } finally {
    writable(temp.path);
    temp.remove();
  }
}

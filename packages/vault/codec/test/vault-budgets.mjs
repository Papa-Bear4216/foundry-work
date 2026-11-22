import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempDisposableSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { initializeVault } from '../dist/index.js';
import { formatRecoveryKey } from '../dist/recovery.js';
import { measurePeakRss } from './peak-rss.mjs';

assert.equal(process.versions.node, '24.22.3');
const asset = name => readFileSync(new URL('./vectors/' + name, import.meta.url));
const cases = JSON.parse(asset('cases.json'));
const vaultId = cases.metadata.vault_id;
const passphrase = cases.passphrase;
const recovery = formatRecoveryKey(Buffer.from(cases.recovery_key, 'hex'));
const script = fileURLToPath(new URL('./vault-probe.mjs', import.meta.url));
const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-vault-budget-'));
const directory = temp.path;
const keyring = join(directory, 'keyring');
mkdirSync(keyring);
writeFileSync(join(keyring, 'keyring.json'), asset(cases.keyring));
initializeVault(directory, {
  vaultId, createdAt: cases.metadata.created_at,
  signingPublicKey: Buffer.from(cases.metadata.signing_public_key, 'base64'),
});

try {
  for (const [command, limitMiB, input] of [
    ['append', 256, { vaultId, recovery, keyId: cases.ids.collection }],
    ['close', 256, { vaultId, recovery }],
    ['verify', 128, undefined],
    ['verify-deep', 256, { vaultId, passphrase }],
  ]) {
    const result = measurePeakRss(script, command, directory, JSON.stringify(input));
    assert.equal(result.status, 0, result.stderr);
    const { peakRssKiB } = JSON.parse(result.stdout);
    assert.ok(Number.isFinite(peakRssKiB) && peakRssKiB > 0);
    const { externalPeakKiB } = result;
    console.log(`${command}: internal ${peakRssKiB} KiB, external ${externalPeakKiB} KiB`);
    assert.ok(Math.max(peakRssKiB, externalPeakKiB) <= limitMiB * 1024, `${command} exceeded ${limitMiB} MiB peak RSS.`);
  }
} finally {
  const segments = join(directory, 'segments');
  for (const name of readdirSync(segments)) {
    const path = join(segments, name);
    chmodSync(path, 0o700);
    for (const file of readdirSync(path)) chmodSync(join(path, file), 0o600);
  }
  temp.remove();
}

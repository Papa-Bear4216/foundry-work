import { chmodSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { initializeVault, unlockByRecovery } from '../src/index.ts';
import { formatRecoveryKey } from '../src/recovery.ts';

// TEST ONLY: all credentials, keys and content come from the synthetic vector fixture.
const asset = name => readFileSync(new URL('./vectors/' + name, import.meta.url));
export const cases = JSON.parse(asset('cases.json'));
export const keyId = cases.ids.collection;
export const identity = {
  vaultId: cases.metadata.vault_id,
  createdAt: cases.metadata.created_at,
  signingPublicKey: Buffer.from(cases.metadata.signing_public_key, 'base64'),
};

export function fixture(directory) {
  mkdirSync(join(directory, 'keyring'));
  writeFileSync(keyringPath(directory), asset(cases.keyring));
  initializeVault(directory, identity);
  return unlockFixture(directory);
}

export function keyringPath(directory) {
  return join(directory, 'keyring', 'keyring.json');
}

export function unlockFixture(directory) {
  return unlockByRecovery(keyringPath(directory), identity.vaultId,
    formatRecoveryKey(Buffer.from(cases.recovery_key, 'hex')));
}

export function writable(directory) {
  for (const entry of readdirSync(join(directory, 'segments'), { withFileTypes: true })) {
    const path = join(directory, 'segments', entry.name);
    if (!entry.isDirectory()) continue;
    chmodSync(path, 0o700);
    for (const item of readdirSync(path, { withFileTypes: true })) {
      if (item.isFile()) chmodSync(join(path, item.name), 0o600);
    }
  }
}

export function event(marker) {
  return { type: 'event', keyId, event: { kind: 'vault.created', body: { marker } } };
}

export function blob(plaintext) {
  return { type: 'blob', keyId, plaintext: Buffer.from(plaintext) };
}

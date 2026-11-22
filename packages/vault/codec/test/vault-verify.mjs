import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import {
  decodeVaultMetadata, guardSecretInput, readSecretFromFd, unlockByPassphrase, verifyVault, verifyVaultDeep,
} from '../dist/index.js';

const args = parseArgs({ options: { deep: { type: 'boolean' } }, allowPositionals: true, strict: false, tokens: true });
guardSecretInput(args, process.env, 1);
const [directory] = args.positionals;
if (!directory || args.tokens.some(token => token.kind === 'option' && token.name !== 'deep')) {
  throw new Error('Usage: vault-verify.mjs [--deep] <vault-directory>');
}
let unlocked;
try {
  if (args.values.deep) {
    const { vault_id } = decodeVaultMetadata(readFileSync(join(directory, 'VAULT.json')));
    unlocked = unlockByPassphrase(join(directory, 'keyring', 'keyring.json'), vault_id, readSecretFromFd());
  }
  const result = unlocked ? verifyVaultDeep(directory, unlocked) : verifyVault(directory);
  console.log(JSON.stringify({ ...result, peakRssKiB: process.resourceUsage().maxRSS }));
} finally {
  if (unlocked) {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

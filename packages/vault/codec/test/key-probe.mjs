import { parseArgs } from 'node:util';
import {
  changePassphrase, create, guardSecretInput, readSecretFromFd, rekeyAll, unlockByPassphrase, unlockByRecovery,
} from '../dist/index.js';

// TEST ONLY: the caller supplies synthetic credentials over stdin.
const path = 'KEYRING.json';
const [command, ...args] = process.argv.slice(2);
try {
  guardSecretInput(parseArgs({ args, strict: false, tokens: true }), process.env);
} catch (error) {
  process.stderr.write(error.message + '\n');
  process.exit(1);
}

try {
  const input = JSON.parse(readSecretFromFd());
  switch (command) {
    case 'create':
      create(path, input);
      break;
    case 'unlock-passphrase':
      unlockByPassphrase(path, input.vaultId, input.passphrase);
      break;
    case 'unlock-recovery':
      unlockByRecovery(path, input.vaultId, input.recoveryKey);
      break;
    case 'change':
      changePassphrase(path, input.vaultId, input.current, input);
      break;
    case 'rekey':
      rekeyAll(path, input.vaultId, { passphrase: input.current }, input);
      break;
    default:
      throw new Error('Unknown operation.');
  }
  process.stdout.write(JSON.stringify({ command, peakRssKiB: process.resourceUsage().maxRSS }) + '\n');
} catch {
  process.stderr.write('Vault probe failed. Supply the operation input as JSON on stdin.\n');
  process.exitCode = 1;
}

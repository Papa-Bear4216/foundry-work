// TEST ONLY: the bin's exact options plus the stuck-synchronous-section hook (reachable only through the API).
import process from 'node:process';
import { runCli } from '../../dist/cli.js';

process.exitCode = await runCli(process.argv.slice(2), {
  exitOnTimeout: true, handleSignals: true, testHooks: { stallSync: true },
});

// TEST ONLY: the bin's exact options plus one test hook (reachable only through the API, never argv or environment).
// Usage: node hook-bin.mjs <hook name> <foundry arguments...>
import process from 'node:process';
import { runCli } from '../../dist/cli.js';

const [hook, ...argv] = process.argv.slice(2);
process.exitCode = await runCli(argv, { exitOnTimeout: true, handleSignals: true, testHooks: { [hook]: true } });

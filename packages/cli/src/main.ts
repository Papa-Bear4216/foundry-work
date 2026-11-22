#!/usr/bin/env node
/** The `foundry` bin. */
import process from 'node:process';
import { runCli } from './cli.ts';

process.on('uncaughtException', () => {
  // Crash text never carries the error message: it could quote input. The lock is recovered as stale later.
  process.stderr.write('foundry: an unexpected internal error occurred [INTERNAL]\n');
  process.exit(2);
});

process.exitCode = await runCli(process.argv.slice(2), { exitOnTimeout: true, handleSignals: true });

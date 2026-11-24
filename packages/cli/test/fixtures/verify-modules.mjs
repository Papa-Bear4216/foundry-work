// TEST ONLY: run one foundry command in this thread, then report whether the SQLite addon was loaded.
// Usage: node verify-modules.mjs <foundry home> verify            -> `vault verify`
//        node verify-modules.mjs <foundry home> rebuild           -> `index rebuild --passphrase-stdin` (positive control)
import { createRequire } from 'node:module';
import process from 'node:process';
import { runCli } from '../../dist/cli.js';

const [home, mode] = process.argv.slice(2);
const argv = mode === 'rebuild' ? ['index', 'rebuild', '--passphrase-stdin'] : ['vault', 'verify'];
const code = await runCli([...argv, '--vault', home], { inline: true, stdinFd: 0, stdout: () => {}, stderr: () => {} });
const loaded = Object.keys(createRequire(import.meta.url).cache).filter(path => /better-sqlite3/iu.test(path));
process.stdout.write(JSON.stringify({ code, loaded }));

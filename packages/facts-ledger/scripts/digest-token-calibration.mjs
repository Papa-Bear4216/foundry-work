#!/usr/bin/env node
// Offline digest token calibration (Step Zero 7). Developer script: runs outside the
// tool and outside its memory budget. It adds no dependency and picks no tokenizer:
// each reference tokenizer is a local command that reads text on stdin and prints one
// integer (the token count) on stdout. Exit code 1 blocks a release.
//
// Usage:
//   node scripts/digest-token-calibration.mjs --digest <file> [--digest <file>]...
//        --tokenizer <name>=<absolute executable> [--tokenizer-arg <name>=<arg>]...
//        [--limit 2000]
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';

const digests = [];
const tokenizers = new Map();
// The release ceiling is 2,000 tokens (Step Zero 7); --limit may only lower it.
const RELEASE_LIMIT = 2000;
let limit = RELEASE_LIMIT;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const flag = argv[i];
  const value = argv[++i];
  if (value === undefined) throw new Error(`Missing value for ${flag}`);
  if (flag === '--digest') digests.push(value);
  else if (flag === '--limit') limit = /^\d+$/.test(value) ? Number(value) : Number.NaN;
  else if (flag === '--tokenizer' || flag === '--tokenizer-arg') {
    const eq = value.indexOf('=');
    if (eq < 1) throw new Error(`${flag} expects <name>=<value>`);
    const name = value.slice(0, eq);
    const rest = value.slice(eq + 1);
    const entry = tokenizers.get(name) ?? { exe: undefined, args: [] };
    if (flag === '--tokenizer') entry.exe = rest;
    else entry.args.push(rest);
    tokenizers.set(name, entry);
  } else throw new Error(`Unknown option: ${flag}`);
}
if (digests.length === 0 || tokenizers.size === 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > RELEASE_LIMIT) {
  process.stderr.write(`Usage: --digest <file>... --tokenizer <name>=<absolute exe> [--tokenizer-arg <name>=<arg>]... [--limit <1..${RELEASE_LIMIT}>]\n`);
  process.exit(2);
}

let blocked = false;
for (const [name, { exe, args }] of [...tokenizers].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
  if (!exe || !isAbsolute(exe)) throw new Error(`Tokenizer ${name} needs an absolute executable path`);
  for (const file of digests) {
    const text = readFileSync(file, 'utf8');
    const r = spawnSync(exe, args, { input: text, encoding: 'utf8', timeout: 60_000, shell: false, windowsHide: true });
    // The whole output must be one nonnegative decimal integer; anything else is a broken adapter.
    const raw = String(r.stdout ?? '').trim();
    const count = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
    if (r.error || r.status !== 0 || !Number.isSafeInteger(count)) {
      process.stdout.write(`${name}\t${file}\tERROR\n`);
      blocked = true;
      continue;
    }
    const over = count > limit;
    blocked ||= over;
    process.stdout.write(`${name}\t${file}\t${count}\t${over ? 'OVER' : 'ok'}\n`);
  }
}
process.stdout.write(blocked ? `BLOCKED: a digest exceeds ${limit} tokens or a tokenizer failed\n` : `ok: all digests within ${limit} tokens\n`);
process.exit(blocked ? 1 : 0);

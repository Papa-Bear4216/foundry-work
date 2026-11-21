import { existsSync, readFileSync } from 'node:fs';

const approved = new Set([
  'MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'BSD-4-Clause',
]);
const locks = [new URL('../package-lock.json', import.meta.url)];
const vaultLock = new URL('../packages/vault/codec/package-lock.json', import.meta.url);
if (existsSync(vaultLock)) locks.push(vaultLock);
const packages = locks.flatMap(path => Object.entries(JSON.parse(readFileSync(path, 'utf8')).packages));
const inventory = readFileSync(new URL('../docs/DEPENDENCIES.md', import.meta.url), 'utf8');
const rows = inventory.split(/\r?\n/).map(line => line.split('|').map(cell => cell.trim()));

let checked = 0;
for (const [path, entry] of packages) {
  const installedName = /(?:^|\/)node_modules\/(?!.*\/node_modules\/)([^/]+(?:\/[^/]+)?)$/.exec(path)?.[1];
  if (!installedName || entry.link) continue;

  const name = entry.name ?? installedName;
  const license = entry.license;
  checked++;
  if (!approved.has(license)) {
    console.error(`${name}: missing or unapproved license (${license ?? 'unknown'}).`);
    process.exitCode = 1;
    continue;
  }

  if (!entry.dev && !rows.some(([, documentedName, documentedLicense, reason]) =>
    documentedName === name && documentedLicense === license && reason)) {
    console.error(`${name}: add its license and runtime justification to docs/DEPENDENCIES.md.`);
    process.exitCode = 1;
  }
}

if (!process.exitCode) console.log(`License check passed (${checked} external npm packages).`);

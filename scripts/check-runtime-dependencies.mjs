import { existsSync, readFileSync } from 'node:fs';

const runtimeFields = [
  'dependencies',
  'optionalDependencies',
  'peerDependencies',
  'bundleDependencies',
  'bundledDependencies',
];

const root = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
for (const name of ['facts-ledger', 'vault', 'vault/codec']) {
  const manifest = new URL(`../packages/${name}/package.json`, import.meta.url);
  if (name === 'vault' && !existsSync(manifest)) continue;

  const pkg = JSON.parse(readFileSync(manifest, 'utf8'));
  for (const field of runtimeFields) {
    const value = pkg[field];
    if (name === 'vault/codec' ? Object.hasOwn(pkg, field)
      : value === true || Object.keys(value ?? {}).length > 0) {
      console.error(`${name}: runtime dependencies are forbidden (${field}).`);
      process.exitCode = 1;
    }
  }

  if (name !== 'vault' && (pkg.engines?.node !== root.engines.node || process.versions.node !== root.engines.node)) {
    console.error(`${name}: the package and running Node must match the workspace pin.`);
    process.exitCode = 1;
  }
}

if (!process.exitCode) console.log('Runtime dependency check passed.');

// TEST ONLY: `foundry import` (design 4a.3) on a fresh `foundry init` vault with a small synthetic multi-part archive.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { decodeKeyring, decodeVaultMetadata, openVaultReplay } from 'vault';
import { initVault, PASSPHRASE, runInline, scratch, takeoutFolder } from './helpers.mjs';

// writeMultiPartTakeoutFolder with 4 contacts, 3 calendar events (one .ics item) and 6 mail messages.
const ITEMS = 4 + 1 + 6;

/** Count item.imported events in the vault (through the vault library, with the recovery key). */
function storedItems(home, recoveryKey, decode) {
  const vaultDir = join(home, 'vault');
  const replay = openVaultReplay(vaultDir, { recoveryKey: decode(recoveryKey) });
  try {
    let count = 0;
    for (const entry of replay.replay()) if (entry.type === 'event' && entry.event.kind === 'item.imported') count++;
    return count;
  } finally {
    replay.close();
  }
}

test('first import into a fresh init vault stores every item in two runs; a second import adds nothing (passphrase: 1 KDF)', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const { folder } = await takeoutFolder(dir);
  const { decodeRecoveryKey } = await import('vault');

  const first = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE + '\n' });
  assert.equal(first.code, 0, first.stderr);
  assert.equal(first.kdf, 1, 'one KDF run across catch-up update, run A, key creation, run B and final update');
  const summary = JSON.parse(first.stdout);
  assert.equal(summary.runs, 2, 'a fresh vault has no collection keys: run A defers, run B stores');
  assert.ok(summary.collectionsCreated >= 3, 'contacts, calendar and mail collections (by year) were created');
  assert.equal(summary.itemsAdded, ITEMS);
  assert.equal(summary.itemsAlreadyPresent, 0);
  assert.equal(summary.itemsSkipped, 0);
  assert.equal(summary.partsCount, 3);
  assert.equal(summary.unrecognisedEntries, 1);
  assert.equal(summary.itemsAdded + summary.itemsAlreadyPresent + summary.itemsSkipped, ITEMS);
  assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), ITEMS);

  // The keyring now holds profile `me`, its rule marker and the collection keys; no second key per name.
  const vaultId = decodeVaultMetadata(readFileSync(join(home, 'vault', 'VAULT.json'))).vault_id;
  const recovery = decodeRecoveryKey(recoveryKey);
  const ring = decodeKeyring(readFileSync(join(home, 'vault', 'keyring', 'keyring.json')), { recoveryKey: recovery }, vaultId);
  try {
    assert.deepEqual([...ring.labels.values()], ['me']);
    const collections = ring.keyring.keys.filter(entry => entry.kind === 'collection');
    assert.equal(collections.length, summary.collectionsCreated + 1, 'collection keys plus the rule marker');
  } finally {
    ring.masterKey.fill(0);
    for (const key of ring.keys.values()) key.fill(0);
  }

  const second = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(second.code, 0, second.stderr);
  assert.equal(second.kdf, 1);
  const again = JSON.parse(second.stdout);
  assert.equal(again.runs, 1, 'every collection key exists: one run');
  assert.equal(again.itemsAdded, 0);
  assert.equal(again.itemsAlreadyPresent, ITEMS);
  assert.equal(again.collectionsCreated, 0);
  assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), ITEMS);

  // Search through the command line finds a contact name, a calendar summary and a mail subject.
  for (const [query, source] of [['Given1', 'contacts'], ['session', 'calendar'], ['Subject', 'mail']]) {
    const found = await runInline(dir, ['search', query, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
    assert.equal(found.code, 0, found.stderr);
    assert.equal(found.kdf, 1);
    const { results } = JSON.parse(found.stdout);
    assert.ok(results.some(hit => hit.source.includes(source)), `${query} finds a ${source} item`);
  }
  const text = await runInline(dir, ['search', 'Given1', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.match(text.stdout, /^\d{4}-\d\d-\d\dT[^ ]+ {2}\S+ {2}.*Given1/mu);

  // The same search after an index rebuild returns the same results.
  const before = await runInline(dir, ['search', 'Subject', '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal((await runInline(dir, ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE })).code, 0);
  const after = await runInline(dir, ['search', 'Subject', '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.deepEqual(JSON.parse(after.stdout).results.map(hit => hit.itemId), JSON.parse(before.stdout).results.map(hit => hit.itemId));
});

test('first import with the recovery key: zero KDF runs across both runs; the first part of a multi-part set opens the set', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const { folder, parts } = await takeoutFolder(dir, { seed: 7 });

  const first = await runInline(dir, ['import', join(folder, parts[0]), '--vault', home, '--recovery-key-stdin'], { stdin: recoveryKey + '\n' });
  assert.equal(first.code, 0, first.stderr);
  assert.equal(first.kdf, 0);
  assert.match(first.stdout, new RegExp(`^Imported ${ITEMS} new item\\(s\\); 0 item\\(s\\) were already stored\\.$`, 'mu'));
  assert.match(first.stdout, /^Parts seen: 3\. Unrecognised entries: 1\.$/mu);
  assert.match(first.stdout, /^New collection keys: \d+\.$/mu);

  const second = await runInline(dir, ['import', folder, '--vault', home, '--recovery-key-stdin'], { stdin: recoveryKey });
  assert.equal(second.code, 0, second.stderr);
  assert.equal(second.kdf, 0);
  assert.match(second.stdout, new RegExp(`^Imported 0 new item\\(s\\); ${ITEMS} item\\(s\\) were already stored\\.$`, 'mu'));
});

test('a later archive with a new collection runs twice again and adds only the new items', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const small = await takeoutFolder(join(dir, 'a'), { contactsCount: 1, calendarEvents: 1, mailMessages: 1 });
  const first = await runInline(dir, ['import', small.folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(first.code, 0, first.stderr);
  const one = JSON.parse(first.stdout);
  assert.equal(one.itemsAdded, 3);

  // More contacts spread over more years: at least one new collection name appears.
  const bigger = await takeoutFolder(join(dir, 'b'), { contactsCount: 5, calendarEvents: 1, mailMessages: 1 });
  const next = await runInline(dir, ['import', bigger.folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(next.code, 0, next.stderr);
  assert.equal(next.kdf, 1);
  const two = JSON.parse(next.stdout);
  assert.equal(two.runs, 2);
  assert.ok(two.collectionsCreated >= 1);
  assert.equal(two.itemsAdded + two.itemsAlreadyPresent + two.itemsSkipped, 5 + 1 + 1);
});

test('import failures: a missing archive path and a folder without archives are typed failures', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const missing = await runInline(dir, ['import', join(dir, 'absent.zip'), '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /\[IO\]\n/u);
  const empty = await runInline(dir, ['import', dir, '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(empty.code, 2);
  assert.match(empty.stderr, /\[EMPTY_ARCHIVE_DIR\]\n/u);
  assert.match(empty.stderr, /running the same import again is safe/u);
});

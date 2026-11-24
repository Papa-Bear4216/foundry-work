// TEST ONLY: `foundry import` (design 4a.3) on a fresh `foundry init` vault with a small synthetic multi-part archive.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import {
  appendFileSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { decodeKeyring, decodeRecoveryKey, decodeVaultMetadata, openVaultReplay, VaultWriter } from 'vault';
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
  assert.equal(missing.stderr.split('\n').length, 2, 'one stderr line');
  assert.doesNotMatch(missing.stderr, /stored so far/u, 'nothing was stored');
  const emptyFolder = join(dir, 'no-archives');
  mkdirSync(emptyFolder);
  const empty = await runInline(dir, ['import', emptyFolder, '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(empty.code, 2);
  assert.match(empty.stderr, /^foundry: [^\n]+ \[EMPTY_ARCHIVE_DIR\]\n$/u, 'one stderr line');
  assert.doesNotMatch(empty.stderr, /stored so far/u, 'nothing was stored');
});

/** Open a writer on the CLI vault and stop a segment seal at `point` (the vault's own crash checkpoint option). */
function interruptSeal(home, recoveryKey, point) {
  const vaultDir = join(home, 'vault');
  const vaultId = decodeVaultMetadata(readFileSync(join(vaultDir, 'VAULT.json'))).vault_id;
  const unlocked = decodeKeyring(readFileSync(join(vaultDir, 'keyring', 'keyring.json')),
    { recoveryKey: decodeRecoveryKey(recoveryKey) }, vaultId);
  try {
    const writer = VaultWriter.open(vaultDir, unlocked, {
      checkpoint(reached) {
        if (reached === point) throw new Error(`TEST ONLY seal stopped at ${point}`);
      },
    });
    try {
      assert.throws(() => writer.closeSegment(), /TEST ONLY seal stopped/u);
    } finally {
      writer.release();
    }
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

test('interrupted seal: the next import lets the vault writer recover the pending seal, then updates the index; nothing is stored twice', async t => {
  for (const point of ['before-segment-rename', 'before-head-update']) {
    await t.test(point, async inner => {
      const dir = scratch(inner);
      const { home, recoveryKey } = await initVault(dir);
      const { folder } = await takeoutFolder(dir);
      const first = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
      assert.equal(first.code, 0, first.stderr);
      interruptSeal(home, recoveryKey, point);
      assert.ok(existsSync(join(home, 'vault', 'HEAD.json.pending')), 'the seal left HEAD.json.pending');

      const again = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
      assert.equal(again.code, 0, again.stderr);
      const summary = JSON.parse(again.stdout);
      assert.equal(summary.itemsAdded, 0);
      assert.equal(summary.itemsAlreadyPresent, ITEMS);
      assert.equal(existsSync(join(home, 'vault', 'HEAD.json.pending')), false, 'the writer recovered the seal');
      assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), ITEMS, 'nothing stored twice');
      const found = await runInline(dir, ['search', 'Given1', '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
      assert.equal(found.code, 0, found.stderr);
      assert.ok(JSON.parse(found.stdout).results.length > 0);
    });
  }
});

test('archive changed between Run A and Run B: exit 2 ARCHIVE_CHANGED, one line, Run B stores nothing; a retry imports everything', async t => {
  const changes = {
    'mtime': (folder, parts) => {
      const path = join(folder, parts[0]);
      const later = new Date(statSync(path).mtimeMs + 20_000);
      utimesSync(path, later, later);
    },
    'bytes (same mtime)': (folder, parts) => {
      const path = join(folder, parts[2]);
      const before = statSync(path);
      appendFileSync(path, Buffer.from('TEST ONLY'));
      utimesSync(path, before.atime, before.mtime);
    },
    'part added': (folder, parts) => {
      copyFileSync(join(folder, parts[2]), join(folder, parts[2].replace('-003.zip', '-004.zip')));
    },
  };
  for (const [label, change] of Object.entries(changes)) {
    await t.test(label, async inner => {
      const dir = scratch(inner);
      const { home, recoveryKey } = await initVault(dir);
      const { folder, parts } = await takeoutFolder(dir);
      let called = 0;
      const hooks = { betweenRuns: path => { called++; assert.equal(path, folder); change(folder, parts); } };
      const result = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE, hooks });
      assert.equal(called, 1);
      assert.equal(result.code, 2);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /^foundry: [^\n]+ \[ARCHIVE_CHANGED\]\n$/u);
      assert.doesNotMatch(result.stderr, /stored so far/u, 'Run A deferred every item; nothing was stored');
      assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), 0, 'Run B stored nothing');
      if (label === 'mtime') {
        const retry = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
        assert.equal(retry.code, 0, retry.stderr);
        assert.equal(JSON.parse(retry.stdout).itemsAdded, ITEMS);
        assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), ITEMS);
      }
    });
  }
});

test('Run B failure: one stderr line with the underlying code; "stored so far" only when this command stored an item', async t => {
  const dir = scratch(t);
  mkdirSync(join(dir, 'fresh'));
  mkdirSync(join(dir, 'used'));
  // A fresh vault: Run A defers every item, so nothing is stored before Run B fails.
  const fresh = await initVault(join(dir, 'fresh'));
  const { folder } = await takeoutFolder(join(dir, 'fresh'));
  const none = await runInline(dir, ['import', folder, '--vault', fresh.home, '--passphrase-stdin'],
    { stdin: PASSPHRASE, hooks: { failRunB: true } });
  assert.equal(none.code, 2);
  // After Run A started, repeating is always safe; nothing was stored, so the index is not behind.
  assert.match(none.stderr, /^foundry: [^\n]+; repeating the import is safe \[IO\]\n$/u);
  assert.doesNotMatch(none.stderr, /stored so far|INDEX_BEHIND|index is behind/u);
  assert.equal(storedItems(fresh.home, fresh.recoveryKey, decodeRecoveryKey), 0);

  // A vault with some collection keys: Run A stores the items of those collections, then Run B fails.
  const used = await initVault(join(dir, 'used'));
  const small = await takeoutFolder(join(dir, 'used', 'a'), { contactsCount: 1, calendarEvents: 1, mailMessages: 1 });
  assert.equal((await runInline(dir, ['import', small.folder, '--vault', used.home, '--passphrase-stdin'], { stdin: PASSPHRASE })).code, 0);
  // Mail messages #2 and #3 fall into the existing mail collection (Run A stores them); new contact years need Run B.
  const bigger = await takeoutFolder(join(dir, 'used', 'b'), { contactsCount: 5, calendarEvents: 1, mailMessages: 3 });
  const before = storedItems(used.home, used.recoveryKey, decodeRecoveryKey);
  const some = await runInline(dir, ['import', bigger.folder, '--vault', used.home, '--passphrase-stdin'],
    { stdin: PASSPHRASE, hooks: { failRunB: true } });
  assert.equal(some.code, 2);
  assert.equal(some.stdout, '');
  assert.match(some.stderr,
    /^foundry: [^\n]+; the index is behind; run `foundry index rebuild`; items stored so far stay stored; repeating the import is safe \[IO\]\n$/u);
  const between = storedItems(used.home, used.recoveryKey, decodeRecoveryKey);
  assert.ok(between > before, 'Run A stored items before Run B failed');
  const retry = await runInline(dir, ['import', bigger.folder, '--vault', used.home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(retry.code, 0, retry.stderr);
  const summary = JSON.parse(retry.stdout);
  assert.equal(summary.itemsAdded + summary.itemsAlreadyPresent + summary.itemsSkipped, 5 + 1 + 3);
  assert.ok(summary.itemsAlreadyPresent >= between - before, 'items stored by the failed command count as already present');
  assert.equal(storedItems(used.home, used.recoveryKey, decodeRecoveryKey), between + summary.itemsAdded, 'nothing stored twice');
});

test('final index update failure: one stderr line, the underlying code, "index is behind" and "stored so far" guidance', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const { folder } = await takeoutFolder(dir);
  const failed = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin'],
    { stdin: PASSPHRASE, hooks: { failFinalIndexUpdate: true } });
  assert.equal(failed.code, 2);
  assert.equal(failed.stdout, '');
  assert.match(failed.stderr,
    /^foundry: [^\n]+; the index is behind; run `foundry index rebuild`; items stored so far stay stored; repeating the import is safe \[IO\]\n$/u);
  assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), ITEMS);

  // Nothing new stored by this command: the index guidance stays, the "stored so far" claim does not.
  const again = await runInline(dir, ['import', folder, '--vault', home, '--passphrase-stdin'],
    { stdin: PASSPHRASE, hooks: { failFinalIndexUpdate: true } });
  assert.equal(again.code, 2);
  assert.match(again.stderr, /^foundry: [^\n]+; the index is behind; run `foundry index rebuild`; repeating the import is safe \[IO\]\n$/u);
});

test('index update between Run A and Run B fails after Run A stored items: one line with "index is behind", "stored so far" and "safe to repeat"', async t => {
  const dir = scratch(t);
  mkdirSync(join(dir, 'used'));
  const used = await initVault(join(dir, 'used'));
  const small = await takeoutFolder(join(dir, 'used', 'a'), { contactsCount: 1, calendarEvents: 1, mailMessages: 1 });
  assert.equal((await runInline(dir, ['import', small.folder, '--vault', used.home, '--passphrase-stdin'], { stdin: PASSPHRASE })).code, 0);
  // Run A stores the mail messages of the existing mail collection; new contact years need keys and Run B.
  const bigger = await takeoutFolder(join(dir, 'used', 'b'), { contactsCount: 5, calendarEvents: 1, mailMessages: 3 });
  const before = storedItems(used.home, used.recoveryKey, decodeRecoveryKey);
  const failed = await runInline(dir, ['import', bigger.folder, '--vault', used.home, '--passphrase-stdin'],
    { stdin: PASSPHRASE, hooks: { failBetweenRunsUpdate: true } });
  assert.equal(failed.code, 2);
  assert.equal(failed.stdout, '');
  assert.match(failed.stderr,
    /^foundry: [^\n]+; the index is behind; run `foundry index rebuild`; items stored so far stay stored; repeating the import is safe \[IO\]\n$/u);
  assert.ok(storedItems(used.home, used.recoveryKey, decodeRecoveryKey) > before, 'Run A stored items before the update failed');
  const retry = await runInline(dir, ['import', bigger.folder, '--vault', used.home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(retry.code, 0, retry.stderr);
});

test('the first part of one export opens only the parts of that export, not every zip in the folder', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const { folder, parts } = await takeoutFolder(dir);
  // A second export (other prefix, other items) and an unrelated zip in the same folder.
  const other = await takeoutFolder(join(dir, 'other'), { seed: 9, contactsCount: 2, calendarEvents: 1, mailMessages: 2 });
  const otherParts = other.parts.map(name => name.replace('20261121T000000Z', '20261122T000000Z'));
  other.parts.forEach((name, i) => copyFileSync(join(other.folder, name), join(folder, otherParts[i])));
  writeFileSync(join(folder, 'notes.zip'), 'TEST ONLY not a zip archive');

  const first = await runInline(dir, ['import', join(folder, parts[0]), '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(first.code, 0, first.stderr);
  const one = JSON.parse(first.stdout);
  assert.equal(one.partsCount, 3);
  assert.equal(one.itemsAdded, ITEMS);
  assert.equal(storedItems(home, recoveryKey, decodeRecoveryKey), ITEMS);

  const second = await runInline(dir, ['import', join(folder, otherParts[0]), '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(second.code, 0, second.stderr);
  assert.equal(JSON.parse(second.stdout).partsCount, 3);

  // The selected export must still be complete: a missing middle part is INVALID_MULTIPART.
  rmSync(join(folder, otherParts[1]));
  const gap = await runInline(dir, ['import', join(folder, otherParts[0]), '--vault', home, '--passphrase-stdin'], { stdin: PASSPHRASE });
  assert.equal(gap.code, 2);
  assert.match(gap.stderr, /^foundry: [^\n]+ \[INVALID_MULTIPART\]\n$/u);
});

test('calendar search text: a long calendar name with many events and an early summary in a truncated event are searchable', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const { generateSyntheticIcalendar, writeZipArchive } = await import('importers');
  const name = `TEST ONLY Zebracalname ${'n'.repeat(4096)}`;
  const long = generateSyntheticIcalendar(1000, 303, name);
  // A first event whose DESCRIPTION runs past the 8 MiB parse limit: its earlier SUMMARY must stay searchable.
  const cut = Buffer.concat([
    Buffer.from('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:test-only-cut\r\nSUMMARY:Earlysummaryword planning\r\nDESCRIPTION:'),
    Buffer.alloc(9 * 1024 * 1024, 'filler '),
    Buffer.from('\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'),
  ]);
  const zip = join(dir, 'calendars.zip');
  await writeZipArchive(zip, [
    { path: 'Takeout/Calendar/Long.ics', data: long, compression: 'store' },
    { path: 'Takeout/Calendar/Cut.ics', data: cut, compression: 'store' },
  ]);
  const imported = await runInline(dir, ['import', zip, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
  assert.equal(imported.code, 0, imported.stderr);
  assert.equal(JSON.parse(imported.stdout).itemsAdded, 2);
  for (const query of ['Zebracalname', 'Earlysummaryword']) {
    const found = await runInline(dir, ['search', query, '--vault', home, '--passphrase-stdin', '--json'], { stdin: PASSPHRASE });
    assert.equal(found.code, 0, found.stderr);
    const { results } = JSON.parse(found.stdout);
    assert.ok(results.length >= 1, `${query} finds its calendar`);
    assert.equal(new Set(results.map(hit => hit.itemId)).size, 1, `${query} finds one item`);
  }
});

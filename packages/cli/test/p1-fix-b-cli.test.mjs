// TEST ONLY: P-1 fix round 1 session B command-line tests (items 3, 4, 8, 9, 10, 11, 13).
// All data, labels and credentials are synthetic and assembled at run time.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { addSensitivityRule, loadVaultProfileState } from 'foundry-profiles';
import { DEFAULT_IMPORTERS, importArchive, openArchive, syntheticEmail, writeZipArchive } from 'importers';
import {
  collectionKeyId,
  decodeKeyring,
  decodeRecoveryKey,
  decodeVaultMetadata,
  ensureCollectionKeys,
  openVaultReplay,
  readVaultRecord,
  VaultWriter,
} from 'vault';
import { mapError } from '../dist/errors.js';
import { initVault, PASSPHRASE, runInline, scratch } from './helpers.mjs';

function allEvents(home, recoveryKey) {
  const replay = openVaultReplay(join(home, 'vault'), { recoveryKey: decodeRecoveryKey(recoveryKey) });
  try {
    const out = [];
    for (const entry of replay.replay()) {
      if (entry.type === 'blob' || (entry.type === 'skipped' && entry.recordType === 'blob')) break;
      if (entry.type === 'event') out.push(entry.event);
    }
    return out;
  } finally {
    replay.close();
  }
}

/** A small mbox archive. Each message body is given; the year comes from its Date header. */
async function mailArchive(dir, name, bodies) {
  const messages = bodies.map(([year, subject, body], i) =>
    [
      `From ${3000 + i}@xxx Mon Mar 04 10:00:00 +0000 ${year}`,
      `From: <${syntheticEmail(`sender-${i}`)}>`,
      `To: <${syntheticEmail(`recipient-${i}`)}>`,
      `Date: Mon, 04 Mar ${year} 10:00:00 +0000`,
      `Subject: ${subject}`,
      'Content-Type: text/plain; charset="utf-8"',
      '',
      body,
      '',
    ].join('\r\n'),
  );
  const zipPath = join(dir, name);
  await writeZipArchive(zipPath, [
    { path: 'Takeout/Mail/All mail Including Spam and Trash.mbox', data: Buffer.from(messages.join(''), 'utf8'), compression: 'deflate' },
  ]);
  return zipPath;
}

const keyed = (home, recoveryKey) => ['--vault', home, '--recovery-key-stdin'];

// --- B1 (item 3) ---

test('B1: --collection without the import profile prefix fails INVALID_COLLECTION with 0 KDF and no write', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const archive = await mailArchive(dir, 'b1.zip', [['2024', 'Synthetic b1', 'Plain words.']]);
  const before = allEvents(home, recoveryKey).length;
  for (const argv of [
    ['import', archive, '--collection', 'shared'],
    ['import', archive, '--profile', 'me', '--collection', 'child/shared'],
    ['import', archive, '--profile', 'child', '--collection', 'me/shared'],
    ['import', archive, '--collection', 'me'],
    ['collection', 'prompt-policy', 'shared', '--child-prompts', 'on'],
    ['collection', 'prompt-policy', 'mee/shared', '--child-prompts', 'on'],
  ]) {
    const res = await runInline(dir, [...argv, ...keyed(home, recoveryKey)], { stdin: recoveryKey + '\n' });
    assert.equal(res.code, 2, `${argv.join(' ')}: ${res.stderr}`);
    assert.equal(res.kdf, 0);
    assert.match(res.stderr, /\[INVALID_COLLECTION\]\n$/u, res.stderr);
  }
  assert.equal(allEvents(home, recoveryKey).length, before);
});

test('B1: child/shared and me/shared are separate collections with separate policies', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  for (const [name, value] of [
    ['child/shared', 'on'],
    ['me/shared', 'off'],
  ]) {
    const res = await runInline(dir, ['collection', 'prompt-policy', name, '--child-prompts', value, ...keyed(home, recoveryKey), '--json'], {
      stdin: recoveryKey + '\n',
    });
    assert.equal(res.code, 0, res.stderr);
    assert.equal(JSON.parse(res.stdout).kind, 'collection.created');
  }
  const list = await runInline(dir, ['collection', 'list', ...keyed(home, recoveryKey), '--json'], { stdin: recoveryKey + '\n' });
  assert.deepEqual(
    JSON.parse(list.stdout).collections.map(c => [c.collection, c.profile, c.allowChildModelPrompts]),
    [
      ['child/shared', 'child', true],
      ['me/shared', 'me', false],
    ],
  );
  // A me import into me/shared is fine; its items are not covered by the child policy.
  const archive = await mailArchive(dir, 'b1b.zip', [['2024', 'Synthetic shared', 'Plain words.']]);
  const imp = await runInline(dir, ['import', archive, '--collection', 'me/shared', ...keyed(home, recoveryKey), '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(imp.code, 0, imp.stderr);
  const events = allEvents(home, recoveryKey).filter(e => e.kind === 'item.imported');
  assert.deepEqual(events.map(e => [e.profile, e.collection]), [['me', 'me/shared']]);
});

// --- B3 (item 10) ---

test('B3: the binding event is written before the key; a stop between them leaves a listed collection and a clean re-import', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const archive = await mailArchive(dir, 'b3.zip', [
    ['2023', 'Synthetic one', 'Plain words one.'],
    ['2024', 'Synthetic two', 'Plain words two.'],
    ['2024', 'Synthetic three', 'Plain words three.'],
  ]);
  const stopped = await runInline(dir, ['import', archive, ...keyed(home, recoveryKey), '--json'], {
    stdin: recoveryKey + '\n',
    hooks: { failAfterCollectionBinding: true },
  });
  assert.equal(stopped.code, 2);
  assert.match(stopped.stderr, /repeating the import is safe \[IO\]\n$/u, stopped.stderr);

  const events = allEvents(home, recoveryKey);
  const bindings = events.filter(e => e.kind === 'collection.created').map(e => e.body);
  assert.deepEqual(bindings, [
    { collection: 'me/google-takeout/mail/2023', owner_profile: 'me' },
    { collection: 'me/google-takeout/mail/2024', owner_profile: 'me' },
  ]);
  assert.equal(events.filter(e => e.kind === 'item.imported').length, 0);
  // No key yet for either name: the event came first.
  const vaultDir = join(home, 'vault');
  const credential = { recoveryKey: decodeRecoveryKey(recoveryKey) };
  const vaultId = decodeVaultMetadata(readFileSync(join(vaultDir, 'VAULT.json'))).vault_id;
  const unlocked = decodeKeyring(readFileSync(join(vaultDir, 'keyring', 'keyring.json')), credential, vaultId);
  try {
    assert.equal(collectionKeyId(unlocked, 'me', 'me/google-takeout/mail/2023'), undefined);
    assert.equal(collectionKeyId(unlocked, 'me', 'me/google-takeout/mail/2024'), undefined);
  } finally {
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }

  const list = await runInline(dir, ['collection', 'list', ...keyed(home, recoveryKey), '--json'], { stdin: recoveryKey + '\n' });
  assert.equal(list.code, 0, list.stderr);
  assert.deepEqual(
    JSON.parse(list.stdout).collections.map(c => [c.collection, c.profile, c.itemCount, c.allowChildModelPrompts]),
    [
      ['me/google-takeout/mail/2023', 'me', 0, false],
      ['me/google-takeout/mail/2024', 'me', 0, false],
    ],
  );

  const again = await runInline(dir, ['import', archive, ...keyed(home, recoveryKey), '--json'], { stdin: recoveryKey + '\n' });
  assert.equal(again.code, 0, again.stderr);
  assert.equal(JSON.parse(again.stdout).itemsAdded, 3);
  const after = allEvents(home, recoveryKey);
  assert.equal(after.filter(e => e.kind === 'item.imported').length, 3);
  assert.equal(after.filter(e => e.kind === 'collection.created').length, 2, 'no second binding for the same names');
  const third = await runInline(dir, ['import', archive, ...keyed(home, recoveryKey), '--json'], { stdin: recoveryKey + '\n' });
  assert.equal(JSON.parse(third.stdout).itemsAdded, 0);
  assert.equal(JSON.parse(third.stdout).itemsAlreadyPresent, 3);
  // A later prompt-policy call on a bound name writes annotation.added.
  const policy = await runInline(dir, ['collection', 'prompt-policy', 'me/google-takeout/mail/2024', '--child-prompts', 'on', ...keyed(home, recoveryKey), '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(JSON.parse(policy.stdout).kind, 'annotation.added');
});

// --- B4 (item 2): the command line maps the importer's INVALID_PROFILE ---

test('B4: an importer INVALID_PROFILE error maps to its own fixed line', () => {
  const error = Object.assign(new Error('INVALID_PROFILE: synthetic'), { name: 'ImportError', code: 'INVALID_PROFILE' });
  const mapped = mapError(error);
  assert.equal(mapped.code, 'INVALID_PROFILE');
  assert.equal(mapped.exit, 2);
  assert.doesNotMatch(mapped.message, /already running/u);
  const busy = mapError(Object.assign(new Error('BUSY: x'), { name: 'ImportError', code: 'BUSY' }));
  assert.match(busy.message, /already running/u);
});

// --- B5 (item 9) ---

test('B5: import into a vault with a pre-P-1 item event fails PRE_PROFILE_VAULT with no new events', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const vaultDir = join(home, 'vault');
  const credential = { recoveryKey: decodeRecoveryKey(recoveryKey) };
  const keyringPath = join(vaultDir, 'keyring', 'keyring.json');
  const vaultId = decodeVaultMetadata(readFileSync(join(vaultDir, 'VAULT.json'))).vault_id;
  // A pre-P-1 vault: the importer library with its own default `<source>/<year>` names, as V-7 builds wrote them.
  const legacyCollection = 'google-takeout/mail/2019';
  ensureCollectionKeys(keyringPath, vaultId, credential, 'me', [legacyCollection]);
  const legacyArchive = await mailArchive(dir, 'legacy.zip', [['2019', 'Synthetic legacy', 'Old plain words.']]);
  const unlocked = decodeKeyring(readFileSync(keyringPath), credential, vaultId);
  const archiveHandle = await openArchive(legacyArchive);
  const writer = VaultWriter.open(vaultDir, unlocked);
  try {
    const result = await importArchive({
      archive: archiveHandle,
      writer,
      importers: DEFAULT_IMPORTERS,
      resolveCollectionKeyId: name => collectionKeyId(unlocked, 'me', name),
      vaultDir,
      unlocked,
      readVaultRecord: (directory, location) => readVaultRecord(directory, location, unlocked),
    });
    assert.equal(result.totalItemsImported, 1);
  } finally {
    writer.release();
    await archiveHandle.close();
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
  assert.deepEqual(
    allEvents(home, recoveryKey).filter(e => e.kind === 'item.imported').map(e => [e.profile, e.collection]),
    [['me', legacyCollection]],
  );
  const before = loadVaultProfileState(vaultDir, credential).lastEventSeq;
  const archive = await mailArchive(dir, 'b5.zip', [['2024', 'Synthetic b5', 'Plain words.']]);
  for (const debug of [[], ['--debug']]) {
    const res = await runInline(dir, ['import', archive, ...keyed(home, recoveryKey), ...debug], { stdin: recoveryKey + '\n' });
    assert.equal(res.code, 2);
    assert.match(res.stderr, /items from before profiles existed; create a new Foundry folder and import again \[PRE_PROFILE_VAULT\]\n$/u, res.stderr);
    assert.doesNotMatch(res.stderr, /repeating the import is safe/u);
  }
  assert.equal(loadVaultProfileState(vaultDir, credential).lastEventSeq, before, 'the refused import wrote nothing');
  // The vault can still be searched and verified.
  const search = await runInline(dir, ['search', 'legacy', ...keyed(home, recoveryKey), '--json'], { stdin: recoveryKey + '\n' });
  assert.equal(search.code, 0, search.stderr);
  assert.equal(JSON.parse(search.stdout).results.length, 1);
  const verified = await runInline(dir, ['vault', 'verify', '--vault', home]);
  assert.equal(verified.code, 0, verified.stderr);
});

// --- B6 (item 8) ---

test('B6: a global secret keyword rule still covers a partner import after profile add me', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const keyword = ['synthetic', 'global', 'marker'].join('-');
  addSensitivityRule(join(home, 'vault'), { recoveryKey: decodeRecoveryKey(recoveryKey) }, { id: 'global-secret', tier: 'secret', keyword });
  for (const argv of [
    ['profile', 'add', 'me', '--display-name', 'Synthetic Owner'],
    ['consent', 'record', 'partner', '--basis', 'exported-by-them'],
  ]) {
    const res = await runInline(dir, [...argv, ...keyed(home, recoveryKey)], { stdin: recoveryKey + '\n' });
    assert.equal(res.code, 0, res.stderr);
  }
  const archive = await mailArchive(dir, 'b6.zip', [
    ['2024', 'Synthetic keyword', `Body with ${keyword} inside.`],
    ['2024', 'Synthetic plain', 'Body with nothing special.'],
  ]);
  const imp = await runInline(dir, ['import', archive, '--profile', 'partner', ...keyed(home, recoveryKey), '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(imp.code, 0, imp.stderr);
  const items = allEvents(home, recoveryKey).filter(e => e.kind === 'item.imported');
  assert.deepEqual(items.map(e => [e.profile, e.sensitivity]), [
    ['partner', 'secret'],
    ['partner', 'personal'],
  ]);
});

// --- B7 (item 11) ---

test('B7: display names and consent notes are printed only by profile list / consent list with --reveal', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const nameMarker = ['Planted', 'Name', 'Marker', '7731'].join('-');
  const noteMarker = ['Planted', 'Note', 'Marker', '4410'].join('-');
  const archive = await mailArchive(dir, 'b7.zip', [['2024', 'Synthetic reveal', 'Plain words.']]);
  const check = (res, argv) => {
    assert.ok(!res.stdout.includes(nameMarker) && !res.stderr.includes(nameMarker), `name leaked: ${argv.join(' ')}`);
    assert.ok(!res.stdout.includes(noteMarker) && !res.stderr.includes(noteMarker), `note leaked: ${argv.join(' ')}`);
  };
  const run = async argv => {
    const res = await runInline(dir, [...argv, ...keyed(home, recoveryKey)], { stdin: recoveryKey + '\n' });
    check(res, argv);
    return res;
  };

  for (const extra of [[], ['--json'], ['--debug'], ['--json', '--debug']]) {
    const added = await run(['profile', 'add', 'partner', '--display-name', nameMarker, ...extra]);
    assert.equal(added.code, 0, added.stderr);
    if (extra.includes('--json')) assert.equal(JSON.parse(added.stdout).displayNameSet, true);
    const recorded = await run(['consent', 'record', 'partner', '--basis', 'other', '--note', noteMarker, ...extra]);
    assert.equal(recorded.code, 0, recorded.stderr);
    if (extra.includes('--json')) assert.equal(JSON.parse(recorded.stdout).noteSet, true);
  }
  for (const extra of [[], ['--json'], ['--debug'], ['--json', '--debug']]) {
    for (const argv of [
      ['profile', 'list'],
      ['consent', 'list'],
      ['collection', 'list'],
      ['collection', 'prompt-policy', 'partner/x', '--child-prompts', 'off'],
      ['import', archive, '--profile', 'partner'],
      ['search', 'Synthetic'],
      ['index', 'rebuild'],
    ]) {
      const res = await run([...argv, ...extra]);
      assert.equal(res.code, 0, `${argv.join(' ')} ${extra.join(' ')}: ${res.stderr}`);
    }
  }
  // Failures with --debug do not print them either.
  const failing = await run(['import', join(dir, 'missing.zip'), '--profile', 'partner', '--debug']);
  assert.equal(failing.code, 2);

  const profileJson = await run(['profile', 'list', '--json']);
  assert.deepEqual(
    JSON.parse(profileJson.stdout).profiles.map(p => [p.profile, p.displayNameSet, 'displayName' in p]),
    [
      ['me', false, false],
      ['partner', true, false],
    ],
  );
  const consentJson = JSON.parse((await run(['consent', 'list', '--json'])).stdout);
  assert.ok(consentJson.consents.every(c => c.noteSet === true && !('note' in c)));
  assert.ok(consentJson.history.length >= 4 && consentJson.history.every(c => c.noteSet === true && !('note' in c)));
  const consentText = await run(['consent', 'list']);
  assert.match(consentText.stdout, /partner {2}other {2}\(note set\)/u);

  // With --reveal (text and JSON) the values are shown.
  for (const extra of [[], ['--json']]) {
    const p = await runInline(dir, ['profile', 'list', '--reveal', ...extra, ...keyed(home, recoveryKey)], { stdin: recoveryKey + '\n' });
    assert.equal(p.code, 0, p.stderr);
    assert.ok(p.stdout.includes(nameMarker));
    assert.ok(!p.stdout.includes(noteMarker));
    const c = await runInline(dir, ['consent', 'list', '--reveal', ...extra, ...keyed(home, recoveryKey)], { stdin: recoveryKey + '\n' });
    assert.equal(c.code, 0, c.stderr);
    assert.ok(c.stdout.includes(noteMarker));
    assert.ok(!c.stdout.includes(nameMarker));
  }
  // --reveal before the flags still leaves the positional count right (it takes no value).
  const early = await runInline(dir, ['consent', 'list', '--reveal', '--vault', home, '--recovery-key-stdin'], { stdin: recoveryKey + '\n' });
  assert.equal(early.code, 0, early.stderr);
  const extraPositional = await runInline(dir, ['consent', 'list', '--reveal', 'extra', '--vault', home, '--recovery-key-stdin'], { stdin: recoveryKey + '\n' });
  assert.equal(extraPositional.code, 1);
  assert.ok(!extraPositional.stderr.includes('extra'));

  // Mutation commands do not take --reveal.
  for (const argv of [
    ['profile', 'add', 'partner', '--display-name', nameMarker, '--reveal'],
    ['consent', 'record', 'partner', '--basis', 'other', '--note', noteMarker, '--reveal'],
    ['collection', 'prompt-policy', 'partner/x', '--child-prompts', 'on', '--reveal'],
    ['collection', 'list', '--reveal'],
    ['import', archive, '--reveal'],
  ]) {
    const res = await runInline(dir, [...argv, ...keyed(home, recoveryKey)], { stdin: recoveryKey + '\n' });
    assert.equal(res.code, 1, argv.join(' '));
    assert.equal(res.kdf, 0);
    check(res, argv);
  }
  // Help names --reveal and the note warning.
  assert.match((await runInline(dir, ['profile', 'list', '--help'])).stdout, /--reveal/u);
  assert.match((await runInline(dir, ['consent', 'list', '--help'])).stdout, /--reveal/u);
  assert.match((await runInline(dir, ['consent', 'record', '--help'])).stdout, /Do not write names or other identifying details in the note\./u);
});

// --- B8 (item 13) ---

test('B8-13: consent record --basis other without a note fails INVALID_CONSENT_NOTE before any KDF', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const before = allEvents(home, recoveryKey).length;
  const res = await runInline(dir, ['consent', 'record', 'partner', '--basis', 'other', '--vault', home, '--passphrase-stdin'], {
    stdin: PASSPHRASE + '\n',
  });
  assert.equal(res.code, 2);
  assert.equal(res.kdf, 0);
  assert.match(res.stderr, /\[INVALID_CONSENT_NOTE\]\n$/u);
  assert.equal(allEvents(home, recoveryKey).length, before);
  const ok = await runInline(dir, ['consent', 'record', 'partner', '--basis', 'exported-by-them', ...keyed(home, recoveryKey)], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(ok.code, 0, ok.stderr);
});

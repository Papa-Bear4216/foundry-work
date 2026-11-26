// TEST ONLY: P-1 fix round 1 session B tests for `foundry-profiles` (items 3, 4, 8, 9, 13, 14, 15).
// Every fixture, label and identifier here is synthetic and built at run time.
import assert from 'node:assert/strict';
import { chmodSync, existsSync, mkdtempDisposableSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  createVault,
  decodeKeyring,
  decodeRecoveryKey,
  decodeVaultMetadata,
  ensureCollectionKeys,
  VaultWriter,
} from 'vault';
// Namespace import: a missing export fails only the tests that use it, not the whole file.
import * as profiles from '../dist/index.js';

const PASSPHRASE = 'TEST ONLY profiles fix-b passphrase';

function makeWritableTree(dir) {
  if (!existsSync(dir)) return;
  try {
    chmodSync(dir, 0o700);
  } catch {
    // ignore
  }
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) makeWritableTree(full);
    else if (entry.isFile()) {
      try {
        chmodSync(full, 0o600);
      } catch {
        // ignore
      }
    }
  }
}

function scratchVault(t) {
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-profiles-b-'));
  t.after(() => {
    makeWritableTree(temp.path);
    temp.remove();
  });
  const vaultDir = join(temp.path, 'vault');
  const created = createVault(vaultDir, { passphrase: PASSPHRASE });
  const credential = { recoveryKey: decodeRecoveryKey(created.recoveryKey) };
  return { vaultDir, vaultId: created.vaultId, credential };
}

/** Append raw events under `<profile>`'s key for `collection` with the vault writer (test fixtures only). */
function appendRawEvents(vaultDir, credential, profile, collection, events, chunk = 1000) {
  const keyringPath = join(vaultDir, 'keyring', 'keyring.json');
  const vaultId = decodeVaultMetadata(readFileSync(join(vaultDir, 'VAULT.json'))).vault_id;
  const keyId = ensureCollectionKeys(keyringPath, vaultId, credential, profile, [collection]).keyIds.get(collection);
  const unlocked = decodeKeyring(readFileSync(keyringPath), credential, vaultId);
  const writer = VaultWriter.open(vaultDir, unlocked);
  try {
    for (let start = 0; start < events.length; start += chunk) {
      writer.appendBatch(events.slice(start, start + chunk).map(event => ({ type: 'event', keyId, event })));
    }
  } finally {
    writer.release();
    unlocked.masterKey.fill(0);
    for (const key of unlocked.keys.values()) key.fill(0);
  }
}

const isCode = code => err => err instanceof profiles.ProfileError && err.code === code;

// --- B1 (item 3): every collection name starts with its profile ---

test('B1: assertCollectionForProfile accepts only <profile>/... names', () => {
  assert.equal(profiles.assertCollectionForProfile('me', 'me/shared'), 'me/shared');
  assert.equal(profiles.assertCollectionForProfile('child', 'child/shared/2024'), 'child/shared/2024');
  for (const [profile, name] of [
    ['me', 'shared'],
    ['me', 'child/shared'],
    ['child', 'me/shared'],
    ['me', 'me'],
    ['me', 'me/'],
    ['me', 'mee/x'],
    ['partner', 'google-takeout/mail/2024'],
    ['me', 'system'],
  ]) {
    assert.throws(() => profiles.assertCollectionForProfile(profile, name), isCode('INVALID_COLLECTION'), `${profile} ${name}`);
  }
  assert.throws(() => profiles.assertCollectionForProfile('Someone', 'Someone/x'), isCode('INVALID_PROFILE'));
  assert.equal(profiles.profileOfCollection('other/a/b'), 'other');
  assert.equal(profiles.profileOfCollection('shared'), undefined);
  assert.equal(profiles.profileOfCollection('child'), undefined);
});

test('B1: prompt-policy needs a profile prefix, and child/shared and me/shared are separate policies', t => {
  const { vaultDir, credential } = scratchVault(t);
  assert.throws(
    () => profiles.setCollectionPromptPolicy(vaultDir, credential, { collection: 'shared', allowChildModelPrompts: true }),
    isCode('INVALID_COLLECTION'),
  );
  assert.throws(
    () =>
      profiles.setCollectionPromptPolicy(vaultDir, credential, {
        collection: 'child/shared',
        allowChildModelPrompts: true,
        ownerProfile: 'me',
      }),
    isCode('INVALID_COLLECTION'),
  );
  assert.equal(profiles.loadVaultProfileState(vaultDir, credential).lastEventSeq, 0, 'a refused policy writes nothing');

  profiles.setCollectionPromptPolicy(vaultDir, credential, { collection: 'child/shared', allowChildModelPrompts: true });
  profiles.setCollectionPromptPolicy(vaultDir, credential, { collection: 'me/shared', allowChildModelPrompts: false });
  const { collections } = profiles.listCollections(vaultDir, credential);
  assert.deepEqual(
    collections.map(c => [c.collection, c.profile, c.allowChildModelPrompts]),
    [
      ['child/shared', 'child', true],
      ['me/shared', 'me', false],
    ],
  );
  const state = profiles.loadVaultProfileState(vaultDir, credential);
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'child', collection: 'child/shared', sensitivity: 'child' }, state),
    { eligible: true },
  );
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'me', collection: 'me/shared', sensitivity: 'child' }, state),
    { eligible: false, reason: 'CHILD_TIER_EXCLUDED' },
  );
});

// --- B2 (item 4): the prompt gate reads only a private copy of the replayed policy ---

test('B2: a hand-built Map, a plain object, undefined and a mutated genuine state cannot switch child data on', t => {
  const { vaultDir, credential } = scratchVault(t);
  const item = { profile: 'child', collection: 'child/x', sensitivity: 'child' };
  const excluded = { eligible: false, reason: 'CHILD_TIER_EXCLUDED' };

  assert.deepEqual(profiles.isPromptEligible(item, new Map([['child/x', true]])), excluded);
  assert.deepEqual(profiles.isPromptEligible(item, new Map([['child/x', { allowChildModelPrompts: true }]])), excluded);
  assert.deepEqual(profiles.isPromptEligible(item, { 'child/x': true }), excluded);
  assert.deepEqual(profiles.isPromptEligible(item, { collections: new Map([['child/x', { allowChildModelPrompts: true }]]) }), excluded);
  assert.deepEqual(profiles.isPromptEligible(item, undefined), excluded);
  assert.deepEqual(profiles.isPromptEligible(item), excluded);
  assert.equal(profiles.filterItemsForModelPrompt([item], new Map([['child/x', true]])).length, 0);

  // A genuine replayed state with no switch event, changed after replay, stays closed.
  const state = profiles.loadVaultProfileState(vaultDir, credential);
  state.collections.set('child/x', { collection: 'child/x', profile: 'child', itemCount: 1, allowChildModelPrompts: true });
  assert.deepEqual(profiles.isPromptEligible(item, state), excluded);
  // A copy of a genuine state (same fields, different object) is not genuine.
  const copy = { ...state, collections: new Map([['child/x', { allowChildModelPrompts: true }]]) };
  assert.deepEqual(profiles.isPromptEligible(item, copy), excluded);

  // A genuine switch event opens exactly that collection; turning it off in the state afterwards does not matter.
  profiles.setCollectionPromptPolicy(vaultDir, credential, { collection: 'child/x', allowChildModelPrompts: true });
  const enabled = profiles.loadVaultProfileState(vaultDir, credential);
  assert.deepEqual(profiles.isPromptEligible(item, enabled), { eligible: true });
  enabled.collections.delete('child/x');
  assert.deepEqual(profiles.isPromptEligible(item, enabled), { eligible: true }, 'the gate reads the private copy, not the map');
  assert.deepEqual(profiles.isPromptEligible(item, state), excluded, 'the older state still holds its own copy');
});

test('B2: an item whose collection does not start with its profile is COLLECTION_PROFILE_MISMATCH', t => {
  const { vaultDir, credential } = scratchVault(t);
  const state = profiles.loadVaultProfileState(vaultDir, credential);
  const mismatch = { eligible: false, reason: 'COLLECTION_PROFILE_MISMATCH' };
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'me', collection: 'google-takeout/mail/2019', sensitivity: 'personal' }, state),
    mismatch,
  );
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'me', collection: 'child/google-takeout/mail/2019', sensitivity: 'personal' }, state),
    mismatch,
  );
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'partner', collection: 'me/x', sensitivity: 'public' }, state),
    mismatch,
  );
  // Secret is checked first and keeps its own reason.
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'me', collection: 'google-takeout/mail/2019', sensitivity: 'secret' }, state),
    { eligible: false, reason: 'SECRET_TIER_EXCLUDED' },
  );
  assert.deepEqual(
    profiles.isPromptEligible({ profile: 'me', collection: 'me/google-takeout/mail/2019', sensitivity: 'personal' }, state),
    { eligible: true },
  );
});

// --- B3 (item 10): the collection binding is recorded before its key exists ---

test('B3: recordCollectionBindings appends collection.created once per name, with no policy', t => {
  const { vaultDir, credential } = scratchVault(t);
  assert.throws(
    () => profiles.recordCollectionBindings(vaultDir, credential, 'me', ['me/a', 'shared']),
    isCode('INVALID_COLLECTION'),
  );
  assert.equal(profiles.loadVaultProfileState(vaultDir, credential).lastEventSeq, 0, 'a refused name writes nothing');

  const first = profiles.recordCollectionBindings(vaultDir, credential, 'partner', ['partner/a/2024', 'partner/b/2024', 'partner/a/2024']);
  assert.deepEqual(first.appended, ['partner/a/2024', 'partner/b/2024']);
  assert.equal(first.eventSeqs.length, 2);
  const again = profiles.recordCollectionBindings(vaultDir, credential, 'partner', ['partner/a/2024', 'partner/b/2024']);
  assert.deepEqual(again.appended, []);

  const { collections } = profiles.listCollections(vaultDir, credential);
  assert.deepEqual(
    collections.map(c => [c.collection, c.profile, c.itemCount, c.allowChildModelPrompts, c.policyEventSeq]),
    [
      ['partner/a/2024', 'partner', 0, false, undefined],
      ['partner/b/2024', 'partner', 0, false, undefined],
    ],
  );
  const policy = profiles.setCollectionPromptPolicy(vaultDir, credential, { collection: 'partner/a/2024', allowChildModelPrompts: true });
  assert.equal(policy.kind, 'annotation.added');
  assert.equal(profiles.listCollections(vaultDir, credential).collections[0].allowChildModelPrompts, true);
});

test('B3: more names than one append batch (1,024) are appended in one call', t => {
  const { vaultDir, credential } = scratchVault(t);
  const names = Array.from({ length: 1100 }, (_, i) => `me/bulk/${String(i).padStart(5, '0')}`);
  const res = profiles.recordCollectionBindings(vaultDir, credential, 'me', names);
  assert.equal(res.appended.length, 1100);
  assert.deepEqual(res.eventSeqs, Array.from({ length: 1100 }, (_, i) => res.eventSeqs[0] + i));
  assert.equal(profiles.listCollections(vaultDir, credential).collections.length, 1100);
});

// --- B5 (item 9): a vault written before P-1 is refused for import ---

test('B5: an item.imported event outside <profile>/... marks the vault as pre-profile', t => {
  const { vaultDir, credential } = scratchVault(t);
  const fresh = profiles.loadVaultProfileState(vaultDir, credential);
  assert.equal(fresh.preProfileItemEvents, 0);
  assert.doesNotThrow(() => profiles.assertProfileVault(fresh));

  appendRawEvents(vaultDir, credential, 'me', 'me/google-takeout/mail/2019', [
    {
      ts: '2026-01-01T00:00:00Z',
      kind: 'item.imported',
      profile: 'me',
      collection: 'me/google-takeout/mail/2019',
      sensitivity: 'personal',
      source: 'google-takeout/mail',
      tags: [],
      body: { blob: '0'.repeat(64), path: 'm/1', mime: 'message/rfc822', size: 1, item_key: '1'.repeat(64) },
    },
  ]);
  assert.equal(profiles.loadVaultProfileState(vaultDir, credential).preProfileItemEvents, 0);

  appendRawEvents(vaultDir, credential, 'me', 'google-takeout/mail/2019', [
    {
      ts: '2026-01-01T00:00:00Z',
      kind: 'item.imported',
      profile: 'me',
      collection: 'google-takeout/mail/2019',
      sensitivity: 'personal',
      source: 'google-takeout/mail',
      tags: [],
      body: { blob: '2'.repeat(64), path: 'm/2', mime: 'message/rfc822', size: 1, item_key: '3'.repeat(64) },
    },
  ]);
  const legacy = profiles.loadVaultProfileState(vaultDir, credential);
  assert.equal(legacy.preProfileItemEvents, 1);
  assert.throws(() => profiles.assertProfileVault(legacy), isCode('PRE_PROFILE_VAULT'));
});

// --- B6 (item 8): global rules stay global ---

test('B6: a global rule still covers partner and other after profile add me', t => {
  const { vaultDir, credential } = scratchVault(t);
  profiles.addSensitivityRule(vaultDir, credential, { id: 'global-kw', tier: 'secret', keyword: 'synthetic-global-keyword' });
  profiles.addSensitivityRule(vaultDir, credential, { id: 'me-kw', tier: 'clinical', profile: 'me', keyword: 'synthetic-me-keyword' });
  profiles.addProfile(vaultDir, credential, { profile: 'me', displayName: 'Synthetic Owner Label' });
  profiles.addProfile(vaultDir, credential, { profile: 'me', displayName: 'Synthetic Owner Label 2' });

  const state = profiles.loadVaultProfileState(vaultDir, credential);
  const byId = new Map(state.sensitivityRules.map(r => [r.id, r]));
  assert.equal(byId.get('global-kw').profile, undefined, 'the global rule keeps no scope');
  assert.equal(byId.get('me-kw').profile, 'me');
  assert.deepEqual(state.profiles.get('me').sensitivityRules.map(r => r.id), ['me-kw']);

  for (const profile of ['me', 'partner', 'other', 'child']) {
    const res = profiles.classifySensitivity({
      profile,
      collection: `${profile}/google-takeout/mail/2024`,
      source: 'google-takeout/mail',
      text: 'Notes with synthetic-global-keyword inside.',
      userRules: state.sensitivityRules,
    });
    assert.equal(res.sensitivity, 'secret', profile);
  }
  const partnerMeRule = profiles.classifySensitivity({
    profile: 'partner',
    collection: 'partner/google-takeout/mail/2024',
    source: 'google-takeout/mail',
    text: 'synthetic-me-keyword',
    userRules: state.sensitivityRules,
  });
  assert.equal(partnerMeRule.sensitivity, 'personal', 'a me-scoped rule does not cover partner');
});

test('B6: an unscoped rule that an older build copied into profile.created replays as global', t => {
  const { vaultDir, credential } = scratchVault(t);
  appendRawEvents(vaultDir, credential, 'me', 'system', [
    {
      ts: '2026-01-01T00:00:00Z',
      kind: 'profile.created',
      profile: 'me',
      collection: 'system',
      sensitivity: 'personal',
      body: { profile: 'me', sensitivity_rules: [{ id: 'copied-global', tier: 'secret', keyword: 'synthetic-copied' }] },
    },
  ]);
  const state = profiles.loadVaultProfileState(vaultDir, credential);
  assert.deepEqual(state.sensitivityRules, [{ id: 'copied-global', tier: 'secret', keyword: 'synthetic-copied' }]);
  assert.deepEqual(state.profiles.get('me').sensitivityRules, []);
});

// --- B8 (items 13, 14, 15) ---

test('B8-13: basis other needs a note; replay ignores an other-basis consent without a note', t => {
  const { vaultDir, credential } = scratchVault(t);
  assert.throws(
    () => profiles.recordConsent(vaultDir, credential, { profile: 'partner', basis: 'other' }),
    isCode('INVALID_CONSENT_NOTE'),
  );
  assert.throws(
    () => profiles.recordConsent(vaultDir, credential, { profile: 'partner', basis: 'other', note: '   ' }),
    isCode('INVALID_CONSENT_NOTE'),
  );
  assert.equal(profiles.assertConsentNoteForBasis('exported-by-them', undefined), undefined);
  assert.equal(profiles.loadVaultProfileState(vaultDir, credential).lastEventSeq, 0);

  // Raw events: an older build (or a foreign writer) stored basis `other` without a note.
  appendRawEvents(vaultDir, credential, 'me', 'system', [
    { ts: '2026-01-01T00:00:00Z', kind: 'consent.recorded', profile: 'me', collection: 'system', sensitivity: 'personal', body: { profile: 'child', basis: 'other' } },
  ]);
  const noNote = profiles.loadVaultProfileState(vaultDir, credential);
  assert.equal(profiles.hasActiveConsent(noNote, 'child'), false);
  assert.throws(() => profiles.assertImportConsent(noNote, 'child'), isCode('CONSENT_REQUIRED'));
  assert.equal(noNote.consentHistory.length, 0);

  const ok = profiles.recordConsent(vaultDir, credential, { profile: 'partner', basis: 'exported-by-them' });
  appendRawEvents(vaultDir, credential, 'me', 'system', [
    { ts: '2026-01-02T00:00:00Z', kind: 'consent.recorded', profile: 'me', collection: 'system', sensitivity: 'personal', body: { profile: 'partner', basis: 'other' } },
  ]);
  const after = profiles.loadVaultProfileState(vaultDir, credential);
  assert.equal(after.consents.get('partner').eventSeq, ok.eventSeq, 'the note-less event does not replace the active consent');
  const withNote = profiles.recordConsent(vaultDir, credential, { profile: 'child', basis: 'other', note: 'Synthetic basis description' });
  assert.equal(profiles.loadVaultProfileState(vaultDir, credential).consents.get('child').eventSeq, withNote.eventSeq);
});

test('B8-14: replay of 5,000 consent events is linear (no per-event history scan)', t => {
  const { vaultDir, credential } = scratchVault(t);
  const N = 5000;
  const subjects = ['partner', 'child', 'other'];
  appendRawEvents(
    vaultDir,
    credential,
    'me',
    'system',
    Array.from({ length: N }, (_, i) => ({
      ts: '2026-01-01T00:00:00Z',
      kind: 'consent.recorded',
      profile: 'me',
      collection: 'system',
      sensitivity: 'personal',
      body: { profile: subjects[i % 3], basis: 'exported-by-them' },
    })),
  );
  // Count every predicate call of Array.prototype.findIndex during the replay (the old code scanned the
  // whole history once per event: about N * N / 2 calls).
  const original = Array.prototype.findIndex;
  let predicateCalls = 0;
  let state;
  Array.prototype.findIndex = function countingFindIndex(predicate, thisArg) {
    return original.call(this, (...args) => {
      predicateCalls++;
      return predicate.apply(thisArg, args);
    });
  };
  try {
    state = profiles.loadVaultProfileState(vaultDir, credential);
  } finally {
    Array.prototype.findIndex = original;
  }
  assert.ok(predicateCalls < 10 * N, `history scans: ${predicateCalls} predicate calls for ${N} events`);
  assert.equal(state.consentHistory.length, N);
  assert.equal(state.consentHistory.filter(c => c.active).length, 3);
  for (let i = 0; i < N - 3; i++) assert.equal(state.consentHistory[i].active, false, `history ${i}`);
});

test('B8-15: defaultCollectionForItem takes the year only from a canonical UTC timestamp', () => {
  const year = ts => profiles.defaultCollectionForItem('me', 'google-takeout/mail', ts).split('/').pop();
  assert.equal(year('2024-garbage'), 'undated');
  assert.equal(year('2024-07-19T12:30:00Z'), '2024');
  assert.equal(year('2024-07-19T12:30:00.123Z'), '2024');
  assert.equal(year('2024-02-29T23:59:59Z'), '2024');
  assert.equal(year('0001-01-01T00:00:00Z'), '0001');
  assert.equal(year('9999-12-31T23:59:59Z'), '9999');
  for (const bad of [
    '2024-02-30T00:00:00Z',
    '2023-02-29T00:00:00Z',
    '2024-13-01T00:00:00Z',
    '2024-00-10T00:00:00Z',
    '2024-01-00T00:00:00Z',
    '2024-01-01T24:00:00Z',
    '2024-01-01T23:60:00Z',
    '2024-01-01T23:59:60Z',
    '2024-01-01',
    '2024-01-01T00:00:00',
    '2024-01-01T00:00:00+00:00',
    '2024-01-01 00:00:00Z',
    '2024-01-01T00:00:00.1Z',
    ' 2024-01-01T00:00:00Z',
    '0000-01-01T00:00:00Z',
    '20240101T000000Z',
  ]) {
    assert.equal(year(bad), 'undated', bad);
  }
});

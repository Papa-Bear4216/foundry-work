// TEST ONLY: comprehensive unit and vault-integration tests for `foundry-profiles` (Work Package P-1).
// Every fixture, token, identifier, and label in this file is synthetic and constructed dynamically.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import crypto from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdtempDisposableSync,
  readdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  createVault,
  decodeKeyring,
  decodeRecoveryKey,
  decodeVaultMetadata,
  encodeKeyring,
  unlockVault,
  verifyVault,
  verifyVaultDeep,
} from 'vault';
import {
  addProfile,
  addSensitivityRule,
  assertCollectionName,
  assertConsentBasis,
  assertConsentNote,
  assertConsentSubjectProfile,
  assertDisplayName,
  assertImportConsent,
  assertProfileId,
  assertUserCollectionName,
  classifySensitivity,
  compareSensitivity,
  CONSENT_BASES,
  defaultCollectionForItem,
  extractBoundedScanSlices,
  filterItemsForModelPrompt,
  hasActiveConsent,
  HEAD_SCAN_BYTES,
  isProfileId,
  isPromptEligible,
  isSensitivityTier,
  listCollections,
  listConsents,
  listProfiles,
  loadVaultProfileState,
  maxSensitivity,
  PROFILE_IDS,
  ProfileError,
  recordConsent,
  SENSITIVITY_PRECEDENCE,
  SENSITIVITY_TIERS,
  setCollectionPromptPolicy,
  TAIL_SCAN_BYTES,
  validateCollectionName,
} from '../dist/index.js';

const PASSPHRASE = 'TEST ONLY profiles suite passphrase';
const AT_CHAR = String.fromCharCode(64);
const INVALID_DOMAIN = ['example', 'invalid'].join('.');

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
  const temp = mkdtempDisposableSync(join(tmpdir(), 'foundry-profiles-'));
  t.after(() => {
    makeWritableTree(temp.path);
    temp.remove();
  });
  const vaultDir = join(temp.path, 'vault');
  const created = createVault(vaultDir, { passphrase: PASSPHRASE });
  const recovery = decodeRecoveryKey(created.recoveryKey);
  return {
    root: temp.path,
    vaultDir,
    vaultId: created.vaultId,
    recoveryKeyText: created.recoveryKey,
    recovery,
    credential: { recoveryKey: recovery },
  };
}

// Dynamic synthetic token builders (never literal secret-scanner strings in source).
function buildPemHeader(kind = 'OPENSSH') {
  return ['-----BEGIN', kind, 'PRIVATE', 'KEY-----'].join(' ');
}

function buildBearerHeader() {
  const partA = 'Ab9Cd8Ef7Gh6Ij5K';
  const partB = 'l4Mn3Op2Qr1St0Uv';
  return `Authorization: ${['Bear', 'er'].join('')} ${partA}.${partB}`;
}

function buildApiPrefixedToken() {
  const prefix = ['s', 'k', '-'].join('');
  const body = Array.from({ length: 6 }, (_, i) => `T${i}x9Z${i}`).join('');
  return `${prefix}${body}`;
}

function buildJwtLikeToken() {
  const seg1 = ['ey', 'JhbGciOiJIUzI1NiJ9'].join('');
  const seg2 = ['ey', 'JzdWIiOiJ0ZXN0LW9ubHkifQ'].join('');
  const seg3 = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  return [seg1, seg2, seg3].join('.');
}

function buildDatabaseUri() {
  const proto = ['post', 'gresql', '://'].join('');
  const user = 'db_reader';
  const secretPart = ['S3cr3t', 'Pass99!'].join('');
  const host = ['db-host', INVALID_DOMAIN].join('.');
  return `${proto}${user}:${secretPart}${AT_CHAR}${host}:5432/synthetic_db`;
}

function buildPasswordAssignment() {
  const k = ['pass', 'word'].join('');
  const v = ['Synthet1c', '#Cred99'].join('');
  return `${k} = "${v}"`;
}

function buildHighEntropySecretAssignment() {
  const k = ['api', 'key'].join('_');
  const v = ['Q9w8E7r6', 'T5y4U3i2', 'O1p0A9s8'].join('_');
  return `${k}: ${v}`;
}

test('generic profiles only: accepts me/partner/child/other and rejects all other identifiers with INVALID_PROFILE', () => {
  assert.deepEqual(PROFILE_IDS, ['me', 'partner', 'child', 'other']);
  for (const id of PROFILE_IDS) {
    assert.equal(isProfileId(id), true);
    assert.equal(assertProfileId(id), id);
  }

  const invalid = [
    '',
    'Me',
    'PARTNER',
    'Child',
    'OTHER',
    ' me',
    'me ',
    'system',
    'guest',
    'household-member',
    'foundry:me',
    'me/mail',
    'child\u0000',
    null,
    undefined,
    42,
    {},
  ];

  for (const bad of invalid) {
    assert.equal(isProfileId(bad), false);
    assert.throws(
      () => assertProfileId(bad),
      err => {
        assert.ok(err instanceof ProfileError);
        assert.equal(err.code, 'INVALID_PROFILE');
        if (typeof bad === 'string' && bad.length >= 4 && !PROFILE_IDS.includes(bad.toLowerCase())) {
          assert.ok(!err.message.includes(bad), 'error message never echoes caller input');
        }
        return true;
      },
    );
  }
});

test('displayName validation: enforces nonempty well-formed UTF-8 <= 128 bytes without control characters and never echoes input', () => {
  assert.equal(assertDisplayName('Household Member A'), 'Household Member A');
  assert.equal(assertDisplayName('Partner — Café \u{1F33F}'), 'Partner — Café \u{1F33F}');
  assert.equal(assertDisplayName('x'.repeat(128)), 'x'.repeat(128));

  const badInputs = [
    '',
    '   ',
    'x'.repeat(129),
    '\u{1F600}'.repeat(33), // 132 UTF-8 bytes
    'bad\u0000name',
    'bad\nline',
    'bad\tchar',
    'unpaired\uD800surrogate',
    123,
  ];
  for (const bad of badInputs) {
    const marker = 'TEST-ONLY-MARKER-DISPLAY';
    const candidate = typeof bad === 'string' && bad.length > 10 ? `${marker}-${bad}` : bad;
    assert.throws(
      () => assertDisplayName(candidate),
      err => {
        assert.ok(err instanceof ProfileError);
        assert.equal(err.code, 'INVALID_DISPLAY_NAME');
        assert.ok(!err.message.includes(marker));
        return true;
      },
    );
  }
});

test('defaultCollectionForItem and collection validation: <profile>/<source>/<year>, undated fallback, 512-byte cap, reserved & traversal checks', () => {
  assert.equal(
    defaultCollectionForItem('me', 'google-takeout/mail', '2024-07-19T12:30:00Z'),
    'me/google-takeout/mail/2024',
  );
  assert.equal(
    defaultCollectionForItem('partner', 'google-takeout/contacts', '0001-01-01T00:00:00Z'),
    'partner/google-takeout/contacts/0001',
  );
  assert.equal(
    defaultCollectionForItem('child', 'google-takeout/calendar', '9999-12-31T23:59:59Z'),
    'child/google-takeout/calendar/9999',
  );
  assert.equal(
    defaultCollectionForItem('other', 'google-takeout/mail', undefined),
    'other/google-takeout/mail/undated',
  );
  assert.equal(
    defaultCollectionForItem('me', 'google-takeout/mail', '0000-01-01T00:00:00Z'),
    'me/google-takeout/mail/undated',
  );
  assert.equal(
    defaultCollectionForItem('me', 'google-takeout/mail', 'not-a-timestamp'),
    'me/google-takeout/mail/undated',
  );

  // Valid custom collection names
  assert.equal(validateCollectionName('me/custom-archive/2025'), true);
  assert.equal(assertUserCollectionName('partner/shared-notes/2024'), 'partner/shared-notes/2024');
  // Internal structural `system` is valid for keyring/assertCollectionName, rejected for user data collections
  assert.equal(assertCollectionName('system'), 'system');
  assert.throws(
    () => assertUserCollectionName('system'),
    err => err instanceof ProfileError && err.code === 'INVALID_COLLECTION',
  );

  const invalidCollections = [
    '',
    ' ',
    ' me/mail/2024',
    'me/mail/2024 ',
    'foundry:reserved/2024',
    'foundry:collection-key-id-rule/v1',
    '/me/mail/2024',
    'me/mail/2024/',
    'me//mail/2024',
    'me/../mail/2024',
    'me/./mail/2024',
    '..',
    '.',
    'me\\mail\\2024',
    'me/mail\u0000/2024',
    'me/mail\n/2024',
    'me/mail\uD800/2024',
    `me/${'a'.repeat(510)}`,
  ];
  for (const bad of invalidCollections) {
    assert.equal(validateCollectionName(bad), false, `expected invalid: ${JSON.stringify(bad)}`);
    assert.throws(
      () => assertUserCollectionName(bad),
      err => err instanceof ProfileError && err.code === 'INVALID_COLLECTION',
    );
  }

  assert.throws(
    () => defaultCollectionForItem('invalid-profile', 'google-takeout/mail', '2024-01-01T00:00:00Z'),
    err => err instanceof ProfileError && err.code === 'INVALID_PROFILE',
  );
  assert.throws(
    () => defaultCollectionForItem('me', '../traversal', '2024-01-01T00:00:00Z'),
    err => err instanceof ProfileError && err.code === 'INVALID_SOURCE',
  );
  assert.throws(
    () => defaultCollectionForItem('me', 'foundry:internal', '2024-01-01T00:00:00Z'),
    err => err instanceof ProfileError && err.code === 'INVALID_SOURCE',
  );
});

test('shipped generic sensitivity rules, precedence order, user vault rules, and bounded 64 MiB slice scanning', () => {
  assert.deepEqual(SENSITIVITY_TIERS, ['public', 'personal', 'private', 'secret', 'clinical', 'child']);
  assert.ok(SENSITIVITY_PRECEDENCE.secret > SENSITIVITY_PRECEDENCE.child);
  assert.ok(SENSITIVITY_PRECEDENCE.child > SENSITIVITY_PRECEDENCE.clinical);
  assert.ok(SENSITIVITY_PRECEDENCE.clinical > SENSITIVITY_PRECEDENCE.private);
  assert.ok(SENSITIVITY_PRECEDENCE.private > SENSITIVITY_PRECEDENCE.personal);
  assert.ok(SENSITIVITY_PRECEDENCE.personal > SENSITIVITY_PRECEDENCE.public);
  assert.equal(maxSensitivity('child', 'clinical'), 'child');
  assert.equal(maxSensitivity('child', 'secret'), 'secret');
  assert.equal(compareSensitivity('private', 'personal') > 0, true);
  assert.equal(isSensitivityTier('clinical'), true);
  assert.equal(isSensitivityTier('confidential'), false);

  // 1. Default `personal` for mail, contacts, calendar
  for (const source of ['google-takeout/mail', 'google-takeout/contacts', 'google-takeout/calendar']) {
    const res = classifySensitivity({
      profile: 'me',
      collection: `me/${source}/2024`,
      source,
      text: 'Ordinary planning message with token and key words in normal English prose.',
    });
    assert.equal(res.sensitivity, 'personal', source);
  }

  // 2. `secret` rules: PEM/SSH/PGP private keys, Bearer/API/JWT tokens, DB URIs, credential assignments
  const secretSamples = [
    buildPemHeader('OPENSSH'),
    buildPemHeader('RSA'),
    ['-----BEGIN', 'PGP', 'PRIVATE', 'KEY', 'BLOCK-----'].join(' '),
    buildBearerHeader(),
    `Header token ${buildApiPrefixedToken()} in text`,
    `Session ${buildJwtLikeToken()}`,
    buildDatabaseUri(),
    buildPasswordAssignment(),
    buildHighEntropySecretAssignment(),
  ];
  for (const sample of secretSamples) {
    const res = classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      plaintext: Buffer.from(sample, 'utf8'),
    });
    assert.equal(res.sensitivity, 'secret', `expected secret for rule sample (${res.rule})`);
  }

  // Placeholder credentials do NOT trigger `secret`
  const placeholderRes = classifySensitivity({
    profile: 'me',
    collection: 'me/google-takeout/mail/2024',
    source: 'google-takeout/mail',
    text: `${['pass', 'word'].join('')} = REDACTED\napi_key = <your-key>`,
  });
  assert.equal(placeholderRes.sensitivity, 'personal');

  // 3. `child` floor on profile === 'child' or `child/...` collection, elevated only by `secret`
  assert.equal(
    classifySensitivity({
      profile: 'child',
      collection: 'child/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      text: 'School schedule and Form 1099-INT and lab results reference range.',
    }).sensitivity,
    'child',
  );
  assert.equal(
    classifySensitivity({
      profile: 'me',
      collection: 'child/shared-calendar/2024',
      source: 'google-takeout/calendar',
      text: 'Shared event.',
    }).sensitivity,
    'child',
  );
  assert.equal(
    classifySensitivity({
      profile: 'child',
      collection: 'child/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      text: buildPemHeader('OPENSSH'),
    }).sensitivity,
    'secret',
  );

  // 4. `clinical` rules: ICD-10, CPT, lab results, discharge summary, Rx/NDC/FHIR
  const clinicalSamples = [
    'Assessment: ICD-10-CM J06.9 acute upper respiratory infection.',
    'Procedure billed under CPT code: 99213.',
    'Laboratory Results: Hemoglobin A1c 5.4%, Reference Range 4.0-5.6%.',
    'Hospital Discharge Summary and follow-up instructions.',
    'Pharmacy refill — Prescription Number: RX884920, NDC: 12345-678-90.',
    '{"resourceType": "DiagnosticReport", "status": "final"}',
  ];
  for (const sample of clinicalSamples) {
    const res = classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      text: sample,
    });
    assert.equal(res.sensitivity, 'clinical', sample);
  }

  // 5. `private` rules: SSN/EIN, W-2/1099/1040, bank routing/IBAN, insurance card/claim/EOB
  const privateSamples = [
    'Taxpayer SSN: 123-45-6789 on file.',
    'Attached: Form W-2 Wage and Tax Statement for 2024.',
    'Enclosed Form 1099-NEC and Form 1040 summary.',
    'Direct deposit Routing Number: 021000021, Checking Account Number: ****4821.',
    'Wire details IBAN: DE89370400440532013000.',
    'Health Insurance Card — Subscriber ID: ZXY99887766, Group Number: GRP4410.',
    'Explanation of Benefits for Claim Number: CLM-2024-8821.',
  ];
  for (const sample of privateSamples) {
    const res = classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      text: sample,
    });
    assert.equal(res.sensitivity, 'private', sample);
  }

  // Precedence: `clinical` + `private` in same item -> `clinical` wins
  assert.equal(
    classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      text: 'Explanation of Benefits (Subscriber ID: SUB99887) with Diagnosis Code E11.9 and CPT: 83036.',
    }).sensitivity,
    'clinical',
  );

  // 6. `public`: ONLY when explicitly set by user rule or `sensitivity:public` tag, never overriding higher rules
  const userPublicRule = {
    id: 'open-newsletter',
    tier: 'public',
    sourcePrefix: 'google-takeout/mail',
    tag: 'published',
  };
  assert.equal(
    classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      tags: ['published'],
      text: 'Public community announcement.',
      userRules: [userPublicRule],
    }).sensitivity,
    'public',
  );
  assert.equal(
    classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      tags: ['sensitivity:public'],
      text: 'Public note.',
    }).sensitivity,
    'public',
  );
  // Higher rule overrides `public` tag/rule!
  assert.equal(
    classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      tags: ['published', 'sensitivity:public'],
      text: 'Contains SSN: 123-45-6789 accidentally.',
      userRules: [userPublicRule],
    }).sensitivity,
    'private',
  );

  // 7. Bounded low-memory scan on a 16 MiB buffer (proves head + tail slices work and total slice length <= 80 KiB)
  const big = Buffer.alloc(16 * 1024 * 1024, 0x61); // 'a'
  const slicesPlain = extractBoundedScanSlices(big);
  assert.equal(slicesPlain.length, 2);
  const decodedChars = slicesPlain.reduce((acc, s) => acc + s.length, 0);
  assert.ok(decodedChars <= HEAD_SCAN_BYTES + TAIL_SCAN_BYTES);

  // Secret placed near the end (in the last 16 KiB tail) of a 16 MiB buffer is still caught!
  const tailMarker = Buffer.from(`\n${buildPemHeader('OPENSSH')}\n`, 'utf8');
  tailMarker.copy(big, big.length - tailMarker.length - 64);
  assert.equal(
    classifySensitivity({
      profile: 'me',
      collection: 'me/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      plaintext: big,
    }).sensitivity,
    'secret',
  );
});

test('vault persistence & replay: profiles, display names, consent events, user rules, and child prompt-policy toggles', t => {
  const { vaultDir, vaultId, credential } = scratchVault(t);
  const session = unlockVault(join(vaultDir, 'keyring', 'keyring.json'), vaultId, credential);
  t.after(() => session.dispose());

  // 1. Add profiles (`me`, `partner`, `child`) with display names stored ONLY inside encrypted vault events
  const meAdded = addProfile(vaultDir, { session }, {
    profile: 'me',
    displayName: 'Primary Owner Label',
  });
  assert.equal(meAdded.profile, 'me');
  assert.equal(meAdded.displayName, 'Primary Owner Label');
  assert.equal(meAdded.eventSeq, 1);

  const partnerAdded = addProfile(vaultDir, { session }, {
    profile: 'partner',
    displayName: 'Household Partner Label',
  });
  assert.equal(partnerAdded.eventSeq, 2);

  const childAdded = addProfile(vaultDir, { session }, {
    profile: 'child',
    displayName: 'Junior Member Label',
  });
  assert.equal(childAdded.eventSeq, 3);

  // Verify plaintext files on disk (VAULT.json, HEAD.json, keyring.json) NEVER contain any displayName!
  for (const rel of [['VAULT.json'], ['HEAD.json'], ['keyring', 'keyring.json']]) {
    const raw = readFileSync(join(vaultDir, ...rel), 'utf8');
    assert.ok(!raw.includes('Primary Owner Label'));
    assert.ok(!raw.includes('Household Partner Label'));
    assert.ok(!raw.includes('Junior Member Label'));
  }

  // 2. Consent rules: `me` needs no consent; `recordConsent` rejects `me` with CONSENT_NOT_APPLICABLE
  assert.throws(
    () => recordConsent(vaultDir, { session }, { profile: 'me', basis: 'other' }),
    err => err instanceof ProfileError && err.code === 'CONSENT_NOT_APPLICABLE',
  );
  assert.throws(
    () => recordConsent(vaultDir, { session }, { profile: 'partner', basis: 'not-a-valid-basis' }),
    err => err instanceof ProfileError && err.code === 'INVALID_CONSENT_BASIS',
  );
  assert.throws(
    () => assertConsentBasis('bad'),
    err => err instanceof ProfileError && err.code === 'INVALID_CONSENT_BASIS',
  );
  assert.throws(
    () => assertConsentSubjectProfile('me'),
    err => err instanceof ProfileError && err.code === 'CONSENT_NOT_APPLICABLE',
  );
  assert.throws(
    () => assertConsentNote('   '),
    err => err instanceof ProfileError && err.code === 'INVALID_CONSENT_NOTE',
  );
  assert.deepEqual(CONSENT_BASES, [
    'exported-by-them',
    'parent-or-guardian',
    'shared-conversation',
    'other',
  ]);

  // Before recording consent, non-`me` profiles fail `assertImportConsent` with CONSENT_REQUIRED
  const stateBeforeConsent = loadVaultProfileState(vaultDir, { session });
  assert.equal(hasActiveConsent(stateBeforeConsent, 'me'), true);
  assert.equal(hasActiveConsent(stateBeforeConsent, 'partner'), false);
  assert.equal(hasActiveConsent(stateBeforeConsent, 'child'), false);
  assert.doesNotThrow(() => assertImportConsent(stateBeforeConsent, 'me'));
  assert.throws(
    () => assertImportConsent(stateBeforeConsent, 'partner'),
    err => err instanceof ProfileError && err.code === 'CONSENT_REQUIRED',
  );
  assert.throws(
    () => assertImportConsent(stateBeforeConsent, 'child'),
    err => err instanceof ProfileError && err.code === 'CONSENT_REQUIRED',
  );

  // Record consent for `partner` and `child`, then update `partner`'s consent basis (append-only history preserved)
  const c1 = recordConsent(vaultDir, { session }, {
    profile: 'partner',
    basis: 'shared-conversation',
    note: 'Initial shared export note',
  });
  const c2 = recordConsent(vaultDir, { session }, {
    profile: 'child',
    basis: 'parent-or-guardian',
    note: 'Guardian archive note',
  });
  const c3 = recordConsent(vaultDir, { session }, {
    profile: 'partner',
    basis: 'exported-by-them',
    note: 'Updated full archive export given directly',
  });
  assert.ok(c3.eventSeq > c2.eventSeq && c2.eventSeq > c1.eventSeq);

  const consentsView = listConsents(vaultDir, { session });
  assert.equal(consentsView.consents.length, 2);
  assert.equal(consentsView.history.length, 3);
  assert.equal(consentsView.consents[0].profile, 'partner');
  assert.equal(consentsView.consents[0].basis, 'exported-by-them');
  assert.equal(consentsView.consents[0].active, true);
  assert.equal(consentsView.history[0].active, false, 'earlier superseded consent marked inactive in history');

  // 3. User-configured generic sensitivity rule stored in vault
  addSensitivityRule(vaultDir, { session }, {
    id: 'mortgage-folder-private',
    tier: 'private',
    profile: 'partner',
    keyword: 'escrow-statement',
  });

  // 4. Collection prompt-policy events (`collection.created` first, then `annotation.added` on subsequent toggles)
  const childColA = 'child/google-takeout/mail/2024';
  const childColB = 'child/google-takeout/calendar/2024';
  const p1 = setCollectionPromptPolicy(vaultDir, { session }, {
    collection: childColA,
    allowChildModelPrompts: true,
  });
  assert.equal(p1.kind, 'collection.created');
  assert.equal(p1.allowChildModelPrompts, true);

  const p2 = setCollectionPromptPolicy(vaultDir, { session }, {
    collection: childColB,
    allowChildModelPrompts: true,
  });
  assert.equal(p2.kind, 'collection.created');

  // Switch `childColB` back OFF -> appends `annotation.added` and latest `seq` wins!
  const p3 = setCollectionPromptPolicy(vaultDir, { session }, {
    collection: childColB,
    allowChildModelPrompts: false,
  });
  assert.equal(p3.kind, 'annotation.added');
  assert.equal(p3.allowChildModelPrompts, false);

  // Replay full state from vault and verify everything
  const state = loadVaultProfileState(vaultDir, { session });
  assert.doesNotThrow(() => assertImportConsent(state, 'partner'));
  assert.doesNotThrow(() => assertImportConsent(state, 'child'));
  assert.throws(
    () => assertImportConsent(state, 'other'),
    err => err instanceof ProfileError && err.code === 'CONSENT_REQUIRED',
  );

  const listedProfiles = listProfiles(vaultDir, { session });
  assert.deepEqual(
    listedProfiles.profiles.map(p => [p.profile, p.displayName, p.consentRecorded, p.consentBasis]),
    [
      ['me', 'Primary Owner Label', true, undefined],
      ['partner', 'Household Partner Label', true, 'exported-by-them'],
      ['child', 'Junior Member Label', true, 'parent-or-guardian'],
    ],
  );

  const listedCols = listCollections(vaultDir, { session });
  assert.deepEqual(
    listedCols.collections.map(c => [c.collection, c.allowChildModelPrompts]),
    [
      [childColB, false],
      [childColA, true],
    ],
  );

  // User rule replayed from vault classifies partner item containing keyword as `private`
  assert.equal(
    classifySensitivity({
      profile: 'partner',
      collection: 'partner/google-takeout/mail/2024',
      source: 'google-takeout/mail',
      text: 'Annual escrow-statement summary.',
      userRules: state.sensitivityRules,
    }).sensitivity,
    'private',
  );

  // 5. Prompt-gating helpers (`isPromptEligible`, `filterItemsForModelPrompt`)
  const candidates = [
    { id: 'me-personal', profile: 'me', collection: 'me/google-takeout/mail/2024', sensitivity: 'personal' },
    { id: 'me-secret', profile: 'me', collection: 'me/google-takeout/mail/2024', sensitivity: 'secret' },
    { id: 'child-allowed', profile: 'child', collection: childColA, sensitivity: 'child' },
    { id: 'child-secret-in-allowed', profile: 'child', collection: childColA, sensitivity: 'secret' },
    { id: 'child-toggled-off', profile: 'child', collection: childColB, sensitivity: 'child' },
    { id: 'child-unconfigured', profile: 'child', collection: 'child/google-takeout/contacts/2024', sensitivity: 'child' },
    { id: 'me-child-tier', profile: 'me', collection: 'me/shared-school/2024', sensitivity: 'child' },
  ];

  assert.deepEqual(isPromptEligible(candidates[0], state), { eligible: true });
  assert.deepEqual(isPromptEligible(candidates[1], state), {
    eligible: false,
    reason: 'SECRET_TIER_EXCLUDED',
  });
  assert.deepEqual(isPromptEligible(candidates[2], state), { eligible: true });
  assert.deepEqual(isPromptEligible(candidates[3], state), {
    eligible: false,
    reason: 'SECRET_TIER_EXCLUDED',
  });
  assert.deepEqual(isPromptEligible(candidates[4], state), {
    eligible: false,
    reason: 'CHILD_TIER_EXCLUDED',
  });
  assert.deepEqual(isPromptEligible(candidates[5], state), {
    eligible: false,
    reason: 'CHILD_TIER_EXCLUDED',
  });
  assert.deepEqual(isPromptEligible(candidates[6], state), {
    eligible: false,
    reason: 'CHILD_TIER_EXCLUDED',
  });

  // Prototype-pollution safety on plain record lookup (`toString` / `constructor` must not count as enabled!)
  assert.deepEqual(
    isPromptEligible(
      { profile: 'child', collection: 'toString', sensitivity: 'child' },
      {},
    ),
    { eligible: false, reason: 'CHILD_TIER_EXCLUDED' },
  );

  const eligibleIds = filterItemsForModelPrompt(candidates, state).map(c => c.id);
  assert.deepEqual(eligibleIds, ['me-personal', 'child-allowed']);

  // Vault public and deep verification pass cleanly on all appended structural events
  verifyVault(vaultDir);
  const unlocked = decodeKeyring(
    readFileSync(join(vaultDir, 'keyring', 'keyring.json')),
    credential,
    decodeVaultMetadata(readFileSync(join(vaultDir, 'VAULT.json'))).vault_id,
  );
  try {
    verifyVaultDeep(vaultDir, unlocked);
  } finally {
    unlocked.masterKey.fill(0);
    for (const k of unlocked.keys.values()) k.fill(0);
  }
});

test('erased profile keys (ERASED): destroying a profile key and its system collection key destroys its displayName without breaking replay', t => {
  const { vaultDir, vaultId, credential, recovery } = scratchVault(t);
  const keyringPath = join(vaultDir, 'keyring', 'keyring.json');

  addProfile(vaultDir, credential, {
    profile: 'me',
    displayName: 'Owner Surviving Label',
  });
  addProfile(vaultDir, credential, {
    profile: 'partner',
    displayName: 'Erased Partner Secret Display Name',
    sensitivityRules: [{ id: 'partner-only-rule', tier: 'private', keyword: 'custom-partner-kw' }],
  });
  recordConsent(vaultDir, credential, {
    profile: 'partner',
    basis: 'exported-by-them',
  });
  setCollectionPromptPolicy(vaultDir, credential, {
    collection: 'child/google-takeout/mail/2024',
    allowChildModelPrompts: true,
  });

  // Simulate P-2 cryptographic erasure of `partner` in keyring.json:
  // mark `partner`'s profile entry and all collection entries parented to `partner` as `destroyed`.
  const unlockedBefore = decodeKeyring(readFileSync(keyringPath), credential, vaultId);
  let rewrittenBytes;
  try {
    const partnerEntry = unlockedBefore.keyring.keys.find(
      e => e.kind === 'profile' && unlockedBefore.labels.get(e.key_id) === 'partner',
    );
    assert.ok(partnerEntry);
    const partnerKeyId = partnerEntry.key_id;
    const destroyedAt = '2026-11-26T12:00:00Z';

    const newEntries = unlockedBefore.keyring.keys.map(entry => {
      if (entry.key_id === partnerKeyId || entry.parent === partnerKeyId) {
        return {
          key_id: entry.key_id,
          kind: entry.kind,
          parent: entry.parent,
          state: 'destroyed',
          destroyed_at: destroyedAt,
        };
      }
      if (entry.state === 'destroyed') {
        return {
          key_id: entry.key_id,
          kind: entry.kind,
          parent: entry.parent,
          state: 'destroyed',
          destroyed_at: entry.destroyed_at,
        };
      }
      return {
        key_id: entry.key_id,
        kind: entry.kind,
        parent: entry.parent,
        state: 'active',
        created_at: entry.created_at,
        key: Buffer.from(unlockedBefore.keys.get(entry.key_id)),
        ...(entry.kind === 'profile' ? { label: unlockedBefore.labels.get(entry.key_id) } : {}),
      };
    });

    rewrittenBytes = encodeKeyring(
      {
        vaultId,
        version: unlockedBefore.keyring.version + 1,
        masterKey: Buffer.from(unlockedBefore.masterKey),
        entries: newEntries,
      },
      PASSPHRASE,
      recovery,
    );
  } finally {
    unlockedBefore.masterKey.fill(0);
    for (const k of unlockedBefore.keys.values()) k.fill(0);
  }
  writeFileSync(keyringPath, rewrittenBytes);

  // Replay MUST succeed without throwing, skip the destroyed `partner` system record,
  // expose zero trace of `Erased Partner Secret Display Name`, and preserve `me`'s audit/policy state!
  const afterErase = loadVaultProfileState(vaultDir, credential);
  assert.equal(afterErase.destroyedProfileCount, 1);
  assert.equal(afterErase.skippedEvents, 1);
  assert.equal(afterErase.profiles.has('partner'), false);
  assert.equal(afterErase.profiles.get('me')?.displayName, 'Owner Surviving Label');
  assert.equal(afterErase.sensitivityRules.length, 0, 'partner custom rule is cryptographically gone');
  assert.equal(
    afterErase.collections.get('child/google-takeout/mail/2024')?.allowChildModelPrompts,
    true,
    'collection policy stored under me/system survives',
  );
  assert.equal(
    afterErase.consents.get('partner')?.basis,
    'exported-by-them',
    'generic consent audit record under me/system survives without personal name',
  );

  // Attempting to re-create `partner` fails closed with VaultFormatError('ERASED') per A-41!
  assert.throws(
    () => addProfile(vaultDir, credential, { profile: 'partner', displayName: 'New Name' }),
    err => err instanceof Error && err.name === 'VaultFormatError' && err.code === 'ERASED',
  );

  // Deep vault verification also reports ERASED cleanly without corruption!
  const unlockedAfter = decodeKeyring(readFileSync(keyringPath), credential, vaultId);
  try {
    assert.throws(
      () => verifyVaultDeep(vaultDir, unlockedAfter),
      err => err instanceof Error && err.code === 'ERASED',
    );
  } finally {
    unlockedAfter.masterKey.fill(0);
    for (const k of unlockedAfter.keys.values()) k.fill(0);
  }
});

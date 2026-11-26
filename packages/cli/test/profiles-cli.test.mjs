// TEST ONLY: end-to-end CLI tests for Work Package P-1 (`profile`, `consent`, `collection`, and `import` wiring).
// All data, labels, emails, and test credentials are synthetic and dynamically assembled.
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { join } from 'node:path';
import { test } from 'node:test';
import { filterItemsForModelPrompt, isPromptEligible, loadVaultProfileState } from 'foundry-profiles';
import { syntheticEmail, writeZipArchive } from 'importers';
import { decodeRecoveryKey, openVaultReplay } from 'vault';
import { initVault, PASSPHRASE, runInline, scratch } from './helpers.mjs';

function readImportedEvents(home, recoveryKey) {
  const vaultDir = join(home, 'vault');
  const replay = openVaultReplay(vaultDir, { recoveryKey: decodeRecoveryKey(recoveryKey) });
  try {
    const out = [];
    for (const entry of replay.replay()) {
      if (entry.type === 'blob') break;
      if (entry.type === 'event' && entry.event.kind === 'item.imported') {
        out.push(entry.event);
      }
    }
    return out;
  } finally {
    replay.close();
  }
}

function buildSyntheticPem() {
  return ['-----BEGIN', 'OPENSSH', 'PRIVATE', 'KEY-----'].join(' ');
}

async function buildClassifiedMailArchive(dir, name = 'classified-mail.zip') {
  const fromAddr = syntheticEmail('sender-a');
  const toAddr = syntheticEmail('recipient-b');
  const messages = [
    // 1. Standard personal email in 2024
    [
      'From 1001@xxx Mon Mar 04 10:00:00 +0000 2024',
      `From: <${fromAddr}>`,
      `To: <${toAddr}>`,
      'Date: Mon, 04 Mar 2024 10:00:00 +0000',
      'Subject: Synthetic project update',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Routine quarterly planning notes.',
      '',
    ].join('\r\n'),
    // 2. Private tax email in 2023
    [
      'From 1002@xxx Tue Apr 11 14:30:00 +0000 2023',
      `From: <${fromAddr}>`,
      `To: <${toAddr}>`,
      'Date: Tue, 11 Apr 2023 14:30:00 +0000',
      'Subject: Synthetic tax filing summary',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Attached Form W-2 Wage and Tax Statement and SSN: 123-45-6789.',
      '',
    ].join('\r\n'),
    // 3. Clinical lab email in 2024
    [
      'From 1003@xxx Wed May 15 09:15:00 +0000 2024',
      `From: <${fromAddr}>`,
      `To: <${toAddr}>`,
      'Date: Wed, 15 May 2024 09:15:00 +0000',
      'Subject: Synthetic clinic portal notice',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Laboratory Results ready: Hemoglobin A1c 5.2%, Reference Range 4.0-5.6%, ICD-10-CM Z00.00.',
      '',
    ].join('\r\n'),
    // 4. Secret key email in 2024
    [
      'From 1004@xxx Thu Jun 20 16:45:00 +0000 2024',
      `From: <${fromAddr}>`,
      `To: <${toAddr}>`,
      'Date: Thu, 20 Jun 2024 16:45:00 +0000',
      'Subject: Synthetic backup key material',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      `Key backup header:\r\n${buildSyntheticPem()}\r\n`,
      '',
    ].join('\r\n'),
  ];

  const zipPath = join(dir, name);
  await writeZipArchive(zipPath, [
    {
      path: 'Takeout/Mail/All mail Including Spam and Trash.mbox',
      data: Buffer.from(messages.join(''), 'utf8'),
      compression: 'deflate',
    },
  ]);
  return zipPath;
}

test('profile, consent, and collection --help take no lock and exit 0', async t => {
  const dir = scratch(t);
  for (const argv of [
    ['profile', 'add', '--help'],
    ['profile', 'list', '--help'],
    ['consent', 'record', '--help'],
    ['consent', 'list', '--help'],
    ['collection', 'prompt-policy', '--help'],
    ['collection', 'list', '--help'],
    ['import', '--help'],
  ]) {
    const res = await runInline(dir, argv);
    assert.equal(res.code, 0, argv.join(' '));
    assert.match(res.stdout, /^Usage: foundry /u);
    assert.equal(res.kdf, 0);
  }
});

test('pre-KDF validation: invalid profiles, personal names, consent for me, and invalid collections fail with 0 KDFs and never echo input', async t => {
  const dir = scratch(t);
  const { home } = await initVault(dir);
  const planted = 'PLANTED-PERSONAL-TOKEN-9912';

  const invalidRuns = [
    [['profile', 'add', planted, '--vault', home, '--passphrase-stdin'], 'INVALID_PROFILE'],
    [['profile', 'add', 'Me', '--vault', home, '--passphrase-stdin'], 'INVALID_PROFILE'],
    [['profile', 'add', 'partner', '--display-name', `   `, '--vault', home, '--passphrase-stdin'], 'INVALID_DISPLAY_NAME'],
    [['consent', 'record', 'me', '--basis', 'other', '--vault', home, '--passphrase-stdin'], 'CONSENT_NOT_APPLICABLE'],
    [['consent', 'record', planted, '--basis', 'other', '--vault', home, '--passphrase-stdin'], 'INVALID_PROFILE'],
    [['consent', 'record', 'partner', '--basis', planted, '--vault', home, '--passphrase-stdin'], 'INVALID_CONSENT_BASIS'],
    [['consent', 'record', 'partner', '--basis', 'other', '--note', '  ', '--vault', home, '--passphrase-stdin'], 'INVALID_CONSENT_NOTE'],
    [['collection', 'prompt-policy', `foundry:${planted}`, '--child-prompts', 'on', '--vault', home, '--passphrase-stdin'], 'INVALID_COLLECTION'],
    [['collection', 'prompt-policy', 'system', '--child-prompts', 'on', '--vault', home, '--passphrase-stdin'], 'INVALID_COLLECTION'],
    [['collection', 'prompt-policy', `../${planted}`, '--child-prompts', 'on', '--vault', home, '--passphrase-stdin'], 'INVALID_COLLECTION'],
    [['import', 'x.zip', '--profile', planted, '--vault', home, '--passphrase-stdin'], 'INVALID_PROFILE'],
    [['import', 'x.zip', '--collection', `foundry:${planted}`, '--vault', home, '--passphrase-stdin'], 'INVALID_COLLECTION'],
    [['import', 'x.zip', '--collection', 'system', '--vault', home, '--passphrase-stdin'], 'INVALID_COLLECTION'],
  ];

  for (const [argv, expectedCode] of invalidRuns) {
    for (const debugFlag of [[], ['--debug']]) {
      const res = await runInline(dir, [...argv, ...debugFlag], { stdin: PASSPHRASE + '\n' });
      assert.equal(res.code, 2, `${argv.join(' ')}: ${res.stderr}`);
      assert.equal(res.kdf, 0, `${argv.join(' ')} ran KDF before validation`);
      assert.match(res.stderr, new RegExp(`\\[${expectedCode}\\]\\n$`, 'u'), res.stderr);
      assert.ok(!res.stderr.includes(planted), `leaked planted input in stderr: ${res.stderr}`);
      assert.ok(!res.stdout.includes(planted), `leaked planted input in stdout: ${res.stdout}`);
    }
  }
});

test('consent guard on foundry import: non-me profiles fail closed with CONSENT_REQUIRED and zero writes until consent is recorded', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const archive = await buildClassifiedMailArchive(dir);

  // 1. Attempt import under `--profile partner` BEFORE consent -> exit 2 CONSENT_REQUIRED, 0 items stored
  const denied = await runInline(
    dir,
    ['import', archive, '--profile', 'partner', '--vault', home, '--passphrase-stdin'],
    { stdin: PASSPHRASE + '\n' },
  );
  assert.equal(denied.code, 2);
  assert.equal(denied.kdf, 1);
  assert.match(denied.stderr, /^foundry: [^\n]+ \[CONSENT_REQUIRED\]\n$/u);
  assert.doesNotMatch(denied.stderr, /repeating the import is safe|stored so far/u);
  assert.equal(readImportedEvents(home, recoveryKey).length, 0);

  // 2. Add partner profile + record consent (1 KDF with passphrase, 0 with recovery key)
  const profAdd = await runInline(
    dir,
    ['profile', 'add', 'partner', '--display-name', 'Household Partner', '--vault', home, '--passphrase-stdin', '--json'],
    { stdin: PASSPHRASE + '\n' },
  );
  assert.equal(profAdd.code, 0, profAdd.stderr);
  assert.equal(profAdd.kdf, 1);
  // B7: a mutation command never prints the display name.
  assert.equal(JSON.parse(profAdd.stdout).displayNameSet, true);
  assert.ok(!profAdd.stdout.includes('Household Partner'));

  const consentRec = await runInline(
    dir,
    [
      'consent',
      'record',
      'partner',
      '--basis',
      'exported-by-them',
      '--note',
      'Provided Takeout archive directly',
      '--vault',
      home,
      '--recovery-key-stdin',
      '--json',
    ],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(consentRec.code, 0, consentRec.stderr);
  assert.equal(consentRec.kdf, 0);
  const consentJson = JSON.parse(consentRec.stdout);
  assert.equal(consentJson.profile, 'partner');
  assert.equal(consentJson.basis, 'exported-by-them');

  // 3. Import under `--profile partner` now succeeds, assigns `<profile>/<source>/<year>` collections and write-time sensitivity!
  const allowed = await runInline(
    dir,
    ['import', archive, '--profile', 'partner', '--vault', home, '--passphrase-stdin', '--json'],
    { stdin: PASSPHRASE + '\n' },
  );
  assert.equal(allowed.code, 0, allowed.stderr);
  assert.equal(allowed.kdf, 1);
  assert.equal(JSON.parse(allowed.stdout).itemsAdded, 4);

  const events = readImportedEvents(home, recoveryKey);
  assert.equal(events.length, 4);
  const byCollectionAndTier = events.map(e => [e.profile, e.collection, e.sensitivity]);
  assert.deepEqual(byCollectionAndTier, [
    ['partner', 'partner/google-takeout/mail/2024', 'personal'],
    ['partner', 'partner/google-takeout/mail/2023', 'private'],
    ['partner', 'partner/google-takeout/mail/2024', 'clinical'],
    ['partner', 'partner/google-takeout/mail/2024', 'secret'],
  ]);

  // 4. `profile list`, `consent list`, `collection list`, `search` with filters, `index rebuild`, `vault verify`
  const pList = await runInline(dir, ['profile', 'list', '--vault', home, '--recovery-key-stdin', '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(pList.code, 0, pList.stderr);
  assert.equal(pList.kdf, 0);
  const profilesOut = JSON.parse(pList.stdout).profiles;
  assert.deepEqual(
    profilesOut.map(p => [p.profile, p.displayName, p.displayNameSet, p.consentRecorded]),
    [
      ['me', undefined, false, true],
      ['partner', undefined, true, true],
    ],
  );
  const pListRevealed = await runInline(dir, ['profile', 'list', '--reveal', '--vault', home, '--recovery-key-stdin', '--json'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(pListRevealed.code, 0, pListRevealed.stderr);
  assert.deepEqual(
    JSON.parse(pListRevealed.stdout).profiles.map(p => [p.profile, p.displayName]),
    [
      ['me', undefined],
      ['partner', 'Household Partner'],
    ],
  );

  const pListText = await runInline(dir, ['profile', 'list', '--vault', home, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(pListText.code, 0);
  assert.match(pListText.stdout, /partner \(name set\) {2}\[consent:exported-by-them\]/u);
  const pListTextRevealed = await runInline(dir, ['profile', 'list', '--reveal', '--vault', home, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
  });
  assert.match(pListTextRevealed.stdout, /partner \(Household Partner\) {2}\[consent:exported-by-them\]/u);

  const cList = await runInline(dir, ['consent', 'list', '--vault', home, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(cList.code, 0);
  assert.match(cList.stdout, /partner {2}exported-by-them {2}\(note set\)/u);
  const cListRevealed = await runInline(dir, ['consent', 'list', '--reveal', '--vault', home, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
  });
  assert.match(cListRevealed.stdout, /partner {2}exported-by-them {2}Provided Takeout archive directly/u);

  // Search filtered by `--profile partner` finds partner items; `--profile me` finds 0
  const searchPartner = await runInline(
    dir,
    ['search', 'Synthetic', '--profile', 'partner', '--vault', home, '--recovery-key-stdin', '--json'],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(searchPartner.code, 0, searchPartner.stderr);
  assert.equal(JSON.parse(searchPartner.stdout).results.length, 4);

  const searchMe = await runInline(
    dir,
    ['search', 'Synthetic', '--profile', 'me', '--vault', home, '--recovery-key-stdin', '--json'],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(searchMe.code, 0, searchMe.stderr);
  assert.equal(JSON.parse(searchMe.stdout).results.length, 0);

  // Rebuild index and verify vault chain + signatures
  const rebuilt = await runInline(dir, ['index', 'rebuild', '--vault', home, '--passphrase-stdin'], {
    stdin: PASSPHRASE + '\n',
  });
  assert.equal(rebuilt.code, 0, rebuilt.stderr);
  assert.equal(rebuilt.kdf, 1);

  const verified = await runInline(dir, ['vault', 'verify', '--vault', home, '--json']);
  assert.equal(verified.code, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stdout).ok, true);
});

test('child profile import, sensitivity floor vs secret elevation, --collection override, and per-collection prompt-policy CLI switch', async t => {
  const dir = scratch(t);
  const { home, recoveryKey } = await initVault(dir);
  const archive = await buildClassifiedMailArchive(dir, 'child-mail.zip');

  // Record guardian consent for `child`
  const consentRes = await runInline(
    dir,
    ['consent', 'record', 'child', '--basis', 'parent-or-guardian', '--vault', home, '--passphrase-stdin'],
    { stdin: PASSPHRASE + '\n' },
  );
  assert.equal(consentRes.code, 0, consentRes.stderr);
  assert.equal(consentRes.kdf, 1);

  // Import archive under `--profile child` (default collection grain `child/google-takeout/mail/<year>`)
  const imp = await runInline(
    dir,
    ['import', archive, '--profile', 'child', '--vault', home, '--recovery-key-stdin', '--json'],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(imp.code, 0, imp.stderr);
  assert.equal(imp.kdf, 0);
  assert.equal(JSON.parse(imp.stdout).itemsAdded, 4);

  // Also test explicit `--collection` override on `import`
  const overrideImp = await runInline(
    dir,
    [
      'import',
      archive,
      '--profile',
      'me',
      '--collection',
      'me/custom-curated/2024',
      '--vault',
      home,
      '--recovery-key-stdin',
      '--json',
    ],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(overrideImp.code, 0, overrideImp.stderr);
  assert.equal(JSON.parse(overrideImp.stdout).itemsAdded, 4);

  const events = readImportedEvents(home, recoveryKey);
  const childEvents = events.filter(e => e.profile === 'child');
  assert.equal(childEvents.length, 4);
  // Under `child`, personal/private/clinical items are elevated to `child`, while `secret` stays `secret`!
  assert.deepEqual(
    childEvents.map(e => [e.collection, e.sensitivity]),
    [
      ['child/google-takeout/mail/2024', 'child'],
      ['child/google-takeout/mail/2023', 'child'],
      ['child/google-takeout/mail/2024', 'child'],
      ['child/google-takeout/mail/2024', 'secret'],
    ],
  );

  const meOverrideEvents = events.filter(e => e.profile === 'me');
  assert.equal(meOverrideEvents.length, 4);
  assert.ok(meOverrideEvents.every(e => e.collection === 'me/custom-curated/2024'));

  // By default, ALL child items are excluded from model prompts (`CHILD_TIER_EXCLUDED` / `SECRET_TIER_EXCLUDED`)
  const vaultDir = join(home, 'vault');
  const credential = { recoveryKey: decodeRecoveryKey(recoveryKey) };
  const stateDefault = loadVaultProfileState(vaultDir, credential);
  assert.equal(filterItemsForModelPrompt(childEvents, stateDefault).length, 0);
  assert.deepEqual(isPromptEligible(childEvents[0], stateDefault), {
    eligible: false,
    reason: 'CHILD_TIER_EXCLUDED',
  });
  assert.deepEqual(isPromptEligible(childEvents[3], stateDefault), {
    eligible: false,
    reason: 'SECRET_TIER_EXCLUDED',
  });

  // Enable child prompts ONLY on `child/google-takeout/mail/2024` via CLI
  const enable2024 = await runInline(
    dir,
    [
      'collection',
      'prompt-policy',
      'child/google-takeout/mail/2024',
      '--child-prompts',
      'on',
      '--vault',
      home,
      '--passphrase-stdin',
      '--json',
    ],
    { stdin: PASSPHRASE + '\n' },
  );
  assert.equal(enable2024.code, 0, enable2024.stderr);
  assert.equal(enable2024.kdf, 1);
  assert.equal(JSON.parse(enable2024.stdout).allowChildModelPrompts, true);
  // B3: the import already recorded `collection.created` (the binding) before it created the key.
  assert.equal(JSON.parse(enable2024.stdout).kind, 'annotation.added');

  const stateEnabled = loadVaultProfileState(vaultDir, credential);
  const eligibleNow = filterItemsForModelPrompt(childEvents, stateEnabled);
  // The 2 non-secret 2024 items in `child/google-takeout/mail/2024` become eligible;
  // the 2023 collection item and the 2024 `secret` item remain excluded!
  assert.equal(eligibleNow.length, 2);
  assert.ok(eligibleNow.every(e => e.collection === 'child/google-takeout/mail/2024' && e.sensitivity === 'child'));

  // Verify `collection list` (JSON + text)
  const colListJson = await runInline(
    dir,
    ['collection', 'list', '--vault', home, '--recovery-key-stdin', '--json'],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(colListJson.code, 0, colListJson.stderr);
  assert.deepEqual(
    JSON.parse(colListJson.stdout).collections.map(c => [c.collection, c.itemCount, c.allowChildModelPrompts]),
    [
      ['child/google-takeout/mail/2023', 1, false],
      ['child/google-takeout/mail/2024', 3, true],
      ['me/custom-curated/2024', 4, false],
    ],
  );

  const colListText = await runInline(dir, ['collection', 'list', '--vault', home, '--recovery-key-stdin'], {
    stdin: recoveryKey + '\n',
  });
  assert.equal(colListText.code, 0);
  assert.match(colListText.stdout, /child\/google-takeout\/mail\/2024 {2}profile=child {2}items=3 {2}child-prompts=on/u);

  // Switch `child/google-takeout/mail/2024` back OFF via CLI -> appends `annotation.added` and excludes child items again!
  const disable2024 = await runInline(
    dir,
    [
      'collection',
      'prompt-policy',
      'child/google-takeout/mail/2024',
      '--child-prompts',
      'off',
      '--vault',
      home,
      '--recovery-key-stdin',
      '--json',
    ],
    { stdin: recoveryKey + '\n' },
  );
  assert.equal(disable2024.code, 0, disable2024.stderr);
  assert.equal(disable2024.kdf, 0);
  assert.equal(JSON.parse(disable2024.stdout).allowChildModelPrompts, false);
  assert.equal(JSON.parse(disable2024.stdout).kind, 'annotation.added');

  const stateDisabled = loadVaultProfileState(vaultDir, credential);
  assert.equal(filterItemsForModelPrompt(childEvents, stateDisabled).length, 0);
});

// --- P-1 fix round 1 session A (item 6): classify the decoded text, not only the raw bytes ---

/** Wrap at 76 characters with CRLF, as MIME bodies are. */
function wrap76(text) {
  const lines = [];
  for (let i = 0; i < text.length; i += 76) lines.push(text.slice(i, i + 76));
  return lines.join('\r\n');
}

/** Quoted-printable with EVERY byte hex-encoded (`=XX`), so no credential text is readable in the raw bytes. */
function quotedPrintableAllHex(text) {
  const encoded = [...Buffer.from(text, 'utf8')].map(b => `=${b.toString(16).toUpperCase().padStart(2, '0')}`);
  const lines = [];
  for (let i = 0; i < encoded.length; i += 24) lines.push(encoded.slice(i, i + 24).join(''));
  return lines.join('=\r\n');
}

async function buildEncodedCredentialMailArchive(dir, name, encoding) {
  const secretBody = `Synthetic restore notes.\n${buildSyntheticPem()}\nEnd of notes.\n`;
  const encodedBody =
    encoding === 'base64' ? wrap76(Buffer.from(secretBody, 'utf8').toString('base64')) : quotedPrintableAllHex(secretBody);
  const message = [
    'From 2001@xxx Mon Mar 04 10:00:00 +0000 2024',
    `From: <${syntheticEmail('sender-enc')}>`,
    `To: <${syntheticEmail('recipient-enc')}>`,
    'Date: Mon, 04 Mar 2024 10:00:00 +0000',
    'Subject: Synthetic encoded notes',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="synthetic-boundary"',
    '',
    '--synthetic-boundary',
    'Content-Type: text/plain; charset="utf-8"',
    `Content-Transfer-Encoding: ${encoding}`,
    '',
    encodedBody,
    '--synthetic-boundary--',
    '',
  ].join('\r\n');
  // The raw bytes alone must not reveal the credential (otherwise the test proves nothing).
  assert.ok(!message.includes('PRIVATE'), `${encoding} fixture leaks the marker into the raw bytes`);
  const zipPath = join(dir, name);
  await writeZipArchive(zipPath, [
    { path: 'Takeout/Mail/All mail Including Spam and Trash.mbox', data: Buffer.from(message, 'utf8'), compression: 'deflate' },
  ]);
  return zipPath;
}

for (const encoding of ['base64', 'quoted-printable']) {
  test(`A2: a mail whose only credential sits inside a ${encoding} text/plain part is secret after import`, async t => {
    const dir = scratch(t);
    const { home, recoveryKey } = await initVault(dir);
    const archive = await buildEncodedCredentialMailArchive(dir, `${encoding}-mail.zip`, encoding);
    const imp = await runInline(dir, ['import', archive, '--vault', home, '--recovery-key-stdin', '--json'], {
      stdin: recoveryKey + '\n',
    });
    assert.equal(imp.code, 0, imp.stderr);
    assert.equal(JSON.parse(imp.stdout).itemsAdded, 1);
    const events = readImportedEvents(home, recoveryKey);
    assert.deepEqual(
      events.map(e => [e.profile, e.collection, e.sensitivity]),
      [['me', 'me/google-takeout/mail/2024', 'secret']],
    );
  });
}

test('A2/B0: classifyImportItem classifies the index text, and falls back to raw bytes with rule derive-failed', async () => {
  const { classifyImportItem } = await import('../dist/classify.js');
  const { classifySensitivity } = await import('foundry-profiles');
  const { itemTextOfPlaintext, loadParsers } = await import('../dist/derive.js');
  const parsers = await loadParsers();
  const indexText = (mime, plaintext) => itemTextOfPlaintext(parsers, mime, plaintext);
  const secretBody = `Notes\n${buildSyntheticPem()}\n`;
  const fromLine = `From: <${syntheticEmail('derive-unit')}>`;
  const mail = Buffer.from(
    [
      fromLine,
      'Subject: Synthetic',
      'Content-Type: text/plain; charset="utf-8"',
      'Content-Transfer-Encoding: base64',
      '',
      wrap76(Buffer.from(secretBody, 'utf8').toString('base64')),
      '',
    ].join('\r\n'),
    'utf8',
  );
  const input = { profile: 'me', collection: 'me/google-takeout/mail/2024', source: 'google-takeout/mail', path: 'm/1' };
  const item = { plaintext: mail, mime: 'message/rfc822', tags: [], profile: 'me', collection: input.collection };

  const ok = classifyImportItem(classifySensitivity, indexText, input, item);
  assert.deepEqual(ok, { sensitivity: 'secret', rule: 'private-key' });
  // B0: the classifier sees exactly the text the index stores for the item.
  assert.ok(indexText('message/rfc822', mail).includes(buildSyntheticPem()));

  const throwing = () => {
    throw new Error('synthetic derive failure');
  };
  const failed = classifyImportItem(classifySensitivity, throwing, input, item);
  assert.deepEqual(failed, { sensitivity: 'personal', rule: 'derive-failed' });
  // A derive failure never assigns `secret` by itself, and raw-byte rules still apply.
  const rawPrivate = { ...item, plaintext: Buffer.from('Taxpayer SSN: 123-45-6789 on file.', 'utf8') };
  assert.deepEqual(classifyImportItem(classifySensitivity, throwing, input, rawPrivate), {
    sensitivity: 'private',
    rule: 'derive-failed',
  });
  // The pipeline's plaintext is left untouched by the derive step.
  assert.ok(mail.toString('utf8').startsWith(fromLine));
  // A type with no index text classifies the raw bytes only, with its normal rule id.
  const other = classifyImportItem(classifySensitivity, indexText, input, { ...rawPrivate, mime: 'application/octet-stream' });
  assert.deepEqual(other, { sensitivity: 'private', rule: 'national-id' });
});

test('B0: the classifier uses the projection limits (8 MiB input slice, truncated flag, 1 MiB text cap)', async () => {
  const { itemTextOfPlaintext, loadParsers, MAX_DERIVE_BYTES, MAX_TEXT_BYTES } = await import('../dist/derive.js');
  const { classifyImportItem } = await import('../dist/classify.js');
  const { classifySensitivity } = await import('foundry-profiles');
  const parsers = await loadParsers();
  // A plain-text item larger than 8 MiB: the text is the first bytes only, capped at 1 MiB.
  const big = Buffer.alloc(MAX_DERIVE_BYTES + 4096, 0x61);
  const text = itemTextOfPlaintext(parsers, 'text/plain', big);
  assert.equal(Buffer.byteLength(text), MAX_TEXT_BYTES);
  // The input is read through a view and never changed.
  assert.ok(big.every(b => b === 0x61));
  // A marker after the 8 MiB slice is not in the index text, but the raw-byte scan of the whole item still finds it.
  const marker = Buffer.from(`\n${buildSyntheticPem()}\n`, 'utf8');
  marker.copy(big, MAX_DERIVE_BYTES + 100);
  assert.ok(!itemTextOfPlaintext(parsers, 'text/plain', big).includes('PRIVATE'));
  const input = { profile: 'me', collection: 'me/custom/2024', source: 'custom/plain', path: 'p/1' };
  const res = classifyImportItem(
    classifySensitivity,
    (mime, plaintext) => itemTextOfPlaintext(parsers, mime, plaintext),
    input,
    { plaintext: big, mime: 'text/plain', tags: [], profile: 'me', collection: input.collection },
  );
  assert.deepEqual(res, { sensitivity: 'secret', rule: 'private-key' });
});

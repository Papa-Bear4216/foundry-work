/**
 * Vault-backed persistence and deterministic replay for profiles, consent notes,
 * collection model-prompt policies, and user sensitivity rules.
 *
 * Key-isolation rules (Architecture 4.3, 5.4, 5.7):
 * - `profile.created` (carrying optional `display_name` and profile-scoped `sensitivity_rules`)
 *   is encrypted under `<profile>`'s own `'system'` collection key so destroying `<profile>`'s
 *   keys in P-2 cryptographically destroys its `display_name` and custom rules.
 * - `consent.recorded` and per-collection prompt policy events (`collection.created`,
 *   `annotation.added`) are encrypted under `'me'`'s `'system'` collection key with generic
 *   identifiers only, keeping audit and policy state replayable without personal names.
 */
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  decodeKeyring,
  decodeVaultMetadata,
  ensureCollectionKeys,
  openVaultReplay,
  VaultWriter,
} from 'vault';
import type { Unlock } from 'vault';
import { ProfileError } from './errors.ts';
import { PROFILE_IDS } from './types.ts';
import type {
  CollectionState,
  ConsentBasis,
  ConsentRecord,
  ConsentSubjectProfileId,
  ProfileId,
  ProfileRecord,
  UserSensitivityRule,
  VaultProfileState,
} from './types.ts';
import { recordReplayedPolicy } from './policy-registry.ts';
import {
  assertCollectionForProfile,
  assertConsentBasis,
  assertConsentNote,
  assertConsentNoteForBasis,
  assertConsentSubjectProfile,
  assertDisplayName,
  assertProfileCollectionName,
  assertProfileId,
  assertUserSensitivityRule,
  formatUtcTimestamp,
  isConsentBasis,
  isConsentSubjectProfile,
  isProfileId,
  profileOfCollection,
  SYSTEM_COLLECTION,
  validateCollectionName,
} from './validation.ts';

const OWNER_PROFILE: ProfileId = 'me';

interface MutableProfileState {
  profile: ProfileId;
  displayName?: string;
  hasKeyringEntry: boolean;
  createdAt?: string;
  updatedAt?: string;
  eventSeq?: number;
  rulesById: Map<string, UserSensitivityRule>;
}

interface MutableCollectionState {
  collection: string;
  profile?: ProfileId;
  itemCount: number;
  createdEventSeen: boolean;
  allowChildModelPrompts: boolean;
  policyEventSeq?: number;
  policyUpdatedAt?: string;
}

function clearUnlocked(unlocked: ReturnType<typeof decodeKeyring>): void {
  unlocked.masterKey.fill(0);
  for (const key of unlocked.keys.values()) key.fill(0);
  unlocked.labels.clear();
}

function vaultPaths(vaultDir: string) {
  const root = resolve(vaultDir);
  return {
    vaultDir: root,
    metadataPath: join(root, 'VAULT.json'),
    keyringPath: join(root, 'keyring', 'keyring.json'),
  };
}

/** Events per `appendBatch` call when many structure events are appended in one writer session. */
const SYSTEM_EVENTS_PER_BATCH = 1024;

function appendSystemEvent(
  vaultDir: string,
  credential: Unlock,
  encryptUnderProfile: ProfileId,
  event: Readonly<Record<string, unknown>>,
): { sequence: number; createdKey: boolean } {
  const { sequences, createdKey } = appendSystemEvents(vaultDir, credential, encryptUnderProfile, [event]);
  return { sequence: sequences[0]!, createdKey };
}

/** Append `events` under `<profile>`'s `'system'` key in ONE writer session (batches of 1,024 events). */
function appendSystemEvents(
  vaultDir: string,
  credential: Unlock,
  encryptUnderProfile: ProfileId,
  events: readonly Readonly<Record<string, unknown>>[],
): { sequences: number[]; createdKey: boolean } {
  const { metadataPath, keyringPath } = vaultPaths(vaultDir);
  const vaultId = decodeVaultMetadata(readFileSync(metadataPath)).vault_id;
  const ensured = ensureCollectionKeys(
    keyringPath,
    vaultId,
    credential,
    encryptUnderProfile,
    [SYSTEM_COLLECTION],
  );
  const keyId = ensured.keyIds.get(SYSTEM_COLLECTION);
  if (!keyId) {
    throw new Error('Failed to resolve system collection key.');
  }

  const unlocked = decodeKeyring(readFileSync(keyringPath), credential, vaultId);
  let writer: VaultWriter | undefined;
  try {
    writer = VaultWriter.open(vaultDir, unlocked);
    const sequences: number[] = [];
    for (let start = 0; start < events.length; start += SYSTEM_EVENTS_PER_BATCH) {
      const slice = events.slice(start, start + SYSTEM_EVENTS_PER_BATCH);
      const results = writer.appendBatch(slice.map(event => ({ type: 'event' as const, keyId, event })));
      for (const res of results) {
        if (!res || res.type !== 'event') {
          throw new Error('Expected event append result from VaultWriter.');
        }
        sequences.push(res.sequence);
      }
    }
    return { sequences, createdKey: ensured.created > 0 };
  } finally {
    try {
      writer?.release();
    } finally {
      clearUnlocked(unlocked);
    }
  }
}

function inferProfileFromCollection(collection: string): ProfileId | undefined {
  const slash = collection.indexOf('/');
  const head = slash === -1 ? collection : collection.slice(0, slash);
  return isProfileId(head) ? head : undefined;
}

/** True for an `item.imported` event that does not follow the P-1 rule `<profile>/...` (fail closed). */
function isPreProfileItem(profile: unknown, collection: unknown): boolean {
  if (!isProfileId(profile) || typeof collection !== 'string') return true;
  return !collection.startsWith(`${profile}/`);
}

/**
 * Replays structural and item metadata events from the vault + keyring to reconstruct
 * profile records, active/historical consent notes, collection policies, and user sensitivity rules.
 *
 * Destroyed collection/profile keys do not fail replay: unreadable events under destroyed
 * collection keys are counted in `skippedEvents` and `destroyedProfileCount` reflects destroyed
 * profile entries in the MAC-verified keyring.
 */
export function loadVaultProfileState(
  vaultDir: string,
  credential: Unlock,
): VaultProfileState {
  const { metadataPath, keyringPath } = vaultPaths(vaultDir);
  const vaultId = decodeVaultMetadata(readFileSync(metadataPath)).vault_id;
  const unlocked = decodeKeyring(readFileSync(keyringPath), credential, vaultId);

  const keyringProfiles = new Set<ProfileId>();
  let destroyedProfileCount = 0;
  try {
    for (const entry of unlocked.keyring.keys) {
      if (entry.kind !== 'profile') continue;
      if (entry.state === 'destroyed') {
        destroyedProfileCount++;
        continue;
      }
      if (entry.state === 'active') {
        const label = unlocked.labels.get(entry.key_id);
        if (isProfileId(label)) keyringProfiles.add(label);
      }
    }
  } finally {
    clearUnlocked(unlocked);
  }

  const profilesMap = new Map<ProfileId, MutableProfileState>();
  const ensureMutableProfile = (profile: ProfileId): MutableProfileState => {
    let existing = profilesMap.get(profile);
    if (!existing) {
      existing = {
        profile,
        hasKeyringEntry: keyringProfiles.has(profile),
        rulesById: new Map(),
      };
      profilesMap.set(profile, existing);
    }
    return existing;
  };

  for (const profile of keyringProfiles) {
    ensureMutableProfile(profile);
  }

  const erasedProfiles = new Set<ProfileId>();
  const activeConsents = new Map<ConsentSubjectProfileId, ConsentRecord>();
  const consentHistory: ConsentRecord[] = [];
  // P-1 fix round 1 (item 14): event sequence -> position in `consentHistory`, so replay stays linear.
  const historyPositionBySeq = new Map<number, number>();
  const deactivateConsent = (record: ConsentRecord): void => {
    const position = historyPositionBySeq.get(record.eventSeq);
    if (position !== undefined) {
      consentHistory[position] = { ...consentHistory[position]!, active: false };
    }
  };
  // P-1 fix round 1 (item 8): global rules (no `profile`) are kept apart from every profile's scoped rules.
  const globalRulesById = new Map<string, UserSensitivityRule>();
  const collectionsMap = new Map<string, MutableCollectionState>();
  let skippedEvents = 0;
  let preProfileItemEvents = 0;

  const ensureMutableCollection = (
    collection: string,
    ownerProfile?: ProfileId,
  ): MutableCollectionState => {
    let existing = collectionsMap.get(collection);
    if (!existing) {
      existing = {
        collection,
        profile: ownerProfile ?? inferProfileFromCollection(collection),
        itemCount: 0,
        createdEventSeen: false,
        allowChildModelPrompts: false,
      };
      collectionsMap.set(collection, existing);
    } else if (existing.profile === undefined && ownerProfile !== undefined) {
      existing.profile = ownerProfile;
    }
    return existing;
  };

  const replaySource = openVaultReplay(vaultDir, credential);
  let lastEventSeq = 0;
  try {
    lastEventSeq = replaySource.boundary.lastEventSequence;
    for (const entry of replaySource.replay()) {
      // Event streams (`events-*.fvr`) always precede blob streams (`pack-*.fvr`) in openVaultReplay.
      // Stopping at the first blob record avoids decrypting stored item blobs while verifying 100% of events.
      if (entry.type === 'blob' || (entry.type === 'skipped' && entry.recordType === 'blob')) {
        break;
      }
      if (entry.type === 'skipped') {
        skippedEvents++;
        continue;
      }

      const { seq, event } = entry;
      const kind = event.kind;
      const ts = typeof event.ts === 'string' ? event.ts : '';
      const body =
        event.body && typeof event.body === 'object' && !Array.isArray(event.body)
          ? (event.body as Record<string, unknown>)
          : undefined;

      if (kind === 'profile.created') {
        const candidateProfile = body?.profile ?? event.profile;
        if (!isProfileId(candidateProfile)) continue;
        const p = ensureMutableProfile(candidateProfile);
        p.createdAt ??= ts || undefined;
        p.updatedAt = ts || p.updatedAt;
        p.eventSeq = seq;
        if (typeof body?.display_name === 'string' && body.display_name.trim().length > 0) {
          try {
            p.displayName = assertDisplayName(body.display_name);
          } catch {
            // Ignore malformed non-Foundry display_name values safely.
          }
        }
        if (Array.isArray(body?.sensitivity_rules)) {
          // `profile.created` replaces this profile's SCOPED rules only. P-1 fix round 1 (C2): a rule without
          // `profile` in the body of profile P's event is scoped to P; it is never global. Only an
          // `annotation.added` rule without `profile`, held under `me`'s key, is global.
          p.rulesById.clear();
          for (const rawRule of body.sensitivity_rules) {
            try {
              const valid = assertUserSensitivityRule(rawRule);
              if (valid.profile === undefined) p.rulesById.set(valid.id, { ...valid, profile: candidateProfile });
              else if (valid.profile === candidateProfile) p.rulesById.set(valid.id, valid);
              // A rule scoped to another profile does not belong in this body: ignored.
            } catch {
              // Ignore malformed rules safely.
            }
          }
        }
      } else if (kind === 'consent.recorded') {
        const subject = body?.profile ?? body?.subject_profile;
        const basis = body?.basis;
        if (!isConsentSubjectProfile(subject) || !isConsentBasis(basis)) continue;
        let note: string | undefined;
        if (typeof body?.note === 'string' && body.note.trim().length > 0) {
          try {
            note = assertConsentNote(body.note);
          } catch {
            note = undefined;
          }
        }
        // P-1 fix round 1 (item 13): basis `other` without a valid note is not consent. The event is
        // skipped whole: it neither becomes active nor replaces an earlier active consent.
        if (basis === 'other' && note === undefined) continue;
        const previous = activeConsents.get(subject);
        if (previous) deactivateConsent(previous);
        const record: ConsentRecord = {
          profile: subject,
          basis,
          ...(note !== undefined ? { note } : {}),
          ts,
          eventSeq: seq,
          active: true,
        };
        activeConsents.set(subject, record);
        historyPositionBySeq.set(seq, consentHistory.length);
        consentHistory.push(record);
      } else if (kind === 'consent.withdrawn') {
        const isNarrow =
          body?.item_id !== undefined ||
          body?.collection !== undefined ||
          body?.target_ref !== undefined ||
          body?.event_seq !== undefined;
        const withdrawnProfile = body?.profile ?? event.profile;
        if (!isNarrow && isConsentSubjectProfile(withdrawnProfile)) {
          const prev = activeConsents.get(withdrawnProfile);
          if (prev) {
            activeConsents.delete(withdrawnProfile);
            deactivateConsent(prev);
          }
        }
      } else if (kind === 'key.destroyed') {
        const targetProfile = body?.profile;
        if (isProfileId(targetProfile)) {
          erasedProfiles.add(targetProfile);
          profilesMap.delete(targetProfile);
          // Global rules live under `me`'s key: erasing `me` erases them too.
          if (targetProfile === OWNER_PROFILE) globalRulesById.clear();
          if (isConsentSubjectProfile(targetProfile)) {
            const prev = activeConsents.get(targetProfile);
            if (prev) {
              activeConsents.delete(targetProfile);
              deactivateConsent(prev);
            }
          }
        }
      } else if (kind === 'collection.created') {
        const rawCollection = body?.collection ?? event.collection;
        if (
          typeof rawCollection !== 'string' ||
          rawCollection === SYSTEM_COLLECTION ||
          !validateCollectionName(rawCollection)
        ) {
          continue;
        }
        // P-1 fix round 1 (B1): a prefixed name belongs to its prefix; a body owner cannot override it.
        const owner =
          profileOfCollection(rawCollection) ??
          (isProfileId(body?.owner_profile)
            ? body.owner_profile
            : isProfileId(body?.profile)
              ? body.profile
              : inferProfileFromCollection(rawCollection));
        const col = ensureMutableCollection(rawCollection, owner);
        col.createdEventSeen = true;
        if (typeof body?.allow_child_model_prompts === 'boolean') {
          col.allowChildModelPrompts = body.allow_child_model_prompts;
          col.policyEventSeq = seq;
          col.policyUpdatedAt = ts || undefined;
        }
      } else if (kind === 'annotation.added') {
        const targetKind = body?.target_kind;
        if (targetKind === 'collection_policy') {
          const rawCollection = body?.collection;
          if (
            typeof rawCollection === 'string' &&
            rawCollection !== SYSTEM_COLLECTION &&
            validateCollectionName(rawCollection) &&
            typeof body?.allow_child_model_prompts === 'boolean'
          ) {
            const col = ensureMutableCollection(rawCollection);
            col.allowChildModelPrompts = body.allow_child_model_prompts;
            col.policyEventSeq = seq;
            col.policyUpdatedAt = ts || undefined;
          }
        } else if (targetKind === 'sensitivity_rule' && body?.rule !== undefined) {
          try {
            const rule = assertUserSensitivityRule(body.rule);
            const eventProfile = isProfileId(event.profile) ? event.profile : OWNER_PROFILE;
            if (rule.profile === undefined && eventProfile === OWNER_PROFILE) {
              // A global rule (written under `me`'s key by `addSensitivityRule`): it covers every profile.
              if (!erasedProfiles.has(OWNER_PROFILE)) globalRulesById.set(rule.id, rule);
            } else {
              const holderProfile = rule.profile ?? eventProfile;
              const scoped: UserSensitivityRule =
                rule.profile === undefined ? { ...rule, profile: holderProfile } : rule;
              if (!erasedProfiles.has(holderProfile)) {
                const p = ensureMutableProfile(holderProfile);
                p.rulesById.set(scoped.id, scoped);
              }
            }
          } catch {
            // Ignore invalid non-Foundry annotation rules safely.
          }
        }
      } else if (kind === 'item.imported') {
        const rawCollection = event.collection;
        const itemProfile = isProfileId(event.profile) ? event.profile : undefined;
        if (isPreProfileItem(event.profile, rawCollection)) preProfileItemEvents++;
        if (
          typeof rawCollection === 'string' &&
          rawCollection !== SYSTEM_COLLECTION &&
          validateCollectionName(rawCollection)
        ) {
          const col = ensureMutableCollection(rawCollection, itemProfile);
          col.itemCount++;
        }
        if (itemProfile && !erasedProfiles.has(itemProfile)) {
          ensureMutableProfile(itemProfile);
        }
      }
    }
  } finally {
    replaySource.close();
  }

  const orderedProfiles = new Map<ProfileId, ProfileRecord>();
  // Global rules first (no `profile`), then every profile's scoped rules, each with its true scope.
  const allSensitivityRules: UserSensitivityRule[] = [...globalRulesById.values()];

  for (const id of PROFILE_IDS) {
    const p = profilesMap.get(id);
    if (!p || erasedProfiles.has(id)) continue;
    const activeConsent = id === 'me' ? undefined : activeConsents.get(id);
    const rules = [...p.rulesById.values()];
    for (const r of rules) allSensitivityRules.push(r);
    orderedProfiles.set(id, {
      profile: id,
      ...(p.displayName !== undefined ? { displayName: p.displayName } : {}),
      hasKeyringEntry: p.hasKeyringEntry,
      consentRequired: id !== 'me',
      consentRecorded: id === 'me' ? true : activeConsent !== undefined,
      ...(activeConsent !== undefined ? { consentBasis: activeConsent.basis } : {}),
      ...(p.createdAt !== undefined ? { createdAt: p.createdAt } : {}),
      ...(p.updatedAt !== undefined ? { updatedAt: p.updatedAt } : {}),
      ...(p.eventSeq !== undefined ? { eventSeq: p.eventSeq } : {}),
      sensitivityRules: rules,
    });
  }

  const orderedConsents = new Map<ConsentSubjectProfileId, ConsentRecord>();
  for (const id of ['partner', 'child', 'other'] as const) {
    const c = activeConsents.get(id);
    if (c) orderedConsents.set(id, c);
  }

  const sortedCollectionNames = [...collectionsMap.keys()].sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  const orderedCollections = new Map<string, CollectionState>();
  for (const name of sortedCollectionNames) {
    const c = collectionsMap.get(name)!;
    orderedCollections.set(name, {
      collection: c.collection,
      ...(c.profile !== undefined ? { profile: c.profile } : {}),
      itemCount: c.itemCount,
      allowChildModelPrompts: c.allowChildModelPrompts,
      ...(c.policyEventSeq !== undefined ? { policyEventSeq: c.policyEventSeq } : {}),
      ...(c.policyUpdatedAt !== undefined ? { policyUpdatedAt: c.policyUpdatedAt } : {}),
    });
  }

  const state: VaultProfileState = {
    vaultId,
    profiles: orderedProfiles,
    consents: orderedConsents,
    consentHistory,
    collections: orderedCollections,
    sensitivityRules: allSensitivityRules,
    destroyedProfileCount,
    skippedEvents,
    lastEventSeq,
    preProfileItemEvents,
  };
  // P-1 fix round 1 (B2): the prompt gate reads only this private copy, taken now. Round 2 (G1): with the
  // vault ID read from `VAULT.json` above.
  recordReplayedPolicy(
    state,
    vaultId,
    [...collectionsMap.values()].map(c => [c.collection, c.allowChildModelPrompts] as const),
  );
  return state;
}

/**
 * P-1 fix round 1 (B5): `foundry import` refuses a vault that holds items from before profiles existed
 * (`item.imported` events whose collection does not start with `<their profile>/`). No migration in P-1:
 * such a vault can still be searched and verified, but takes no new imports.
 * Throws `ProfileError('PRE_PROFILE_VAULT')`.
 */
export function assertProfileVault(state: VaultProfileState): void {
  if (state.preProfileItemEvents > 0) {
    throw new ProfileError(
      'PRE_PROFILE_VAULT',
      'This vault holds items from before profiles existed. Create a new Foundry folder and import again.',
    );
  }
}

export interface AddProfileInput {
  readonly profile: ProfileId;
  readonly displayName?: string;
  readonly sensitivityRules?: readonly UserSensitivityRule[];
  readonly now?: () => Date;
}

export interface AddProfileResult {
  readonly profile: ProfileId;
  readonly displayName?: string;
  readonly sensitivityRules: readonly UserSensitivityRule[];
  readonly ts: string;
  readonly eventSeq: number;
  readonly createdKey: boolean;
}

/**
 * Records or updates a generic profile (`'me' | 'partner' | 'child' | 'other'`).
 * Encrypted under `<profile>`'s own `'system'` collection key so profile erasure destroys `display_name`.
 */
export function addProfile(
  vaultDir: string,
  credential: Unlock,
  input: AddProfileInput,
): AddProfileResult {
  const profile = assertProfileId(input.profile);
  const displayName =
    input.displayName === undefined ? undefined : assertDisplayName(input.displayName);
  const suppliedRules = input.sensitivityRules?.map(rule => {
    const valid = assertUserSensitivityRule(rule);
    if (valid.profile !== undefined && valid.profile !== profile) {
      throw new ProfileError(
        'INVALID_SENSITIVITY_RULE',
        'Profile-scoped sensitivity rule does not match target profile.',
      );
    }
    return valid.profile === undefined ? { ...valid, profile } : valid;
  });

  const current = loadVaultProfileState(vaultDir, credential);
  const existing = current.profiles.get(profile);
  const effectiveDisplayName = displayName ?? existing?.displayName;
  // P-1 fix round 1 (item 8): only rules scoped to THIS profile go into its `profile.created` body.
  // `ProfileRecord.sensitivityRules` holds scoped rules only; global rules stay in their own events.
  const effectiveRules =
    suppliedRules ?? (existing?.sensitivityRules ?? []).filter(rule => rule.profile === profile);
  const ts = formatUtcTimestamp(input.now?.() ?? new Date());

  const body: Record<string, unknown> = { profile };
  if (effectiveDisplayName !== undefined) body.display_name = effectiveDisplayName;
  // P-1 fix round 2 (S1): an explicitly supplied empty list is written (`sensitivity_rules: []`), so replay
  // clears this profile's earlier scoped rules. Omitting the field keeps them (they are carried over above).
  if (suppliedRules !== undefined || effectiveRules.length > 0) body.sensitivity_rules = effectiveRules;

  const appended = appendSystemEvent(vaultDir, credential, profile, {
    ts,
    kind: 'profile.created',
    profile,
    collection: SYSTEM_COLLECTION,
    sensitivity: profile === 'child' ? 'child' : 'personal',
    body,
  });

  return {
    profile,
    ...(effectiveDisplayName !== undefined ? { displayName: effectiveDisplayName } : {}),
    sensitivityRules: effectiveRules,
    ts,
    eventSeq: appended.sequence,
    createdKey: appended.createdKey,
  };
}

export function listProfiles(
  vaultDir: string,
  credential: Unlock,
): { profiles: ProfileRecord[]; destroyedProfileCount: number } {
  const state = loadVaultProfileState(vaultDir, credential);
  return {
    profiles: [...state.profiles.values()],
    destroyedProfileCount: state.destroyedProfileCount,
  };
}

export interface RecordConsentInput {
  readonly profile: ConsentSubjectProfileId;
  readonly basis: ConsentBasis;
  readonly note?: string;
  readonly now?: () => Date;
}

export interface RecordConsentResult {
  readonly profile: ConsentSubjectProfileId;
  readonly basis: ConsentBasis;
  readonly note?: string;
  readonly ts: string;
  readonly eventSeq: number;
}

/**
 * Appends a `consent.recorded` event under `'me'`'s `'system'` collection key.
 * Rejects `'me'` with `ProfileError('CONSENT_NOT_APPLICABLE')`.
 */
export function recordConsent(
  vaultDir: string,
  credential: Unlock,
  input: RecordConsentInput,
): RecordConsentResult {
  const profile = assertConsentSubjectProfile(input.profile);
  const basis = assertConsentBasis(input.basis);
  // Basis `other` requires a nonempty note (P-1 fix round 1, item 13).
  const note = assertConsentNoteForBasis(basis, input.note);
  const ts = formatUtcTimestamp(input.now?.() ?? new Date());

  const body: Record<string, unknown> = { profile, basis };
  if (note !== undefined) body.note = note;

  const appended = appendSystemEvent(vaultDir, credential, OWNER_PROFILE, {
    ts,
    kind: 'consent.recorded',
    profile: OWNER_PROFILE,
    collection: SYSTEM_COLLECTION,
    sensitivity: 'personal',
    body,
  });

  return {
    profile,
    basis,
    ...(note !== undefined ? { note } : {}),
    ts,
    eventSeq: appended.sequence,
  };
}

export function listConsents(
  vaultDir: string,
  credential: Unlock,
): { consents: ConsentRecord[]; history: readonly ConsentRecord[] } {
  const state = loadVaultProfileState(vaultDir, credential);
  return {
    consents: [...state.consents.values()],
    history: state.consentHistory,
  };
}

export function hasActiveConsent(state: VaultProfileState, profile: ProfileId): boolean {
  const valid = assertProfileId(profile);
  if (valid === 'me') return true;
  return state.consents.has(valid);
}

/**
 * Enforces the write-time import guard: non-`'me'` profiles must have an active `consent.recorded`
 * event in the vault before any archive item is imported. Fails closed with `CONSENT_REQUIRED`.
 */
export function assertImportConsent(state: VaultProfileState, profile: ProfileId): void {
  const valid = assertProfileId(profile);
  if (valid === 'me') return;
  if (!state.consents.has(valid)) {
    throw new ProfileError(
      'CONSENT_REQUIRED',
      'Active consent must be recorded in the vault before importing data for a non-owner profile.',
    );
  }
}

export interface SetCollectionPromptPolicyInput {
  readonly collection: string;
  readonly allowChildModelPrompts: boolean;
  readonly ownerProfile?: ProfileId;
  readonly now?: () => Date;
}

export interface SetCollectionPromptPolicyResult {
  readonly collection: string;
  readonly allowChildModelPrompts: boolean;
  readonly kind: 'collection.created' | 'annotation.added';
  readonly ts: string;
  readonly eventSeq: number;
}

/** Every collection name that has a readable `collection.created` event (one replay of the event streams). */
function collectionCreatedNames(vaultDir: string, credential: Unlock): Set<string> {
  const names = new Set<string>();
  const replaySource = openVaultReplay(vaultDir, credential);
  try {
    for (const entry of replaySource.replay()) {
      if (entry.type === 'blob' || (entry.type === 'skipped' && entry.recordType === 'blob')) {
        break;
      }
      if (entry.type !== 'event') continue;
      if (entry.event.kind !== 'collection.created') continue;
      const body =
        entry.event.body && typeof entry.event.body === 'object' && !Array.isArray(entry.event.body)
          ? (entry.event.body as Record<string, unknown>)
          : undefined;
      const candidate = body?.collection ?? entry.event.collection;
      if (typeof candidate === 'string') names.add(candidate);
    }
    return names;
  } finally {
    replaySource.close();
  }
}

function hasCollectionCreatedEvent(vaultDir: string, credential: Unlock, collection: string): boolean {
  return collectionCreatedNames(vaultDir, credential).has(collection);
}

export interface RecordCollectionBindingsResult {
  /** Names that got a new `collection.created` event, in the order given. */
  readonly appended: readonly string[];
  readonly eventSeqs: readonly number[];
  /** True when this call created `'me'`'s `'system'` collection key (the first structure event of the vault). */
  readonly createdSystemKey: boolean;
}

/**
 * P-1 fix round 1 (B3, A-41 limits 1 and 5): record the binding of each collection name to its owner
 * profile durably, BEFORE its key is created. For every name without a `collection.created` event yet
 * (one replay), appends `collection.created` with body `{ collection, owner_profile }` under `'me'`'s
 * `'system'` key, all in one writer session. No `allow_child_model_prompts` field: the policy stays at its
 * default (`false`). Every name must be `<profile>/...` (`INVALID_COLLECTION` otherwise, before any write).
 * Event first, key second: a crash between them leaves an event without a key, which is harmless.
 */
export function recordCollectionBindings(
  vaultDir: string,
  credential: Unlock,
  profile: ProfileId,
  collections: readonly string[],
  options: { now?: () => Date } = {},
): RecordCollectionBindingsResult {
  const owner = assertProfileId(profile);
  const wanted: string[] = [];
  const seen = new Set<string>();
  for (const name of collections) {
    const valid = assertCollectionForProfile(owner, name);
    if (!seen.has(valid)) {
      seen.add(valid);
      wanted.push(valid);
    }
  }
  if (wanted.length === 0) return { appended: [], eventSeqs: [], createdSystemKey: false };
  const existing = collectionCreatedNames(vaultDir, credential);
  const missing = wanted.filter(name => !existing.has(name));
  if (missing.length === 0) return { appended: [], eventSeqs: [], createdSystemKey: false };
  const ts = formatUtcTimestamp(options.now?.() ?? new Date());
  const { sequences, createdKey } = appendSystemEvents(
    vaultDir,
    credential,
    OWNER_PROFILE,
    missing.map(collection => ({
      ts,
      kind: 'collection.created',
      profile: OWNER_PROFILE,
      collection: SYSTEM_COLLECTION,
      sensitivity: 'personal',
      body: { collection, owner_profile: owner },
    })),
  );
  return { appended: missing, eventSeqs: sequences, createdSystemKey: createdKey };
}

/**
 * Sets or toggles `allowChildModelPrompts` on a collection as an append-only vault event
 * under `'me'`'s `'system'` collection key (`collection.created` on first creation, else
 * `annotation.added` with `target_kind: 'collection_policy'`; latest `seq` wins on replay).
 */
export function setCollectionPromptPolicy(
  vaultDir: string,
  credential: Unlock,
  input: SetCollectionPromptPolicyInput,
): SetCollectionPromptPolicyResult {
  // P-1 fix round 1 (B1): only a name with a valid profile prefix; that prefix is the owner profile.
  const { collection, profile: ownerProfile } = assertProfileCollectionName(input.collection);
  if (input.ownerProfile !== undefined && assertProfileId(input.ownerProfile) !== ownerProfile) {
    throw new ProfileError('INVALID_COLLECTION', 'Collection owner profile must equal the collection name prefix.');
  }
  if (typeof input.allowChildModelPrompts !== 'boolean') {
    throw new TypeError('allowChildModelPrompts must be a boolean.');
  }
  const ts = formatUtcTimestamp(input.now?.() ?? new Date());
  const alreadyCreated = hasCollectionCreatedEvent(vaultDir, credential, collection);
  const kind: 'collection.created' | 'annotation.added' = alreadyCreated
    ? 'annotation.added'
    : 'collection.created';

  const body: Record<string, unknown> =
    kind === 'collection.created'
      ? {
          collection,
          owner_profile: ownerProfile,
          allow_child_model_prompts: input.allowChildModelPrompts,
        }
      : {
          target_kind: 'collection_policy',
          collection,
          allow_child_model_prompts: input.allowChildModelPrompts,
        };

  const appended = appendSystemEvent(vaultDir, credential, OWNER_PROFILE, {
    ts,
    kind,
    profile: OWNER_PROFILE,
    collection: SYSTEM_COLLECTION,
    sensitivity: 'personal',
    body,
  });

  return {
    collection,
    allowChildModelPrompts: input.allowChildModelPrompts,
    kind,
    ts,
    eventSeq: appended.sequence,
  };
}

export function listCollections(
  vaultDir: string,
  credential: Unlock,
): { collections: CollectionState[] } {
  const state = loadVaultProfileState(vaultDir, credential);
  return { collections: [...state.collections.values()] };
}

export interface AddSensitivityRuleResult {
  readonly rule: UserSensitivityRule;
  readonly ts: string;
  readonly eventSeq: number;
}

/**
 * Appends a user-configured generic sensitivity rule as an `annotation.added` event in the vault
 * (encrypted under `rule.profile ?? 'me'`'s `'system'` collection key).
 */
export function addSensitivityRule(
  vaultDir: string,
  credential: Unlock,
  ruleInput: UserSensitivityRule,
  options: { now?: () => Date } = {},
): AddSensitivityRuleResult {
  const rule = assertUserSensitivityRule(ruleInput);
  const targetProfile: ProfileId = rule.profile ?? OWNER_PROFILE;
  const ts = formatUtcTimestamp(options.now?.() ?? new Date());

  const appended = appendSystemEvent(vaultDir, credential, targetProfile, {
    ts,
    kind: 'annotation.added',
    profile: targetProfile,
    collection: SYSTEM_COLLECTION,
    sensitivity: targetProfile === 'child' ? 'child' : 'personal',
    body: {
      target_kind: 'sensitivity_rule',
      rule,
    },
  });

  return { rule, ts, eventSeq: appended.sequence };
}

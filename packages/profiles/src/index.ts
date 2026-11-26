export { ProfileError } from './errors.ts';
export type { ProfileErrorCode } from './errors.ts';

export {
  CONSENT_BASES,
  CONSENT_SUBJECT_PROFILES,
  PROFILE_IDS,
  SENSITIVITY_TIERS,
} from './types.ts';
export type {
  ClassificationInput,
  ClassificationResult,
  CollectionState,
  ConsentBasis,
  ConsentRecord,
  ConsentSubjectProfileId,
  ProfileId,
  ProfileRecord,
  PromptCandidateItem,
  PromptEligibility,
  PromptExclusionReason,
  SensitivityTier,
  UserSensitivityRule,
  VaultProfileState,
} from './types.ts';

export {
  assertCollectionForProfile,
  assertCollectionName,
  assertConsentBasis,
  assertConsentNote,
  assertConsentNoteForBasis,
  assertConsentSubjectProfile,
  assertDisplayName,
  assertProfileCollectionName,
  assertProfileId,
  assertSensitivityTier,
  assertSourceId,
  assertUserCollectionName,
  assertUserSensitivityRule,
  defaultCollectionForItem,
  formatUtcTimestamp,
  isConsentBasis,
  isConsentSubjectProfile,
  isProfileId,
  isSensitivityTier,
  MAX_COLLECTION_BYTES,
  MAX_CONSENT_NOTE_BYTES,
  MAX_DISPLAY_NAME_BYTES,
  MAX_RULE_ID_BYTES,
  MAX_RULE_PATTERN_BYTES,
  profileOfCollection,
  RESERVED_COLLECTION_PREFIX,
  SYSTEM_COLLECTION,
  validateCollectionName,
} from './validation.ts';

export {
  byteScanWindows,
  classifySensitivity,
  compareSensitivity,
  DEFAULT_SENSITIVITY_BY_SOURCE,
  defaultSensitivityForSource,
  maxSensitivity,
  SCAN_OVERLAP_BYTES,
  SCAN_WINDOW_BYTES,
  SENSITIVITY_PRECEDENCE,
  SHIPPED_SCAN_PATTERNS,
  stringScanWindows,
} from './sensitivity.ts';
export type { ShippedScanPattern } from './sensitivity.ts';

export { filterItemsForModelPrompt, isPromptEligible } from './prompt-policy.ts';

export {
  addProfile,
  addSensitivityRule,
  assertImportConsent,
  assertProfileVault,
  hasActiveConsent,
  listCollections,
  listConsents,
  listProfiles,
  loadVaultProfileState,
  recordCollectionBindings,
  recordConsent,
  setCollectionPromptPolicy,
} from './store.ts';
export type {
  AddProfileInput,
  AddProfileResult,
  AddSensitivityRuleResult,
  RecordCollectionBindingsResult,
  RecordConsentInput,
  RecordConsentResult,
  SetCollectionPromptPolicyInput,
  SetCollectionPromptPolicyResult,
} from './store.ts';

export const PROFILE_IDS = ['me', 'partner', 'child', 'other'] as const;
export type ProfileId = (typeof PROFILE_IDS)[number];

export const CONSENT_SUBJECT_PROFILES = ['partner', 'child', 'other'] as const;
export type ConsentSubjectProfileId = (typeof CONSENT_SUBJECT_PROFILES)[number];

export const SENSITIVITY_TIERS = [
  'public',
  'personal',
  'private',
  'secret',
  'clinical',
  'child',
] as const;
export type SensitivityTier = (typeof SENSITIVITY_TIERS)[number];

export const CONSENT_BASES = [
  'exported-by-them',
  'parent-or-guardian',
  'shared-conversation',
  'other',
] as const;
export type ConsentBasis = (typeof CONSENT_BASES)[number];

/**
 * User-configured generic sensitivity rule stored inside vault events.
 * At least one matcher (`sourcePrefix`, `pathContains`, `tag`, `keyword`) must be defined.
 */
export interface UserSensitivityRule {
  readonly id: string;
  readonly tier: SensitivityTier;
  readonly profile?: ProfileId;
  readonly sourcePrefix?: string;
  readonly pathContains?: string;
  readonly tag?: string;
  readonly keyword?: string;
}

export interface ClassificationInput {
  readonly source: string;
  readonly profile?: string;
  readonly collection?: string;
  readonly title?: string;
  readonly path?: string;
  readonly text?: string;
  readonly plaintext?: Uint8Array;
  /**
   * Text derived from the item by its source's deriver (for example a decoded base64 or
   * quoted-printable mail body). Scanned in addition to `plaintext`, through the same windows.
   */
  readonly derivedTexts?: readonly string[];
  readonly mime?: string;
  readonly tags?: readonly string[];
  readonly explicitTier?: SensitivityTier;
  readonly userRules?: readonly UserSensitivityRule[];
}

export interface ClassificationResult {
  readonly sensitivity: SensitivityTier;
  readonly rule: string;
}

export interface ProfileRecord {
  readonly profile: ProfileId;
  readonly displayName?: string;
  readonly hasKeyringEntry: boolean;
  readonly consentRequired: boolean;
  readonly consentRecorded: boolean;
  readonly consentBasis?: ConsentBasis;
  readonly createdAt?: string;
  readonly updatedAt?: string;
  readonly eventSeq?: number;
  readonly sensitivityRules: readonly UserSensitivityRule[];
}

export interface ConsentRecord {
  readonly profile: ConsentSubjectProfileId;
  readonly basis: ConsentBasis;
  readonly note?: string;
  readonly ts: string;
  readonly eventSeq: number;
  readonly active: boolean;
}

export interface CollectionState {
  readonly collection: string;
  readonly profile?: ProfileId;
  readonly itemCount: number;
  readonly allowChildModelPrompts: boolean;
  readonly policyEventSeq?: number;
  readonly policyUpdatedAt?: string;
}

export interface VaultProfileState {
  readonly profiles: ReadonlyMap<ProfileId, ProfileRecord>;
  readonly consents: ReadonlyMap<ConsentSubjectProfileId, ConsentRecord>;
  readonly consentHistory: readonly ConsentRecord[];
  readonly collections: ReadonlyMap<string, CollectionState>;
  readonly sensitivityRules: readonly UserSensitivityRule[];
  readonly destroyedProfileCount: number;
  readonly skippedEvents: number;
  readonly lastEventSeq: number;
}

export interface PromptCandidateItem {
  readonly profile: string;
  readonly collection: string;
  readonly sensitivity: SensitivityTier;
}

export type PromptExclusionReason = 'SECRET_TIER_EXCLUDED' | 'CHILD_TIER_EXCLUDED';

export type PromptEligibility =
  | { readonly eligible: true }
  | { readonly eligible: false; readonly reason: PromptExclusionReason };

export type CollectionPolicyEntry =
  | boolean
  | { readonly allowChildModelPrompts: boolean };

export type CollectionPolicyLookup =
  | Pick<VaultProfileState, 'collections'>
  | ReadonlyMap<string, CollectionPolicyEntry>
  | Readonly<Record<string, CollectionPolicyEntry>>;

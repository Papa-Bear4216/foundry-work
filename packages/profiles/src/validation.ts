import { Buffer } from 'node:buffer';
import { ProfileError } from './errors.ts';
import {
  CONSENT_BASES,
  CONSENT_SUBJECT_PROFILES,
  PROFILE_IDS,
  SENSITIVITY_TIERS,
} from './types.ts';
import type {
  ConsentBasis,
  ConsentSubjectProfileId,
  ProfileId,
  SensitivityTier,
  UserSensitivityRule,
} from './types.ts';

export const SYSTEM_COLLECTION = 'system';
export const RESERVED_COLLECTION_PREFIX = 'foundry:';
export const MAX_COLLECTION_BYTES = 512;
export const MAX_DISPLAY_NAME_BYTES = 128;
export const MAX_CONSENT_NOTE_BYTES = 2048;
export const MAX_RULE_ID_BYTES = 128;
export const MAX_RULE_PATTERN_BYTES = 256;

const PROFILE_SET: ReadonlySet<string> = new Set(PROFILE_IDS);
const CONSENT_SUBJECT_SET: ReadonlySet<string> = new Set(CONSENT_SUBJECT_PROFILES);
const CONSENT_BASIS_SET: ReadonlySet<string> = new Set(CONSENT_BASES);
const SENSITIVITY_SET: ReadonlySet<string> = new Set(SENSITIVITY_TIERS);

function hasControlChars(value: string, allowLineBreaks = false): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (allowLineBreaks && (code === 0x09 || code === 0x0a || code === 0x0d)) continue;
    if (code <= 0x1f || code === 0x7f || (code >= 0x80 && code <= 0x9f)) return true;
  }
  return false;
}

export function isProfileId(value: unknown): value is ProfileId {
  return typeof value === 'string' && PROFILE_SET.has(value);
}

export function assertProfileId(value: unknown): ProfileId {
  if (!isProfileId(value)) {
    throw new ProfileError(
      'INVALID_PROFILE',
      'Profile must be one of the generic identifiers: me, partner, child, other.',
    );
  }
  return value;
}

export function isConsentSubjectProfile(value: unknown): value is ConsentSubjectProfileId {
  return typeof value === 'string' && CONSENT_SUBJECT_SET.has(value);
}

export function assertConsentSubjectProfile(value: unknown): ConsentSubjectProfileId {
  const profile = assertProfileId(value);
  if (profile === 'me') {
    throw new ProfileError(
      'CONSENT_NOT_APPLICABLE',
      'Profile "me" is the vault owner and does not use a third-party consent note.',
    );
  }
  return profile;
}

export function assertDisplayName(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.isWellFormed() ||
    value.trim().length === 0 ||
    hasControlChars(value, false) ||
    Buffer.byteLength(value, 'utf8') > MAX_DISPLAY_NAME_BYTES
  ) {
    throw new ProfileError(
      'INVALID_DISPLAY_NAME',
      `Display name must be nonempty well-formed UTF-8 of at most ${MAX_DISPLAY_NAME_BYTES} bytes without control characters.`,
    );
  }
  return value;
}

export function isConsentBasis(value: unknown): value is ConsentBasis {
  return typeof value === 'string' && CONSENT_BASIS_SET.has(value);
}

export function assertConsentBasis(value: unknown): ConsentBasis {
  if (!isConsentBasis(value)) {
    throw new ProfileError(
      'INVALID_CONSENT_BASIS',
      'Consent basis must be one of: exported-by-them, parent-or-guardian, shared-conversation, other.',
    );
  }
  return value;
}

export function assertConsentNote(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.isWellFormed() ||
    value.trim().length === 0 ||
    hasControlChars(value, true) ||
    Buffer.byteLength(value, 'utf8') > MAX_CONSENT_NOTE_BYTES
  ) {
    throw new ProfileError(
      'INVALID_CONSENT_NOTE',
      `Consent note must be nonempty well-formed UTF-8 of at most ${MAX_CONSENT_NOTE_BYTES} bytes without control characters.`,
    );
  }
  return value;
}

export function isSensitivityTier(value: unknown): value is SensitivityTier {
  return typeof value === 'string' && SENSITIVITY_SET.has(value);
}

export function assertSensitivityTier(value: unknown): SensitivityTier {
  if (!isSensitivityTier(value)) {
    throw new ProfileError(
      'INVALID_SENSITIVITY',
      'Sensitivity tier must be one of: public, personal, private, secret, clinical, child.',
    );
  }
  return value;
}

function validSlashSegments(value: string): boolean {
  if (value.startsWith('/') || value.endsWith('/') || value.includes('\\')) return false;
  const parts = value.split('/');
  for (const part of parts) {
    if (part.length === 0 || part === '.' || part === '..') return false;
  }
  return true;
}

/**
 * Validates any logical collection name stored in the vault keyring (`<= 512` UTF-8 bytes,
 * well-formed Unicode, never starting with `foundry:`, no NUL/control bytes or path traversal).
 */
export function validateCollectionName(value: unknown): value is string {
  if (typeof value !== 'string' || !value.isWellFormed()) return false;
  if (value.length === 0 || value.trim() !== value) return false;
  if (value.startsWith(RESERVED_COLLECTION_PREFIX)) return false;
  if (hasControlChars(value, false)) return false;
  if (!validSlashSegments(value)) return false;
  const bytes = Buffer.byteLength(value, 'utf8');
  return bytes >= 1 && bytes <= MAX_COLLECTION_BYTES;
}

export function assertCollectionName(value: unknown): string {
  if (!validateCollectionName(value)) {
    throw new ProfileError(
      'INVALID_COLLECTION',
      `Collection name must be nonempty well-formed UTF-8 of at most ${MAX_COLLECTION_BYTES} bytes without reserved prefixes, control characters, or path-traversal segments.`,
    );
  }
  return value;
}

/**
 * Validates a user-facing data collection name. Rejects the reserved structural stream `'system'`
 * in addition to all `assertCollectionName` checks.
 */
export function assertUserCollectionName(value: unknown): string {
  const name = assertCollectionName(value);
  if (name === SYSTEM_COLLECTION) {
    throw new ProfileError(
      'INVALID_COLLECTION',
      'Collection name "system" is reserved for structural vault events.',
    );
  }
  return name;
}

export function assertSourceId(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.isWellFormed() ||
    value.length === 0 ||
    value.trim() !== value ||
    value.startsWith(RESERVED_COLLECTION_PREFIX) ||
    hasControlChars(value, false) ||
    !validSlashSegments(value)
  ) {
    throw new ProfileError(
      'INVALID_SOURCE',
      'Source identifier must be nonempty well-formed UTF-8 slash-delimited segments without reserved prefixes or traversal.',
    );
  }
  return value;
}

/**
 * Default collection grain (Product 9, Architecture 5.4, Decisions A-5):
 * `${profile}/${source}/${year}` for 4-digit UTC years `0001`–`9999` when `sourceTs`
 * starts with `YYYY-`, else `${profile}/${source}/undated`.
 */
export function defaultCollectionForItem(
  profile: ProfileId,
  source: string,
  sourceTs?: string,
): string {
  const validProfile = assertProfileId(profile);
  const validSource = assertSourceId(source);
  let year = 'undated';
  if (typeof sourceTs === 'string') {
    const match = /^(\d{4})-/u.exec(sourceTs);
    if (match) {
      const numericYear = Number.parseInt(match[1]!, 10);
      if (numericYear >= 1 && numericYear <= 9999) {
        year = match[1]!;
      }
    }
  }
  const collection = `${validProfile}/${validSource}/${year}`;
  if (Buffer.byteLength(collection, 'utf8') > MAX_COLLECTION_BYTES) {
    throw new ProfileError(
      'INVALID_SOURCE',
      `Derived collection name exceeds the ${MAX_COLLECTION_BYTES}-byte limit.`,
    );
  }
  return assertUserCollectionName(collection);
}

function validRuleField(value: unknown, maxBytes: number): value is string {
  if (typeof value !== 'string' || !value.isWellFormed()) return false;
  if (value.trim().length === 0 || hasControlChars(value, false)) return false;
  return Buffer.byteLength(value, 'utf8') <= maxBytes;
}

export function assertUserSensitivityRule(value: unknown): UserSensitivityRule {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProfileError('INVALID_SENSITIVITY_RULE', 'Sensitivity rule must be an object.');
  }
  const raw = value as Record<string, unknown>;
  if (!validRuleField(raw.id, MAX_RULE_ID_BYTES)) {
    throw new ProfileError(
      'INVALID_SENSITIVITY_RULE',
      `Sensitivity rule id must be nonempty UTF-8 of at most ${MAX_RULE_ID_BYTES} bytes.`,
    );
  }
  const tier = assertSensitivityTier(raw.tier);
  const profile = raw.profile === undefined ? undefined : assertProfileId(raw.profile);

  let sourcePrefix: string | undefined;
  if (raw.sourcePrefix !== undefined) {
    sourcePrefix = assertSourceId(raw.sourcePrefix);
    if (Buffer.byteLength(sourcePrefix, 'utf8') > MAX_RULE_PATTERN_BYTES) {
      throw new ProfileError('INVALID_SENSITIVITY_RULE', 'Sensitivity rule sourcePrefix exceeds maximum length.');
    }
  }

  let pathContains: string | undefined;
  if (raw.pathContains !== undefined) {
    if (!validRuleField(raw.pathContains, MAX_RULE_PATTERN_BYTES)) {
      throw new ProfileError('INVALID_SENSITIVITY_RULE', 'Sensitivity rule pathContains is invalid.');
    }
    pathContains = raw.pathContains;
  }

  let tag: string | undefined;
  if (raw.tag !== undefined) {
    if (!validRuleField(raw.tag, MAX_RULE_PATTERN_BYTES)) {
      throw new ProfileError('INVALID_SENSITIVITY_RULE', 'Sensitivity rule tag is invalid.');
    }
    tag = raw.tag;
  }

  let keyword: string | undefined;
  if (raw.keyword !== undefined) {
    if (!validRuleField(raw.keyword, MAX_RULE_PATTERN_BYTES)) {
      throw new ProfileError('INVALID_SENSITIVITY_RULE', 'Sensitivity rule keyword is invalid.');
    }
    keyword = raw.keyword;
  }

  if (
    sourcePrefix === undefined &&
    pathContains === undefined &&
    tag === undefined &&
    keyword === undefined
  ) {
    throw new ProfileError(
      'INVALID_SENSITIVITY_RULE',
      'Sensitivity rule must define at least one matcher (sourcePrefix, pathContains, tag, or keyword).',
    );
  }

  return {
    id: raw.id,
    tier,
    ...(profile !== undefined ? { profile } : {}),
    ...(sourcePrefix !== undefined ? { sourcePrefix } : {}),
    ...(pathContains !== undefined ? { pathContains } : {}),
    ...(tag !== undefined ? { tag } : {}),
    ...(keyword !== undefined ? { keyword } : {}),
  };
}

/** Returns canonical Architecture 4.5 UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`. */
export function formatUtcTimestamp(date: Date = new Date()): string {
  return date.toISOString().replace(/\.\d{3}Z$/u, 'Z');
}

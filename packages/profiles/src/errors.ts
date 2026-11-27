export type ProfileErrorCode =
  | 'INVALID_PROFILE'
  | 'INVALID_DISPLAY_NAME'
  | 'INVALID_COLLECTION'
  | 'INVALID_SOURCE'
  | 'INVALID_CONSENT_BASIS'
  | 'CONSENT_NOT_APPLICABLE'
  | 'CONSENT_REQUIRED'
  | 'INVALID_CONSENT_NOTE'
  | 'INVALID_SENSITIVITY'
  | 'INVALID_SENSITIVITY_RULE'
  | 'PRE_PROFILE_VAULT';

/**
 * Typed domain error for profile, collection, sensitivity, and consent invariants.
 * Messages are fixed generic strings and never echo caller-supplied names, notes, or paths.
 */
export class ProfileError extends Error {
  readonly code: ProfileErrorCode;

  constructor(code: ProfileErrorCode, message: string) {
    super(message);
    this.name = 'ProfileError';
    this.code = code;
  }
}

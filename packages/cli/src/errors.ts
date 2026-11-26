/**
 * Error mapping for the `foundry` command line (design 4.6).
 *
 * Every failure becomes ONE stderr line `foundry: <short message> [<CODE>]`. The message comes from the tables below,
 * never from `error.message`: a library message could quote input, and a secret must never reach any output.
 */

/** A failure raised by the command line itself. `exit` 1 means usage error, 2 means typed failure. */
export class CliError extends Error {
  readonly code: string;
  readonly exit: 1 | 2;

  constructor(code: string, message: string, exit: 1 | 2 = 2) {
    super(message);
    this.name = 'CliError';
    this.code = code;
    this.exit = exit;
  }
}

export const usage = (message: string): CliError => new CliError('USAGE', message, 1);

const VAULT_MESSAGES: Readonly<Record<string, string>> = {
  AUTH: 'the passphrase or recovery key is wrong, or the keyring is damaged',
  MAC: 'the keyring failed its integrity check, or the credential is wrong',
  KEY: 'a key is missing or does not belong to this vault',
  KDF: 'the keyring uses key-derivation settings this version does not accept',
  ERASED: 'the vault holds records whose keys were erased',
  VERSION: 'the vault uses a format version this program does not know',
  INVENTORY: 'the vault folder holds unexpected or missing files',
  CHAIN: 'the vault segment chain is broken',
  SIGNATURE: 'a vault manifest signature is invalid',
  HEAD: 'the vault head file does not match the segments',
  ANCHOR: 'the vault does not match the expected anchor',
  FILE: 'a vault file is damaged',
  FILE_SIZE: 'a vault file has the wrong size',
  FILE_HASH: 'a vault file has the wrong checksum',
  SEQUENCE: 'the vault event sequence is broken',
  LENGTH: 'a vault record is truncated or too long',
  SCHEMA: 'a vault file does not have the expected structure',
  CANONICAL: 'a vault file is not in canonical form',
};

const INDEX_MESSAGES: Readonly<Record<string, string>> = {
  ADDON: 'the encrypted index engine could not be loaded',
  KEY: 'the index key does not match the vault keyring; run `foundry index rebuild`',
  FORMAT: 'the index files are damaged; run `foundry index rebuild`',
  CONFIG: 'the index folder belongs to another vault or uses another setting',
  EXTENSION: 'the index engine lacks a required extension',
  PLAIN_POLICY: 'an unencrypted index is not allowed here',
  PROJECTION: 'the index cannot be brought up to date; run `foundry index rebuild`',
};

const ARCHIVE_MESSAGES: Readonly<Record<string, string>> = {
  EMPTY_ARCHIVE_DIR: 'the folder holds no .zip archive',
  INVALID_MULTIPART: 'the archive parts do not form one complete export set',
  PATH_TRAVERSAL: 'the archive holds an unsafe entry path',
  ENCRYPTED_ENTRY: 'the archive holds an encrypted entry, which is not supported',
  UNSUPPORTED_COMPRESSION: 'the archive uses a compression method that is not supported',
  ENTRY_BOMB: 'an archive entry expands beyond the safety limit',
  DUPLICATE_ENTRY: 'the archive holds the same entry twice',
};

const PROFILE_MESSAGES: Readonly<Record<string, string>> = {
  INVALID_PROFILE: 'profile must be one of the generic identifiers: me, partner, child or other',
  INVALID_DISPLAY_NAME: 'display name must be nonempty well-formed UTF-8 (at most 128 bytes, no control characters)',
  INVALID_COLLECTION: 'collection name must start with its profile and a slash (for example me/holidays), and must not be reserved or use unsafe path segments',
  INVALID_SOURCE: 'source identifier is invalid or produces an oversized collection name',
  INVALID_CONSENT_BASIS: 'consent basis must be one of: exported-by-them, parent-or-guardian, shared-conversation or other',
  CONSENT_NOT_APPLICABLE: 'profile "me" is the vault owner and does not need a consent note',
  CONSENT_REQUIRED: 'consent must be recorded for this profile before importing; run `foundry consent record`',
  INVALID_CONSENT_NOTE: 'consent note must be nonempty well-formed UTF-8 (at most 2048 bytes, no control characters); basis "other" needs a --note',
  INVALID_SENSITIVITY: 'sensitivity tier must be one of: public, personal, private, secret, clinical or child',
  INVALID_SENSITIVITY_RULE: 'user sensitivity rule is invalid',
  PRE_PROFILE_VAULT: 'this vault holds items from before profiles existed; create a new Foundry folder and import again',
};

const IMPORT_MESSAGES: Readonly<Record<string, string>> = {
  BUSY: 'another import is already running on this vault writer',
  INVALID_PROFILE: 'profile must be one of the generic identifiers: me, partner, child or other',
};

const RECOVERY_FORMAT = new Set([
  'Invalid recovery key format.', 'Recovery key checksum mismatch.', 'Invalid recovery key padding.',
]);

export interface MappedError {
  code: string;
  message: string;
  exit: 1 | 2;
}

function named(error: unknown, name: string): error is { code: string; name: string } {
  return error instanceof Error && error.name === name && typeof (error as { code?: unknown }).code === 'string';
}

/** True for the plain errors `decodeRecoveryKey` throws for a badly formatted recovery key. */
export function isRecoveryFormatError(error: unknown): boolean {
  return error instanceof Error && error.name === 'Error' && RECOVERY_FORMAT.has(error.message);
}

/** Map any thrown value to one short line. Never reads `error.message` into the output. */
export function mapError(error: unknown, context: { erasedInImport?: boolean } = {}): MappedError {
  if (error instanceof CliError) return { code: error.code, message: error.message, exit: error.exit };
  if (named(error, 'VaultFormatError')) {
    if (error.code === 'ERASED' && context.erasedInImport) {
      return { code: 'ERASED', message: 'a collection in this archive was erased; it is not imported again', exit: 2 };
    }
    return { code: error.code, message: VAULT_MESSAGES[error.code] ?? 'the vault reported an error', exit: 2 };
  }
  if (named(error, 'IndexError') || named(error, 'OutdatedSchemaError')) {
    return { code: error.code, message: INDEX_MESSAGES[error.code] ?? 'the index reported an error', exit: 2 };
  }
  if (named(error, 'ArchiveError')) {
    return { code: error.code, message: ARCHIVE_MESSAGES[error.code] ?? 'the archive is damaged or not supported', exit: 2 };
  }
  if (named(error, 'ProfileError')) {
    return { code: error.code, message: PROFILE_MESSAGES[error.code] ?? 'profile or consent validation failed', exit: 2 };
  }
  if (named(error, 'ImportError')) {
    return { code: error.code, message: IMPORT_MESSAGES[error.code] ?? 'the import reported an error', exit: 2 };
  }
  if (isRecoveryFormatError(error)) {
    return { code: 'RECOVERY_KEY_FORMAT', message: 'the recovery key is not in the expected format', exit: 2 };
  }
  const errno = (error as { code?: unknown } | null)?.code;
  if (typeof errno === 'string' && /^E[A-Z0-9]+$/u.test(errno)) {
    return { code: 'IO', message: `a file operation failed (${errno})`, exit: 2 };
  }
  return { code: 'INTERNAL', message: 'an unexpected internal error occurred; run again with --debug for details', exit: 2 };
}

/** The one stderr line for a mapped error. Fixed guidance texts go into the same line, before the code. */
export function errorLine(mapped: MappedError, guidance: readonly string[] = []): string {
  return `foundry: ${[mapped.message, ...guidance].join('; ')} [${mapped.code}]\n`;
}

/**
 * `--debug` text: the error's name, code and stack, with every given secret removed. A redaction pass runs even
 * though library messages carry codes only, so a future message that quotes input still cannot leak a secret.
 */
export function debugText(error: unknown, secrets: readonly string[]): string {
  let text = error instanceof Error ? (error.stack ?? `${error.name}: ${error.message}`) : `non-error value of type ${typeof error}`;
  for (const secret of secrets) {
    if (!secret) continue;
    text = text.split(secret).join('[REDACTED]');
    for (const line of secret.split(/\r?\n/u)) if (line.length >= 4) text = text.split(line).join('[REDACTED]');
  }
  return `foundry: debug: ${text}\n`;
}

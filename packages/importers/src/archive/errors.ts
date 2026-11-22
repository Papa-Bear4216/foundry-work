export type ArchiveErrorCode =
  | 'INVALID_FORMAT'
  | 'TRUNCATED_CENTRAL_DIRECTORY'
  | 'BAD_OFFSET'
  | 'OVERLAPPING_ENTRIES'
  | 'PATH_TRAVERSAL'
  | 'DUPLICATE_ENTRY'
  | 'UNSUPPORTED_COMPRESSION'
  | 'ENCRYPTED_ENTRY'
  | 'ENTRY_BOMB'
  | 'SIZE_MISMATCH'
  | 'CRC_MISMATCH'
  | 'EMPTY_ARCHIVE_DIR';

export class ArchiveError extends Error {
  readonly code: ArchiveErrorCode;

  constructor(code: ArchiveErrorCode, message: string) {
    super(`${code}: ${message}`);
    this.name = 'ArchiveError';
    this.code = code;
  }
}

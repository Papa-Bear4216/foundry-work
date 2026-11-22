export type {
  Archive,
  ArchiveEntry,
  Derived,
  Deriver,
  ImportCheckpointInfo,
  ImportCrashPoint,
  Importer,
  ImportResult,
  ItemErrorCode,
  ItemErrorInfo,
  RawItem,
  SensitivityTier,
  SourceImportCounts,
  SplitOptions,
  StoredItem,
  UnlockedKeyringLike,
  VaultAppend,
  VaultAppendResult,
  VaultRecordLocation,
  VaultWriterLike,
} from './types.js';

export {
  computeItemKey,
  DEFAULT_MAX_ITEM_BYTES,
  DEFAULT_PROFILE,
  DEFAULT_SENSITIVITY_BY_SOURCE,
  defaultCollectionName,
  defaultSensitivityForSource,
  formatUtcTimestamp,
  normalizeTimestamp,
  uniqueSorted,
} from './defaults.js';

export { ArchiveError } from './archive/errors.js';
export type { ArchiveErrorCode } from './archive/errors.js';
export { openZipFile, openZipReader, validateArchivePath } from './archive/zip-reader.js';
export type { RandomAccessReader, ZipOpenOptions } from './archive/zip-reader.js';
export { comparePartNames, openArchive, parsePartName } from './archive/multipart.js';
export type { ParsedPartName } from './archive/multipart.js';

export { ItemSkipError } from './importers/errors.js';
export { getParamValue, parseContentLine } from './importers/content-line.js';
export type { ContentLineParam, ParsedContentLine } from './importers/content-line.js';

export {
  CONTACTS_SOURCE_ID,
  contactsDeriver,
  contactsImporter,
  formatContactText,
  parseVcard,
} from './importers/contacts.js';
export type { ParsedContact } from './importers/contacts.js';

export {
  CALENDAR_SOURCE_ID,
  calendarDeriver,
  calendarImporter,
  parseIcalendar,
} from './importers/calendar.js';
export type { ParsedCalendar, ParsedCalendarEvent } from './importers/calendar.js';

export {
  decodeRfc2047,
  isMboxSeparatorLine,
  MAIL_SOURCE_ID,
  mailDeriver,
  mailImporter,
  parseAddressList,
  parseEmailMessage,
} from './importers/mail.js';
export type { ParsedEmail, ParsedEmailAddress } from './importers/mail.js';

export { computeBlobId, deriveCollectionIdKey, loadExistingItemKeys } from './vault-state.js';
export type { ReadVaultRecordFn } from './vault-state.js';

export { importArchive, ImportError } from './pipeline.js';
export type { ImportArchiveOptions, ImportErrorCode } from './pipeline.js';

export {
  createSeededRng,
  generateSyntheticIcalendar,
  generateSyntheticMbox,
  generateSyntheticVcards,
  syntheticEmail,
  writeMultiPartTakeoutFolder,
  writeStreamedZip64Archive,
  writeSyntheticLargeMboxZip,
  writeZipArchive,
} from './fixtures/generators.js';
export type {
  SeededRng,
  StreamedZip64Entry,
  SyntheticMboxOptions,
  ZipBuildEntry,
} from './fixtures/generators.js';

import { calendarDeriver, calendarImporter } from './importers/calendar.js';
import { contactsDeriver, contactsImporter } from './importers/contacts.js';
import { mailDeriver, mailImporter } from './importers/mail.js';
import type { Deriver, Importer } from './types.js';

export const DEFAULT_IMPORTERS: readonly Importer[] = Object.freeze([
  contactsImporter,
  calendarImporter,
  mailImporter,
]);

export const DEFAULT_DERIVERS: readonly Deriver[] = Object.freeze([
  contactsDeriver,
  calendarDeriver,
  mailDeriver,
]);

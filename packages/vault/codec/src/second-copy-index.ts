/**
 * The `vault/second-copy` package entry (P-3, ruling R18-8 D2): Mode B second copy, printable anchor, write-once
 * export and scheduler reminders. It is kept out of the main entry (`vault`), so commands that never use a second
 * copy (search, import, index rebuild, verify) load none of these modules. The CLI loads this entry with a dynamic
 * `import()` inside the P-3 command handlers only. It re-exports the main entry too, so a P-3 handler needs one import.
 */
export * from './index.ts';
export {
  addCopyRecord, assertCadence, assertCopyLabel, CADENCE_DAYS, CADENCES, canonicalPath, checkFileSystem,
  checkSecondCopySession, verifySecondCopy, COPY_REGISTERED,
  COPY_SEALED, copyRegisteredBody, copyRegisterStatus, copySealedBody, defaultRunner, diskRelation, emptyRegister,
  fatFileSystems, initSecondCopy, inspectCopyTarget, loadCopyRegister, MAX_REGISTER_BYTES, newCopyId,
  openSecondCopySession, OVERDUE_DAYS, pathInside, probeFileSystem, readCopyIdentity, readCopyRegister, recordSeal,
  registerFromEvents, replayCopyRegister, SecondCopyError, selectCopy, writeCopyRegister,
} from './second-copy.ts';
export type {
  Cadence, CommandResult, CommandRunner, CopyCheck, CopyCheckpoint, CopyEvent, CopyHead, CopyInitResult, CopyRecord, CopyRegister,
  CopyStatus, CopyTargetState, DiskRelation, FileSystemProbe, FileSystemReport, InitOptions, RegisterState,
  RegisterStatus, SealResult, SecondCopyErrorCode, SessionOptions, SessionReport, TargetOptions,
} from './second-copy.ts';
export { anchorPayload, anchorQr, anchorQrSvg, anchorQrText, anchorText, chainAnchor, parseAnchor } from './anchor.ts';
export { encodeQr, renderQrSvg, renderQrText } from './qr.ts';
export type { QrCode, QrErrorCorrection, QrOptions } from './qr.ts';
export { exportVaultIso, MAX_EXTENT_BYTES, MAX_FILE_SECTIONS, writeIsoImage } from './iso9660.ts';
export type { ExportIsoResult, IsoDirectoryInput, IsoEntryInput, IsoFileInput, WriteIsoOptions } from './iso9660.ts';
export {
  cronCommand, cronLine, installReminder, notifyDesktop, reminderArgs, reminderName, reminderStatus, removeReminder,
  runReminder, systemdUnits, systemdWord, WINDOWS_CONSOLE, WINDOWS_PROMPT, windowsConsoleArguments, windowsTaskXml,
} from './schedule.ts';
export type {
  ReminderDelivery, ReminderInstallResult, ReminderJob, ReminderJobStatus, ReminderRemoveResult, ReminderResult,
  ScheduledCadence, SchedulerEnvironment, SchedulerMethod,
} from './schedule.ts';

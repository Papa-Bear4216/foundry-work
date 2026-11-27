export { VaultFormatError, sha256 } from './bytes.ts';
export type { ErrorCode } from './bytes.ts';
export { FRAME_BYTES, decodeRecord, decryptRecord, encodeRecord, scanRecords } from './record.ts';
export type { RecordFields } from './record.ts';
export { GENESIS_HASH, decodeManifest, decodeVaultMetadata, encodeManifest, signingPublicKey, verifySegment } from './manifest.ts';
export type { ChainPosition, Manifest, ManifestFile } from './manifest.ts';
export { blobId, collectionIdKey, decodeKeyring, encodeKeyring, UnlockSession } from './keyring.ts';
export type { KdfParallelism, Unlock, VaultCredential } from './keyring.ts';
export {
  changePassphrase, create, rekeyAll, resetPassphrase, unlockByPassphrase, unlockByRecovery, unlockVault,
} from './keys.ts';
export type { RekeyHandoff } from './keys.ts';
export { decodeRecoveryKey } from './recovery.ts';
export { guardSecretInput, readSecretFromFd } from './secret-input.ts';
export { createVault, initializeVault, VaultWriter } from './vault-writer.ts';
export type { VaultAppend, VaultAppendResult, VaultCrashPoint, VaultWriterOptions } from './vault-writer.ts';
export { readVaultRecord, verifyVault, verifyVaultDeep } from './vault-reader.ts';
export type { VaultRecordLocation } from './vault-reader.ts';
export type { VaultAnchor, VerifyOptions } from './vault-directory.ts';
export type { UnlockedKeyring } from './record-file.ts';
export { openVaultReplay } from './vault-replay.ts';
export type { ReplayLocation, ReplayOptions, VaultReplayItem } from './vault-replay.ts';
export { retireIndexKey, stageIndexKey } from './index-keys.ts';
export { collectionKeyId, ensureCollectionKeys } from './collection-keys.ts';
export type { EnsureCollectionKeysResult } from './collection-keys.ts';
// P-3: Mode B second copy, printable anchor, write-once export and scheduler reminders.
export {
  addCopyRecord, assertCadence, assertCopyLabel, CADENCE_DAYS, CADENCES, checkFileSystem, copyRegisterStatus,
  defaultRunner, diskRelation, emptyRegister, FAT_FILE_SYSTEMS, initSecondCopy, openSecondCopySession, OVERDUE_DAYS,
  probeFileSystem, readCopyRegister, recordSeal, SecondCopyError, selectCopy, writeCopyRegister,
} from './second-copy.ts';
export type {
  Cadence, CommandResult, CommandRunner, CopyCheckpoint, CopyHead, CopyInitResult, CopyRecord, CopyRegister,
  CopyStatus, DiskRelation, FileSystemProbe, FileSystemReport, RegisterStatus, SealResult, SecondCopyErrorCode,
  SessionOptions, SessionReport, TargetOptions,
} from './second-copy.ts';
export { anchorPayload, anchorQr, anchorQrSvg, anchorQrText, anchorText, chainAnchor, parseAnchor } from './anchor.ts';
export { encodeQr, renderQrSvg, renderQrText } from './qr.ts';
export { exportVaultIso, MAX_EXTENT_BYTES, writeIsoImage } from './iso9660.ts';
export type { ExportIsoResult, IsoEntryInput, WriteIsoOptions } from './iso9660.ts';
export type { QrCode, QrErrorCorrection, QrOptions } from './qr.ts';

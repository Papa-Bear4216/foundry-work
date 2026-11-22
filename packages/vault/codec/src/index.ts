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

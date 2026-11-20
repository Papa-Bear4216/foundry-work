export {
  BLOCK_STATUSES,
  SENSITIVITY_LEVELS,
  type Block,
  type BlockInput,
  type BlockStatus,
  type CheckedPredicate,
  type CommandEvidence,
  type DisplayBadge,
  type Embedder,
  type FactEvidence,
  type FactInput,
  type FactRetraction,
  type FactScope,
  type FactTier,
  type FileEvidence,
  type FreshnessAssessment,
  type FreshnessResolver,
  type FreshnessStatus,
  type IndexState,
  type IndexSyncResult,
  type IndexedFact,
  type ManualEvidence,
  type QueryLabel,
  type QueryOptions,
  type QueryOutcomeStatus,
  type QueryResult,
  type QueryResultItem,
  type QueryStage,
  type ScanReport,
  type Sensitivity,
  type TokenUsage,
} from './types.js';

export {
  LOG_HEAD_HASH_BYTES,
  MAX_LINE_BYTES,
  appendBlock,
  compareBytewise,
  readLogHeaderFromFd,
  readLogHeaderState,
  replaceFileWithRetry,
  scanFdRange,
  scanLog,
  type StreamScanState,
} from './log.js';

export {
  INDEX_SCHEMA_VERSION,
  defaultIndexPath,
  openSyncedIndexForQuery,
  rebuildIndex,
  syncIndex,
} from './index-db.js';

export {
  SHA256_HEX_RE,
  isValidCheckedPredicate,
  normalizeTextForFts,
} from './normalize.js';

export {
  createCommandEmbedder,
  createHttpEmbedder,
  defaultFreshnessResolver,
  extractSearchTokens,
  formatQueryText,
  queryFacts,
  sanitizeInlineText,
} from './query.js';

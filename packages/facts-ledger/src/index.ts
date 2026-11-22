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
  type AppendBlockOptions,
  type ExpectedLogPrecondition,
  type StreamScanState,
} from './log.js';

export {
  INDEX_SCHEMA_VERSION,
  ReadOnlyIndexError,
  defaultIndexPath,
  openIndexReadOnlyStrict,
  openSyncedIndexForQuery,
  rebuildIndex,
  syncIndex,
} from './index-db.js';

export {
  SHA256_HEX_RE,
  formatCheckedPredicateClaim,
  isValidCheckedPredicate,
  normalizeTextForFts,
  tokenizeForFts,
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

export { addFact, buildFact, assertValidClaim, MAX_CLAIM_BYTES, MAX_QUOTE_BYTES, type AddFactOptions } from './add.js';
export { FreshnessChecker, createRepoFreshnessResolver, pinnedCommitOf, type FreshnessCheckerOptions } from './freshness.js';
export { RepoUnavailableError, resolveGitExecutable, runTemplate, templateNames, validateTemplateCall, type TemplateRun } from './git.js';
export { assertRelativePath, assertRepoName, defaultRepoMapPath, loadRepoMap, type RepoMap } from './repos.js';
export { assertNoSecrets, findSecret } from './secrets.js';
export { formatVerifyText, verifyFacts, type VerifyItem, type VerifyOptions, type VerifyResult } from './verify.js';
export { DIGEST_MAX_BYTES, digestFormatProblems, digestLine, generateDigest, type DigestOptions, type DigestResult } from './digest.js';
export {
  MAX_ANSWER_BYTES,
  MAX_DISTINCT_CITATIONS,
  MAX_STORED_PROBLEMS,
  checkAnswer,
  formatCheckAnswerText,
  type AnswerProblem,
  type CheckAnswerOptions,
  type CheckAnswerResult,
} from './check-answer.js';
export {
  computeUsage,
  formatUsageText,
  type ExactTokenCount,
  type TokenTotals,
  type UsageGroup,
  type UsageOptions,
  type UsageReport,
} from './usage.js';
export {
  EVAL_TAKEOUT_FACT_ID,
  NOW_MS,
  PROJECT as GATE_PROJECT,
  REPO as GATE_REPO,
  buildEvalFixture,
  buildGateFixture,
  evalFactCatalog,
  gateFactCatalog,
  type DeclaredFactState,
  type GateFactCatalogEntry,
  type GateFixture,
} from './eval/fixture.js';
export {
  CASES as EVAL_CASES,
  normalizeEvalValue,
  type AcceptOption,
  type AnswerType,
  type CaseQuery,
  type CitationPrefix,
  type EvalCase,
  type EvalExpectation,
} from './eval/cases.js';
export { AGENT_RULES_TEXT, answerTypeHint, buildEvalPrompt } from './eval/prompt.js';
export {
  DEFAULT_CASE_TIMEOUT_MS,
  MAX_ABSTAIN_PAYLOAD_BYTES,
  MAX_CASE_TIMEOUT_MS,
  MAX_EVAL_CASE_PROBLEMS,
  SNAPSHOT_GIT_TIMEOUT_MS,
  assertValidCaseTimeoutMs,
  buildModelChildEnv,
  deriveModelName,
  estimateTokens,
  estimateTokensFromBytes,
  formatDryRunPrompts,
  formatEvalText,
  gitSnapshotCommand,
  runEval,
  runEvalDryRun,
  runModelCommand,
  scoreEvalAnswer,
  selectEvalCases,
  snapshotFileIntegrity,
  stripFixturePaths,
  type EvalCaseResult,
  type EvalDryRunCase,
  type EvalDryRunResult,
  type EvalOptions,
  type EvalOutcome,
  type EvalOutcomeCounts,
  type EvalResult,
  type EvalScoreResult,
  type FileIntegritySnapshot,
  type ModelCommandOptions,
  type ModelCommandResult,
} from './eval/runner.js';

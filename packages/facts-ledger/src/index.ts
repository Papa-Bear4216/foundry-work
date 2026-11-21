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
  checkAnswer,
  formatCheckAnswerText,
  type AnswerProblem,
  type CheckAnswerOptions,
  type CheckAnswerResult,
} from './check-answer.js';
export {
  computeUsage,
  formatUsageText,
  type TokenTotals,
  type UsageGroup,
  type UsageOptions,
  type UsageReport,
} from './usage.js';
export {
  NOW_MS,
  PROJECT as GATE_PROJECT,
  REPO as GATE_REPO,
  buildGateFixture,
  gateFactCatalog,
  type DeclaredFactState,
  type GateFactCatalogEntry,
  type GateFixture,
} from './eval/fixture.js';
export {
  CASES as EVAL_CASES,
  type AbstainExpectation,
  type CaseQuery,
  type CitationPrefix,
  type CiteExpectation,
  type EvalCase,
  type EvalExpectation,
} from './eval/cases.js';
export { AGENT_RULES_TEXT, buildEvalPrompt } from './eval/prompt.js';
export {
  DEFAULT_CASE_TIMEOUT_MS,
  deriveModelName,
  estimateTokens,
  estimateTokensFromBytes,
  formatDryRunPrompts,
  formatEvalText,
  runEval,
  runEvalDryRun,
  runModelCommand,
  scoreEvalAnswer,
  selectEvalCases,
  type EvalCaseResult,
  type EvalDryRunCase,
  type EvalDryRunResult,
  type EvalOptions,
  type EvalOutcome,
  type EvalOutcomeCounts,
  type EvalResult,
  type ModelCommandResult,
} from './eval/runner.js';

import { TextEncoder } from 'node:util';
import { FreshnessChecker } from './freshness.js';
import {
  blobIds,
  decodeUtf8,
  headCommit,
  MANUAL_DEFAULT_TTL_S,
  readBlob,
  repoDirFor,
  runTemplate,
  sha256Hex,
  TEMPLATE_DEFAULT_TTL_S,
} from './git.js';
import { appendBlock } from './log.js';
import { formatCheckedPredicateClaim, isValidCheckedPredicate } from './normalize.js';
import { assertRelativePath, assertRepoName, type RepoMap } from './repos.js';
import { assertNoSecrets } from './secrets.js';
import {
  SENSITIVITY_LEVELS,
  type Block,
  type CheckedPredicate,
  type CommandEvidence,
  type FactEvidence,
  type FactInput,
  type FactScope,
  type FileEvidence,
  type ManualEvidence,
  type Sensitivity,
} from './types.js';

export const MAX_CLAIM_BYTES = 300;
export const MAX_QUOTE_BYTES = 200;

const encoder = new TextEncoder();

export interface EvidenceFileRequest {
  readonly repo: string;
  readonly path: string;
  /** `N` or `N-M`, 1-based and inclusive. */
  readonly lines?: string;
}

export interface EvidenceCommandRequest {
  readonly template: string;
  readonly args: readonly string[];
}

export interface AddFactOptions {
  readonly logPath: string;
  readonly repos: RepoMap;
  readonly agent: string;
  readonly project: string;
  readonly intent: string;
  readonly reasoning: string;
  readonly traceId?: string;
  readonly check?: CheckedPredicate;
  readonly claim?: string;
  readonly note?: string;
  readonly tags?: readonly string[];
  readonly sensitivity?: Sensitivity;
  readonly scope?: FactScope;
  readonly supersedesFact?: string;
  readonly evidenceFiles?: readonly EvidenceFileRequest[];
  readonly evidenceCommands?: readonly EvidenceCommandRequest[];
  readonly manual?: { readonly description: string; readonly outputSha256?: string; readonly ttlS?: number };
  readonly nowMs?: number;
}

function isoSeconds(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, '+00:00');
}

/** One sentence, one line, no control characters, at most 300 bytes (Step Zero 3.2). */
export function assertValidClaim(claim: unknown): asserts claim is string {
  if (typeof claim !== 'string' || claim.trim().length === 0) throw new Error('A claim is required');
  if (/[\u0000-\u001f\u007f]/.test(claim)) throw new Error('Claim must be one line without control characters');
  if (encoder.encode(claim).length > MAX_CLAIM_BYTES) throw new Error(`Claim exceeds ${MAX_CLAIM_BYTES} bytes`);
}

/** Truncate to at most `max` UTF-8 bytes without splitting a character. */
function truncateUtf8(text: string, max: number): string {
  if (encoder.encode(text).length <= max) return text;
  let out = '';
  let bytes = 0;
  for (const ch of text) {
    const n = encoder.encode(ch).length;
    if (bytes + n > max) break;
    out += ch;
    bytes += n;
  }
  return out;
}

/** Exact text of lines `N` or `N-M` from the committed file, without the final line break. */
function sliceLines(content: string, lines: string): string {
  const m = /^(\d+)(?:-(\d+))?$/.exec(lines);
  if (!m) throw new Error(`Invalid --evidence-file line range: ${lines}`);
  const start = Number(m[1]);
  const end = m[2] ? Number(m[2]) : start;
  if (start < 1 || end < start) throw new Error(`Invalid --evidence-file line range: ${lines}`);
  const starts = [0];
  for (let i = 0; i < content.length; i++) if (content[i] === '\n') starts.push(i + 1);
  if (end > starts.length || (end === starts.length && starts[end - 1] === content.length)) {
    throw new Error(`Line range ${lines} is past the end of the file`);
  }
  const from = starts[start - 1] as number;
  const to = end < starts.length ? (starts[end] as number) - 1 : content.length;
  return content.slice(from, to).replace(/\r$/, '');
}

function fileEvidence(repos: RepoMap, req: EvidenceFileRequest, quoteOverride?: string): FileEvidence {
  assertRepoName(req.repo);
  assertRelativePath(req.path);
  const dir = repoDirFor(repos, req.repo);
  const head = headCommit(dir);
  if (!head) throw new Error(`Repository ${req.repo} has no commits`);
  const blob = blobIds(dir, head, [req.path]).get(req.path);
  if (!blob) throw new Error(`${req.repo}:${req.path} is not committed at HEAD`);
  let quote = quoteOverride;
  if (quote === undefined && req.lines) {
    quote = truncateUtf8(sliceLines(decodeUtf8(readBlob(dir, blob)), req.lines), MAX_QUOTE_BYTES);
  }
  return {
    type: 'file',
    repo: req.repo,
    path: req.path,
    commit: head,
    blob,
    ...(req.lines ? { lines: req.lines } : {}),
    ...(quote !== undefined && quote.length > 0 ? { quote } : {}),
  };
}

function commandEvidence(repos: RepoMap, req: EvidenceCommandRequest, nowMs: number): { ev: CommandEvidence; output: string } {
  const run = runTemplate(repos, req.template, req.args);
  return {
    ev: {
      type: 'command',
      template: run.template,
      template_version: run.templateVersion,
      args: run.args,
      exit_code: run.exitCode,
      output_sha256: run.outputSha256,
      ran_at: isoSeconds(nowMs),
      ttl_s: TEMPLATE_DEFAULT_TTL_S,
    },
    output: decodeUtf8(run.output),
  };
}

/** Evidence generated from a checked predicate (the predicate itself was just re-run and holds). */
function predicateEvidence(
  repos: RepoMap,
  check: CheckedPredicate,
  nowMs: number,
): { evidence: FactEvidence[]; outputs: string[] } {
  const c = check as Record<string, unknown>;
  switch (c['predicate']) {
    case 'file_exists':
    case 'file_blob_is':
    case 'file_lacks':
      return { evidence: [fileEvidence(repos, { repo: String(c['repo']), path: String(c['path']) })], outputs: [] };
    case 'file_contains': {
      const text = String(c['text']);
      const quote = encoder.encode(text).length <= MAX_QUOTE_BYTES ? text : undefined;
      return {
        evidence: [fileEvidence(repos, { repo: String(c['repo']), path: String(c['path']) }, quote)],
        outputs: [],
      };
    }
    case 'file_absent': {
      const r = commandEvidence(repos, { template: 'git-ls-files', args: [String(c['repo']), String(c['path'])] }, nowMs);
      return { evidence: [r.ev], outputs: [r.output] };
    }
    case 'command_output_is': {
      const r = commandEvidence(repos, { template: String(c['template']), args: c['args'] as string[] }, nowMs);
      return { evidence: [r.ev], outputs: [r.output] };
    }
    default:
      throw new Error(`Unsupported checked predicate: ${String(c['predicate'])}`);
  }
}

/** Build one fact from the request, re-running the predicate and resolving evidence ids itself. */
export function buildFact(options: AddFactOptions): FactInput {
  const nowMs = options.nowMs ?? Date.now();
  const sensitivity = options.sensitivity ?? 'personal';
  if (!(SENSITIVITY_LEVELS as readonly string[]).includes(sensitivity)) {
    throw new Error(`Invalid sensitivity: ${String(sensitivity)}`);
  }
  if (sensitivity === 'secret') throw new Error('A `secret` fact is refused outright; it is never written to the ledger');
  const scope: FactScope = options.scope ?? 'current';
  const tags = [...new Set(options.tags ?? [])];
  for (const tag of tags) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(tag)) throw new Error(`Invalid tag: ${JSON.stringify(tag)}`);
  }
  const note = options.note ?? '';
  if (/[\u0000-\u0008\u000b-\u001f\u007f]/.test(note) || encoder.encode(note).length > 2000) {
    throw new Error('Note must be at most 2000 bytes without control characters');
  }

  const evidence: FactEvidence[] = [];
  const outputs: string[] = [];
  let claim: string;
  let tier: 'checked' | 'asserted';
  let check: CheckedPredicate | null = null;

  if (options.check !== undefined) {
    if (options.claim !== undefined) {
      throw new Error('A checked fact gets its claim from the predicate; put your own words in --note');
    }
    if (!isValidCheckedPredicate(options.check)) throw new Error('Invalid checked predicate');
    const c = options.check as Record<string, unknown>;
    if (c['predicate'] !== 'command_output_is') assertRepoName(c['repo']);
    if (typeof c['path'] === 'string') assertRelativePath(c['path']);
    if (scope === 'at-commit' && (c['predicate'] === 'file_absent' || c['predicate'] === 'command_output_is')) {
      throw new Error(`Predicate ${String(c['predicate'])} only supports scope current`);
    }
    // Keep only the fields the predicate defines, so the stored check is exactly the claim.
    check = Object.fromEntries(
      Object.entries(c).filter(([k]) => ['predicate', 'repo', 'path', 'blob', 'text', 'template', 'args', 'output_sha256'].includes(k)),
    ) as CheckedPredicate;
    claim = formatCheckedPredicateClaim(check);
    tier = 'checked';
    const holds = new FreshnessChecker({ repos: options.repos }).evaluatePredicate(check, 'current', null);
    if (holds !== true) {
      throw new Error(holds === false ? 'Predicate does not hold; nothing written' : 'Predicate could not be evaluated (repository not present?)');
    }
    const generated = predicateEvidence(options.repos, check, nowMs);
    evidence.push(...generated.evidence);
    outputs.push(...generated.outputs);
  } else {
    if (options.claim === undefined) throw new Error('Give either --check or --claim');
    claim = options.claim;
    tier = 'asserted';
  }
  assertValidClaim(claim);

  for (const req of options.evidenceFiles ?? []) evidence.push(fileEvidence(options.repos, req));
  for (const req of options.evidenceCommands ?? []) {
    const r = commandEvidence(options.repos, req, nowMs);
    evidence.push(r.ev);
    outputs.push(r.output);
  }
  if (options.manual) {
    const description = options.manual.description;
    if (typeof description !== 'string' || description.trim().length === 0 || /[\u0000-\u001f\u007f]/.test(description)) {
      throw new Error('Manual evidence needs a one-line description');
    }
    const outputSha256 = options.manual.outputSha256 ?? sha256Hex(description);
    if (!/^[0-9a-f]{64}$/.test(outputSha256)) throw new Error('Manual evidence output hash must be 64 hex characters');
    const manual: ManualEvidence = {
      type: 'manual',
      description,
      output_sha256: outputSha256,
      ran_at: isoSeconds(nowMs),
      ttl_s: options.manual.ttlS ?? MANUAL_DEFAULT_TTL_S,
    };
    evidence.push(manual);
  }
  if (evidence.length === 0) throw new Error('A fact without evidence is rejected');
  if (scope === 'at-commit' && !evidence.some((ev) => ev.type === 'file')) {
    throw new Error('An at-commit fact needs file evidence that pins the commit');
  }

  const secretFields: Record<string, string> = { claim, note };
  evidence.forEach((ev, i) => {
    const quote = (ev as unknown as Record<string, unknown>)['quote'];
    if (typeof quote === 'string') secretFields[`evidence[${i}].quote`] = quote;
    const description = (ev as unknown as Record<string, unknown>)['description'];
    if (typeof description === 'string') secretFields[`evidence[${i}].description`] = description;
  });
  outputs.forEach((out, i) => {
    secretFields[`command output ${i}`] = out;
  });
  if (check) secretFields['check'] = JSON.stringify(check);
  assertNoSecrets(secretFields);

  return {
    fact_id: '',
    tier,
    scope,
    check,
    claim,
    note,
    tags,
    sensitivity,
    verified_at: isoSeconds(nowMs),
    supersedes: options.supersedesFact ?? null,
    evidence,
  };
}

/** `facts add`: build, validate and append one fact in its own block. */
export function addFact(options: AddFactOptions): Block {
  for (const [field, value] of Object.entries({ agent: options.agent, project: options.project, intent: options.intent, reasoning: options.reasoning })) {
    if (typeof value !== 'string' || value.trim().length === 0) throw new Error(`--${field} is required`);
  }
  assertNoSecrets({ intent: options.intent, reasoning: options.reasoning });
  const fact = buildFact(options);
  const touches = [...new Set(fact.evidence?.flatMap((ev) => (ev.type === 'file' ? [ev.path] : [])) ?? [])];
  return appendBlock(options.logPath, {
    agent: options.agent,
    project: options.project,
    intent: options.intent,
    reasoning: options.reasoning,
    ...(options.traceId ? { trace_id: options.traceId } : {}),
    status: 'done',
    touches,
    schema: 2,
    facts: [fact],
    retracted_facts: [],
  });
}

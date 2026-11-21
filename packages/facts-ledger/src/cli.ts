#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';
import { addFact } from './add.js';
import { MAX_ANSWER_BYTES, checkAnswer, formatCheckAnswerText } from './check-answer.js';
import { assertDigestProject, generateDigest } from './digest.js';
import {
  formatDryRunPrompts,
  formatEvalText,
  runEval,
  runEvalDryRun,
} from './eval/runner.js';
import { FreshnessChecker } from './freshness.js';
import { templateNames } from './git.js';
import { defaultIndexPath, rebuildIndex } from './index-db.js';
import { loadRepoMap } from './repos.js';
import { computeUsage, formatUsageText } from './usage.js';
import { verifyFacts, verifyOutputChunks } from './verify.js';
import {
  createCommandEmbedder,
  createHttpEmbedder,
  formatQueryText,
  queryFacts,
  sanitizeInlineText,
} from './query.js';
import { type CheckedPredicate, type Embedder, type FactScope, type Sensitivity, type TokenUsage } from './types.js';

interface ParsedArgs {
  readonly command: string | undefined;
  readonly logPath: string;
  readonly indexPath: string | undefined;
  readonly id: string | undefined;
  readonly tag: string | undefined;
  readonly path: string | undefined;
  readonly commit: string | undefined;
  readonly repo: string | undefined;
  readonly history: boolean;
  readonly limit: number | undefined;
  readonly maxSensitivity: Exclude<Sensitivity, 'secret'> | undefined;
  readonly embedUrl: string | undefined;
  readonly embedCmd: string | undefined;
  readonly embedArgs: readonly string[];
  readonly embedModel: string | undefined;
  readonly minSemanticScore: number | undefined;
  readonly json: boolean;
  readonly stats: boolean;
  readonly positionals: readonly string[];
  readonly tags: readonly string[];
  readonly add: Record<string, string>;
  readonly evidenceFiles: readonly string[];
  readonly evidenceArgs: readonly string[];
  readonly fact: string | undefined;
  readonly all: boolean;
  readonly rerun: boolean;
  readonly write: boolean;
  readonly modelCmd: string | undefined;
  readonly modelArgs: readonly string[];
  readonly modelName: string | undefined;
  readonly caseTimeoutMs: number | undefined;
  readonly cases: readonly string[] | undefined;
  readonly dryRun: boolean;
  readonly since: string | undefined;
}

const VALID_MAX_SENSITIVITY = new Set(['public', 'personal', 'private', 'clinical', 'child']);

function parseJsonStringArrayEnv(raw: string, varName: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${varName} must be a JSON array of strings`);
  }
  if (!Array.isArray(parsed) || !parsed.every((item) => typeof item === 'string')) {
    throw new Error(`${varName} must be a JSON array of strings`);
  }
  return parsed;
}

function parseMinSemanticScore(raw: string): number {
  if (raw.trim().length === 0) {
    throw new Error('--min-semantic-score must be a finite number in [-1, 1]');
  }
  const value = Number(raw);
  if (!Number.isFinite(value) || value < -1 || value > 1) {
    throw new Error('--min-semantic-score must be a finite number in [-1, 1]');
  }
  return value;
}

function parseCliArgs(argv: readonly string[]): ParsedArgs {
  const command = argv[0];
  let logPath = process.env['FACTS_LEDGER_LOG'] || 'ledger.jsonl';
  let indexPath: string | undefined;
  let id: string | undefined;
  let tag: string | undefined;
  let path: string | undefined;
  let commit: string | undefined;
  let repo: string | undefined;
  let history = false;
  let limit: number | undefined;
  let maxSensitivity: Exclude<Sensitivity, 'secret'> | undefined;
  let cliEmbedUrl: string | undefined;
  let cliEmbedCmd: string | undefined;
  const cliEmbedArgs: string[] = [];
  let embedModel = process.env['FACTS_LEDGER_EMBED_MODEL'] || undefined;
  let minSemanticScore =
    process.env['FACTS_LEDGER_MIN_SEMANTIC_SCORE'] !== undefined &&
    process.env['FACTS_LEDGER_MIN_SEMANTIC_SCORE'].trim().length > 0
      ? parseMinSemanticScore(process.env['FACTS_LEDGER_MIN_SEMANTIC_SCORE'])
      : undefined;
  let json = false;
  let stats = false;
  const positionals: string[] = [];
  const tags: string[] = [];
  const add: Record<string, string> = {};
  const evidenceFiles: string[] = [];
  const evidenceArgs: string[] = [];
  let fact: string | undefined;
  let all = false;
  let rerun = false;
  let write = false;
  let modelCmd: string | undefined;
  const modelArgs: string[] = [];
  let modelName: string | undefined;
  let caseTimeoutMs: number | undefined;
  let cases: string[] | undefined;
  let dryRun = false;
  let since: string | undefined;

  for (let i = 1; i < argv.length; i++) {
    const arg = argv[i];
    const next = (): string => {
      const value = argv[++i];
      if (value === undefined) throw new Error(`Missing value for flag ${arg}`);
      return value;
    };

    switch (arg) {
      case '--log':
        logPath = next();
        break;
      case '--index':
        indexPath = next();
        break;
      case '--id':
        id = next();
        break;
      case '--tag':
        tag = next();
        tags.push(tag);
        break;
      case '--check':
      case '--claim':
      case '--note':
      case '--sensitivity':
      case '--scope':
      case '--manual':
      case '--supersedes-fact':
      case '--agent':
      case '--project':
      case '--intent':
      case '--reasoning':
      case '--trace-id':
      case '--evidence-cmd':
      case '--model':
      case '--task':
      case '--input-tokens':
      case '--output-tokens':
        add[arg.slice(2)] = next();
        break;
      case '--from-agent':
      case '--tokens-measured':
        add[arg.slice(2)] = 'true';
        break;
      case '--evidence-file':
        evidenceFiles.push(next());
        break;
      case '--evidence-arg':
        evidenceArgs.push(next());
        break;
      case '--fact':
        fact = next();
        break;
      case '--all':
        all = true;
        break;
      case '--rerun':
        rerun = true;
        break;
      case '--write':
        write = true;
        break;
      case '--path':
        path = next();
        break;
      case '--commit':
        commit = next();
        break;
      case '--repo':
        repo = next();
        break;
      case '--history':
        history = true;
        break;
      case '--limit': {
        const parsed = Number.parseInt(next(), 10);
        if (!Number.isFinite(parsed) || parsed < 1) {
          throw new Error('--limit must be a positive integer');
        }
        limit = parsed;
        break;
      }
      case '--max-sensitivity': {
        const val = next();
        if (!VALID_MAX_SENSITIVITY.has(val)) {
          throw new Error(`Invalid --max-sensitivity value: ${val}`);
        }
        maxSensitivity = val as Exclude<Sensitivity, 'secret'>;
        break;
      }
      case '--embed-url':
        cliEmbedUrl = next();
        break;
      case '--embed-cmd':
        cliEmbedCmd = next();
        break;
      case '--embed-arg':
        cliEmbedArgs.push(next());
        break;
      case '--embed-model':
        embedModel = next();
        break;
      case '--min-semantic-score':
        minSemanticScore = parseMinSemanticScore(next());
        break;
      case '--model-cmd':
        modelCmd = next();
        break;
      case '--model-arg':
        modelArgs.push(next());
        break;
      case '--model-name':
        modelName = next();
        break;
      case '--case-timeout-ms': {
        const raw = next();
        if (!/^\d{1,9}$/.test(raw)) {
          throw new Error('--case-timeout-ms must be a positive integer');
        }
        const parsed = Number.parseInt(raw, 10);
        if (!Number.isFinite(parsed) || parsed < 1) {
          throw new Error('--case-timeout-ms must be a positive integer');
        }
        caseTimeoutMs = parsed;
        break;
      }
      case '--cases':
        cases = next().split(',');
        break;
      case '--dry-run':
      case '--print-prompts':
        dryRun = true;
        break;
      case '--since':
        since = next();
        break;
      case '--json':
        json = true;
        break;
      case '--stats':
        stats = true;
        break;
      default:
        if (arg.startsWith('--')) {
          throw new Error(`Unknown option: ${arg}`);
        }
        positionals.push(arg);
        break;
    }
  }

  if (cliEmbedUrl !== undefined && cliEmbedCmd !== undefined) {
    throw new Error('Specify at most one of --embed-url or --embed-cmd');
  }

  const envEmbedUrl = process.env['FACTS_LEDGER_EMBED_URL'] || undefined;
  const envEmbedCmd = process.env['FACTS_LEDGER_EMBED_CMD'] || undefined;

  let embedUrl: string | undefined;
  let embedCmd: string | undefined;
  if (cliEmbedUrl !== undefined) {
    embedUrl = cliEmbedUrl;
  } else if (cliEmbedCmd !== undefined) {
    embedCmd = cliEmbedCmd;
  } else {
    if (envEmbedUrl && envEmbedCmd) {
      throw new Error('Conflicting FACTS_LEDGER_EMBED_URL and FACTS_LEDGER_EMBED_CMD environment variables');
    }
    embedUrl = envEmbedUrl;
    embedCmd = envEmbedCmd;
  }

  if (cliEmbedArgs.length > 0 && !embedCmd) {
    throw new Error('--embed-arg requires --embed-cmd or FACTS_LEDGER_EMBED_CMD');
  }
  if (modelArgs.length > 0 && !modelCmd) {
    throw new Error('--model-arg requires --model-cmd');
  }

  let embedArgs: string[] = [];
  if (embedCmd) {
    if (cliEmbedArgs.length > 0) {
      embedArgs = cliEmbedArgs;
    } else if (process.env['FACTS_LEDGER_EMBED_ARGS'] && process.env['FACTS_LEDGER_EMBED_ARGS'].trim().length > 0) {
      embedArgs = parseJsonStringArrayEnv(
        process.env['FACTS_LEDGER_EMBED_ARGS'],
        'FACTS_LEDGER_EMBED_ARGS',
      );
    }
  }

  return {
    command,
    logPath,
    indexPath,
    id,
    tag,
    path,
    commit,
    repo,
    history,
    limit,
    maxSensitivity,
    embedUrl,
    embedCmd,
    embedArgs,
    embedModel,
    minSemanticScore,
    json,
    stats,
    positionals,
    tags,
    add,
    evidenceFiles,
    evidenceArgs,
    fact,
    all,
    rerun,
    write,
    modelCmd,
    modelArgs,
    modelName,
    caseTimeoutMs,
    cases,
    dryRun,
    since,
  };
}

/** Section 3.1: damaged log lines are reported on every run. */
function warnBadLines(report: { readonly badLineCount: number; readonly badLineNumbers: readonly number[] }): void {
  if (report.badLineCount > 0) {
    process.stderr.write(`Warning: skipped ${report.badLineCount} bad log line(s) at line(s): ${report.badLineNumbers.join(', ')}\n`);
  }
}

/** Storage flags the user chose, repeated in the digest's closing query command. */
const TOKEN_FLAGS = ['model', 'task', 'input-tokens', 'output-tokens'] as const;

/** `token_usage` from `--model --task --input-tokens --output-tokens [--tokens-measured]`: all four or none. */
function tokenUsageFromArgs(a: Record<string, string>): { tokenUsage?: TokenUsage } {
  const given = TOKEN_FLAGS.filter((f) => a[f] !== undefined);
  if (given.length === 0) {
    if (a['tokens-measured'] !== undefined) throw new Error('--tokens-measured needs --model, --task, --input-tokens and --output-tokens');
    return {};
  }
  if (given.length !== TOKEN_FLAGS.length) {
    throw new Error('Token usage needs all of --model, --task, --input-tokens and --output-tokens');
  }
  const count = (flag: string): number => {
    const raw = a[flag] as string;
    if (!/^\d{1,15}$/.test(raw)) throw new Error(`--${flag} must be a non-negative integer`);
    return Number(raw);
  };
  return {
    tokenUsage: {
      model: a['model'] as string,
      task: a['task'] as string,
      input: count('input-tokens'),
      output: count('output-tokens'),
      measured: a['tokens-measured'] === 'true',
    },
  };
}

function digestQueryFlags(args: ParsedArgs): string[] {
  const flags: string[] = [];
  if (args.logPath !== (process.env['FACTS_LEDGER_LOG'] || 'ledger.jsonl')) flags.push('--log', args.logPath);
  if (args.indexPath) flags.push('--index', args.indexPath);
  return flags;
}

function buildEmbedderFromArgs(args: ParsedArgs): Embedder | undefined {
  if (args.embedUrl !== undefined) {
    return createHttpEmbedder(args.embedUrl, args.embedModel);
  }
  if (args.embedCmd !== undefined) {
    return createCommandEmbedder(args.embedCmd, args.embedArgs, args.embedModel);
  }
  return undefined;
}

function usageText(): string {
  return [
    'Usage:',
    '  facts rebuild [--log <file>] [--index <file>] [--json] [--stats]',
    '  facts query [text] [--id <id>] [--tag <tag>] [--path <path>] [--commit <sha>] [--repo <name>] [--history] [--limit <n>] [--max-sensitivity <tier>] [--embed-url <url> | --embed-cmd <exe> [--embed-arg <arg>]] [--embed-model <name>] [--min-semantic-score <float>] [--log <file>] [--index <file>] [--json] [--stats]',
    '  facts add --project <p> --intent <text> --reasoning <text> [--agent <name>]',
    '            (--check <predicate json> | --claim <sentence>) [--repo <name>] [--evidence-file <path>[:N[-M]]]...',
    '            [--evidence-cmd <template> [--evidence-arg <arg>]...] [--manual <description>]',
    '            [--note <text>] [--tag <tag>]... [--sensitivity <tier>] [--scope current|at-commit] [--supersedes-fact <id>]',
    '  facts verify (--fact <id> | --tag <tag> | --all) [--rerun] [--write [--agent <name>]] [--json]',
    '  facts digest --project <p> [--max-sensitivity <tier>] [--json]   (writes digest.<project>.md beside the index; at most 6,000 bytes)',
    '  facts check-answer <file> [--max-sensitivity <tier>] [--json]   (every non-blank line: a statement with [fact:<id>] or [asserted:<id>], or ABSTAIN: <text>)',
    '  facts eval --model-cmd <exe> [--model-arg <arg>]... [--model-name <label>] [--case-timeout-ms <n>] [--cases <id,...>] [--project <p>] [--agent <name>] [--log <file>] [--json] [--stats]',
    '  facts eval --dry-run [--cases <id,...>] [--json] [--stats]   (print deterministic prompts without running a model)',
    '  facts usage [--since <iso>] [--project <p>] [--log <file>] [--json] [--stats]   (measured and estimated totals kept separate)',
    '  facts add ... --from-agent --model <id> --task <label> --input-tokens <n> --output-tokens <n> [--tokens-measured]',
    '',
    `Command templates: ${templateNames().join(', ')}. Git templates take the repo name first.`,
    'Repo names map to local checkouts in a per-machine file outside any repository (FACTS_LEDGER_REPOS).',
    '',
    'Known limits: an asserted claim can become false while its quote stays intact; a claim about absence',
    'across a whole repository cannot be pinned to one file and should use command evidence; a renamed file',
    'reads as stale until re-verified; uncommitted changes are not seen (facts are checked against HEAD);',
    'submodules are separate repositories.',
    '',
    'Note: Ledger files are append-only; run `facts rebuild` after any manual edit or repair of historical lines.',
  ].join('\n');
}

function parseEvidenceFile(raw: string, repo: string | undefined): { repo: string; path: string; lines?: string } {
  if (!repo) throw new Error('--evidence-file needs --repo <name>');
  const m = /^(.*):(\d+(?:-\d+)?)$/.exec(raw);
  return m ? { repo, path: m[1] as string, lines: m[2] as string } : { repo, path: raw };
}

function parseCheck(raw: string): CheckedPredicate {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('--check must be a JSON predicate object');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('--check must be a JSON predicate object');
  }
  return parsed as CheckedPredicate;
}

function agentName(args: ParsedArgs): string {
  return args.add['agent'] || process.env['FACTS_LEDGER_AGENT'] || 'facts-cli';
}

async function run(): Promise<void> {
  const started = process.hrtime.bigint();
  let args: ParsedArgs;
  try {
    args = parseCliArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${sanitizeInlineText((err as Error).message)}\n${usageText()}\n`);
    process.exitCode = 2;
    return;
  }

  if (!args.command || args.command === '--help' || args.command === '-h') {
    process.stdout.write(`${usageText()}\n`);
    return;
  }

  const indexPath = args.indexPath ?? defaultIndexPath(args.logPath);

  try {
    if (args.command === 'rebuild') {
      const result = rebuildIndex(args.logPath, indexPath);
      if (args.json) {
        process.stdout.write(`${JSON.stringify(result)}\n`);
      } else {
        if (result.badLines.badLineCount > 0) {
          process.stderr.write(
            `Warning: skipped ${result.badLines.badLineCount} bad log line(s) at line(s): ${result.badLines.badLineNumbers.join(', ')}\n`,
          );
        }
        process.stdout.write(
          `Rebuilt ${result.indexPath}: ${result.indexedBlocks} block(s), ${result.indexedFacts} fact(s).\n`,
        );
      }
    } else if (args.command === 'query') {
      const queryText = args.positionals.join(' ').trim();
      const embedder = buildEmbedderFromArgs(args);
      const checker = new FreshnessChecker({ repos: loadRepoMap() });
      const result = await queryFacts({
        logPath: args.logPath,
        indexPath,
        text: queryText.length > 0 ? queryText : undefined,
        id: args.id,
        tag: args.tag,
        path: args.path,
        commit: args.commit,
        repo: args.repo,
        history: args.history,
        limit: args.limit,
        maxSensitivity: args.maxSensitivity,
        embedder,
        minSemanticScore: args.minSemanticScore,
        freshnessResolver: checker.resolver(),
        freshnessPrefetch: checker.prefetcher(),
      });
      if (args.json) {
        process.stdout.write(`${JSON.stringify(result)}\n`);
      } else {
        process.stdout.write(`${formatQueryText(result)}\n`);
      }
    } else if (args.command === 'add') {
      const repos = loadRepoMap();
      const a = args.add;
      const sensitivity = a['sensitivity'] as Sensitivity | undefined;
      const scope = a['scope'] as FactScope | undefined;
      if (scope !== undefined && scope !== 'current' && scope !== 'at-commit') {
        throw new Error('--scope must be current or at-commit');
      }
      if (args.evidenceArgs.length > 0 && !a['evidence-cmd']) throw new Error('--evidence-arg requires --evidence-cmd');
      // Validate before the append: the block cannot be taken back if the digest then fails.
      assertDigestProject(a['project'] || process.env['FACTS_LEDGER_PROJECT'] || '');
      const block = addFact({
        logPath: args.logPath,
        repos,
        agent: agentName(args),
        project: a['project'] || process.env['FACTS_LEDGER_PROJECT'] || '',
        intent: a['intent'] ?? '',
        reasoning: a['reasoning'] ?? '',
        ...(a['trace-id'] ? { traceId: a['trace-id'] } : {}),
        ...(a['check'] !== undefined ? { check: parseCheck(a['check']) } : {}),
        ...(a['claim'] !== undefined ? { claim: a['claim'] } : {}),
        ...(a['note'] !== undefined ? { note: a['note'] } : {}),
        tags: args.tags,
        ...(sensitivity ? { sensitivity } : {}),
        ...(scope ? { scope } : {}),
        ...(a['supersedes-fact'] ? { supersedesFact: a['supersedes-fact'] } : {}),
        evidenceFiles: args.evidenceFiles.map((raw) => parseEvidenceFile(raw, args.repo)),
        evidenceCommands: a['evidence-cmd'] ? [{ template: a['evidence-cmd'], args: args.evidenceArgs }] : [],
        ...(a['manual'] !== undefined ? { manual: { description: a['manual'] } } : {}),
        ...(a['from-agent'] === 'true' ? { fromAgent: true } : {}),
        ...tokenUsageFromArgs(a),
      });
      const fact = block.facts?.[0];
      if (args.json) {
        process.stdout.write(`${JSON.stringify(block)}\n`);
      } else {
        process.stdout.write(`Appended block ${block.id}: fact ${fact?.fact_id ?? '?'} (${fact?.tier ?? '?'})\n`);
      }
      // Every facts add regenerates the project's digest (Step Zero 7).
      const regenerated = generateDigest({
        logPath: args.logPath,
        indexPath,
        project: block.project,
        repos,
        ...(args.maxSensitivity ? { maxSensitivity: args.maxSensitivity } : {}),
        queryFlags: digestQueryFlags(args),
      });
      warnBadLines(regenerated.badLines);
    } else if (args.command === 'digest') {
      const project = args.add['project'] || process.env['FACTS_LEDGER_PROJECT'];
      if (!project) throw new Error('--project is required');
      const result = generateDigest({
        logPath: args.logPath,
        indexPath,
        project,
        repos: loadRepoMap(),
        ...(args.maxSensitivity ? { maxSensitivity: args.maxSensitivity } : {}),
        queryFlags: digestQueryFlags(args),
      });
      warnBadLines(result.badLines);
      process.stdout.write(args.json ? `${JSON.stringify(result)}\n` : result.text);
    } else if (args.command === 'verify') {
      const result = verifyFacts({
        logPath: args.logPath,
        indexPath,
        repos: loadRepoMap(),
        ...(args.fact ? { id: args.fact } : {}),
        ...(args.tag ? { tag: args.tag } : {}),
        all: args.all,
        rerun: args.rerun,
        ...(args.write ? { writeAs: agentName(args) } : {}),
      });
      // Written in pieces: a 10,000-fact report as one string costs several MiB (Step Zero 10.4).
      let pending = '';
      for (const chunk of verifyOutputChunks(result, args.json)) {
        pending += chunk;
        if (pending.length >= 65536) {
          process.stdout.write(pending);
          pending = '';
        }
      }
      process.stdout.write(`${pending}\n`);
    } else if (args.command === 'check-answer') {
      const file = args.positionals[0];
      if (!file || args.positionals.length > 1) throw new Error('check-answer takes exactly one answer file');
      const st = statSync(file);
      if (!st.isFile()) throw new Error('check-answer needs a regular file');
      if (st.size > MAX_ANSWER_BYTES) throw new Error(`Answer exceeds ${MAX_ANSWER_BYTES} bytes`);
      const result = await checkAnswer(readFileSync(file, 'utf8'), {
        logPath: args.logPath,
        indexPath,
        repos: loadRepoMap(),
        ...(args.maxSensitivity ? { maxSensitivity: args.maxSensitivity } : {}),
      });
      process.stdout.write(args.json ? `${JSON.stringify(result)}\n` : `${formatCheckAnswerText(result)}\n`);
      if (!result.ok) process.exitCode = 1;
    } else if (args.command === 'eval') {
      if (args.dryRun) {
        const dry = await runEvalDryRun(args.cases);
        process.stdout.write(args.json ? `${JSON.stringify(dry)}\n` : `${formatDryRunPrompts(dry)}\n`);
      } else {
        if (!args.modelCmd) {
          throw new Error('--model-cmd is required (or pass --dry-run to inspect prompts)');
        }
        const project = args.add['project'] || process.env['FACTS_LEDGER_PROJECT'] || 'facts-eval';
        const result = await runEval({
          modelCmd: args.modelCmd,
          modelArgs: args.modelArgs,
          ...(args.modelName !== undefined ? { modelName: args.modelName } : {}),
          ...(args.caseTimeoutMs !== undefined ? { caseTimeoutMs: args.caseTimeoutMs } : {}),
          ...(args.cases !== undefined ? { caseIds: args.cases } : {}),
          logPath: args.logPath,
          project,
          agent: agentName(args),
        });
        process.stdout.write(args.json ? `${JSON.stringify(result)}\n` : `${formatEvalText(result)}\n`);
      }
    } else if (args.command === 'usage') {
      const result = computeUsage({
        logPath: args.logPath,
        ...(args.since !== undefined ? { since: args.since } : {}),
        ...(args.add['project'] !== undefined ? { project: args.add['project'] } : {}),
      });
      warnBadLines(result.badLines);
      process.stdout.write(args.json ? `${JSON.stringify(result)}\n` : `${formatUsageText(result)}\n`);
    } else {
      process.stderr.write(`Unknown command: ${args.command}\n${usageText()}\n`);
      process.exitCode = 2;
    }
  } catch (err) {
    process.stderr.write(`Error: ${sanitizeInlineText((err as Error).message)}\n`);
    process.exitCode = 1;
  } finally {
    if (args.stats) {
      const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
      const maxRssKiB = process.resourceUsage().maxRSS;
      process.stderr.write(
        `stats: maxRssKiB=${maxRssKiB} elapsedMs=${elapsedMs.toFixed(2)}\n`,
      );
    }
  }
}

await run();

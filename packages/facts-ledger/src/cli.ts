#!/usr/bin/env node
import { defaultIndexPath, rebuildIndex } from './index-db.js';
import {
  createCommandEmbedder,
  createHttpEmbedder,
  formatQueryText,
  queryFacts,
  sanitizeInlineText,
} from './query.js';
import { type Embedder, type Sensitivity } from './types.js';

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
  };
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
    '',
    'Note: Ledger files are append-only; run `facts rebuild` after any manual edit or repair of historical lines.',
  ].join('\n');
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
      });
      if (args.json) {
        process.stdout.write(`${JSON.stringify(result)}\n`);
      } else {
        process.stdout.write(`${formatQueryText(result)}\n`);
      }
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

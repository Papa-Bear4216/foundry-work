#!/usr/bin/env node
import { defaultIndexPath, rebuildIndex } from './index-db.js';
import { formatQueryText, queryFacts } from './query.js';
import { type Sensitivity } from './types.js';

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
  readonly json: boolean;
  readonly stats: boolean;
  readonly positionals: readonly string[];
}

const VALID_MAX_SENSITIVITY = new Set(['public', 'personal', 'private', 'clinical', 'child']);

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
    json,
    stats,
    positionals,
  };
}

function usageText(): string {
  return [
    'Usage:',
    '  facts rebuild [--log <file>] [--index <file>] [--json] [--stats]',
    '  facts query [text] [--id <id>] [--tag <tag>] [--path <path>] [--commit <sha>] [--repo <name>] [--history] [--limit <n>] [--max-sensitivity <tier>] [--log <file>] [--index <file>] [--json] [--stats]',
  ].join('\n');
}

async function run(): Promise<void> {
  const started = process.hrtime.bigint();
  let args: ParsedArgs;
  try {
    args = parseCliArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n${usageText()}\n`);
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
    process.stderr.write(`Error: ${(err as Error).message}\n`);
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

// Step Zero 8 & 3.1 rule 7: streaming token usage reporter (`facts usage`).
// Keeps measured (provider-reported) and estimated totals strictly separate.
import { compareBytewise, scanLog } from './log.js';
import { sanitizeInlineText } from './query.js';
import { type ScanReport, type TokenUsage } from './types.js';

export interface UsageOptions {
  readonly logPath: string;
  readonly since?: string;
  readonly project?: string;
}

export interface TokenTotals {
  readonly blocks: number;
  readonly input: number;
  readonly output: number;
  readonly total: number;
}

export interface UsageGroup {
  readonly agent: string;
  readonly task: string;
  readonly models: readonly string[];
  readonly measured: TokenTotals;
  readonly estimated: TokenTotals;
}

export interface UsageReport {
  readonly logPath: string;
  readonly project: string | null;
  readonly since: string | null;
  readonly blocksScanned: number;
  readonly blocksWithUsage: number;
  readonly groups: readonly UsageGroup[];
  readonly totals: {
    readonly measured: TokenTotals;
    readonly estimated: TokenTotals;
  };
  readonly badLines: ScanReport;
}

interface MutableTotals {
  blocks: number;
  input: number;
  output: number;
}

interface MutableGroup {
  readonly agent: string;
  readonly task: string;
  readonly models: Set<string>;
  readonly measured: MutableTotals;
  readonly estimated: MutableTotals;
}

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/;

function parseSince(raw: string): number {
  const trimmed = raw.trim();
  if (!ISO_DATE_RE.test(trimmed)) {
    throw new Error(`Invalid --since timestamp (expected ISO-8601 date or timestamp): ${raw}`);
  }
  const ms = Date.parse(trimmed);
  if (!Number.isFinite(ms)) {
    throw new Error(`Invalid --since timestamp: ${raw}`);
  }
  return ms;
}

function isValidTokenUsage(value: unknown): value is TokenUsage {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const u = value as Record<string, unknown>;
  return (
    typeof u['model'] === 'string' &&
    u['model'].length > 0 &&
    typeof u['task'] === 'string' &&
    u['task'].length > 0 &&
    typeof u['input'] === 'number' &&
    Number.isSafeInteger(u['input']) &&
    u['input'] >= 0 &&
    typeof u['output'] === 'number' &&
    Number.isSafeInteger(u['output']) &&
    u['output'] >= 0 &&
    typeof u['measured'] === 'boolean'
  );
}

function freezeTotals(m: MutableTotals): TokenTotals {
  return {
    blocks: m.blocks,
    input: m.input,
    output: m.output,
    total: m.input + m.output,
  };
}

/**
 * Stream `options.logPath` with `scanLog` and aggregate `token_usage` by agent and task.
 * Superseded blocks are counted too (their token usage happened).
 * Measured (`measured: true`) and estimated (`measured: false`) totals are kept strictly apart.
 */
export function computeUsage(options: UsageOptions): UsageReport {
  const sinceMs = options.since !== undefined ? parseSince(options.since) : undefined;
  const projectFilter = options.project;
  const groups = new Map<string, MutableGroup>();
  const totalMeasured: MutableTotals = { blocks: 0, input: 0, output: 0 };
  const totalEstimated: MutableTotals = { blocks: 0, input: 0, output: 0 };
  let blocksScanned = 0;
  let blocksWithUsage = 0;

  const badLines = scanLog(options.logPath, (block) => {
    blocksScanned++;
    if (projectFilter !== undefined && block.project !== projectFilter) return;
    if (sinceMs !== undefined) {
      const tsMs = Date.parse(block.ts);
      if (!Number.isFinite(tsMs) || tsMs < sinceMs) return;
    }
    if (!isValidTokenUsage(block.token_usage)) return;

    blocksWithUsage++;
    const usage = block.token_usage;
    const key = `${block.agent}\u0000${usage.task}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        agent: block.agent,
        task: usage.task,
        models: new Set<string>(),
        measured: { blocks: 0, input: 0, output: 0 },
        estimated: { blocks: 0, input: 0, output: 0 },
      };
      groups.set(key, group);
    }
    group.models.add(usage.model);
    const bucket = usage.measured ? group.measured : group.estimated;
    const overall = usage.measured ? totalMeasured : totalEstimated;
    bucket.blocks++;
    bucket.input += usage.input;
    bucket.output += usage.output;
    overall.blocks++;
    overall.input += usage.input;
    overall.output += usage.output;
  });

  const sortedGroups: UsageGroup[] = [...groups.values()]
    .sort((a, b) => compareBytewise(a.agent, b.agent) || compareBytewise(a.task, b.task))
    .map((g) => ({
      agent: g.agent,
      task: g.task,
      models: [...g.models].sort(compareBytewise),
      measured: freezeTotals(g.measured),
      estimated: freezeTotals(g.estimated),
    }));

  return {
    logPath: options.logPath,
    project: projectFilter ?? null,
    since: options.since ?? null,
    blocksScanned,
    blocksWithUsage,
    groups: sortedGroups,
    totals: {
      measured: freezeTotals(totalMeasured),
      estimated: freezeTotals(totalEstimated),
    },
    badLines,
  };
}

function formatSection(
  title: string,
  rows: ReadonlyArray<{
    readonly agent: string;
    readonly task: string;
    readonly models: readonly string[];
    readonly totals: TokenTotals;
  }>,
  overall: TokenTotals,
): string[] {
  const lines = [title];
  if (rows.length === 0) {
    lines.push('  (none)');
    return lines;
  }
  for (const row of rows) {
    const models = row.models.map(sanitizeInlineText).join(',');
    lines.push(
      `  agent=${sanitizeInlineText(row.agent)} task=${sanitizeInlineText(row.task)} blocks=${row.totals.blocks} input=${row.totals.input} output=${row.totals.output} total=${row.totals.total} models=${models}`,
    );
  }
  lines.push(
    `  TOTAL blocks=${overall.blocks} input=${overall.input} output=${overall.output} total=${overall.total}`,
  );
  return lines;
}

export function formatUsageText(report: UsageReport): string {
  const lines: string[] = [];
  if (report.badLines.badLineCount > 0) {
    lines.push(
      `Warning: skipped ${report.badLines.badLineCount} bad log line(s) at line(s): ${report.badLines.badLineNumbers.join(', ')}`,
    );
  }
  const filters: string[] = [];
  if (report.project !== null) filters.push(`project=${sanitizeInlineText(report.project)}`);
  if (report.since !== null) filters.push(`since=${sanitizeInlineText(report.since)}`);
  const filterText = filters.length > 0 ? ` (${filters.join(', ')})` : '';
  lines.push(
    `Usage${filterText}: scanned ${report.blocksScanned} block(s), ${report.blocksWithUsage} with token_usage.`,
  );
  lines.push('Measured and estimated token counts are reported separately and never combined.');

  const measuredRows = report.groups
    .filter((g) => g.measured.blocks > 0)
    .map((g) => ({ agent: g.agent, task: g.task, models: g.models, totals: g.measured }));
  const estimatedRows = report.groups
    .filter((g) => g.estimated.blocks > 0)
    .map((g) => ({ agent: g.agent, task: g.task, models: g.models, totals: g.estimated }));

  lines.push(...formatSection('Measured (provider-reported):', measuredRows, report.totals.measured));
  lines.push(...formatSection('Estimated (not provider-reported):', estimatedRows, report.totals.estimated));
  return lines.join('\n');
}

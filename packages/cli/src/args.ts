/**
 * Command table and argument parsing (design 4.2, 4.3, 4.4; P-1 profile/consent/collection commands).
 *
 * Order: a loose parse finds the command words, `guardSecretInput` runs on the tokens and the environment, and only
 * then the strict parse runs. Usage errors never quote argv text (an argument could be a mistyped secret).
 */
import { parseArgs } from 'node:util';
import type { ParseArgsOptionConfig } from 'node:util';
import { guardSecretInput } from 'vault';
import { usage } from './errors.ts';

export type CommandName =
  | 'init'
  | 'import'
  | 'search'
  | 'vault verify'
  | 'index rebuild'
  | 'vault reset-passphrase'
  | 'profile add'
  | 'profile list'
  | 'consent record'
  | 'consent list'
  | 'collection prompt-policy'
  | 'collection list';

/** Seconds (design 4.8). */
export const DEFAULT_TIMEOUTS: Readonly<Record<CommandName, number>> = {
  'init': 120,
  'vault reset-passphrase': 120,
  'search': 120,
  'profile add': 120,
  'profile list': 120,
  'consent record': 120,
  'consent list': 120,
  'collection prompt-policy': 120,
  'collection list': 120,
  'vault verify': 3600,
  'import': 21600,
  'index rebuild': 21600,
};

export const MAX_TIMEOUT_SECONDS = 604800;

interface CommandSpec {
  words: number;
  positional?: 'path' | 'query' | 'profile' | 'collection';
  options: readonly string[];
  keyed: boolean;
}

const COMMON = ['vault', 'timeout', 'debug', 'help'] as const;
const CREDENTIAL = ['passphrase-stdin', 'recovery-key-stdin'] as const;
const FILTERS = ['from', 'until', 'source', 'profile', 'collection', 'tier', 'limit'] as const;
const P1_STRING_OPTIONS = ['display-name', 'basis', 'note', 'child-prompts'] as const;

const COMMANDS: Readonly<Record<CommandName, CommandSpec>> = {
  'init': { words: 1, options: [...COMMON, 'passphrase-stdin'], keyed: false },
  'import': { words: 1, positional: 'path', options: [...COMMON, ...CREDENTIAL, 'json', 'profile', 'collection'], keyed: true },
  'search': { words: 1, positional: 'query', options: [...COMMON, ...CREDENTIAL, 'json', ...FILTERS], keyed: true },
  'vault verify': { words: 2, options: [...COMMON, 'json'], keyed: false },
  'index rebuild': { words: 2, options: [...COMMON, ...CREDENTIAL, 'json'], keyed: true },
  'vault reset-passphrase': { words: 2, options: [...COMMON, ...CREDENTIAL], keyed: false },
  'profile add': { words: 2, positional: 'profile', options: [...COMMON, ...CREDENTIAL, 'json', 'display-name'], keyed: true },
  'profile list': { words: 2, options: [...COMMON, ...CREDENTIAL, 'json', 'reveal'], keyed: true },
  'consent record': { words: 2, positional: 'profile', options: [...COMMON, ...CREDENTIAL, 'json', 'basis', 'note'], keyed: true },
  'consent list': { words: 2, options: [...COMMON, ...CREDENTIAL, 'json', 'reveal'], keyed: true },
  'collection prompt-policy': { words: 2, positional: 'collection', options: [...COMMON, ...CREDENTIAL, 'json', 'child-prompts'], keyed: true },
  'collection list': { words: 2, options: [...COMMON, ...CREDENTIAL, 'json'], keyed: true },
};

const STRING_OPTIONS = new Set(['vault', 'timeout', ...FILTERS, ...P1_STRING_OPTIONS]);
// `reveal` is a boolean (it takes no value), so the loose parse and `guardSecretInput` never count the token after
// it as its value: that token stays a positional and is counted against the declared positionals.
const ALL_OPTIONS: Record<string, ParseArgsOptionConfig> = Object.fromEntries(
  [...new Set([...COMMON, ...CREDENTIAL, ...FILTERS, ...P1_STRING_OPTIONS, 'json', 'reveal', 'version'])]
    .map(name => [name, { type: STRING_OPTIONS.has(name) ? 'string' : 'boolean' } as ParseArgsOptionConfig]),
);
ALL_OPTIONS.help = { type: 'boolean', short: 'h' };

export interface SearchFilters {
  from?: string;
  until?: string;
  source?: string;
  profile?: string;
  collection?: string;
  tier?: string;
  limit?: number;
}

export type ParsedCommand =
  | { kind: 'help'; command?: CommandName }
  | { kind: 'version' }
  | {
    kind: 'run';
    command: CommandName;
    vault?: string;
    timeoutSeconds: number;
    debug: boolean;
    json: boolean;
    passphraseStdin: boolean;
    recoveryKeyStdin: boolean;
    path?: string;
    query?: string;
    targetProfile?: string;
    targetCollection?: string;
    importProfile?: string;
    importCollection?: string;
    displayName?: string;
    basis?: string;
    note?: string;
    childPrompts?: boolean;
    reveal: boolean;
    filters: SearchFilters;
  };

function commandOf(positionals: readonly string[]): CommandName | undefined {
  const [first, second] = positionals;
  if (first === 'init' || first === 'import' || first === 'search') return first;
  if (first === 'vault' && (second === 'verify' || second === 'reset-passphrase')) return `vault ${second}`;
  if (first === 'index' && second === 'rebuild') return 'index rebuild';
  if (first === 'profile' && (second === 'add' || second === 'list')) return `profile ${second}`;
  if (first === 'consent' && (second === 'record' || second === 'list')) return `consent ${second}`;
  if (first === 'collection' && (second === 'prompt-policy' || second === 'list')) return `collection ${second}`;
  return undefined;
}

function integerOption(raw: string | boolean | undefined, name: string, min: number, max: number): number | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || !/^[0-9]{1,7}$/u.test(raw)) throw usage(`--${name} needs a whole number from ${min} to ${max}`);
  const value = Number(raw);
  if (value < min || value > max) throw usage(`--${name} needs a whole number from ${min} to ${max}`);
  return value;
}

function dateOption(raw: string | boolean | undefined, name: string): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== 'string' || raw.length > 64 || Number.isNaN(new Date(raw).getTime())) {
    throw usage(`--${name} needs a date such as 2024-01-31 or 2024-01-31T12:00:00Z`);
  }
  return raw;
}

function textOption(raw: string | boolean | undefined): string | undefined {
  return typeof raw === 'string' ? raw : undefined;
}

function childPromptsOption(raw: string | boolean | undefined): boolean {
  if (raw === 'on') return true;
  if (raw === 'off') return false;
  throw usage('--child-prompts needs on or off');
}

function missingPositionalMessage(kind: NonNullable<CommandSpec['positional']>): string {
  switch (kind) {
    case 'path':
      return 'name the archive file or folder to import';
    case 'query':
      return 'give a search query';
    case 'profile':
      return 'give a profile identifier (me, partner, child or other)';
    case 'collection':
      return 'give a collection name';
  }
}

/** Parse argv (without the node and script paths). Throws `CliError` (exit 1) or the guard's plain `Error`. */
export function parseCommandLine(argv: readonly string[], env: Readonly<Record<string, string | undefined>>): ParsedCommand {
  const args = [...argv];
  let loose;
  try {
    loose = parseArgs({ args, options: ALL_OPTIONS, strict: false, allowPositionals: true, tokens: true });
  } catch {
    throw usage('the command line could not be read; see `foundry --help`');
  }
  const command = commandOf(loose.positionals);
  const spec = command === undefined ? undefined : COMMANDS[command];
  const declared = spec === undefined ? Math.min(loose.positionals.length, 2) : spec.words + (spec.positional ? 1 : 0);
  // Design 4.4: the secret-input guard runs first, before any other decision about the arguments.
  guardSecretInput({ tokens: loose.tokens ?? [] }, env, declared);

  if (command === undefined || spec === undefined) {
    if (loose.positionals.length === 0 && loose.values.version === true) return { kind: 'version' };
    if (loose.positionals.length === 0 && loose.values.help === true) return { kind: 'help' };
    throw usage('unknown command; see `foundry --help`');
  }

  const options: Record<string, ParseArgsOptionConfig> = {};
  for (const name of spec.options) options[name] = ALL_OPTIONS[name]!;
  let parsed;
  try {
    parsed = parseArgs({ args, options, strict: true, allowPositionals: true });
  } catch {
    throw usage(`unknown option or missing value; see \`foundry ${command} --help\``);
  }
  const { values, positionals } = parsed;
  if (values.help === true) return { kind: 'help', command };
  const operand = positionals[spec.words];
  if (spec.positional) {
    const missing =
      operand === undefined ||
      ((spec.positional === 'path' || spec.positional === 'query') && operand === '');
    if (missing) throw usage(missingPositionalMessage(spec.positional));
  }
  if (positionals.length > spec.words + (spec.positional ? 1 : 0)) throw usage('too many arguments');
  const passphraseStdin = values['passphrase-stdin'] === true;
  const recoveryKeyStdin = values['recovery-key-stdin'] === true;
  if (spec.keyed && passphraseStdin && recoveryKeyStdin) {
    throw usage('give either --passphrase-stdin or --recovery-key-stdin, not both');
  }
  const vault = textOption(values.vault);
  if (values.vault !== undefined && !vault) throw usage('--vault needs a folder');

  const basis = command === 'consent record' ? textOption(values.basis) : undefined;
  if (command === 'consent record' && basis === undefined) {
    throw usage('--basis is required; see `foundry consent record --help`');
  }
  const childPrompts =
    command === 'collection prompt-policy' ? childPromptsOption(values['child-prompts']) : undefined;

  return {
    kind: 'run',
    command,
    vault,
    timeoutSeconds: integerOption(values.timeout, 'timeout', 1, MAX_TIMEOUT_SECONDS) ?? DEFAULT_TIMEOUTS[command],
    debug: values.debug === true,
    json: values.json === true,
    passphraseStdin,
    recoveryKeyStdin,
    path: spec.positional === 'path' ? operand : undefined,
    query: spec.positional === 'query' ? operand : undefined,
    targetProfile: spec.positional === 'profile' ? operand : undefined,
    targetCollection: spec.positional === 'collection' ? operand : undefined,
    importProfile: command === 'import' ? textOption(values.profile) : undefined,
    importCollection: command === 'import' ? textOption(values.collection) : undefined,
    displayName: command === 'profile add' ? textOption(values['display-name']) : undefined,
    basis,
    note: command === 'consent record' ? textOption(values.note) : undefined,
    childPrompts,
    reveal: values.reveal === true,
    filters: command !== 'search' ? {} : {
      from: dateOption(values.from, 'from'),
      until: dateOption(values.until, 'until'),
      source: textOption(values.source),
      profile: textOption(values.profile),
      collection: textOption(values.collection),
      tier: textOption(values.tier),
      limit: integerOption(values.limit, 'limit', 1, 1000),
    },
  };
}

export function isKeyed(command: CommandName): boolean {
  return COMMANDS[command].keyed;
}

export const HELP: Readonly<Record<CommandName | 'main', string>> = {
  main: `Usage: foundry <command> [options]

Commands:
  init                                      Create a new vault (asks for a new passphrase).
  import <archive|folder>                   Import a Takeout archive, then update the index.
  search <query>                            Search the index.
  profile add <me|partner|child|other>      Add or update a generic profile in the vault.
  profile list                              List profiles recorded in the vault.
  consent record <partner|child|other>      Record consent for storing another person's data.
  consent list                              List active and historical consent records.
  collection prompt-policy <collection>     Switch child-tier model prompt inclusion on or off.
  collection list                           List collections and their prompt policies.
  vault verify                              Check the vault without a key.
  vault reset-passphrase                    Set a new passphrase with the recovery key.
  index rebuild                             Build a new index from the vault.

Global options:
  --vault <dir>      Foundry home folder. Default: $FOUNDRY_HOME, else <home>/Foundry.
  --timeout <s>      Wall-clock limit in seconds (1 to 604800).
  --debug            Show error details (never secrets).
  --json             Machine output.
  --help, --version

Secrets are never read from arguments or environment variables. They come from a
terminal prompt, or from stdin with --passphrase-stdin / --recovery-key-stdin.
`,
  'init': 'Usage: foundry init [--vault <dir>] [--passphrase-stdin]\n',
  'import': 'Usage: foundry import <archive.zip|first-part.zip|folder> [--profile <me|partner|child|other>] [--collection <profile>/<name>]\n'
    + '       [--json] [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  A --collection name must start with the import profile and a slash, for example me/holidays.\n',
  'search': 'Usage: foundry search <query> [--from <date>] [--until <date>] [--source <s>] [--profile <p>]\n'
    + '       [--collection <c>] [--tier <t>] [--limit <1-1000>] [--json] [--passphrase-stdin | --recovery-key-stdin]\n',
  'vault verify': 'Usage: foundry vault verify [--json]\n',
  'index rebuild': 'Usage: foundry index rebuild [--json] [--passphrase-stdin | --recovery-key-stdin]\n',
  'vault reset-passphrase': 'Usage: foundry vault reset-passphrase [--recovery-key-stdin] [--passphrase-stdin]\n'
    + '  With both flags, stdin line 1 is the recovery key and line 2 the new passphrase.\n',
  'profile add': 'Usage: foundry profile add <me|partner|child|other> [--display-name <name>] [--json]\n'
    + '       [--passphrase-stdin | --recovery-key-stdin]\n',
  'profile list': 'Usage: foundry profile list [--reveal] [--json] [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  Display names are shown as "(name set)" unless you give --reveal.\n',
  'consent record': 'Usage: foundry consent record <partner|child|other> --basis <exported-by-them|parent-or-guardian|shared-conversation|other>\n'
    + '       [--note <text>] [--json] [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  --basis other needs a --note that says what the basis is.\n'
    + '  The note is free text, stored under the owner\'s (me) key, and it stays after the other person\'s data is erased.\n'
    + '  Do not write names or other identifying details in the note.\n',
  'consent list': 'Usage: foundry consent list [--reveal] [--json] [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  Consent notes are shown as "(note set)" unless you give --reveal.\n',
  'collection prompt-policy': 'Usage: foundry collection prompt-policy <profile>/<collection> --child-prompts <on|off> [--json]\n'
    + '       [--passphrase-stdin | --recovery-key-stdin]\n',
  'collection list': 'Usage: foundry collection list [--json] [--passphrase-stdin | --recovery-key-stdin]\n',
};

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
  | 'collection list'
  // P-3: Mode B second copy, write-once export and reminders (Architecture 8.1, A-44).
  | 'vault copy init'
  | 'vault seal'
  | 'vault session'
  | 'vault status'
  | 'vault reminder'
  | 'vault export-iso'
  | 'vault verify-copy'
  | 'vault schedule set'
  | 'vault schedule status'
  | 'vault schedule remove';

/** P-3 commands: `vault copy init`, `vault seal` and `vault session` are keyed; the others never read a key. */
export const SECOND_COPY_COMMANDS: readonly CommandName[] = [
  'vault copy init', 'vault seal', 'vault session', 'vault status', 'vault reminder', 'vault export-iso',
  'vault verify-copy', 'vault schedule set', 'vault schedule status', 'vault schedule remove',
];

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
  'vault copy init': 600,
  'vault status': 120,
  'vault schedule set': 120,
  'vault schedule status': 120,
  'vault schedule remove': 120,
  'vault reminder': 3600,
  'vault seal': 21600,
  'vault session': 21600,
  'vault export-iso': 21600,
  'vault verify-copy': 3600,
};

export const MAX_TIMEOUT_SECONDS = 604800;

interface CommandSpec {
  words: number;
  positional?: 'path' | 'query' | 'profile' | 'collection' | 'target' | 'output';
  options: readonly string[];
  keyed: boolean;
}

const COMMON = ['vault', 'timeout', 'debug', 'help'] as const;
const CREDENTIAL = ['passphrase-stdin', 'recovery-key-stdin'] as const;
const FILTERS = ['from', 'until', 'source', 'profile', 'collection', 'tier', 'limit'] as const;
const P1_STRING_OPTIONS = ['display-name', 'basis', 'note', 'child-prompts'] as const;
const P3_STRING_OPTIONS = ['label', 'copy', 'anchor-svg', 'cadence', 'anchor'] as const;
const P3_BOOLEAN_OPTIONS = ['qr-invert', 'include-keyring-irreversible', 'verify', 'adopt'] as const;

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
  'collection list': { words: 2, options: [...COMMON, ...CREDENTIAL, 'json', 'reveal'], keyed: true },
  // Keyed since fix round 1 (R18-2): it appends a `copy.registered` event before it writes the register.
  'vault copy init': { words: 3, positional: 'target', options: [...COMMON, ...CREDENTIAL, 'json', 'label', 'adopt'], keyed: true },
  'vault seal': { words: 2, positional: 'target', options: [...COMMON, ...CREDENTIAL, 'json', 'copy', 'anchor-svg', 'qr-invert'], keyed: true },
  'vault session': { words: 2, positional: 'target', options: [...COMMON, ...CREDENTIAL, 'json', 'copy', 'anchor-svg', 'qr-invert'], keyed: true },
  'vault status': { words: 2, options: [...COMMON, 'json'], keyed: false },
  'vault reminder': { words: 2, options: [...COMMON, 'json', 'verify'], keyed: false },
  'vault export-iso': { words: 2, positional: 'output', options: [...COMMON, 'json', 'include-keyring-irreversible'], keyed: false },
  // Keyless check of a second copy against an anchor or the recorded seal (fix round 1, finding 32).
  'vault verify-copy': { words: 2, positional: 'target', options: [...COMMON, 'json', 'anchor', 'copy'], keyed: false },
  'vault schedule set': { words: 3, options: [...COMMON, 'json', 'cadence', 'verify'], keyed: false },
  'vault schedule status': { words: 3, options: [...COMMON, 'json'], keyed: false },
  'vault schedule remove': { words: 3, options: [...COMMON, 'json'], keyed: false },
};

const STRING_OPTIONS = new Set(['vault', 'timeout', ...FILTERS, ...P1_STRING_OPTIONS, ...P3_STRING_OPTIONS]);
// `reveal` is a boolean (it takes no value), so the loose parse and `guardSecretInput` never count the token after
// it as its value: that token stays a positional and is counted against the declared positionals.
const ALL_OPTIONS: Record<string, ParseArgsOptionConfig> = Object.fromEntries(
  [...new Set([...COMMON, ...CREDENTIAL, ...FILTERS, ...P1_STRING_OPTIONS, ...P3_STRING_OPTIONS, ...P3_BOOLEAN_OPTIONS,
    'json', 'reveal', 'version'])]
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
    /** P-3: the second-copy folder (`vault copy init`, `vault seal`, `vault session`). */
    target?: string;
    /** P-3: the image file `vault export-iso` writes. */
    output?: string;
    label?: string;
    copyLabel?: string;
    anchorSvg?: string;
    qrInvert?: boolean;
    includeKeyring?: boolean;
    cadence?: string;
    verifyChain?: boolean;
    adopt?: boolean;
    /** `vault verify-copy --anchor`: the compact anchor text. */
    anchor?: string;
  };

function commandOf(positionals: readonly string[]): CommandName | undefined {
  const [first, second, third] = positionals;
  // P-3: three-word commands are checked first; they never match an earlier two-word command.
  if (first === 'vault' && second === 'copy' && third === 'init') return 'vault copy init';
  if (first === 'vault' && second === 'schedule' && (third === 'set' || third === 'status' || third === 'remove')) {
    return `vault schedule ${third}`;
  }
  if (first === 'vault' && (second === 'seal' || second === 'session' || second === 'status' || second === 'reminder'
    || second === 'export-iso' || second === 'verify-copy')) {
    return `vault ${second}`;
  }
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
    case 'target':
      return 'name the second-copy folder on the external drive';
    case 'output':
      return 'name the image file to write, for example vault.iso';
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
      ((spec.positional === 'path' || spec.positional === 'query' || spec.positional === 'target'
        || spec.positional === 'output') && operand === '');
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
  const cadence = command === 'vault schedule set' ? textOption(values.cadence) : undefined;
  if (command === 'vault schedule set' && !['daily', 'weekly', 'monthly', 'manual'].includes(cadence ?? '')) {
    throw usage('--cadence needs daily, weekly, monthly or manual');
  }
  for (const name of ['label', 'copy', 'anchor-svg'] as const) {
    if (values[name] !== undefined && !textOption(values[name])) throw usage(`--${name} needs a value`);
  }

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
    ...(spec.positional === 'target' ? { target: operand } : {}),
    ...(spec.positional === 'output' ? { output: operand } : {}),
    ...(SECOND_COPY_COMMANDS.includes(command) ? {
      label: textOption(values.label),
      copyLabel: textOption(values.copy),
      anchorSvg: textOption(values['anchor-svg']),
      anchor: textOption(values.anchor),
      qrInvert: values['qr-invert'] === true,
      includeKeyring: values['include-keyring-irreversible'] === true,
      cadence,
      verifyChain: values.verify === true,
      adopt: values.adopt === true,
    } : {}),
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
  vault copy init <folder>                  Prepare a second-copy folder on an external drive.
  vault seal <folder>                       Seal the vault and bring the second copy up to date.
  vault session <folder>                    The same as vault seal (the Mode B vault session).
  vault status                              Show the second copies and when each was last sealed.
  vault export-iso <file.iso>               Write the sealed vault as a disc image (no keyring).
  vault verify-copy <folder>                Check a second copy against an anchor or the last seal (no key).
  vault schedule set --cadence <c>          Install a reminder: daily, weekly, monthly or manual.
  vault schedule status                     Show the installed reminder.
  vault schedule remove                     Remove the reminder.
  vault reminder                            Check the seal age (run by the reminder; no key).

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
    + '       [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  The output names a default collection (<profile>/<source>/<year>); a custom name is shown as "(custom)".\n',
  'collection list': 'Usage: foundry collection list [--reveal] [--json] [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  Custom collection names are shown as "custom collection N" unless you give --reveal.\n',
  'vault copy init': 'Usage: foundry vault copy init <folder> [--label <name>] [--adopt] [--json]\n'
    + '       [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  The folder must be on an external drive formatted exFAT, NTFS, ext4, APFS or similar (FAT32 is refused).\n'
    + '  It must be empty, an unfinished copy init of this device, or a second copy of this vault.\n'
    + '  --label: letters, digits, dot, dash, underscore (1-32). Repeat with the same --label to finish an\n'
    + '  interrupted init. --adopt: take over a copy of this vault that another record or device set up (its copy id\n'
    + '  is replaced; the old and new ids are printed).\n',
  'vault seal': 'Usage: foundry vault seal <folder> [--copy <label>] [--anchor-svg <file.svg>] [--qr-invert] [--json]\n'
    + '       [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  Checks the drive without a key, stops on a rolled-back or different chain, then closes the open segment,\n'
    + '  copies the new segments and the keyring, re-checks them and marks them read-only. Prints the chain anchor\n'
    + '  as text and as a QR code. Afterwards: switch on the drive\'s write-protect and disconnect it.\n',
  'vault session': 'Usage: foundry vault session <folder> [--copy <label>] [--anchor-svg <file.svg>] [--qr-invert] [--json]\n'
    + '       [--passphrase-stdin | --recovery-key-stdin]\n'
    + '  The Mode B vault session; the same steps as foundry vault seal.\n',
  'vault status': 'Usage: foundry vault status [--json]\n'
    + '  Shows each second copy, its last seal, whether its keyring copy is current, and the overdue banner.\n',
  'vault reminder': 'Usage: foundry vault reminder [--verify] [--json]\n'
    + '  Checks the seal age against the cadence and records the check. --verify also runs the keyless vault check.\n'
    + '  The scheduled reminder runs this command; it never reads a key.\n',
  'vault export-iso': 'Usage: foundry vault export-iso <file.iso> [--include-keyring-irreversible] [--json]\n'
    + '  Writes VAULT.json, HEAD.json and every sealed segment as an ISO 9660 + Joliet image. The keyring is left out:\n'
    + '  a key burned to a disc can never be erased. --include-keyring-irreversible adds it anyway.\n',
  'vault verify-copy': 'Usage: foundry vault verify-copy <folder> [--anchor <compact anchor>] [--copy <label>] [--json]\n'
    + '  Checks a second copy without a key. With --anchor (the "compact" line of a printed anchor), the copy must hold\n'
    + '  that segment with that hash, so an older copy fails; no Foundry folder is needed. Without it, the copy must hold\n'
    + '  the last seal recorded on this device for it (a copy never sealed here cannot be checked this way).\n',
  'vault schedule set': 'Usage: foundry vault schedule set --cadence <daily|weekly|monthly|manual> [--verify] [--json]\n'
    + '  Windows: a per-user Task Scheduler task. Linux: a systemd --user timer, else a crontab line.\n'
    + '  manual: no reminder job; the overdue banner still shows after 14 days.\n',
  'vault schedule status': 'Usage: foundry vault schedule status [--json]\n',
  'vault schedule remove': 'Usage: foundry vault schedule remove [--json]\n',
};

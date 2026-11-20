import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';

/** Repository name -> absolute local checkout. Names enter the log; paths never do. */
export type RepoMap = ReadonlyMap<string, string>;

export const REPO_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function assertRepoName(name: unknown): asserts name is string {
  if (typeof name !== 'string' || !REPO_NAME_RE.test(name)) {
    throw new Error(`Invalid repo name (a name, never a path): ${JSON.stringify(name)}`);
  }
}

/**
 * A repository-relative path: forward slashes, no `..` segment, no drive, no leading
 * slash, no pathspec magic, no control characters.
 */
export function assertRelativePath(path: unknown): asserts path is string {
  if (
    typeof path !== 'string' ||
    path.length === 0 ||
    path.length > 1024 ||
    path.startsWith('/') ||
    path.startsWith('-') ||
    path.includes('\\') ||
    path.includes(':') ||
    /[\u0000-\u001f\u007f]/.test(path) ||
    path.split('/').some((seg) => seg === '' || seg === '.' || seg === '..')
  ) {
    throw new Error(`Invalid repository-relative path: ${JSON.stringify(path)}`);
  }
}

/** Per-machine config location, outside any repository. `FACTS_LEDGER_REPOS` overrides. */
export function defaultRepoMapPath(): string {
  const override = process.env['FACTS_LEDGER_REPOS'];
  if (override) return override;
  if (process.platform === 'win32') {
    const appData = process.env['APPDATA'] || join(homedir(), 'AppData', 'Roaming');
    return join(appData, 'facts-ledger', 'repos.json');
  }
  const xdg = process.env['XDG_CONFIG_HOME'] || join(homedir(), '.config');
  return join(xdg, 'facts-ledger', 'repos.json');
}

function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

/**
 * Load the repo map: a JSON object `{ "<name>": "<absolute path>" }`. A missing file is
 * an empty map (every `file` evidence is then `unverifiable`). The file must not live
 * inside any repository it maps.
 */
export function loadRepoMap(path = defaultRepoMapPath()): RepoMap {
  if (!existsSync(path)) return new Map();
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new Error(`Repo map is not valid JSON: ${path}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Repo map must be a JSON object of name -> absolute path');
  }
  const map = new Map<string, string>();
  const configReal = realpathSync(path);
  for (const [name, dir] of Object.entries(parsed as Record<string, unknown>)) {
    assertRepoName(name);
    if (typeof dir !== 'string' || !isAbsolute(dir)) {
      throw new Error(`Repo map entry ${name} must be an absolute path`);
    }
    const abs = resolve(dir);
    const real = existsSync(abs) ? realpathSync(abs) : abs;
    if (isInside(real, configReal)) {
      throw new Error(`Repo map must live outside the repositories it maps (${name})`);
    }
    map.set(name, real);
  }
  return map;
}

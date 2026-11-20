/**
 * Secret-pattern scan (Step Zero 3.2). Runs over `claim`, `note`, `quote` and command
 * output before anything is written. A hit rejects the write. The list is deliberately
 * small and high-precision; it is a guard, not a full secret scanner.
 */
const SECRET_PATTERNS: readonly { readonly name: string; readonly re: RegExp }[] = [
  { name: 'private key block', re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ },
  { name: 'AWS access key id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'GitHub token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/ },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'API secret key', re: /\bsk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/ },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'JSON web token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  {
    name: 'credential assignment',
    re: /\b(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?token|auth[_-]?token|bearer)\b\s*[:=]\s*["']?[^\s"']{8,}/i,
  },
];

/** Return the name of the first secret pattern found in `text`, or null. */
export function findSecret(text: string): string | null {
  for (const { name, re } of SECRET_PATTERNS) {
    if (re.test(text)) return name;
  }
  return null;
}

/** Throw if any field contains a secret pattern. The message never echoes the match. */
export function assertNoSecrets(fields: Readonly<Record<string, string | null | undefined>>): void {
  for (const [field, value] of Object.entries(fields)) {
    if (typeof value !== 'string' || value.length === 0) continue;
    const hit = findSecret(value);
    if (hit) throw new Error(`Secret pattern (${hit}) found in ${field}; write rejected`);
  }
}

/**
 * Rule-only generic sensitivity classification (Product Spec section 9, Extraction Plan section 2).
 *
 * Zero network calls, zero model calls, zero household-specific identifiers.
 * The whole item is scanned through overlapping windows: at most `SCAN_WINDOW_BYTES` of bytes (or
 * UTF-16 code units for string input) are decoded or sliced at a time, and each window overlaps the
 * previous one by `SCAN_OVERLAP_BYTES`. Every shipped pattern has a bounded longest match shorter than
 * the overlap, so a match that crosses a window edge lies whole inside the next window.
 */
import type {
  ClassificationInput,
  ClassificationResult,
  SensitivityTier,
  UserSensitivityRule,
} from './types.ts';
import { assertSensitivityTier, assertUserSensitivityRule } from './validation.ts';

/** Maximum bytes (or UTF-16 code units for string input) decoded or sliced per scan window (64 KiB). */
export const SCAN_WINDOW_BYTES = 64 * 1024;
/** Minimum overlap between two consecutive scan windows (4 KiB). Longer than every shipped match. */
export const SCAN_OVERLAP_BYTES = 4 * 1024;

const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

/** Precedence rank (`secret > child > clinical > private > personal > public`). */
export const SENSITIVITY_PRECEDENCE: Readonly<Record<SensitivityTier, number>> = Object.freeze({
  public: 0,
  personal: 1,
  private: 2,
  clinical: 3,
  child: 4,
  secret: 5,
});

export const DEFAULT_SENSITIVITY_BY_SOURCE: Readonly<Record<string, SensitivityTier>> = Object.freeze({
  'google-takeout/contacts': 'personal',
  'google-takeout/calendar': 'personal',
  'google-takeout/mail': 'personal',
});

export function defaultSensitivityForSource(source: string): SensitivityTier {
  return Object.hasOwn(DEFAULT_SENSITIVITY_BY_SOURCE, source)
    ? DEFAULT_SENSITIVITY_BY_SOURCE[source]!
    : 'personal';
}

export function compareSensitivity(a: SensitivityTier, b: SensitivityTier): number {
  return SENSITIVITY_PRECEDENCE[a] - SENSITIVITY_PRECEDENCE[b];
}

export function maxSensitivity(a: SensitivityTier, b: SensitivityTier): SensitivityTier {
  return compareSensitivity(a, b) >= 0 ? a : b;
}

function trimUtf8End(bytes: Uint8Array, limit: number): number {
  let end = Math.min(limit, bytes.byteLength);
  if (end <= 0 || end >= bytes.byteLength) return end;
  if ((bytes[end]! & 0xc0) !== 0x80) return end;
  let lead = end - 1;
  while (lead > 0 && end - lead < 4 && (bytes[lead]! & 0xc0) === 0x80) {
    lead--;
  }
  return (bytes[lead]! & 0xc0) === 0xc0 ? lead : end;
}

/**
 * Yields the decoded windows of `bytes`, one at a time (never the whole item as one string).
 *
 * A window is at most `SCAN_WINDOW_BYTES` bytes, its end moved back to a UTF-8 character start. The next
 * window starts at least `SCAN_OVERLAP_BYTES` before the previous end, moved back to a character start. So
 * every byte span of at most `SCAN_OVERLAP_BYTES` bytes lies whole inside one window. Each window starts
 * more than 60 KiB after the previous start, so the loop always advances.
 */
export function* byteScanWindows(bytes: Uint8Array): Generator<string, void, undefined> {
  const total = bytes.byteLength;
  let start = 0;
  while (start < total) {
    if (total - start <= SCAN_WINDOW_BYTES) {
      yield utf8Decoder.decode(bytes.subarray(start, total));
      return;
    }
    const end = trimUtf8End(bytes, start + SCAN_WINDOW_BYTES);
    yield utf8Decoder.decode(bytes.subarray(start, end));
    let next = end - SCAN_OVERLAP_BYTES;
    for (let back = 0; back < 3 && (bytes[next]! & 0xc0) === 0x80; back++) next--;
    start = next;
  }
}

const isHighSurrogate = (code: number): boolean => code >= 0xd800 && code <= 0xdbff;
const isLowSurrogate = (code: number): boolean => code >= 0xdc00 && code <= 0xdfff;

/**
 * Yields windows of `text` of at most `SCAN_WINDOW_BYTES` UTF-16 code units, overlapping by at least
 * `SCAN_OVERLAP_BYTES` code units, never cutting a surrogate pair. Windows are `slice`s, not copies of
 * the whole string. A match of B UTF-8 bytes is at most B code units, so the byte bound covers strings.
 */
export function* stringScanWindows(text: string): Generator<string, void, undefined> {
  const total = text.length;
  let start = 0;
  while (start < total) {
    if (total - start <= SCAN_WINDOW_BYTES) {
      yield start === 0 ? text : text.slice(start);
      return;
    }
    let end = start + SCAN_WINDOW_BYTES;
    if (isHighSurrogate(text.charCodeAt(end - 1))) end--;
    yield text.slice(start, end);
    let next = end - SCAN_OVERLAP_BYTES;
    if (isLowSurrogate(text.charCodeAt(next))) next--;
    start = next;
  }
}

const PLACEHOLDER_VALUES = new Set([
  'none',
  'null',
  'nil',
  'false',
  'true',
  'undefined',
  'redacted',
  '[redacted]',
  'changeme',
  'example',
  'placeholder',
  'your_api_key',
  'your_api_key_here',
  'your-api-key',
  'your_secret_here',
  'insert_here',
]);

function isPlaceholderCredential(raw: string): boolean {
  const lower = raw.toLowerCase();
  if (PLACEHOLDER_VALUES.has(lower)) return true;
  if (/^[*x._-]{4,}$/iu.test(raw)) return true;
  if ((raw.startsWith('<') && raw.endsWith('>')) || (raw.startsWith('${') && raw.endsWith('}'))) {
    return true;
  }
  return false;
}

function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<number, number>();
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    counts.set(code, (counts.get(code) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function characterClassCount(value: string): number {
  let upper = 0;
  let lower = 0;
  let digit = 0;
  let symbol = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c >= 0x41 && c <= 0x5a) upper = 1;
    else if (c >= 0x61 && c <= 0x7a) lower = 1;
    else if (c >= 0x30 && c <= 0x39) digit = 1;
    else symbol = 1;
  }
  return upper + lower + digit + symbol;
}

// Every whitespace / separator run below is bounded (`{0,16}`, `{1,16}`, `{1,32}`) so that the longest
// possible match of every shipped pattern stays below `SCAN_OVERLAP_BYTES` (A1, P-1 fix round 1).
const PRIVATE_KEY_RE =
  /-----BEGIN[ \t]{1,16}(?:[A-Z0-9-]{1,32}[ \t]{1,16}){0,5}PRIVATE[ \t]{1,16}KEY(?:[ \t]{1,16}BLOCK)?-----|PuTTY-User-Key-File-[23]:/iu;

// Global: every match is checked, so a placeholder in an early match cannot hide a later credential (A3).
const BEARER_HEADER_RE =
  /\bAuthorization[ \t]{0,16}:[ \t]{0,16}Bearer[ \t]{1,16}([A-Za-z0-9._~+/=-]{16,512})/giu;

const KNOWN_TOKEN_PREFIX_RE =
  /\b(?:sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,256}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|xox[baprs]-[A-Za-z0-9-]{16,255}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,512}\.eyJ[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512})\b/u;

// P-1 fix round 2 (C2): an optional closing quote after the key name, so JSON / quoted keys
// (`"api_key": "..."`, `'secret' = '...'`) are recognised.
const TOKEN_ASSIGNMENT_RE =
  /\b(?:oauth|access|refresh|bearer|api|client|auth)[ _-]{0,16}(?:token|secret|key)['"]?[ \t]{0,16}[:=][ \t]{0,16}['"]?([A-Za-z0-9._~+/=-]{16,512})/giu;

// Global, like the bearer pattern (A3). P-1 fix round 2 (C1): the host part stops at `,`, `;`, `/`,
// whitespace, quotes, `<` and `>`, so adjacent URIs are separate matches and a placeholder password in the
// first cannot hide a real password in the next.
const DB_CONNECTION_URI_RE =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql):\/\/[^/\s:@]{1,128}:([^/\s@]{1,256})@[^\s'",;/<>]{1,256}/giu;

const CREDENTIAL_ASSIGNMENT_RE =
  /\b(password|passwd|pwd|passphrase|secret|secret[_-]?key|private[_-]?key|api[_-]?key|credential)['"]?[ \t]{0,16}[:=][ \t]{0,16}['"]?([^\s'"\r\n;,]{8,256})/giu;

/** True when some match of the global `pattern` has a capture group `group` that is not a placeholder. */
function hasRealCredentialMatch(pattern: RegExp, field: string, group: number): boolean {
  pattern.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(field)) !== null) {
    if (!isPlaceholderCredential(match[group]!)) {
      pattern.lastIndex = 0;
      return true;
    }
  }
  return false;
}

function detectSecretRule(field: string): string | undefined {
  if (PRIVATE_KEY_RE.test(field)) return 'private-key';

  if (hasRealCredentialMatch(BEARER_HEADER_RE, field, 1)) {
    return 'bearer-token';
  }

  if (KNOWN_TOKEN_PREFIX_RE.test(field)) {
    return 'api-token';
  }

  TOKEN_ASSIGNMENT_RE.lastIndex = 0;
  let tokenMatch: RegExpExecArray | null;
  while ((tokenMatch = TOKEN_ASSIGNMENT_RE.exec(field)) !== null) {
    const candidate = tokenMatch[1]!;
    if (!isPlaceholderCredential(candidate)) {
      return 'oauth-or-api-token';
    }
  }

  if (hasRealCredentialMatch(DB_CONNECTION_URI_RE, field, 1)) {
    return 'database-credentials';
  }

  CREDENTIAL_ASSIGNMENT_RE.lastIndex = 0;
  let credMatch: RegExpExecArray | null;
  while ((credMatch = CREDENTIAL_ASSIGNMENT_RE.exec(field)) !== null) {
    const keyName = credMatch[1]!.toLowerCase();
    const candidate = credMatch[2]!;
    if (isPlaceholderCredential(candidate)) continue;
    if (
      keyName === 'password' ||
      keyName === 'passwd' ||
      keyName === 'pwd' ||
      keyName === 'passphrase'
    ) {
      return 'credential-assignment';
    }
    if (
      candidate.length >= 16 &&
      characterClassCount(candidate) >= 2 &&
      shannonEntropy(candidate) >= 3.2
    ) {
      return 'high-entropy-credential';
    }
  }

  return undefined;
}

const CLINICAL_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  [
    'clinical-code',
    /\bICD-(?:9|10)(?:-[A-Z]{2})?(?:[ \t:#-]{1,16}[A-TV-Z][0-9][0-9AB](?:\.[0-9A-Z]{1,4})?)?\b|\b(?:diagnosis|diagnostic)[ \t]{1,16}code[ \t:#-]{0,16}[A-TV-Z][0-9][0-9AB]\.[0-9A-Z]{1,4}\b|\bCPT(?:[ \t]{1,16}code)?[ \t:#-]{1,16}\d{5}\b/iu,
  ],
  [
    'clinical-lab',
    /\b(?:laboratory|lab)[ \t]{1,16}(?:result|report)s?\b|\breference[ \t]{1,16}range\b|\b(?:comprehensive[ \t]{1,16}metabolic[ \t]{1,16}panel|complete[ \t]{1,16}blood[ \t]{1,16}count|hemoglobin[ \t]{1,16}a1c)\b/iu,
  ],
  [
    'clinical-record',
    /\bdischarge[ \t]{1,16}(?:summary|instructions|diagnosis)\b|\bmedical[ \t]{1,16}record[ \t]{1,16}(?:number|no\.?|#)\b|\bMRN[ \t:#-]{1,16}[A-Z0-9-]{4,32}\b|"resourceType"[ \t]{0,16}:[ \t]{0,16}"(?:Patient|Observation|DiagnosticReport|MedicationRequest|Condition|Immunization)"/iu,
  ],
  [
    'clinical-prescription',
    /\b(?:prescription|rx)[ \t]{0,16}(?:number|no\.?|#|id|fill)\b|\bNDC[ \t:#-]{1,16}\d{4,5}-\d{3,4}-\d{1,2}\b/iu,
  ],
];

// Ported and generalized from predecessor sensitivity.ts generic rules (national IDs, tax forms,
// financial accounts, insurance documents), mapped to Foundry's `private` tier per Product Spec section 9.
const PRIVATE_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  [
    'national-id',
    /\b(?:social[ \t_-]{0,16}security[ \t_-]{0,16}(?:number|no\.?|card)|employer[ \t_-]{0,16}identification[ \t_-]{0,16}number|national[ \t_-]{0,16}id(?:entity)?[ \t_-]{0,16}number)\b|(?:^|[^a-z0-9])(?:ssn|ein|tin|fein)[ \t]{0,16}[:#-][ \t]{0,16}[0-9-]{9,11}\b|(?<![0-9A-Za-z+-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![0-9A-Za-z-])/iu,
  ],
  [
    'tax-document',
    /\b(?:form[ \t_-]{0,16}(?:1040(?:[ -]?(?:sr|nr|es|x))?|1099(?:-[a-z]{1,4})?|w-?[249])|w-2[ \t]{1,16}(?:wage|form|tax)|1099-(?:int|div|misc|nec|b|r|k)|tax[ \t_-]{0,16}return|wage[ \t]{1,16}and[ \t]{1,16}tax[ \t]{1,16}statement)\b/iu,
  ],
  [
    'financial-account',
    /\b(?:routing|aba)[ \t_-]{0,16}(?:number|no\.?|#)[ \t:#_-]{0,16}\d{9}\b|\b(?:bank|checking|savings|brokerage)[ \t_-]{0,16}account[ \t_-]{0,16}(?:number|no\.?|#)[ \t:#_-]{0,16}[A-Z0-9*-]{4,34}\b|\bIBAN[ \t:#_-]{0,16}[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/iu,
  ],
  [
    'insurance-document',
    /\binsurance[ \t_-]{0,16}(?:card|policy|claim)\b|\bexplanation[ \t_-]{0,16}of[ \t_-]{0,16}benefits\b|\b(?:subscriber|policy|claim)[ \t_-]{0,16}(?:id|number|no\.?)[ \t:#_-]{0,16}[A-Z0-9-]{4,32}\b|\bmember[ \t_-]{0,16}id[ \t:#_-]{0,16}[A-Z0-9-]{5,32}\b/iu,
  ],
];

/** A frozen description of one shipped pattern: its rule id, `RegExp.source` and `RegExp.flags`. */
export interface ShippedScanPattern {
  readonly id: string;
  readonly source: string;
  readonly flags: string;
}

/**
 * Every shipped pattern with its rule id, for the overlap-bound test. Each longest match is shorter than
 * `SCAN_OVERLAP_BYTES`. The two credential-assignment rule ids share one pattern.
 * P-1 fix round 1 (B12): frozen `{ id, source, flags }` records, never the live `RegExp` objects, so no
 * caller can change a pattern (or its `lastIndex`) that the classifier uses.
 */
export const SHIPPED_SCAN_PATTERNS: ReadonlyArray<ShippedScanPattern> = Object.freeze(
  ([
    ['private-key', PRIVATE_KEY_RE],
    ['bearer-token', BEARER_HEADER_RE],
    ['api-token', KNOWN_TOKEN_PREFIX_RE],
    ['oauth-or-api-token', TOKEN_ASSIGNMENT_RE],
    ['database-credentials', DB_CONNECTION_URI_RE],
    ['credential-assignment', CREDENTIAL_ASSIGNMENT_RE],
    ...CLINICAL_RULES,
    ...PRIVATE_RULES,
  ] as ReadonlyArray<readonly [string, RegExp]>).map(([id, pattern]) =>
    Object.freeze({ id, source: pattern.source, flags: pattern.flags }),
  ),
);

function isChildScoped(profile?: string, collection?: string): boolean {
  if (profile === 'child') return true;
  if (typeof collection === 'string') {
    return collection === 'child' || collection.startsWith('child/');
  }
  return false;
}

/** The rule's non-keyword matchers (scope, source, path, tag). The keyword is matched per scan window. */
function matchesUserRuleMetadata(
  rule: UserSensitivityRule,
  source: string,
  profile: string | undefined,
  normalizedPathLower: string,
  lowerTags: ReadonlySet<string>,
): boolean {
  if (rule.profile !== undefined && rule.profile !== profile) return false;
  if (rule.sourcePrefix !== undefined) {
    if (source !== rule.sourcePrefix && !source.startsWith(`${rule.sourcePrefix}/`)) {
      return false;
    }
  }
  if (rule.pathContains !== undefined) {
    if (!normalizedPathLower.includes(rule.pathContains.toLowerCase())) return false;
  }
  if (rule.tag !== undefined) {
    if (!lowerTags.has(rule.tag.toLowerCase())) return false;
  }
  return true;
}

/**
 * Every text field of the item as scan windows, in a fixed order: title, path, `text`, `plaintext`, then
 * each of `derivedTexts`. Lazy: only one window is alive at a time.
 */
function* scanWindows(
  input: ClassificationInput,
  normalizedPath: string,
): Generator<string, void, undefined> {
  if (input.title) yield* stringScanWindows(input.title);
  if (normalizedPath) yield* stringScanWindows(normalizedPath);
  if (typeof input.text === 'string' && input.text.length > 0) yield* stringScanWindows(input.text);
  if (input.plaintext && input.plaintext.byteLength > 0) yield* byteScanWindows(input.plaintext);
  for (const derived of input.derivedTexts ?? []) {
    if (typeof derived === 'string' && derived.length > 0) yield* stringScanWindows(derived);
  }
}

/**
 * Classifies an item into one of the six Foundry sensitivity tiers using deterministic
 * generic rules plus optional vault-stored user rules.
 *
 * Precedence (highest wins): `'secret' > 'child' > 'clinical' > 'private' > 'personal' > 'public'`.
 * `'public'` is chosen only when explicitly set by a matching user rule, `'sensitivity:public'` tag,
 * or `explicitTier: 'public'`, and never overrides a higher matched rule. `archiveTags` (untrusted) never
 * choose `public` and only raise the tier above what the rules give.
 */
export function classifySensitivity(input: ClassificationInput): ClassificationResult {
  if (input.explicitTier !== undefined) {
    assertSensitivityTier(input.explicitTier);
  }
  const validatedRules = input.userRules?.map(rule => assertUserSensitivityRule(rule)) ?? [];

  const normalizedPath = (input.path ?? '').replaceAll('\\', '/');
  const tags = input.tags ?? [];
  const archiveTags = input.archiveTags ?? [];
  const childScoped = isChildScoped(input.profile, input.collection);

  // User rules: the non-keyword matchers are decided once; a keyword is searched in every window.
  // A user rule's `tag` matcher matches trusted and archive tags alike.
  const normalizedPathLower = normalizedPath.toLowerCase();
  const lowerTags = new Set([...tags, ...archiveTags].map(t => t.toLowerCase()));
  const ruleMetadataMatch = validatedRules.map(rule =>
    matchesUserRuleMetadata(rule, input.source, input.profile, normalizedPathLower, lowerTags),
  );
  const keywordNeedles = validatedRules.map(rule => rule.keyword?.toLowerCase());
  const keywordHit = validatedRules.map(rule => rule.keyword === undefined);
  const clinicalHit = CLINICAL_RULES.map(() => false);
  const privateHit = PRIVATE_RULES.map(() => false);

  // 1. One pass over the whole item, one window at a time. Shipped `secret` rules win immediately
  //    (highest possible tier); every other rule records its first hit and is then skipped.
  for (const field of scanWindows(input, normalizedPath)) {
    const secretRule = detectSecretRule(field);
    if (secretRule !== undefined) {
      return { sensitivity: 'secret', rule: secretRule };
    }
    if (!childScoped) {
      for (let i = 0; i < CLINICAL_RULES.length; i++) {
        if (!clinicalHit[i] && CLINICAL_RULES[i]![1].test(field)) clinicalHit[i] = true;
      }
      for (let i = 0; i < PRIVATE_RULES.length; i++) {
        if (!privateHit[i] && PRIVATE_RULES[i]![1].test(field)) privateHit[i] = true;
      }
    }
    let lowerField: string | undefined;
    for (let i = 0; i < validatedRules.length; i++) {
      if (keywordHit[i] || !ruleMetadataMatch[i]) continue;
      lowerField ??= field.toLowerCase();
      if (lowerField.includes(keywordNeedles[i]!)) keywordHit[i] = true;
    }
  }

  let best: ClassificationResult | undefined;
  const consider = (candidate: ClassificationResult): void => {
    if (!best || compareSensitivity(candidate.sensitivity, best.sensitivity) > 0) {
      best = candidate;
    }
  };

  // 2. Explicit tier / explicit sensitivity tag (e.g. `sensitivity:public`).
  if (input.explicitTier !== undefined) {
    consider({ sensitivity: input.explicitTier, rule: 'explicit' });
  }
  for (const rawTag of tags) {
    const lower = rawTag.trim().toLowerCase();
    if (lower === 'sensitivity:public') {
      consider({ sensitivity: 'public', rule: 'tag:public' });
    } else if (lower.startsWith('sensitivity:')) {
      const tagTier = lower.slice('sensitivity:'.length);
      if (
        tagTier === 'personal' ||
        tagTier === 'private' ||
        tagTier === 'clinical' ||
        tagTier === 'child' ||
        tagTier === 'secret'
      ) {
        consider({ sensitivity: tagTier, rule: `tag:${tagTier}` });
      }
    }
  }

  // 3. Vault-stored user rules (may elevate to `secret` or assign `public` when nothing higher matches).
  for (let i = 0; i < validatedRules.length; i++) {
    if (ruleMetadataMatch[i] && keywordHit[i]) {
      const rule = validatedRules[i]!;
      consider({ sensitivity: rule.tier, rule: `user:${rule.id}` });
    }
  }

  // Archive tags (untrusted, C3): the highest `sensitivity:<tier>` among them, never `public`. It is applied
  // only when it is higher than what the rules give (the source default when no rule matched).
  let archiveTier: SensitivityTier | undefined;
  for (const rawTag of archiveTags) {
    const lower = rawTag.trim().toLowerCase();
    if (!lower.startsWith('sensitivity:')) continue;
    const tagTier = lower.slice('sensitivity:'.length);
    if (
      tagTier === 'personal' ||
      tagTier === 'private' ||
      tagTier === 'clinical' ||
      tagTier === 'child' ||
      tagTier === 'secret'
    ) {
      archiveTier = archiveTier === undefined ? tagTier : maxSensitivity(archiveTier, tagTier);
    }
  }
  const raisedByArchive = (ruled: ClassificationResult): ClassificationResult =>
    archiveTier !== undefined && compareSensitivity(archiveTier, ruled.sensitivity) > 0
      ? { sensitivity: archiveTier, rule: `archive-tag:${archiveTier}` }
      : ruled;

  if (best?.sensitivity === 'secret') {
    return best;
  }

  // 4. `child` profile or `child/...` collection floor (outranked only by `secret`).
  if (childScoped) {
    consider({ sensitivity: 'child', rule: 'child-profile' });
    return raisedByArchive(best!);
  }

  // 5. Shipped generic `clinical` rules (first matching rule in list order).
  const clinicalIndex = clinicalHit.indexOf(true);
  if (clinicalIndex !== -1) {
    consider({ sensitivity: 'clinical', rule: CLINICAL_RULES[clinicalIndex]![0] });
  }

  // 6. Shipped generic `private` rules (only needed if nothing >= `private` matched yet).
  if (!best || compareSensitivity(best.sensitivity, 'private') < 0) {
    const privateIndex = privateHit.indexOf(true);
    if (privateIndex !== -1) {
      consider({ sensitivity: 'private', rule: PRIVATE_RULES[privateIndex]![0] });
    }
  }

  // 7. Return matched tier (including explicit/user `public`), or source default (`personal`).
  return raisedByArchive(best ?? { sensitivity: defaultSensitivityForSource(input.source), rule: 'default' });
}

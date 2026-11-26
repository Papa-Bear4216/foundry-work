/**
 * Rule-only generic sensitivity classification (Product Spec section 9, Extraction Plan section 2).
 *
 * Zero network calls, zero model calls, zero household-specific identifiers.
 * Plaintext byte buffers are inspected through bounded head/tail UTF-8 slices so 64 MiB items
 * allocate at most 80 KiB of temporary text and stay well inside the 256 MiB import budget.
 */
import type {
  ClassificationInput,
  ClassificationResult,
  SensitivityTier,
  UserSensitivityRule,
} from './types.ts';
import { assertSensitivityTier, assertUserSensitivityRule } from './validation.ts';

/** Maximum leading bytes decoded from `plaintext` during write-time classification (64 KiB). */
export const HEAD_SCAN_BYTES = 64 * 1024;
/** Maximum trailing bytes decoded from `plaintext` when item length exceeds head + tail (16 KiB). */
export const TAIL_SCAN_BYTES = 16 * 1024;

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

function skipUtf8Continuation(bytes: Uint8Array, start: number): number {
  let idx = Math.max(0, start);
  const cap = Math.min(bytes.byteLength, idx + 4);
  while (idx < cap && (bytes[idx]! & 0xc0) === 0x80) {
    idx++;
  }
  return idx;
}

/**
 * Extracts bounded UTF-8 text slices from `plaintext` and/or `text` without copying raw `Uint8Array` bytes.
 */
export function extractBoundedScanSlices(
  plaintext?: Uint8Array,
  text?: string,
): readonly string[] {
  const slices: string[] = [];

  if (typeof text === 'string' && text.length > 0) {
    const maxChars = HEAD_SCAN_BYTES + TAIL_SCAN_BYTES;
    if (text.length <= maxChars) {
      slices.push(text);
    } else {
      slices.push(text.slice(0, HEAD_SCAN_BYTES));
      slices.push(text.slice(text.length - TAIL_SCAN_BYTES));
    }
  }

  if (plaintext && plaintext.byteLength > 0) {
    const total = plaintext.byteLength;
    if (total <= HEAD_SCAN_BYTES + TAIL_SCAN_BYTES) {
      slices.push(utf8Decoder.decode(plaintext));
    } else {
      const headEnd = trimUtf8End(plaintext, HEAD_SCAN_BYTES);
      const tailStart = skipUtf8Continuation(plaintext, total - TAIL_SCAN_BYTES);
      slices.push(utf8Decoder.decode(plaintext.subarray(0, headEnd)));
      if (tailStart < total) {
        slices.push(utf8Decoder.decode(plaintext.subarray(tailStart, total)));
      }
    }
  }

  return slices;
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

const PRIVATE_KEY_RE =
  /-----BEGIN[ \t]+(?:[A-Z0-9-]+[ \t]+){0,5}PRIVATE[ \t]+KEY(?:[ \t]+BLOCK)?-----|PuTTY-User-Key-File-[23]:/iu;

const BEARER_HEADER_RE =
  /\bAuthorization[ \t]*:[ \t]*Bearer[ \t]+([A-Za-z0-9._~+/=-]{16,512})/iu;

const KNOWN_TOKEN_PREFIX_RE =
  /\b(?:sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,256}|gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255}|xox[baprs]-[A-Za-z0-9-]{16,255}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{10,512}\.eyJ[A-Za-z0-9_-]{10,512}\.[A-Za-z0-9_-]{10,512})\b/u;

const TOKEN_ASSIGNMENT_RE =
  /\b(?:oauth|access|refresh|bearer|api|client|auth)[ _-]*(?:token|secret|key)[ \t]*[:=][ \t]*['"]?([A-Za-z0-9._~+/=-]{16,512})/giu;

const DB_CONNECTION_URI_RE =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql):\/\/[^/\s:@]{1,128}:([^/\s@]{1,256})@[^\s'"]{1,256}/iu;

const CREDENTIAL_ASSIGNMENT_RE =
  /\b(password|passwd|pwd|passphrase|secret|secret[_-]?key|private[_-]?key|api[_-]?key|credential)[ \t]*[:=][ \t]*['"]?([^\s'"\r\n;,]{8,256})/giu;

function detectSecretRule(field: string): string | undefined {
  if (PRIVATE_KEY_RE.test(field)) return 'private-key';

  const bearerMatch = BEARER_HEADER_RE.exec(field);
  if (bearerMatch && !isPlaceholderCredential(bearerMatch[1]!)) {
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

  const dbMatch = DB_CONNECTION_URI_RE.exec(field);
  if (dbMatch && !isPlaceholderCredential(dbMatch[1]!)) {
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
    /\bICD-(?:9|10)(?:-[A-Z]{2})?(?:[ \t:#-]+[A-TV-Z][0-9][0-9AB](?:\.[0-9A-Z]{1,4})?)?\b|\b(?:diagnosis|diagnostic)[ \t]+code[ \t:#-]*[A-TV-Z][0-9][0-9AB]\.[0-9A-Z]{1,4}\b|\bCPT(?:[ \t]+code)?[ \t:#-]+\d{5}\b/iu,
  ],
  [
    'clinical-lab',
    /\b(?:laboratory|lab)[ \t]+(?:result|report)s?\b|\breference[ \t]+range\b|\b(?:comprehensive[ \t]+metabolic[ \t]+panel|complete[ \t]+blood[ \t]+count|hemoglobin[ \t]+a1c)\b/iu,
  ],
  [
    'clinical-record',
    /\bdischarge[ \t]+(?:summary|instructions|diagnosis)\b|\bmedical[ \t]+record[ \t]+(?:number|no\.?|#)\b|\bMRN[ \t:#-]+[A-Z0-9-]{4,32}\b|"resourceType"[ \t]*:[ \t]*"(?:Patient|Observation|DiagnosticReport|MedicationRequest|Condition|Immunization)"/iu,
  ],
  [
    'clinical-prescription',
    /\b(?:prescription|rx)[ \t]*(?:number|no\.?|#|id|fill)\b|\bNDC[ \t:#-]+\d{4,5}-\d{3,4}-\d{1,2}\b/iu,
  ],
];

// Ported and generalized from predecessor sensitivity.ts generic rules (national IDs, tax forms,
// financial accounts, insurance documents), mapped to Foundry's `private` tier per Product Spec section 9.
const PRIVATE_RULES: ReadonlyArray<readonly [string, RegExp]> = [
  [
    'national-id',
    /\b(?:social[ \t_-]*security[ \t_-]*(?:number|no\.?|card)|employer[ \t_-]*identification[ \t_-]*number|national[ \t_-]*id(?:entity)?[ \t_-]*number)\b|(?:^|[^a-z0-9])(?:ssn|ein|tin|fein)[ \t]*[:#-][ \t]*[0-9-]{9,11}\b|(?<![0-9A-Za-z+-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![0-9A-Za-z-])/iu,
  ],
  [
    'tax-document',
    /\b(?:form[ \t_-]*(?:1040(?:[ -]?(?:sr|nr|es|x))?|1099(?:-[a-z]{1,4})?|w-?[249])|w-2[ \t]+(?:wage|form|tax)|1099-(?:int|div|misc|nec|b|r|k)|tax[ \t_-]*return|wage[ \t]+and[ \t]+tax[ \t]+statement)\b/iu,
  ],
  [
    'financial-account',
    /\b(?:routing|aba)[ \t_-]*(?:number|no\.?|#)[ \t:#_-]*\d{9}\b|\b(?:bank|checking|savings|brokerage)[ \t_-]*account[ \t_-]*(?:number|no\.?|#)[ \t:#_-]*[A-Z0-9*-]{4,34}\b|\bIBAN[ \t:#_-]*[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/iu,
  ],
  [
    'insurance-document',
    /\binsurance[ \t_-]*(?:card|policy|claim)\b|\bexplanation[ \t_-]*of[ \t_-]*benefits\b|\b(?:subscriber|policy|claim)[ \t_-]*(?:id|number|no\.?)[ \t:#_-]*[A-Z0-9-]{4,32}\b|\bmember[ \t_-]*id[ \t:#_-]*[A-Z0-9-]{5,32}\b/iu,
  ],
];

function isChildScoped(profile?: string, collection?: string): boolean {
  if (profile === 'child') return true;
  if (typeof collection === 'string') {
    return collection === 'child' || collection.startsWith('child/');
  }
  return false;
}

function matchesUserRule(
  rule: UserSensitivityRule,
  source: string,
  profile: string | undefined,
  normalizedPathLower: string,
  lowerTags: ReadonlySet<string>,
  lowerFields: readonly string[],
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
  if (rule.keyword !== undefined) {
    const needle = rule.keyword.toLowerCase();
    if (!lowerFields.some(f => f.includes(needle))) return false;
  }
  return true;
}

/**
 * Classifies an item into one of the six Foundry sensitivity tiers using deterministic
 * generic rules plus optional vault-stored user rules.
 *
 * Precedence (highest wins): `'secret' > 'child' > 'clinical' > 'private' > 'personal' > 'public'`.
 * `'public'` is chosen only when explicitly set by a matching user rule, `'sensitivity:public'` tag,
 * or `explicitTier: 'public'`, and never overrides a higher matched rule.
 */
export function classifySensitivity(input: ClassificationInput): ClassificationResult {
  if (input.explicitTier !== undefined) {
    assertSensitivityTier(input.explicitTier);
  }
  const validatedRules = input.userRules?.map(rule => assertUserSensitivityRule(rule)) ?? [];

  const normalizedPath = (input.path ?? '').replaceAll('\\', '/');
  const textSlices = extractBoundedScanSlices(input.plaintext, input.text);
  const fields: string[] = [];
  if (input.title) fields.push(input.title);
  if (normalizedPath) fields.push(normalizedPath);
  for (const slice of textSlices) fields.push(slice);

  // 1. Shipped `secret` rules always win immediately (highest possible tier).
  for (const field of fields) {
    const secretRule = detectSecretRule(field);
    if (secretRule !== undefined) {
      return { sensitivity: 'secret', rule: secretRule };
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
  const tags = input.tags ?? [];
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
  if (validatedRules.length > 0) {
    const normalizedPathLower = normalizedPath.toLowerCase();
    const lowerTags = new Set(tags.map(t => t.toLowerCase()));
    const lowerFields = fields.map(f => f.toLowerCase());
    for (const rule of validatedRules) {
      if (
        matchesUserRule(
          rule,
          input.source,
          input.profile,
          normalizedPathLower,
          lowerTags,
          lowerFields,
        )
      ) {
        consider({ sensitivity: rule.tier, rule: `user:${rule.id}` });
      }
    }
  }

  if (best?.sensitivity === 'secret') {
    return best;
  }

  // 4. `child` profile or `child/...` collection floor (outranked only by `secret`).
  if (isChildScoped(input.profile, input.collection)) {
    consider({ sensitivity: 'child', rule: 'child-profile' });
    return best!;
  }

  // 5. Shipped generic `clinical` rules.
  for (const [ruleId, pattern] of CLINICAL_RULES) {
    if (fields.some(field => pattern.test(field))) {
      consider({ sensitivity: 'clinical', rule: ruleId });
      break;
    }
  }

  // 6. Shipped generic `private` rules (only needed if nothing >= `private` matched yet).
  if (!best || compareSensitivity(best.sensitivity, 'private') < 0) {
    for (const [ruleId, pattern] of PRIVATE_RULES) {
      if (fields.some(field => pattern.test(field))) {
        consider({ sensitivity: 'private', rule: ruleId });
        break;
      }
    }
  }

  // 7. Return matched tier (including explicit/user `public`), or source default (`personal`).
  if (best) return best;
  return { sensitivity: defaultSensitivityForSource(input.source), rule: 'default' };
}

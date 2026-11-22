/**
 * @file importers/content-line.ts
 * Single-pass O(N) RFC 5545 (iCalendar) / RFC 6350 (vCard) content-line scanner.
 * Avoids regex backtracking on malformed lines containing many semicolons without a colon.
 */

export interface ContentLineParam {
  /** Uppercase parameter name, or empty string for vCard 2.1 bare parameters (e.g. `;CELL`). */
  readonly name: string;
  readonly value: string;
}

export interface ParsedContentLine {
  /** Uppercase property name (without optional vCard group prefix). */
  readonly name: string;
  readonly params: readonly ContentLineParam[];
  readonly value: string;
}

function isPropertyChar(code: number): boolean {
  return (
    (code >= 0x41 && code <= 0x5a) || // A-Z
    (code >= 0x61 && code <= 0x7a) || // a-z
    (code >= 0x30 && code <= 0x39) || // 0-9
    code === 0x2d                     // -
  );
}

function isGroupChar(code: number): boolean {
  return isPropertyChar(code) || code === 0x5f; // _
}

function validateAndExtractPropName(segment: string, allowGroup: boolean): string | null {
  if (segment.length === 0) return null;
  let propStart = 0;
  if (allowGroup) {
    const dot = segment.indexOf('.');
    if (dot !== -1) {
      if (dot === 0 || dot === segment.length - 1) return null;
      for (let i = 0; i < dot; i++) {
        if (!isGroupChar(segment.charCodeAt(i))) return null;
      }
      propStart = dot + 1;
    }
  }
  for (let i = propStart; i < segment.length; i++) {
    if (!isPropertyChar(segment.charCodeAt(i))) return null;
  }
  return segment.slice(propStart).toUpperCase();
}

function stripOuterQuotes(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/**
 * Parses `[group.]NAME *(;PARAM) : VALUE` in a single O(N) pass over `line`.
 * Returns `null` if no unquoted `:` separator exists or if the property name is invalid.
 */
export function parseContentLine(
  line: string,
  options: { allowGroup?: boolean } = {},
): ParsedContentLine | null {
  const len = line.length;
  if (len === 0) return null;

  let inQuotes = false;
  let colonPos = -1;
  let nameEnd = -1;
  const semiPositions: number[] = [];

  for (let i = 0; i < len; i++) {
    const ch = line.charCodeAt(i);
    if (ch === 0x22) {
      // '"'
      inQuotes = !inQuotes;
    } else if (!inQuotes) {
      if (ch === 0x3b) {
        // ';'
        if (nameEnd === -1) nameEnd = i;
        semiPositions.push(i);
      } else if (ch === 0x3a) {
        // ':'
        if (nameEnd === -1) nameEnd = i;
        colonPos = i;
        break;
      }
    }
  }

  if (colonPos === -1 || nameEnd <= 0) return null;

  const propName = validateAndExtractPropName(line.slice(0, nameEnd), Boolean(options.allowGroup));
  if (!propName) return null;

  const params: ContentLineParam[] = [];
  for (let idx = 0; idx < semiPositions.length; idx++) {
    const start = semiPositions[idx]! + 1;
    const end = idx + 1 < semiPositions.length ? semiPositions[idx + 1]! : colonPos;
    const token = line.slice(start, end).trim();
    if (!token) continue;
    const eq = token.indexOf('=');
    if (eq === -1) {
      params.push({ name: '', value: token });
    } else {
      const pName = token.slice(0, eq).trim().toUpperCase();
      const pValue = stripOuterQuotes(token.slice(eq + 1));
      params.push({ name: pName, value: pValue });
    }
  }

  return {
    name: propName,
    params,
    value: line.slice(colonPos + 1),
  };
}

export function getParamValue(params: readonly ContentLineParam[], name: string): string | undefined {
  const upper = name.toUpperCase();
  for (const p of params) {
    if (p.name === upper) {
      const val = p.value.trim();
      return val || undefined;
    }
  }
  return undefined;
}

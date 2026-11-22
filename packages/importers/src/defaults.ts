import { createHash } from 'node:crypto';
import type { SensitivityTier } from './types.js';

/** Default profile before P-1 introduces multi-profile configuration (DECISIONS.md A-36). */
export const DEFAULT_PROFILE = 'me';

/** Per-item plaintext byte cap enforced before buffering past it (DECISIONS.md A-36). */
export const DEFAULT_MAX_ITEM_BYTES = 64 * 1024 * 1024;

/**
 * Fixed default sensitivity tier per importer source before P-1 rules arrive (DECISIONS.md A-36).
 * Matches Architecture 4.3 (`"sensitivity": "personal"`).
 */
export const DEFAULT_SENSITIVITY_BY_SOURCE: Readonly<Record<string, SensitivityTier>> = Object.freeze({
  'google-takeout/contacts': 'personal',
  'google-takeout/calendar': 'personal',
  'google-takeout/mail': 'personal',
});

export function defaultSensitivityForSource(source: string): SensitivityTier {
  return DEFAULT_SENSITIVITY_BY_SOURCE[source] ?? 'personal';
}

/** Computes the default logical collection `<source>/<year>` (or `<source>/undated`). */
export function defaultCollectionName(source: string, sourceTs?: string): string {
  if (sourceTs) {
    const match = /^(\d{4})-/.exec(sourceTs);
    if (match) return `${source}/${match[1]}`;
  }
  return `${source}/undated`;
}

/** Returns canonical RFC 8785 / Architecture 4.5 UTC timestamp `YYYY-MM-DDTHH:MM:SSZ`. */
export function formatUtcTimestamp(date: Date): string {
  const iso = date.toISOString();
  return iso.replace(/\.\d{3}Z$/u, 'Z');
}

const MONTH_INDEX: Readonly<Record<string, number>> = Object.freeze({
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11,
});

const TZ_OFFSET_MINUTES: Readonly<Record<string, number>> = Object.freeze({
  utc: 0,
  gmt: 0,
  ut: 0,
  z: 0,
  edt: -240,
  est: -300,
  cdt: -300,
  cst: -360,
  mdt: -360,
  mst: -420,
  pdt: -420,
  pst: -480,
});

function parseTimezoneOffsetMinutes(tz: string | undefined): number | undefined {
  if (!tz) return 0; // Zone-less timestamps are always interpreted as UTC (DECISIONS.md A-36).
  const trimmed = tz.trim();
  if (!trimmed) return 0;
  const lower = trimmed.toLowerCase();
  if (lower in TZ_OFFSET_MINUTES) return TZ_OFFSET_MINUTES[lower]!;
  const m = /^([+-])(\d{2}):?(\d{2})$/.exec(trimmed);
  if (!m) return undefined;
  const sign = m[1] === '-' ? -1 : 1;
  const hours = Number.parseInt(m[2]!, 10);
  const mins = Number.parseInt(m[3]!, 10);
  if (hours > 23 || mins > 59) return undefined;
  return sign * (hours * 60 + mins);
}

function buildValidatedUtcTimestamp(
  year: number,
  monthZeroBased: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  offsetMinutes: number,
): string | undefined {
  if (
    year < 1 ||
    year > 9999 ||
    monthZeroBased < 0 ||
    monthZeroBased > 11 ||
    day < 1 ||
    day > 31 ||
    hour < 0 ||
    hour > 23 ||
    minute < 0 ||
    minute > 59 ||
    second < 0 ||
    second > 59
  ) {
    return undefined;
  }
  const baseDate = new Date(0);
  baseDate.setUTCFullYear(year, monthZeroBased, day);
  baseDate.setUTCHours(hour, minute, second, 0);
  if (
    baseDate.getUTCFullYear() !== year ||
    baseDate.getUTCMonth() !== monthZeroBased ||
    baseDate.getUTCDate() !== day ||
    baseDate.getUTCHours() !== hour ||
    baseDate.getUTCMinutes() !== minute ||
    baseDate.getUTCSeconds() !== second
  ) {
    return undefined;
  }
  const utcMs = baseDate.getTime() - offsetMinutes * 60_000;
  if (!Number.isFinite(utcMs)) return undefined;
  const utcDate = new Date(utcMs);
  const finalYear = utcDate.getUTCFullYear();
  if (finalYear < 1 || finalYear > 9999) return undefined;
  return formatUtcTimestamp(utcDate);
}

/**
 * Parses an ISO-8601, iCalendar/vCard compact, RFC 5322, or asctime date string into canonical UTC
 * `YYYY-MM-DDTHH:MM:SSZ` using explicit grammars that identify the zone field. Zone-less date-times
 * are ALWAYS interpreted as UTC regardless of host time zone; unsupported forms return `undefined`
 * deterministically (never delegates to `Date.parse`, per DECISIONS.md A-36).
 */
export function normalizeTimestamp(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;

  // 1. Compact iCalendar / vCard date-time: YYYYMMDDTHHMMSS[Z|±HHMM|±HH:MM]
  const compactDateTime = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z|[+-]\d{2}:?\d{2})?$/i.exec(trimmed);
  if (compactDateTime) {
    const [, y, m, d, hh, mm, ss, tz] = compactDateTime;
    const offset = parseTimezoneOffsetMinutes(tz);
    if (offset === undefined) return undefined;
    return buildValidatedUtcTimestamp(
      Number.parseInt(y!, 10),
      Number.parseInt(m!, 10) - 1,
      Number.parseInt(d!, 10),
      Number.parseInt(hh!, 10),
      Number.parseInt(mm!, 10),
      Number.parseInt(ss!, 10),
      offset,
    );
  }

  // 2. Compact date-only: YYYYMMDD
  const compactDate = /^(\d{4})(\d{2})(\d{2})$/.exec(trimmed);
  if (compactDate) {
    const [, y, m, d] = compactDate;
    return buildValidatedUtcTimestamp(
      Number.parseInt(y!, 10),
      Number.parseInt(m!, 10) - 1,
      Number.parseInt(d!, 10),
      0,
      0,
      0,
      0,
    );
  }

  // 3. ISO-8601 date-only: YYYY-MM-DD
  const isoDate = /^(\d{4})-(\d{2})-(\d{2})$/.exec(trimmed);
  if (isoDate) {
    const [, y, m, d] = isoDate;
    return buildValidatedUtcTimestamp(
      Number.parseInt(y!, 10),
      Number.parseInt(m!, 10) - 1,
      Number.parseInt(d!, 10),
      0,
      0,
      0,
      0,
    );
  }

  // 4. ISO-8601 date-time (zone-less defaults strictly to UTC): YYYY-MM-DD[T ]HH:MM[:SS[.fff]][Z|±HH:MM|±HHMM]
  const isoDateTime =
    /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:\s*(Z|[+-]\d{2}:?\d{2}))?$/i.exec(trimmed);
  if (isoDateTime) {
    const [, y, m, d, hh, mm, ss, tz] = isoDateTime;
    const offset = parseTimezoneOffsetMinutes(tz);
    if (offset === undefined) return undefined;
    return buildValidatedUtcTimestamp(
      Number.parseInt(y!, 10),
      Number.parseInt(m!, 10) - 1,
      Number.parseInt(d!, 10),
      Number.parseInt(hh!, 10),
      Number.parseInt(mm!, 10),
      ss ? Number.parseInt(ss, 10) : 0,
      offset,
    );
  }

  // 5. RFC 5322 email date (zone-less defaults strictly to UTC): [Day,] DD Mon YYYY H(H):MM[:SS] [TZ] [(comment)]
  const rfc5322 =
    /^(?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+)?(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s+([+-]\d{2}:?\d{2}|[A-Za-z]{1,5}))?(?:\s+\([^)]*\))?$/i.exec(
      trimmed,
    );
  if (rfc5322) {
    const [, d, mon, y, hh, mm, ss, tz] = rfc5322;
    const monthIdx = MONTH_INDEX[mon!.toLowerCase()];
    const offset = parseTimezoneOffsetMinutes(tz);
    if (monthIdx !== undefined && offset !== undefined) {
      return buildValidatedUtcTimestamp(
        Number.parseInt(y!, 10),
        monthIdx,
        Number.parseInt(d!, 10),
        Number.parseInt(hh!, 10),
        Number.parseInt(mm!, 10),
        ss ? Number.parseInt(ss, 10) : 0,
        offset,
      );
    }
    return undefined;
  }

  // 6. Asctime / mbox date (zone-less defaults strictly to UTC): Day Mon DD HH:MM:SS [TZ] YYYY [TZ]
  const asctime =
    /^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}|[A-Za-z]{1,5}))?\s+(\d{4})(?:\s+([+-]\d{4}))?$/i.exec(
      trimmed,
    );
  if (asctime) {
    const [, mon, d, hh, mm, ss, tzBefore, y, tzAfter] = asctime;
    if (tzBefore && tzAfter) return undefined;
    const monthIdx = MONTH_INDEX[mon!.toLowerCase()];
    const offset = parseTimezoneOffsetMinutes(tzBefore ?? tzAfter);
    if (monthIdx !== undefined && offset !== undefined) {
      return buildValidatedUtcTimestamp(
        Number.parseInt(y!, 10),
        monthIdx,
        Number.parseInt(d!, 10),
        Number.parseInt(hh!, 10),
        Number.parseInt(mm!, 10),
        Number.parseInt(ss!, 10),
        offset,
      );
    }
    return undefined;
  }

  // Any format not accepted by the explicit grammars above maps deterministically to undated.
  return undefined;
}

/** Bytewise ASCII/UTF-16 deduplicated sort (Architecture 11 deterministic ordering). */
export function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/**
 * Deterministic idempotent item key (64 lowercase hex chars).
 * Incorporates the collection-keyed blobId so identical content at the same path in
 * the same profile/collection/source maps to one key, and key destruction removes confirmability.
 */
export function computeItemKey(
  profile: string,
  collection: string,
  source: string,
  path: string,
  blobId: string,
): string {
  const payload = JSON.stringify([profile, collection, source, path, blobId]);
  return createHash('sha256').update(payload).digest('hex');
}

import { createHash } from 'node:crypto';
import type { SensitivityTier } from './types.js';

/** Default profile before P-1 introduces multi-profile configuration (DECISIONS.md A-36). */
export const DEFAULT_PROFILE = 'me';

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

/** Parses an ISO-8601, iCalendar/vCard compact, or RFC 5322 date string into canonical UTC `YYYY-MM-DDTHH:MM:SSZ`. */
export function normalizeTimestamp(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;

  // Compact iCalendar / vCard UTC or local forms: YYYYMMDDTHHMMSSZ or YYYYMMDDTHHMMSS or YYYYMMDD
  const compactDateTime = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(Z?)$/i.exec(trimmed);
  if (compactDateTime) {
    const [, y, m, d, hh, mm, ss] = compactDateTime;
    const candidate = `${y}-${m}-${d}T${hh}:${mm}:${ss}Z`;
    const parsed = Date.parse(candidate);
    if (Number.isFinite(parsed)) return formatUtcTimestamp(new Date(parsed));
    return undefined;
  }

  const compactDate = /^(\d{4})(\d{2})(\d{2})$/.exec(trimmed);
  if (compactDate) {
    const [, y, m, d] = compactDate;
    const candidate = `${y}-${m}-${d}T00:00:00Z`;
    const parsed = Date.parse(candidate);
    if (Number.isFinite(parsed)) return formatUtcTimestamp(new Date(parsed));
    return undefined;
  }

  const parsed = Date.parse(trimmed);
  if (!Number.isFinite(parsed)) return undefined;
  const date = new Date(parsed);
  const year = date.getUTCFullYear();
  if (year < 1 || year > 9999) return undefined;
  return formatUtcTimestamp(date);
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

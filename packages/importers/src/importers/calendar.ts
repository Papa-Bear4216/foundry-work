/**
 * @file importers/calendar.ts
 * Google Takeout Calendar (iCalendar / RFC 5545) lossless importer and deriver.
 */

import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import type { ArchiveEntry, Derived, Deriver, Importer, ItemErrorInfo, RawItem, SplitOptions, StoredItem } from '../types.js';
import { DEFAULT_MAX_ITEM_BYTES, formatUtcTimestamp, normalizeTimestamp, uniqueSorted } from '../defaults.js';
import { getParamValue, parseContentLine } from './content-line.js';
import { ItemSkipError } from './errors.js';

export const CALENDAR_SOURCE_ID = 'google-takeout/calendar';

export interface ParsedCalendarEvent {
  uid?: string;
  summary?: string;
  description?: string;
  location?: string;
  dtstart?: string;
  dtend?: string;
  dtstamp?: string;
  status?: string;
  rrule?: string;
  organizer?: { address: string; name?: string };
  attendees: Array<{ address: string; name?: string; partstat?: string }>;
  categories: string[];
  geo?: { lat: number; lng: number };
}

export interface ParsedCalendar {
  calendarName?: string;
  events: ParsedCalendarEvent[];
}

function unescapeIcalText(value: string): string {
  return value.replace(/\\([,;nN\\])/g, (_, esc: string) => {
    if (esc === 'n' || esc === 'N') return '\n';
    return esc;
  });
}

function cleanMailto(value: string): string {
  return value.replace(/^mailto:/i, '').trim();
}

/** Parses RFC 5545 iCalendar content into calendar metadata and VEVENT records. */
export function parseIcalendar(icsText: string): ParsedCalendar {
  const cleaned = icsText.replace(/^\ufeff/, '');
  // RFC 5545 section 3.1 line unfolding: CRLF/LF followed by single space or horizontal tab.
  const unfolded = cleaned.replace(/\r?\n[ \t]/g, '');

  let calendarName: string | undefined;
  const events: ParsedCalendarEvent[] = [];
  let inEvent = false;
  let current: ParsedCalendarEvent | null = null;

  for (const rawLine of unfolded.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    const upper = line.toUpperCase();
    if (upper === 'BEGIN:VEVENT') {
      inEvent = true;
      current = { attendees: [], categories: [] };
      continue;
    }
    if (upper === 'END:VEVENT') {
      if (current) events.push(current);
      current = null;
      inEvent = false;
      continue;
    }

    const parsedLine = parseContentLine(line);
    if (!parsedLine) continue;
    const prop = parsedLine.name;
    const params = parsedLine.params;
    const rawVal = parsedLine.value.trim();

    if (!inEvent) {
      if (prop === 'X-WR-CALNAME' && !calendarName && rawVal) {
        calendarName = unescapeIcalText(rawVal);
      }
      continue;
    }

    if (!current) continue;
    switch (prop) {
      case 'UID':
        current.uid = rawVal;
        break;
      case 'SUMMARY':
        current.summary = unescapeIcalText(rawVal);
        break;
      case 'DESCRIPTION':
        current.description = unescapeIcalText(rawVal);
        break;
      case 'LOCATION':
        current.location = unescapeIcalText(rawVal);
        break;
      case 'DTSTART':
        current.dtstart = normalizeTimestamp(rawVal);
        break;
      case 'DTEND':
        current.dtend = normalizeTimestamp(rawVal);
        break;
      case 'DTSTAMP':
        current.dtstamp = normalizeTimestamp(rawVal);
        break;
      case 'STATUS':
        current.status = rawVal.toUpperCase();
        break;
      case 'RRULE':
        current.rrule = rawVal;
        break;
      case 'ORGANIZER': {
        const address = cleanMailto(rawVal);
        if (address) {
          current.organizer = { address, name: getParamValue(params, 'CN') };
        }
        break;
      }
      case 'ATTENDEE': {
        const address = cleanMailto(rawVal);
        if (address) {
          current.attendees.push({
            address,
            name: getParamValue(params, 'CN'),
            partstat: getParamValue(params, 'PARTSTAT'),
          });
        }
        break;
      }
      case 'CATEGORIES':
        for (const cat of rawVal.split(',')) {
          const item = unescapeIcalText(cat).trim();
          if (item) current.categories.push(item);
        }
        break;
      case 'GEO': {
        const parts = rawVal.split(';');
        if (parts.length === 2) {
          const lat = Number.parseFloat(parts[0]!);
          const lng = Number.parseFloat(parts[1]!);
          if (Number.isFinite(lat) && Number.isFinite(lng) && lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) {
            current.geo = { lat, lng };
          }
        }
        break;
      }
    }
  }

  for (const ev of events) {
    ev.categories = uniqueSorted(ev.categories);
  }

  return { calendarName, events };
}

function formatEventText(ev: ParsedCalendarEvent, calendarName?: string): string {
  const lines: string[] = [];
  lines.push(`Event: ${ev.summary ?? '(untitled event)'}`);
  if (calendarName) lines.push(`Calendar: ${calendarName}`);
  if (ev.dtstart) lines.push(`Start: ${ev.dtstart}`);
  if (ev.dtend) lines.push(`End: ${ev.dtend}`);
  if (ev.location) lines.push(`Location: ${ev.location}`);
  if (ev.status) lines.push(`Status: ${ev.status}`);
  if (ev.rrule) lines.push(`Recurrence: ${ev.rrule}`);
  if (ev.organizer) {
    const org = ev.organizer.name ? `${ev.organizer.name} <${ev.organizer.address}>` : ev.organizer.address;
    lines.push(`Organizer: ${org}`);
  }
  if (ev.attendees.length > 0) {
    const rendered = ev.attendees
      .map(a => (a.name ? `${a.name} <${a.address}>` : a.address))
      .join(', ');
    lines.push(`Attendees: ${rendered}`);
  }
  if (ev.categories.length > 0) lines.push(`Categories: ${ev.categories.join(', ')}`);
  if (ev.description) lines.push(`Description: ${ev.description}`);
  return lines.join('\n');
}

async function readStreamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return Buffer.concat(chunks);
}

async function readStreamBounded(
  stream: Readable,
  maxBytes: number,
): Promise<{ buffer: Buffer; exceeded: false } | { exceeded: true; observedBytes: number }> {
  const chunks: Buffer[] = [];
  let total = 0;
  let exceeded = false;

  for await (const rawChunk of stream) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk as Uint8Array);
    total += chunk.length;
    if (exceeded) continue;
    if (total > maxBytes) {
      chunks.length = 0;
      exceeded = true;
      continue;
    }
    chunks.push(chunk);
  }

  if (exceeded) return { exceeded: true, observedBytes: total };
  return { buffer: chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks), exceeded: false };
}

function extractCalendarTimestamp(parsed: ParsedCalendar, mtime?: Date): string | undefined {
  let earliest: string | undefined;
  for (const ev of parsed.events) {
    const ts = ev.dtstart ?? ev.dtstamp;
    if (ts && (!earliest || ts < earliest)) earliest = ts;
  }
  if (earliest) return earliest;
  return mtime ? formatUtcTimestamp(mtime) : undefined;
}

export const calendarImporter: Importer = {
  id: CALENDAR_SOURCE_ID,
  matches(entry: ArchiveEntry): boolean {
    const lower = entry.path.toLowerCase();
    return lower.endsWith('.ics') || lower.endsWith('.ical');
  },
  async *split(entry: ArchiveEntry, options?: SplitOptions): AsyncIterable<RawItem> {
    const maxItemBytes = options?.maxItemBytes ?? DEFAULT_MAX_ITEM_BYTES;
    const reportError = (info: ItemErrorInfo): void => {
      if (options?.onItemError) {
        options.onItemError(info);
        return;
      }
      throw new ItemSkipError(info);
    };

    if (entry.size > maxItemBytes) {
      reportError({
        code: 'ITEM_TOO_LARGE',
        source: CALENDAR_SOURCE_ID,
        entryPath: entry.path,
        itemPath: entry.path,
        message: `Calendar file ${entry.path} (${entry.size} bytes) exceeds per-item limit (${maxItemBytes} bytes).`,
        limitBytes: maxItemBytes,
        observedBytes: entry.size,
      });
      return;
    }

    // Architecture 7: lossless original calendar file stored as one item (preserves VTIMEZONE and VCALENDAR metadata).
    const read = await readStreamBounded(entry.open(), maxItemBytes);
    if (read.exceeded) {
      reportError({
        code: 'ITEM_TOO_LARGE',
        source: CALENDAR_SOURCE_ID,
        entryPath: entry.path,
        itemPath: entry.path,
        message: `Calendar file ${entry.path} (${read.observedBytes} bytes) exceeds per-item limit (${maxItemBytes} bytes).`,
        limitBytes: maxItemBytes,
        observedBytes: read.observedBytes,
      });
      return;
    }

    const raw = read.buffer;
    const parsed = parseIcalendar(raw.toString('utf8'));
    const sourceTs = extractCalendarTimestamp(parsed, entry.mtime);
    const tags = ['calendar'];
    if (parsed.calendarName) tags.push(parsed.calendarName.toLowerCase());
    yield {
      bytes: Readable.from([raw]),
      path: entry.path,
      mime: 'text/calendar',
      sourceTs,
      tags: uniqueSorted(tags),
      meta: parsed.calendarName ? { calendarName: parsed.calendarName } : undefined,
    };
  },
};

export const calendarDeriver: Deriver = {
  id: CALENDAR_SOURCE_ID,
  version: 1,
  async *derive(item: StoredItem, bytes: Readable): AsyncIterable<Derived> {
    const raw = await readStreamToBuffer(bytes);
    const parsed = parseIcalendar(raw.toString('utf8'));

    for (const ev of parsed.events) {
      const eventTs = ev.dtstart ?? ev.dtstamp ?? item.sourceTs;
      const tags = uniqueSorted([...item.tags, 'event', ...ev.categories.map(c => c.toLowerCase())]);

      yield {
        kind: 'text',
        title: ev.summary ?? '(untitled event)',
        text: formatEventText(ev, parsed.calendarName),
        structured: {
          entityType: 'calendar_event',
          calendarName: parsed.calendarName,
          uid: ev.uid,
          summary: ev.summary,
          description: ev.description,
          location: ev.location,
          dtstart: ev.dtstart,
          dtend: ev.dtend,
          dtstamp: ev.dtstamp,
          status: ev.status,
          rrule: ev.rrule,
          organizer: ev.organizer,
          attendees: ev.attendees,
          categories: ev.categories,
        },
        sourceTs: eventTs,
        tags,
      };

      if (ev.geo) {
        yield {
          kind: 'place',
          latE7: Math.round(ev.geo.lat * 1e7),
          lngE7: Math.round(ev.geo.lng * 1e7),
          ts: eventTs,
          label: ev.location ?? ev.summary,
        };
      }

      if (ev.organizer || ev.attendees.length > 0) {
        const nodes: Array<{ kind: string; canonicalKey: string; label: string }> = [];
        const edges: Array<{ srcKind: string; srcKey: string; dstKind: string; dstKey: string; kind: string }> = [];
        const seen = new Set<string>();
        const addPerson = (addr: string, name?: string) => {
          const key = `email:${addr.toLowerCase()}`;
          if (!seen.has(key)) {
            seen.add(key);
            nodes.push({ kind: 'person', canonicalKey: key, label: name ?? addr });
          }
          return key;
        };

        const orgKey = ev.organizer ? addPerson(ev.organizer.address, ev.organizer.name) : undefined;
        for (const att of ev.attendees) {
          const attKey = addPerson(att.address, att.name);
          if (orgKey && orgKey !== attKey) {
            edges.push({
              srcKind: 'person',
              srcKey: orgKey,
              dstKind: 'person',
              dstKey: attKey,
              kind: 'invited',
            });
          }
        }
        yield { kind: 'graph_evidence', nodes, edges };
      }
    }
  },
};

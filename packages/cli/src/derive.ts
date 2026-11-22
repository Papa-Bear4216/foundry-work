/**
 * Search text for imported items (builder's choice, for A-39).
 *
 * The index's default deriver handles `text/plain` only, but imported items are `message/rfc822`, `text/vcard` and
 * `text/calendar`. The importers' Derivers are async; the index's `derive` hook is synchronous. This module adapts the
 * importers' exported SYNCHRONOUS parsers (`parseEmailMessage`, `parseVcard` + `formatContactText`, `parseIcalendar`)
 * and produces the same kind of text lines the async Derivers produce. Every index call of the command line passes
 * the same `projection` (same version), otherwise the index would rebuild or report a stale generation.
 *
 * Memory: at most `MAX_DERIVE_BYTES` of an item's plaintext is copied for parsing; the copy is zeroed afterwards.
 * A larger item (for example a mail with a big attachment) is parsed from its first `MAX_DERIVE_BYTES`, which hold
 * the headers and the leading text parts.
 */
import { Buffer } from 'node:buffer';
import type { DeriveItem, ProjectionOptions } from 'foundry-index';
import type { ParsedCalendarEvent } from 'importers';

/** Not 1: an index built with the default (plain-text-only) deriver is rebuilt instead of trusted. */
export const DERIVER_VERSION = 2;
export const MAX_DERIVE_BYTES = 8 * 1024 * 1024;
const MAX_CHUNKS = 1024;
const CHUNK_CHARS = 800;

type Parsers = Pick<typeof import('importers'), 'parseEmailMessage' | 'parseVcard' | 'formatContactText' | 'parseIcalendar'>;

/** Split text into chunks of at most 800 characters (cut at whitespace when possible), at most 1,024 chunks. */
export function chunkPlainText(text: string): string[] {
  const chunks: string[] = [];
  let rest = text.replace(/\r\n?/gu, '\n').trim();
  while (rest.length > 0 && chunks.length < MAX_CHUNKS) {
    let cut = rest.length;
    if (rest.length > CHUNK_CHARS) {
      const window = rest.slice(0, CHUNK_CHARS);
      const space = Math.max(window.lastIndexOf('\n'), window.lastIndexOf(' '));
      cut = space >= CHUNK_CHARS / 2 ? space : CHUNK_CHARS;
      if (/[\uD800-\uDBFF]/u.test(rest[cut - 1] ?? '')) cut--;
    }
    const chunk = rest.slice(0, cut).trim();
    if (chunk) chunks.push(chunk);
    rest = rest.slice(cut).trimStart();
  }
  return chunks;
}

function copyFrames(frames: Iterable<Uint8Array>): Buffer {
  const parts: Buffer[] = [];
  let total = 0;
  for (const frame of frames) {
    if (total >= MAX_DERIVE_BYTES) continue; // keep iterating so the index can authenticate the rest
    const take = Math.min(frame.length, MAX_DERIVE_BYTES - total);
    const copy = Buffer.alloc(take);
    copy.set(frame.subarray(0, take));
    parts.push(copy);
    total += take;
  }
  const bytes = Buffer.concat(parts, total);
  for (const part of parts) part.fill(0);
  return bytes;
}

const person = (a: { name?: string; address: string }) => (a.name ? `${a.name} <${a.address}>` : a.address);

function eventText(ev: ParsedCalendarEvent, calendarName?: string): string {
  const lines = [`Event: ${ev.summary ?? '(untitled event)'}`];
  if (calendarName) lines.push(`Calendar: ${calendarName}`);
  if (ev.dtstart) lines.push(`Start: ${ev.dtstart}`);
  if (ev.dtend) lines.push(`End: ${ev.dtend}`);
  if (ev.location) lines.push(`Location: ${ev.location}`);
  if (ev.organizer) lines.push(`Organizer: ${person(ev.organizer)}`);
  if (ev.attendees.length > 0) lines.push(`Attendees: ${ev.attendees.map(person).join(', ')}`);
  if (ev.categories.length > 0) lines.push(`Categories: ${ev.categories.join(', ')}`);
  if (ev.description) lines.push(`Description: ${ev.description}`);
  return lines.join('\n');
}

/** The text of one item, or undefined when its type has no text deriver. Parse failures yield no text. */
export function itemText(parsers: Parsers, mime: string | null, bytes: Buffer): string | undefined {
  const type = (mime ?? '').split(';', 1)[0]!.trim().toLowerCase();
  try {
    if (type === 'message/rfc822') {
      const mail = parsers.parseEmailMessage(bytes);
      const lines = [`Subject: ${mail.subject}`];
      if (mail.from.length > 0) lines.push(`From: ${mail.from.map(person).join(', ')}`);
      if (mail.to.length > 0) lines.push(`To: ${mail.to.map(person).join(', ')}`);
      if (mail.cc.length > 0) lines.push(`Cc: ${mail.cc.map(person).join(', ')}`);
      if (mail.date) lines.push(`Date: ${mail.date}`);
      if (mail.labels.length > 0) lines.push(`Labels: ${mail.labels.join(', ')}`);
      if (mail.attachments.length > 0) lines.push(`Attachments: ${mail.attachments.map(a => a.filename).join(', ')}`);
      if (mail.bodyText) lines.push('', mail.bodyText);
      return lines.join('\n');
    }
    if (type === 'text/vcard') {
      const contact = parsers.parseVcard(bytes.toString('utf8'));
      return contact ? parsers.formatContactText(contact) : '';
    }
    if (type === 'text/calendar') {
      const calendar = parsers.parseIcalendar(bytes.toString('utf8'));
      return calendar.events.map(ev => eventText(ev, calendar.calendarName)).join('\n\n');
    }
    if (type === 'text/plain') return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
  return undefined;
}

/** Build the projection options every index call of the command line uses. */
export async function loadProjection(): Promise<ProjectionOptions> {
  const { parseEmailMessage, parseVcard, formatContactText, parseIcalendar } = await import('importers');
  const parsers: Parsers = { parseEmailMessage, parseVcard, formatContactText, parseIcalendar };
  return {
    version: DERIVER_VERSION,
    derive(item: DeriveItem, frames: Iterable<Uint8Array>): Iterable<string> {
      const bytes = copyFrames(frames);
      try {
        return chunkPlainText(itemText(parsers, item.mime, bytes) ?? '');
      } finally {
        bytes.fill(0);
      }
    },
  };
}

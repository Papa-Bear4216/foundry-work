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
 * the headers and the leading text parts. For a calendar cut this way, the completed fields of the cut event are kept.
 * The rendered text of one item is at most `MAX_TEXT_BYTES` (UTF-8) for EVERY type (mail, vCard, plain text,
 * calendar): each is rendered into one byte budget, and the chunks the index receives are capped again in total. A
 * calendar is bounded while it is built and names its calendar once, not once per event.
 */
import { Buffer } from 'node:buffer';
import type { DeriveItem, ProjectionOptions } from 'foundry-index';
import type { ParsedCalendarEvent } from 'importers';

/** Not 1: an index built with the default (plain-text-only) deriver is rebuilt instead of trusted. */
export const DERIVER_VERSION = 2;
export const MAX_DERIVE_BYTES = 8 * 1024 * 1024;
export const MAX_TEXT_BYTES = 1024 * 1024;
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

/** Copy at most `MAX_DERIVE_BYTES`; `truncated` says whether the item had more bytes. */
function copyFrames(frames: Iterable<Uint8Array>): { bytes: Buffer; truncated: boolean } {
  const parts: Buffer[] = [];
  let total = 0;
  let truncated = false;
  for (const frame of frames) {
    if (total >= MAX_DERIVE_BYTES) { // keep iterating so the index can authenticate the rest
      if (frame.length > 0) truncated = true;
      continue;
    }
    const take = Math.min(frame.length, MAX_DERIVE_BYTES - total);
    if (take < frame.length) truncated = true;
    const copy = Buffer.alloc(take);
    copy.set(frame.subarray(0, take));
    parts.push(copy);
    total += take;
  }
  const bytes = Buffer.concat(parts, total);
  for (const part of parts) part.fill(0);
  return { bytes, truncated };
}

/** Collects text pieces up to `limit` (default `MAX_TEXT_BYTES`) UTF-8 bytes. At the cap it stops adding text. */
class TextBudget {
  readonly #pieces: string[] = [];
  #left: number;

  constructor(limit = MAX_TEXT_BYTES) {
    this.#left = limit;
  }

  get full(): boolean {
    return this.#left <= 0;
  }

  /** Add one piece; returns false when the cap is reached (the piece may have been cut to fit). */
  add(piece: string): boolean {
    if (this.#left <= 0) return false;
    const size = Buffer.byteLength(piece);
    if (size <= this.#left) {
      this.#pieces.push(piece);
      this.#left -= size;
      return this.#left > 0;
    }
    // Cut to fit. Every code unit takes at least one UTF-8 byte, so the first `#left` code units hold at least
    // `#left` bytes. Cut those bytes at `#left`, moved back to the start of a character (never inside one).
    const head = Buffer.from(piece.slice(0, this.#left), 'utf8');
    let cut = Math.min(this.#left, head.length);
    while (cut > 0 && cut < head.length && (head[cut]! & 0xc0) === 0x80) cut--;
    this.#pieces.push(head.subarray(0, cut).toString('utf8'));
    this.#left = 0;
    return false;
  }

  text(): string {
    return this.#pieces.join('');
  }
}

/**
 * A calendar cut by the 8 MiB input limit: the parser keeps only events it saw END:VEVENT for. Drop every field that
 * may be incomplete, then close an open event so its completed fields stay. A field is complete when the next
 * physical line starts a new field (not a space or tab, which would continue it). So:
 * - the text after the last line break never ended: drop it (it may also end inside a UTF-8 character);
 * - if that text was empty or a continuation, the field before it is not proven complete either: drop it too.
 */
function closeTruncatedCalendar(ics: string): string {
  const lines = ics.split(/\r?\n/u);
  const cut = lines.pop() ?? '';
  if (cut === '' || /^[ \t]/u.test(cut)) {
    while (lines.length > 0 && /^[ \t]/u.test(lines[lines.length - 1]!)) lines.pop(); // its continuation lines
    lines.pop(); // the field they continue
  }
  let open = false;
  for (const line of lines) {
    const upper = line.trim().toUpperCase();
    if (upper === 'BEGIN:VEVENT') open = true;
    else if (upper === 'END:VEVENT') open = false;
  }
  if (open) lines.push('END:VEVENT');
  lines.push('END:VCALENDAR');
  return lines.join('\r\n') + '\r\n';
}

const person = (a: { name?: string; address: string }) => (a.name ? `${a.name} <${a.address}>` : a.address);

/** One event's lines. The calendar name is rendered once per item, at the top, not per event. */
function eventText(ev: ParsedCalendarEvent): string {
  const lines = [`Event: ${ev.summary ?? '(untitled event)'}`];
  if (ev.dtstart) lines.push(`Start: ${ev.dtstart}`);
  if (ev.dtend) lines.push(`End: ${ev.dtend}`);
  if (ev.location) lines.push(`Location: ${ev.location}`);
  if (ev.organizer) lines.push(`Organizer: ${person(ev.organizer)}`);
  if (ev.attendees.length > 0) lines.push(`Attendees: ${ev.attendees.map(person).join(', ')}`);
  if (ev.categories.length > 0) lines.push(`Categories: ${ev.categories.join(', ')}`);
  if (ev.description) lines.push(`Description: ${ev.description}`);
  return lines.join('\n');
}

/**
 * The text of one item, at most `MAX_TEXT_BYTES` (UTF-8), or undefined when its type has no text deriver. Parse
 * failures yield no text. `truncated`: `bytes` is the first `MAX_DERIVE_BYTES` of a larger item. Every type (mail,
 * vCard, plain text, calendar) is rendered into ONE `TextBudget`, piece by piece, so the byte cap is the same for all.
 */
export function itemText(parsers: Parsers, mime: string | null, bytes: Buffer, truncated = false): string | undefined {
  const budget = new TextBudget();
  return renderItem(parsers, mime, bytes, truncated, budget) ? budget.text() : undefined;
}

/** Render the item's text into `budget`. False when its type has no text deriver. A parse failure adds no text. */
function renderItem(parsers: Parsers, mime: string | null, bytes: Buffer, truncated: boolean, budget: TextBudget): boolean {
  const type = (mime ?? '').split(';', 1)[0]!.trim().toLowerCase();
  if (!['message/rfc822', 'text/vcard', 'text/calendar', 'text/plain'].includes(type)) return false;
  const lines = (values: readonly string[]) => {
    values.forEach((line, i) => {
      if (!budget.full) budget.add((i > 0 ? '\n' : '') + line);
    });
  };
  try {
    if (type === 'message/rfc822') {
      const mail = parsers.parseEmailMessage(bytes);
      const head = [`Subject: ${mail.subject}`];
      if (mail.from.length > 0) head.push(`From: ${mail.from.map(person).join(', ')}`);
      if (mail.to.length > 0) head.push(`To: ${mail.to.map(person).join(', ')}`);
      if (mail.cc.length > 0) head.push(`Cc: ${mail.cc.map(person).join(', ')}`);
      if (mail.date) head.push(`Date: ${mail.date}`);
      if (mail.labels.length > 0) head.push(`Labels: ${mail.labels.join(', ')}`);
      if (mail.attachments.length > 0) head.push(`Attachments: ${mail.attachments.map(a => a.filename).join(', ')}`);
      if (mail.bodyText) head.push('', mail.bodyText);
      lines(head);
    } else if (type === 'text/vcard') {
      const contact = parsers.parseVcard(bytes.toString('utf8'));
      if (contact) budget.add(parsers.formatContactText(contact));
    } else if (type === 'text/calendar') {
      const ics = bytes.toString('utf8');
      const calendar = parsers.parseIcalendar(truncated ? closeTruncatedCalendar(ics) : ics);
      // Bounded while it is built: the name once, then events until the 1 MiB cap.
      if (calendar.calendarName) budget.add(`Calendar: ${calendar.calendarName}\n\n`);
      calendar.events.forEach((ev, i) => {
        if (!budget.full) budget.add((i > 0 ? '\n\n' : '') + eventText(ev));
      });
    } else {
      budget.add(new TextDecoder().decode(bytes));
    }
  } catch {
    // A parse failure yields no text (text added before the failure stays: it is already within the cap).
  }
  return true;
}

/**
 * Chunks of at most `MAX_TEXT_BYTES` in total (UTF-8). `itemText` already caps the text; this second cap is on what
 * the index actually receives, so no chunking change can push one item's search text past 1 MiB.
 */
export function capChunks(chunks: readonly string[]): string[] {
  const out: string[] = [];
  let left = MAX_TEXT_BYTES;
  for (const chunk of chunks) {
    const budget = new TextBudget(left);
    budget.add(chunk);
    const kept = budget.text();
    if (kept) out.push(kept);
    left -= Buffer.byteLength(kept);
    if (left <= 0 || kept.length < chunk.length) break;
  }
  return out;
}

/** Build the projection options every index call of the command line uses. */
export async function loadProjection(): Promise<ProjectionOptions> {
  const { parseEmailMessage, parseVcard, formatContactText, parseIcalendar } = await import('importers');
  const parsers: Parsers = { parseEmailMessage, parseVcard, formatContactText, parseIcalendar };
  return {
    version: DERIVER_VERSION,
    derive(item: DeriveItem, frames: Iterable<Uint8Array>): Iterable<string> {
      const { bytes, truncated } = copyFrames(frames);
      try {
        return capChunks(chunkPlainText(itemText(parsers, item.mime, bytes, truncated) ?? ''));
      } finally {
        bytes.fill(0);
      }
    },
  };
}

/**
 * @file importers/mail.ts
 * Google Takeout Mail (mbox / RFC 4155 + RFC 5322) streaming lossless splitter and deriver.
 *
 * `split` streams mbox files with flat O(1) memory regardless of archive size, keeping
 * the exact `From ` separator line in each stored message (and in event metadata) so
 * concatenating stored messages reproduces the input mbox byte-for-byte.
 */

import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import type { ArchiveEntry, Derived, Deriver, Importer, RawItem, SplitOptions, StoredItem } from '../types.js';
import { DEFAULT_MAX_ITEM_BYTES, normalizeTimestamp, uniqueSorted } from '../defaults.js';

export const MAIL_SOURCE_ID = 'google-takeout/mail';

const MAX_HEADER_PEEK_BYTES = 64 * 1024;
const MAX_SEPARATOR_LINE_BYTES = 1024;

// Matches standard RFC 4155 / Google Takeout mbox `From ` separator lines without splitting prose.
const MBOX_SEPARATOR_RE =
  /^From \S+ (?:(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4}|\s+[A-Za-z]{2,5})?\s+\d{4}(?:\s+[+-]\d{4})?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\r\n]*)$/;

export function isMboxSeparatorLine(line: Buffer): boolean {
  if (line.length < 20 || line.length > MAX_SEPARATOR_LINE_BYTES) return false;
  if (
    line[0] !== 0x46 || // F
    line[1] !== 0x72 || // r
    line[2] !== 0x6f || // o
    line[3] !== 0x6d || // m
    line[4] !== 0x20    // space
  ) {
    return false;
  }
  let end = line.length;
  if (end > 0 && line[end - 1] === 0x0a) end--;
  if (end > 0 && line[end - 1] === 0x0d) end--;
  const text = line.subarray(0, end).toString('utf8');
  return MBOX_SEPARATOR_RE.test(text);
}

function parseSeparatorTimestamp(separatorLine: string): string | undefined {
  // Format: `From <addr> Mon Jan 01 12:34:56 +0000 2024` or `From <addr> Mon Jan  1 12:34:56 2024`
  const m =
    /^From \S+ ((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\s+(?:[+-]\d{4}|[A-Za-z]{2,5}))?\s+\d{4}(?:\s+[+-]\d{4})?)$/.exec(
      separatorLine,
    );
  if (m) {
    return normalizeTimestamp(m[1]);
  }
  const iso = /^From \S+ (\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s*(?:Z|[+-]\d{2}:?\d{2}))?)$/i.exec(separatorLine);
  if (iso) return normalizeTimestamp(iso[1]);
  return undefined;
}

function parseGmailLabels(headerValue: string): string[] {
  const labels: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < headerValue.length; i++) {
    const ch = headerValue[i]!;
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === ',' && !inQuotes) {
      const trimmed = current.trim();
      if (trimmed) labels.push(trimmed.toLowerCase());
      current = '';
    } else {
      current += ch;
    }
  }
  const trimmed = current.trim();
  if (trimmed) labels.push(trimmed.toLowerCase());
  return uniqueSorted(labels);
}

function parseHeaderMetadata(headerBytes: Buffer): {
  mboxSeparator?: string;
  sourceTs?: string;
  tags: string[];
  messageId?: string;
} {
  const text = headerBytes.toString('utf8');
  const lines = text.split(/\r?\n/);
  let startIdx = 0;
  let mboxSeparator: string | undefined;

  if (lines.length > 0 && MBOX_SEPARATOR_RE.test(lines[0]!)) {
    mboxSeparator = lines[0]!;
    startIdx = 1;
  }

  // Unfold RFC 5322 headers up to first blank line.
  const unfolded: string[] = [];
  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i]!;
    if (line === '') break;
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ' ' + line.trim();
    } else {
      unfolded.push(line);
    }
  }

  let dateHeader: string | undefined;
  let messageId: string | undefined;
  const tags: string[] = ['mail'];

  for (const h of unfolded) {
    const colon = h.indexOf(':');
    if (colon === -1) continue;
    const name = h.slice(0, colon).trim().toLowerCase();
    const val = h.slice(colon + 1).trim();
    if (name === 'date' && !dateHeader) dateHeader = val;
    else if (name === 'message-id' && !messageId) messageId = val;
    else if (name === 'x-gmail-labels') {
      for (const lbl of parseGmailLabels(val)) tags.push(lbl);
    }
  }

  const sourceTs = normalizeTimestamp(dateHeader) ?? (mboxSeparator ? parseSeparatorTimestamp(mboxSeparator) : undefined);
  return { mboxSeparator, sourceTs, tags: uniqueSorted(tags), messageId };
}

/**
 * Pull-based line/chunk cursor over an mbox Readable stream.
 * Maintains O(1) memory: buffers at most one partial line (up to MAX_SEPARATOR_LINE_BYTES)
 * plus a single message's header prefix (up to MAX_HEADER_PEEK_BYTES).
 */
class MboxCursor {
  readonly #iter: AsyncIterator<Buffer>;
  #buffer: Buffer = Buffer.alloc(0);
  #eof = false;
  #atLineStart = true;
  #stashedNextSeparator: Buffer | null = null;

  constructor(source: Readable) {
    this.#iter = source[Symbol.asyncIterator]();
  }

  async #fill(): Promise<boolean> {
    if (this.#eof) return false;
    const next = await this.#iter.next();
    if (next.done) {
      this.#eof = true;
      return false;
    }
    const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value as Uint8Array);
    if (chunk.length === 0) return this.#fill();
    this.#buffer = this.#buffer.length > 0 ? Buffer.concat([this.#buffer, chunk]) : chunk;
    return true;
  }

  /**
   * Returns the next chunk belonging to the current message, or null when the current message ends.
   * When `isFirstChunkOfMessage` is true, a leading `From ` separator is consumed as part of the message;
   * otherwise a `From ` separator at line start terminates the current message and is stashed for the next.
   */
  async readMessageChunk(allowLeadingSeparator: boolean): Promise<Buffer | null> {
    if (allowLeadingSeparator && this.#stashedNextSeparator) {
      const sep = this.#stashedNextSeparator;
      this.#stashedNextSeparator = null;
      this.#atLineStart = true;
      return sep;
    }

    while (true) {
      if (this.#buffer.length === 0) {
        const got = await this.#fill();
        if (!got) return null;
      }

      if (!this.#atLineStart) {
        const nl = this.#buffer.indexOf(0x0a);
        if (nl === -1) {
          const out = this.#buffer;
          this.#buffer = Buffer.alloc(0);
          return out;
        }
        const out = this.#buffer.subarray(0, nl + 1);
        this.#buffer = this.#buffer.subarray(nl + 1);
        this.#atLineStart = true;
        return out;
      }

      // We are at the start of a line. Check if it can possibly start with `From `.
      if (this.#buffer.length < 5 && !this.#eof) {
        await this.#fill();
        if (this.#buffer.length < 5 && !this.#eof) continue;
      }

      const startsWithFrom =
        this.#buffer.length >= 5 &&
        this.#buffer[0] === 0x46 &&
        this.#buffer[1] === 0x72 &&
        this.#buffer[2] === 0x6f &&
        this.#buffer[3] === 0x6d &&
        this.#buffer[4] === 0x20;

      if (startsWithFrom) {
        let nl = this.#buffer.indexOf(0x0a);
        while (nl === -1 && this.#buffer.length <= MAX_SEPARATOR_LINE_BYTES && !this.#eof) {
          await this.#fill();
          nl = this.#buffer.indexOf(0x0a);
        }
        const lineEnd = nl !== -1 ? nl + 1 : this.#buffer.length;
        const candidateLine = this.#buffer.subarray(0, lineEnd);
        if (!allowLeadingSeparator && isMboxSeparatorLine(candidateLine)) {
          this.#stashedNextSeparator = Buffer.from(candidateLine);
          this.#buffer = this.#buffer.subarray(lineEnd);
          this.#atLineStart = true;
          return null;
        }
        this.#buffer = this.#buffer.subarray(lineEnd);
        this.#atLineStart = nl !== -1;
        return candidateLine;
      }

      // Not starting with `From `: scan forward until a `\nFrom ` or end of buffer.
      let scanFrom = 0;
      let emitEnd = this.#buffer.length;
      let nextAtLineStart = false;

      while (scanFrom < this.#buffer.length) {
        const nl = this.#buffer.indexOf(0x0a, scanFrom);
        if (nl === -1) {
          emitEnd = this.#buffer.length;
          nextAtLineStart = false;
          break;
        }
        const afterNl = nl + 1;
        if (afterNl >= this.#buffer.length) {
          emitEnd = afterNl;
          nextAtLineStart = true;
          break;
        }
        if (this.#buffer[afterNl] === 0x46) {
          // Potential `From ` after this newline; stop right after `\n` so the next iteration checks it cleanly.
          emitEnd = afterNl;
          nextAtLineStart = true;
          break;
        }
        scanFrom = afterNl;
      }

      const out = this.#buffer.subarray(0, emitEnd);
      this.#buffer = this.#buffer.subarray(emitEnd);
      this.#atLineStart = nextAtLineStart;
      return out;
    }
  }

  async hasMore(): Promise<boolean> {
    if (this.#stashedNextSeparator || this.#buffer.length > 0) return true;
    return this.#fill();
  }
}

function findHeaderEnd(buf: Buffer): number {
  const crlf = buf.indexOf('\r\n\r\n');
  const lf = buf.indexOf('\n\n');
  if (crlf === -1 && lf === -1) return -1;
  if (crlf === -1) return lf + 2;
  if (lf === -1) return crlf + 4;
  return crlf < lf ? crlf + 4 : lf + 2;
}

/** Copies message chunks into fixed 64 KiB blocks so a buffered message holds few objects. */
class MessageBlocks {
  readonly blocks: Buffer[] = [];
  #block: Buffer | null = null;
  #used = 0;

  push(chunk: Buffer): void {
    let rest = chunk;
    while (rest.length > 0) {
      if (this.#block === null) {
        this.#block = Buffer.allocUnsafe(MESSAGE_BLOCK_BYTES);
        this.#used = 0;
      }
      const take = Math.min(rest.length, MESSAGE_BLOCK_BYTES - this.#used);
      rest.copy(this.#block, this.#used, 0, take);
      this.#used += take;
      rest = rest.subarray(take);
      if (this.#used === MESSAGE_BLOCK_BYTES) {
        this.blocks.push(this.#block);
        this.#block = null;
      }
    }
  }

  finish(): Buffer[] {
    if (this.#block !== null && this.#used > 0) this.blocks.push(Buffer.from(this.#block.subarray(0, this.#used)));
    this.#block = null;
    return this.blocks;
  }
}

/** Streams buffered blocks and releases each one as it is read, so nothing stays referenced here. */
function blockStream(blocks: Buffer[]): Readable {
  let next = 0;
  return new Readable({
    highWaterMark: MESSAGE_BLOCK_BYTES,
    read() {
      if (next >= blocks.length) {
        blocks.length = 0;
        this.push(null);
        return;
      }
      const block = blocks[next]!;
      blocks[next++] = EMPTY;
      this.push(block);
    },
  });
}

const MESSAGE_BLOCK_BYTES = 64 * 1024;
const EMPTY = Buffer.alloc(0);

/**
 * Splits an mbox entry into messages. Each message is buffered only up to `maxItemBytes`
 * (A-36 Finding 7): an over-limit message is dropped at the limit, the rest of it is read
 * forward to the next separator without buffering, `ITEM_TOO_LARGE` is reported through
 * `onItemError`, and splitting continues. Skipped messages keep their `#N` number, so paths
 * and item keys of later messages do not depend on the limit.
 */
async function* splitMboxStream(entry: ArchiveEntry, options?: SplitOptions): AsyncIterable<RawItem> {
  const maxItemBytes = Math.max(1, options?.maxItemBytes ?? DEFAULT_MAX_ITEM_BYTES);
  const peekLimit = Math.min(MAX_HEADER_PEEK_BYTES, maxItemBytes + 1);
  const cursor = new MboxCursor(entry.open());
  let messageIndex = 0;

  while (await cursor.hasMore()) {
    // Peek up to MAX_HEADER_PEEK_BYTES (or end of headers / end of message) to extract timestamp & labels.
    const prefixChunks: Buffer[] = [];
    let prefixBytes = 0;
    let messageEndedDuringPeek = false;
    let first = true;

    while (prefixBytes < peekLimit) {
      const chunk = await cursor.readMessageChunk(first);
      first = false;
      if (chunk === null) {
        messageEndedDuringPeek = true;
        break;
      }
      prefixChunks.push(Buffer.from(chunk));
      prefixBytes += chunk.length;
      const combined = prefixChunks.length === 1 ? prefixChunks[0]! : Buffer.concat(prefixChunks);
      if (findHeaderEnd(combined) !== -1) {
        prefixChunks.length = 0;
        prefixChunks.push(combined);
        break;
      }
    }

    if (prefixBytes === 0) continue;

    const headerBuffer = prefixChunks.length === 1 ? prefixChunks[0]! : Buffer.concat(prefixChunks);
    prefixChunks.length = 0;
    messageIndex++;
    const itemPath = `${entry.path}#${messageIndex}`;

    // Buffer the message up to the limit. Past the limit, drop every buffered byte and read
    // forward to the next separator, counting bytes only.
    let observedBytes = headerBuffer.length;
    let blocks: MessageBlocks | null = observedBytes > maxItemBytes ? null : new MessageBlocks();
    if (!messageEndedDuringPeek) {
      for (;;) {
        const chunk = await cursor.readMessageChunk(false);
        if (chunk === null) break;
        observedBytes += chunk.length;
        if (blocks === null) continue;
        if (observedBytes > maxItemBytes) {
          blocks = null;
          continue;
        }
        blocks.push(chunk);
      }
    }

    if (blocks === null) {
      options?.onItemError?.({
        code: 'ITEM_TOO_LARGE',
        source: MAIL_SOURCE_ID,
        entryPath: entry.path,
        itemPath,
        message: `Mail message ${itemPath} (${observedBytes} bytes) exceeds per-item limit (${maxItemBytes} bytes).`,
        limitBytes: maxItemBytes,
        observedBytes,
      });
      continue;
    }

    const meta = parseHeaderMetadata(headerBuffer);
    // The stream owns this array and empties it while it is read; this generator keeps no reference.
    const messageBlocks = blocks.finish();
    blocks = null;
    messageBlocks.unshift(headerBuffer);
    const itemMeta: Record<string, unknown> = {};
    if (meta.mboxSeparator !== undefined) itemMeta.mbox_separator = meta.mboxSeparator;
    if (meta.messageId !== undefined) itemMeta.message_id = meta.messageId;

    yield {
      bytes: blockStream(messageBlocks),
      path: itemPath,
      mime: 'message/rfc822',
      sourceTs: meta.sourceTs,
      tags: meta.tags,
      meta: Object.keys(itemMeta).length > 0 ? itemMeta : undefined,
    };
  }
}

// --- RFC 5322 / MIME / RFC 2047 Deriver ---

function decodeQuotedPrintableBytes(input: string, underscoreAsSpace = false): Buffer {
  const cleaned = input.replace(/=\r?\n/g, '');
  const out: number[] = [];
  for (let i = 0; i < cleaned.length; i++) {
    const ch = cleaned[i]!;
    if (underscoreAsSpace && ch === '_') {
      out.push(0x20);
    } else if (ch === '=' && i + 2 < cleaned.length) {
      const hex = cleaned.slice(i + 1, i + 3);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        out.push(Number.parseInt(hex, 16));
        i += 2;
        continue;
      }
      out.push(0x3d);
    } else {
      const encoded = Buffer.from(ch, 'utf8');
      for (const b of encoded) out.push(b);
    }
  }
  return Buffer.from(out);
}

/** Decodes RFC 2047 encoded words (`=?charset?B|Q?text?=`). */
export function decodeRfc2047(value: string): string {
  // Collapse whitespace between adjacent encoded words per RFC 2047 section 6.2.
  const collapsed = value.replace(/\?=\s+=\?/g, '?==?');
  return collapsed.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_full, charset: string, enc: string, payload: string) => {
    const buf =
      enc.toUpperCase() === 'B'
        ? Buffer.from(payload, 'base64')
        : decodeQuotedPrintableBytes(payload, true);
    const lower = charset.toLowerCase();
    if (lower === 'iso-8859-1' || lower === 'latin1' || lower === 'latin-1') {
      return buf.toString('latin1');
    }
    return buf.toString('utf8');
  });
}

function parseHeaders(headerText: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  const lines = headerText.split(/\r?\n/);
  const unfolded: string[] = [];
  for (const line of lines) {
    if ((line.startsWith(' ') || line.startsWith('\t')) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ' ' + line.trim();
    } else if (line.length > 0) {
      unfolded.push(line);
    }
  }
  for (const line of unfolded) {
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const val = line.slice(colon + 1).trim();
    const list = map.get(key);
    if (list) list.push(val);
    else map.set(key, [val]);
  }
  return map;
}

function parseContentType(raw: string | undefined): { mime: string; boundary?: string; charset?: string; name?: string } {
  if (!raw) return { mime: 'text/plain' };
  const parts = raw.split(';');
  const mime = parts[0]!.trim().toLowerCase() || 'text/plain';
  let boundary: string | undefined;
  let charset: string | undefined;
  let name: string | undefined;
  for (let i = 1; i < parts.length; i++) {
    const eq = parts[i]!.indexOf('=');
    if (eq === -1) continue;
    const k = parts[i]!.slice(0, eq).trim().toLowerCase();
    const v = parts[i]!.slice(eq + 1).trim().replace(/^"|"$/g, '');
    if (k === 'boundary') boundary = v;
    else if (k === 'charset') charset = v;
    else if (k === 'name') name = decodeRfc2047(v);
  }
  return { mime, boundary, charset, name };
}

function decodeBodyContent(body: string, cte: string | undefined, charset: string | undefined): string {
  const enc = (cte ?? '').trim().toLowerCase();
  let buf: Buffer;
  if (enc === 'base64') {
    buf = Buffer.from(body.replace(/\s+/g, ''), 'base64');
  } else if (enc === 'quoted-printable') {
    buf = decodeQuotedPrintableBytes(body, false);
  } else {
    buf = Buffer.from(body, 'utf8');
  }
  const lowerCharset = (charset ?? 'utf-8').toLowerCase();
  if (lowerCharset === 'iso-8859-1' || lowerCharset === 'latin1') {
    return buf.toString('latin1');
  }
  return buf.toString('utf8');
}

function stripHtmlTags(html: string): string {
  return html
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(?:p|div|li|tr|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

interface ExtractedMime {
  plainParts: string[];
  htmlParts: string[];
  attachments: Array<{ filename: string; mime: string }>;
}

function extractMimeParts(headers: Map<string, string[]>, body: string, out: ExtractedMime, depth = 0): void {
  if (depth > 8) return;
  const ct = parseContentType(headers.get('content-type')?.[0]);
  const cte = headers.get('content-transfer-encoding')?.[0];
  const disp = headers.get('content-disposition')?.[0] ?? '';

  if (ct.mime.startsWith('multipart/') && ct.boundary) {
    const marker = `--${ct.boundary}`;
    const sections = body.split(marker);
    for (let i = 1; i < sections.length; i++) {
      let section = sections[i]!;
      if (section.startsWith('--')) break;
      section = section.replace(/^\r?\n/, '');
      const sepCrlf = section.indexOf('\r\n\r\n');
      const sepLf = section.indexOf('\n\n');
      let splitAt = -1;
      let sepLen = 0;
      if (sepCrlf !== -1 && (sepLf === -1 || sepCrlf < sepLf)) {
        splitAt = sepCrlf;
        sepLen = 4;
      } else if (sepLf !== -1) {
        splitAt = sepLf;
        sepLen = 2;
      }
      if (splitAt === -1) continue;
      const partHeaders = parseHeaders(section.slice(0, splitAt));
      const partBody = section.slice(splitAt + sepLen).replace(/\r?\n$/, '');
      extractMimeParts(partHeaders, partBody, out, depth + 1);
    }
    return;
  }

  const filenameMatch = /filename\*?=(?:"([^"]*)"|([^;\s]*))/i.exec(disp);
  const filename = filenameMatch ? decodeRfc2047((filenameMatch[1] ?? filenameMatch[2] ?? '').trim()) : ct.name;
  const isAttachment = /^attachment/i.test(disp.trim()) || (Boolean(filename) && !ct.mime.startsWith('text/'));

  if (isAttachment) {
    out.attachments.push({ filename: filename ?? 'attachment', mime: ct.mime });
    return;
  }

  if (ct.mime === 'text/plain') {
    const decoded = decodeBodyContent(body, cte, ct.charset).trim();
    if (decoded) out.plainParts.push(decoded);
  } else if (ct.mime === 'text/html') {
    const decoded = stripHtmlTags(decodeBodyContent(body, cte, ct.charset));
    if (decoded) out.htmlParts.push(decoded);
  }
}

export interface ParsedEmailAddress {
  name?: string;
  address: string;
}

export function parseAddressList(raw: string | undefined): ParsedEmailAddress[] {
  if (!raw) return [];
  const results: ParsedEmailAddress[] = [];
  const parts = raw.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/);
  for (const part of parts) {
    const trimmed = decodeRfc2047(part.trim());
    if (!trimmed) continue;
    const angle = /^(.*)<([^<>]+)>$/.exec(trimmed);
    if (angle) {
      const name = angle[1]!.trim().replace(/^"|"$/g, '') || undefined;
      const address = angle[2]!.trim();
      if (address) results.push({ name, address });
    } else if (trimmed.includes('@')) {
      results.push({ address: trimmed });
    }
  }
  return results;
}

export interface ParsedEmail {
  mboxSeparator?: string;
  subject: string;
  from: ParsedEmailAddress[];
  to: ParsedEmailAddress[];
  cc: ParsedEmailAddress[];
  date?: string;
  messageId?: string;
  inReplyTo?: string;
  labels: string[];
  bodyText: string;
  attachments: Array<{ filename: string; mime: string }>;
}

/** Parses a single raw email (with or without leading mbox `From ` line) into structured fields and text. */
export function parseEmailMessage(rawBytes: Buffer): ParsedEmail {
  let raw = rawBytes.toString('utf8');
  let mboxSeparator: string | undefined;

  const firstNl = raw.indexOf('\n');
  const firstLine = (firstNl === -1 ? raw : raw.slice(0, firstNl)).replace(/\r$/, '');
  if (MBOX_SEPARATOR_RE.test(firstLine)) {
    mboxSeparator = firstLine;
    raw = firstNl === -1 ? '' : raw.slice(firstNl + 1);
  }

  const sepCrlf = raw.indexOf('\r\n\r\n');
  const sepLf = raw.indexOf('\n\n');
  let headerPart = raw;
  let bodyPart = '';
  if (sepCrlf !== -1 && (sepLf === -1 || sepCrlf < sepLf)) {
    headerPart = raw.slice(0, sepCrlf);
    bodyPart = raw.slice(sepCrlf + 4);
  } else if (sepLf !== -1) {
    headerPart = raw.slice(0, sepLf);
    bodyPart = raw.slice(sepLf + 2);
  }

  const headers = parseHeaders(headerPart);
  const subject = decodeRfc2047(headers.get('subject')?.[0] ?? '') || '(no subject)';
  const from = parseAddressList(headers.get('from')?.join(', '));
  const to = parseAddressList(headers.get('to')?.join(', '));
  const cc = parseAddressList(headers.get('cc')?.join(', '));
  const date =
    normalizeTimestamp(headers.get('date')?.[0]) ??
    (mboxSeparator ? parseSeparatorTimestamp(mboxSeparator) : undefined);
  const messageId = headers.get('message-id')?.[0];
  const inReplyTo = headers.get('in-reply-to')?.[0];
  const labels = parseGmailLabels(headers.get('x-gmail-labels')?.join(', ') ?? '');

  // Unescape mboxo/mboxrd `>From ` lines in body when deriving readable text.
  const unescapedBody = bodyPart.replace(/(^|\r?\n)>+(From )/g, '$1$2');
  const extracted: ExtractedMime = { plainParts: [], htmlParts: [], attachments: [] };
  extractMimeParts(headers, unescapedBody, extracted);
  const bodyText =
    extracted.plainParts.length > 0
      ? extracted.plainParts.join('\n\n')
      : extracted.htmlParts.join('\n\n');

  return {
    mboxSeparator,
    subject,
    from,
    to,
    cc,
    date,
    messageId,
    inReplyTo,
    labels,
    bodyText,
    attachments: extracted.attachments,
  };
}

async function readStreamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return Buffer.concat(chunks);
}

export const mailImporter: Importer = {
  id: MAIL_SOURCE_ID,
  matches(entry: ArchiveEntry): boolean {
    return entry.path.toLowerCase().endsWith('.mbox');
  },
  split(entry: ArchiveEntry, options?: SplitOptions): AsyncIterable<RawItem> {
    return splitMboxStream(entry, options);
  },
};

export const mailDeriver: Deriver = {
  id: MAIL_SOURCE_ID,
  version: 1,
  async *derive(item: StoredItem, bytes: Readable): AsyncIterable<Derived> {
    const raw = await readStreamToBuffer(bytes);
    const parsed = parseEmailMessage(raw);
    const lines: string[] = [`Subject: ${parsed.subject}`];
    if (parsed.from.length > 0) {
      lines.push(`From: ${parsed.from.map(a => (a.name ? `${a.name} <${a.address}>` : a.address)).join(', ')}`);
    }
    if (parsed.to.length > 0) {
      lines.push(`To: ${parsed.to.map(a => (a.name ? `${a.name} <${a.address}>` : a.address)).join(', ')}`);
    }
    if (parsed.cc.length > 0) {
      lines.push(`Cc: ${parsed.cc.map(a => (a.name ? `${a.name} <${a.address}>` : a.address)).join(', ')}`);
    }
    if (parsed.date) lines.push(`Date: ${parsed.date}`);
    if (parsed.labels.length > 0) lines.push(`Labels: ${parsed.labels.join(', ')}`);
    if (parsed.attachments.length > 0) {
      lines.push(`Attachments: ${parsed.attachments.map(a => `${a.filename} (${a.mime})`).join(', ')}`);
    }
    if (parsed.bodyText) {
      lines.push('');
      lines.push(parsed.bodyText);
    }

    const tags = uniqueSorted([...item.tags, ...parsed.labels]);

    yield {
      kind: 'text',
      title: parsed.subject,
      text: lines.join('\n'),
      structured: {
        entityType: 'email',
        subject: parsed.subject,
        from: parsed.from,
        to: parsed.to,
        cc: parsed.cc,
        date: parsed.date,
        messageId: parsed.messageId,
        inReplyTo: parsed.inReplyTo,
        labels: parsed.labels,
        attachments: parsed.attachments,
        mboxSeparator: parsed.mboxSeparator,
      },
      sourceTs: parsed.date ?? item.sourceTs,
      tags,
    };

    if (parsed.from.length > 0 || parsed.to.length > 0 || parsed.cc.length > 0) {
      const nodes: Array<{ kind: string; canonicalKey: string; label: string }> = [];
      const edges: Array<{ srcKind: string; srcKey: string; dstKind: string; dstKey: string; kind: string }> = [];
      const seen = new Set<string>();
      const addAddr = (a: ParsedEmailAddress) => {
        const key = `email:${a.address.toLowerCase()}`;
        if (!seen.has(key)) {
          seen.add(key);
          nodes.push({ kind: 'person', canonicalKey: key, label: a.name ?? a.address });
        }
        return key;
      };
      const senders = parsed.from.map(addAddr);
      const recipients = [...parsed.to, ...parsed.cc].map(addAddr);
      for (const s of senders) {
        for (const r of recipients) {
          if (s !== r) {
            edges.push({ srcKind: 'person', srcKey: s, dstKind: 'person', dstKey: r, kind: 'emailed' });
          }
        }
      }
      yield { kind: 'graph_evidence', nodes, edges };
    }
  },
};

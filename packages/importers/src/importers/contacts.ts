/**
 * @file importers/contacts.ts
 * Google Takeout Contacts (vCard / VCF) lossless splitter and deriver.
 *
 * Ported through the scrub gate from predecessor contacts parsing logic,
 * rewritten for Foundry's two-stage Importer/Deriver contract (Architecture 7).
 */

import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import type { ArchiveEntry, Derived, Deriver, Importer, ItemErrorInfo, RawItem, SplitOptions, StoredItem } from '../types.js';
import { DEFAULT_MAX_ITEM_BYTES, normalizeTimestamp, uniqueSorted } from '../defaults.js';
import { getParamValue, parseContentLine } from './content-line.js';
import type { ContentLineParam } from './content-line.js';
import { ItemSkipError } from './errors.js';

export const CONTACTS_SOURCE_ID = 'google-takeout/contacts';

const LOGICAL_MARKER_MAX_CHARS = 32;

export interface ParsedContact {
  name: string;
  firstName?: string;
  lastName?: string;
  nickname?: string;
  company?: string;
  jobTitle?: string;
  phones: Array<{ type?: string; number: string }>;
  emails: Array<{ type?: string; address: string }>;
  addresses: Array<{ type?: string; formatted: string }>;
  notes?: string;
  birthday?: string;
  rev?: string;
  categories: string[];
}

function decodeQuotedPrintable(input: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < input.length; i++) {
    if (input[i] === '=' && i + 2 < input.length) {
      const hex = input.slice(i + 1, i + 3);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        bytes.push(Number.parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    const encoded = Buffer.from(input[i]!, 'utf8');
    for (const b of encoded) bytes.push(b);
  }
  return Buffer.from(bytes).toString('utf8');
}

function unescapeVcardValue(value: string): string {
  return value.replace(/\\([,;nN\\])/g, (_, esc: string) => {
    if (esc === 'n' || esc === 'N') return '\n';
    return esc;
  });
}

function extractParamType(params: readonly ContentLineParam[]): string | undefined {
  const explicit = getParamValue(params, 'TYPE');
  if (explicit) return explicit;
  // vCard 2.1 bare type parameters such as ;CELL or ;HOME;VOICE
  const bare = params
    .filter(p => p.name === '' && p.value.length > 0 && p.value.toUpperCase() !== 'QUOTED-PRINTABLE')
    .map(p => p.value);
  return bare.length > 0 ? bare.join(',') : undefined;
}

function isQuotedPrintableParams(params: readonly ContentLineParam[]): boolean {
  for (const p of params) {
    if (p.name === 'ENCODING' && p.value.toUpperCase() === 'QUOTED-PRINTABLE') return true;
    if (p.name === '' && p.value.toUpperCase() === 'QUOTED-PRINTABLE') return true;
  }
  return false;
}

/** Parses a single vCard (RFC 2425/2426/6350) into a structured contact record. */
export function parseVcard(cardText: string): ParsedContact | null {
  const cleaned = cardText.replace(/^\ufeff/, '');
  // Unfold quoted-printable soft breaks and RFC folded continuation lines.
  const unfolded = cleaned.replace(/=\r?\n/g, '').replace(/\r?\n[ \t]/g, '');

  let name = '';
  let first = '';
  let last = '';
  let nickname: string | undefined;
  let company: string | undefined;
  let jobTitle: string | undefined;
  let birthday: string | undefined;
  let rev: string | undefined;
  const phones: Array<{ type?: string; number: string }> = [];
  const emails: Array<{ type?: string; address: string }> = [];
  const addresses: Array<{ type?: string; formatted: string }> = [];
  const notes: string[] = [];
  const categories: string[] = [];

  for (const rawLine of unfolded.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parsedLine = parseContentLine(line, { allowGroup: true });
    if (!parsedLine) continue;

    const prop = parsedLine.name;
    const params = parsedLine.params;
    let value = parsedLine.value.trim();

    if (isQuotedPrintableParams(params)) {
      value = decodeQuotedPrintable(value);
    }

    if (prop === 'FN') {
      const unescaped = unescapeVcardValue(value).trim();
      if (!name && unescaped) name = unescaped;
    } else if (prop === 'N') {
      const parts = value.split(';').map(p => unescapeVcardValue(p).trim());
      last = parts[0] ?? '';
      first = parts[1] ?? '';
      if (!name && (first || last)) name = `${first} ${last}`.trim();
    } else if (prop === 'NICKNAME') {
      const nick = unescapeVcardValue(value).trim();
      if (nick) nickname = nick;
    } else if (prop === 'TEL') {
      const number = unescapeVcardValue(value).replace(/^tel:/i, '').trim();
      if (number) {
        phones.push({ type: extractParamType(params), number });
      }
    } else if (prop === 'EMAIL') {
      const address = unescapeVcardValue(value).trim();
      if (address) {
        emails.push({ type: extractParamType(params), address });
      }
    } else if (prop === 'ADR') {
      const parts = value
        .split(';')
        .map(p => unescapeVcardValue(p).trim())
        .filter(Boolean);
      if (parts.length > 0) {
        addresses.push({ type: extractParamType(params), formatted: parts.join(', ') });
      }
    } else if (prop === 'ORG') {
      const org = value
        .split(';')
        .map(p => unescapeVcardValue(p).trim())
        .filter(Boolean)
        .join(' ');
      if (org) company = org;
    } else if (prop === 'TITLE') {
      const title = unescapeVcardValue(value).trim();
      if (title) jobTitle = title;
    } else if (prop === 'NOTE') {
      const note = unescapeVcardValue(value).trim();
      if (note) notes.push(note);
    } else if (prop === 'BDAY') {
      const bday = unescapeVcardValue(value).trim();
      if (bday) birthday = bday;
    } else if (prop === 'REV') {
      const normalized = normalizeTimestamp(value);
      if (normalized) rev = normalized;
    } else if (prop === 'CATEGORIES') {
      for (const cat of value.split(',')) {
        const cleanedCat = unescapeVcardValue(cat).trim();
        if (cleanedCat) categories.push(cleanedCat);
      }
    }
  }

  if (!name) {
    if (company) name = company;
    else if (phones.length > 0) name = phones[0]!.number;
    else if (emails.length > 0) name = emails[0]!.address;
    else return null;
  }

  return {
    name,
    firstName: first || undefined,
    lastName: last || undefined,
    nickname,
    company,
    jobTitle,
    phones,
    emails,
    addresses,
    notes: notes.length > 0 ? notes.join(' | ') : undefined,
    birthday,
    rev,
    categories: uniqueSorted(categories),
  };
}

/** Renders a parsed contact into deterministic searchable plaintext. */
export function formatContactText(contact: ParsedContact): string {
  const lines: string[] = [`Contact: ${contact.name}`];
  if (contact.nickname) lines.push(`Nickname: ${contact.nickname}`);
  if (contact.company || contact.jobTitle) {
    const job = [contact.company, contact.jobTitle ? `(${contact.jobTitle})` : ''].filter(Boolean).join(' ');
    lines.push(`Organization: ${job}`);
  }
  if (contact.phones.length > 0) {
    lines.push(`Phones: ${contact.phones.map(p => (p.type ? `${p.type}: ${p.number}` : p.number)).join(', ')}`);
  }
  if (contact.emails.length > 0) {
    lines.push(`Emails: ${contact.emails.map(e => (e.type ? `${e.type}: ${e.address}` : e.address)).join(', ')}`);
  }
  if (contact.addresses.length > 0) {
    lines.push(`Addresses: ${contact.addresses.map(a => (a.type ? `${a.type}: ${a.formatted}` : a.formatted)).join('; ')}`);
  }
  if (contact.birthday) lines.push(`Birthday: ${contact.birthday}`);
  if (contact.categories.length > 0) lines.push(`Categories: ${contact.categories.join(', ')}`);
  if (contact.notes) lines.push(`Notes: ${contact.notes}`);
  return lines.join('\n');
}

function entryTags(entryPath: string): string[] {
  const segments = entryPath.split('/').filter(Boolean);
  const tags = ['contacts'];
  if (segments.length >= 2) {
    const folder = segments[segments.length - 2]!;
    if (!/^(?:takeout|contacts)$/i.test(folder)) {
      tags.push(folder.toLowerCase());
    }
  }
  return uniqueSorted(tags);
}

function extractRevFromCard(cardBytes: Buffer): string | undefined {
  const text = cardBytes.toString('utf8').replace(/^\ufeff/, '').replace(/\r?\n[ \t]/g, '');
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const parsed = parseContentLine(line, { allowGroup: true });
    if (parsed && parsed.name === 'REV') {
      const normalized = normalizeTimestamp(parsed.value.trim());
      if (normalized) return normalized;
    }
  }
  return undefined;
}

async function readStreamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return Buffer.concat(chunks);
}

/**
 * Splits a vCard stream into lossless per-contact RawItems, preserving exact physical bytes
 * for every BEGIN:VCARD ... END:VCARD block. Recognises BEGIN/END markers only on complete
 * unfolded RFC logical lines, bounds every card and unterminated line to maxItemBytes before
 * accumulating past it, and reports nested BEGIN or unfinished final cards as typed errors.
 */
async function* splitVcardStream(entry: ArchiveEntry, options?: SplitOptions): AsyncIterable<RawItem> {
  const maxItemBytes = options?.maxItemBytes ?? DEFAULT_MAX_ITEM_BYTES;
  const baseTags = entryTags(entry.path);
  const source = entry.open();

  const reportError = (info: ItemErrorInfo): void => {
    if (options?.onItemError) {
      options.onItemError(info);
      return;
    }
    throw new ItemSkipError(info);
  };

  let carryChunks: Buffer[] = [];
  let carryBytes = 0;
  let skippingOversizedPhysLine = false;
  let isFirstPhysLine = true;

  // Pending unfolded logical line (physical buffers kept verbatim; prefix capped for marker checks).
  let hasPending = false;
  let pendingPhys: Buffer[] = [];
  let pendingBytes = 0;
  let pendingHasContent = false;
  let pendingLogicalPrefix = '';
  let pendingLogicalOverflow = false;
  let pendingOversized = false;

  // Current card accumulator.
  let inCard = false;
  let cardOrdinal = 0;
  let cardChunks: Buffer[] = [];
  let cardBytes = 0;
  let oversizedCard = false;

  const appendLogicalText = (slice: Buffer): void => {
    if (pendingLogicalOverflow || slice.length === 0) return;
    const needed = LOGICAL_MARKER_MAX_CHARS - pendingLogicalPrefix.length;
    if (slice.length > needed) {
      pendingLogicalOverflow = true;
      return;
    }
    pendingLogicalPrefix += slice.toString('utf8');
    if (pendingLogicalPrefix.length > LOGICAL_MARKER_MAX_CHARS) {
      pendingLogicalOverflow = true;
    }
  };

  const markCurrentCardOversized = (observedBytes: number): void => {
    const alreadyReported = oversizedCard;
    cardChunks = [];
    cardBytes = 0;
    oversizedCard = true;
    if (!alreadyReported) {
      reportError({
        code: 'ITEM_TOO_LARGE',
        source: CONTACTS_SOURCE_ID,
        entryPath: entry.path,
        itemPath: inCard ? `${entry.path}#${cardOrdinal}` : entry.path,
        message: `vCard item exceeds per-item limit (${maxItemBytes} bytes).`,
        limitBytes: maxItemBytes,
        observedBytes,
      });
    }
  };

  const flushPendingLogicalLine = (): { card: Buffer; ordinal: number } | null => {
    if (!hasPending) return null;

    const phys = pendingPhys;
    const physLen = pendingBytes;
    const logicalKey = pendingLogicalOverflow || pendingOversized ? '' : pendingLogicalPrefix.toUpperCase();

    hasPending = false;
    pendingPhys = [];
    pendingBytes = 0;
    pendingHasContent = false;
    pendingLogicalPrefix = '';
    pendingLogicalOverflow = false;
    pendingOversized = false;

    if (logicalKey === 'BEGIN:VCARD') {
      if (inCard) {
        if (!oversizedCard) {
          reportError({
            code: 'VCARD_NESTED_BEGIN',
            source: CONTACTS_SOURCE_ID,
            entryPath: entry.path,
            itemPath: `${entry.path}#${cardOrdinal}`,
            message: `Nested BEGIN:VCARD encountered before END:VCARD in ${entry.path}#${cardOrdinal}.`,
          });
        }
        cardChunks = [];
        cardBytes = 0;
        oversizedCard = false;
      }
      cardOrdinal++;
      inCard = true;
      if (physLen > maxItemBytes) {
        markCurrentCardOversized(physLen);
        return null;
      }
      cardChunks = phys;
      cardBytes = physLen;
      return null;
    }

    if (logicalKey === 'END:VCARD') {
      if (!inCard) return null;
      if (oversizedCard) {
        inCard = false;
        oversizedCard = false;
        cardChunks = [];
        cardBytes = 0;
        return null;
      }
      if (cardBytes + physLen > maxItemBytes) {
        const observed = cardBytes + physLen;
        markCurrentCardOversized(observed);
        inCard = false;
        oversizedCard = false;
        return null;
      }
      for (const b of phys) cardChunks.push(b);
      const fullCard = Buffer.concat(cardChunks);
      const completedOrdinal = cardOrdinal;
      inCard = false;
      oversizedCard = false;
      cardChunks = [];
      cardBytes = 0;
      return { card: fullCard, ordinal: completedOrdinal };
    }

    if (inCard && !oversizedCard) {
      if (cardBytes + physLen > maxItemBytes) {
        markCurrentCardOversized(cardBytes + physLen);
      } else {
        for (const b of phys) cardChunks.push(b);
        cardBytes += physLen;
      }
    }
    return null;
  };

  const onPhysicalLine = (lineBuf: Buffer, wasOversized: boolean): { card: Buffer; ordinal: number } | null => {
    let contentStart = 0;
    let contentEnd = lineBuf.length;

    if (isFirstPhysLine) {
      isFirstPhysLine = false;
      if (!wasOversized && lineBuf.length >= 3 && lineBuf[0] === 0xef && lineBuf[1] === 0xbb && lineBuf[2] === 0xbf) {
        contentStart = 3;
      }
    }
    if (contentEnd > contentStart && lineBuf[contentEnd - 1] === 0x0a) contentEnd--;
    if (contentEnd > contentStart && lineBuf[contentEnd - 1] === 0x0d) contentEnd--;

    const isContinuation =
      !wasOversized &&
      hasPending &&
      pendingHasContent &&
      contentEnd > contentStart &&
      (lineBuf[contentStart] === 0x20 || lineBuf[contentStart] === 0x09);

    if (isContinuation) {
      if (pendingOversized || oversizedCard) return null;
      const projectedPending = pendingBytes + lineBuf.length;
      const projectedCard = inCard ? cardBytes + projectedPending : projectedPending;
      if (projectedPending > maxItemBytes || projectedCard > maxItemBytes) {
        pendingPhys = [];
        pendingBytes = 0;
        pendingOversized = true;
        if (inCard) {
          markCurrentCardOversized(projectedCard);
        } else {
          reportError({
            code: 'ITEM_TOO_LARGE',
            source: CONTACTS_SOURCE_ID,
            entryPath: entry.path,
            itemPath: entry.path,
            message: `Folded vCard line exceeds per-item limit (${maxItemBytes} bytes).`,
            limitBytes: maxItemBytes,
            observedBytes: projectedPending,
          });
        }
        return null;
      }
      pendingPhys.push(lineBuf);
      pendingBytes = projectedPending;
      appendLogicalText(lineBuf.subarray(contentStart + 1, contentEnd));
      return null;
    }

    const completed = flushPendingLogicalLine();

    if (wasOversized) {
      hasPending = true;
      pendingPhys = [];
      pendingBytes = 0;
      pendingHasContent = true;
      pendingLogicalPrefix = '';
      pendingLogicalOverflow = true;
      pendingOversized = true;
      if (inCard && !oversizedCard) {
        markCurrentCardOversized(maxItemBytes + 1);
      }
      return completed;
    }

    hasPending = true;
    pendingHasContent = contentEnd > contentStart;
    pendingLogicalPrefix = '';
    pendingLogicalOverflow = false;
    pendingOversized = false;
    appendLogicalText(lineBuf.subarray(contentStart, contentEnd));

    // Bound combined in-flight buffers before holding cardChunks + pendingPhys past maxItemBytes.
    if (inCard && !oversizedCard && pendingLogicalOverflow && cardBytes + lineBuf.length > maxItemBytes) {
      pendingPhys = [];
      pendingBytes = 0;
      pendingOversized = true;
      markCurrentCardOversized(cardBytes + lineBuf.length);
    } else if (inCard && !oversizedCard) {
      pendingPhys = [lineBuf];
      pendingBytes = lineBuf.length;
    } else if (!inCard && !pendingLogicalOverflow) {
      // Outside a card we only need to retain potential BEGIN:VCARD physical bytes.
      pendingPhys = [lineBuf];
      pendingBytes = lineBuf.length;
    } else {
      pendingPhys = [];
      pendingBytes = 0;
    }

    return completed;
  };

  const makeRawItem = (completed: { card: Buffer; ordinal: number }): RawItem => {
    const sourceTs = extractRevFromCard(completed.card);
    return {
      bytes: Readable.from([completed.card]),
      path: `${entry.path}#${completed.ordinal}`,
      mime: 'text/vcard',
      sourceTs,
      tags: baseTags,
    };
  };

  for await (const rawChunk of source) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk as Uint8Array);
    let start = 0;

    while (start < chunk.length) {
      const nl = chunk.indexOf(0x0a, start);
      if (skippingOversizedPhysLine) {
        if (nl === -1) {
          start = chunk.length;
        } else {
          skippingOversizedPhysLine = false;
          const completed = onPhysicalLine(Buffer.alloc(0), true);
          if (completed) yield makeRawItem(completed);
          start = nl + 1;
        }
        continue;
      }

      const sliceEnd = nl === -1 ? chunk.length : nl + 1;
      const sliceLen = sliceEnd - start;

      const lineTooLong = carryBytes + sliceLen > maxItemBytes;
      const cardTooLargeMidLine =
        inCard &&
        !oversizedCard &&
        carryBytes + sliceLen > LOGICAL_MARKER_MAX_CHARS &&
        cardBytes + pendingBytes + carryBytes + sliceLen > maxItemBytes;

      if (lineTooLong || cardTooLargeMidLine) {
        const observed = lineTooLong ? carryBytes + sliceLen : cardBytes + pendingBytes + carryBytes + sliceLen;
        carryChunks = [];
        carryBytes = 0;
        if (inCard) {
          markCurrentCardOversized(observed);
        } else {
          reportError({
            code: 'ITEM_TOO_LARGE',
            source: CONTACTS_SOURCE_ID,
            entryPath: entry.path,
            itemPath: entry.path,
            message: `Unterminated vCard line exceeds per-item limit (${maxItemBytes} bytes).`,
            limitBytes: maxItemBytes,
            observedBytes: observed,
          });
        }
        if (nl === -1) {
          skippingOversizedPhysLine = true;
          start = chunk.length;
        } else {
          const completed = onPhysicalLine(Buffer.alloc(0), true);
          if (completed) yield makeRawItem(completed);
          start = nl + 1;
        }
        continue;
      }

      const piece = Buffer.from(chunk.subarray(start, sliceEnd));
      if (nl === -1) {
        carryChunks.push(piece);
        carryBytes += piece.length;
        start = chunk.length;
      } else {
        const lineBuf = carryChunks.length === 0 ? piece : Buffer.concat([...carryChunks, piece]);
        carryChunks = [];
        carryBytes = 0;
        const completed = onPhysicalLine(lineBuf, false);
        if (completed) yield makeRawItem(completed);
        start = nl + 1;
      }
    }
  }

  if (skippingOversizedPhysLine) {
    const completed = onPhysicalLine(Buffer.alloc(0), true);
    if (completed) yield makeRawItem(completed);
  } else if (carryChunks.length > 0) {
    const lineBuf = carryChunks.length === 1 ? carryChunks[0]! : Buffer.concat(carryChunks);
    carryChunks = [];
    carryBytes = 0;
    const completed = onPhysicalLine(lineBuf, false);
    if (completed) yield makeRawItem(completed);
  }

  const finalCompleted = flushPendingLogicalLine();
  if (finalCompleted) yield makeRawItem(finalCompleted);

  if (inCard && !oversizedCard) {
    reportError({
      code: 'VCARD_UNFINISHED',
      source: CONTACTS_SOURCE_ID,
      entryPath: entry.path,
      itemPath: `${entry.path}#${cardOrdinal}`,
      message: `Unfinished vCard reached EOF without END:VCARD in ${entry.path}#${cardOrdinal}.`,
    });
  }
}

export const contactsImporter: Importer = {
  id: CONTACTS_SOURCE_ID,
  matches(entry: ArchiveEntry): boolean {
    const lower = entry.path.toLowerCase();
    return lower.endsWith('.vcf') || lower.endsWith('.vcard');
  },
  split(entry: ArchiveEntry, options?: SplitOptions): AsyncIterable<RawItem> {
    return splitVcardStream(entry, options);
  },
};

export const contactsDeriver: Deriver = {
  id: CONTACTS_SOURCE_ID,
  version: 1,
  async *derive(item: StoredItem, bytes: Readable): AsyncIterable<Derived> {
    const raw = await readStreamToBuffer(bytes);
    const contact = parseVcard(raw.toString('utf8'));
    if (!contact) return;

    const tags = uniqueSorted([
      ...item.tags,
      'contact',
      ...contact.categories.map(c => c.toLowerCase()),
    ]);

    yield {
      kind: 'text',
      title: `Contact: ${contact.name}`,
      text: formatContactText(contact),
      structured: {
        entityType: 'contact',
        name: contact.name,
        firstName: contact.firstName,
        lastName: contact.lastName,
        nickname: contact.nickname,
        company: contact.company,
        jobTitle: contact.jobTitle,
        phones: contact.phones,
        emails: contact.emails,
        addresses: contact.addresses,
        notes: contact.notes,
        birthday: contact.birthday,
        categories: contact.categories,
      },
      sourceTs: contact.rev ?? item.sourceTs,
      tags,
    };

    const primaryKey =
      contact.emails[0]?.address.toLowerCase() ??
      contact.phones[0]?.number.replace(/\s+/g, '') ??
      contact.name.toLowerCase();
    const nodes: Array<{ kind: string; canonicalKey: string; label: string }> = [
      { kind: 'person', canonicalKey: `contact:${primaryKey}`, label: contact.name },
    ];
    const edges: Array<{ srcKind: string; srcKey: string; dstKind: string; dstKey: string; kind: string }> = [];

    if (contact.company) {
      const orgKey = `org:${contact.company.toLowerCase()}`;
      nodes.push({ kind: 'organization', canonicalKey: orgKey, label: contact.company });
      edges.push({
        srcKind: 'person',
        srcKey: `contact:${primaryKey}`,
        dstKind: 'organization',
        dstKey: orgKey,
        kind: 'affiliated_with',
      });
    }

    yield { kind: 'graph_evidence', nodes, edges };
  },
};

/**
 * @file importers/contacts.ts
 * Google Takeout Contacts (vCard / VCF) lossless splitter and deriver.
 *
 * Ported through the scrub gate from predecessor contacts parsing logic,
 * rewritten for Foundry's two-stage Importer/Deriver contract (Architecture 7).
 */

import { Buffer } from 'node:buffer';
import { Readable } from 'node:stream';
import type { ArchiveEntry, Derived, Deriver, Importer, RawItem, StoredItem } from '../types.js';
import { normalizeTimestamp, uniqueSorted } from '../defaults.js';

export const CONTACTS_SOURCE_ID = 'google-takeout/contacts';

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

function extractParamType(params: string): string | undefined {
  const match = /(?:^|;)TYPE=([^;:]+)/i.exec(params);
  if (match) return match[1]!.replace(/^"|"$/g, '').trim() || undefined;
  // vCard 2.1 bare type parameters such as ;CELL or ;HOME;VOICE
  const bare = params
    .split(';')
    .map(p => p.trim())
    .filter(p => p.length > 0 && !p.includes('='));
  return bare.length > 0 ? bare.join(',') : undefined;
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
    const match = /^(?:[\w-]+\.)?([A-Za-z0-9-]+)((?:;[^:]*)*):(.*)$/.exec(line);
    if (!match) continue;

    const prop = match[1]!.toUpperCase();
    const params = match[2] ?? '';
    let value = match[3]!.trim();

    if (/ENCODING=QUOTED-PRINTABLE/i.test(params) || /(?:^|;)QUOTED-PRINTABLE(?:;|$)/i.test(params)) {
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
  const text = cardBytes.toString('utf8');
  const match = /(?:^|\r?\n)REV(?:;[^:]*)?:([^\r\n]+)/i.exec(text);
  return match ? normalizeTimestamp(match[1]!.trim()) : undefined;
}

async function readStreamToBuffer(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return Buffer.concat(chunks);
}

/**
 * Splits a vCard stream into lossless per-contact RawItems, preserving original bytes
 * for every BEGIN:VCARD ... END:VCARD block.
 */
async function* splitVcardStream(entry: ArchiveEntry): AsyncIterable<RawItem> {
  const baseTags = entryTags(entry.path);
  const source = entry.open();
  let carry = Buffer.alloc(0);
  let cardChunks: Buffer[] = [];
  let inCard = false;
  let cardIndex = 0;

  const emitLine = (lineBuf: Buffer): Buffer | null => {
    const trimmed = lineBuf.toString('utf8').replace(/^\ufeff/, '').trim().toUpperCase();
    if (trimmed === 'BEGIN:VCARD') {
      inCard = true;
      cardChunks = [lineBuf];
      return null;
    }
    if (inCard) {
      cardChunks.push(lineBuf);
      if (trimmed === 'END:VCARD') {
        const fullCard = Buffer.concat(cardChunks);
        cardChunks = [];
        inCard = false;
        return fullCard;
      }
    }
    return null;
  };

  for await (const rawChunk of source) {
    const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk as Uint8Array);
    const data = carry.length > 0 ? Buffer.concat([carry, chunk]) : chunk;
    let start = 0;
    while (start < data.length) {
      const nl = data.indexOf(0x0a, start);
      if (nl === -1) break;
      const lineBuf = data.subarray(start, nl + 1);
      const completed = emitLine(Buffer.from(lineBuf));
      if (completed) {
        cardIndex++;
        const sourceTs = extractRevFromCard(completed);
        yield {
          bytes: Readable.from([completed]),
          path: `${entry.path}#${cardIndex}`,
          mime: 'text/vcard',
          sourceTs,
          tags: baseTags,
        };
      }
      start = nl + 1;
    }
    carry = start < data.length ? Buffer.from(data.subarray(start)) : Buffer.alloc(0);
  }

  if (carry.length > 0) {
    const completed = emitLine(carry);
    if (completed) {
      cardIndex++;
      const sourceTs = extractRevFromCard(completed);
      yield {
        bytes: Readable.from([completed]),
        path: `${entry.path}#${cardIndex}`,
        mime: 'text/vcard',
        sourceTs,
        tags: baseTags,
      };
    }
  }
}

export const contactsImporter: Importer = {
  id: CONTACTS_SOURCE_ID,
  matches(entry: ArchiveEntry): boolean {
    const lower = entry.path.toLowerCase();
    return lower.endsWith('.vcf') || lower.endsWith('.vcard');
  },
  split(entry: ArchiveEntry): AsyncIterable<RawItem> {
    return splitVcardStream(entry);
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

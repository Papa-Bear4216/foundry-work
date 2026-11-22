import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { Readable } from 'node:stream';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  calendarDeriver,
  calendarImporter,
  contactsDeriver,
  contactsImporter,
  generateSyntheticIcalendar,
  generateSyntheticMbox,
  generateSyntheticVcards,
  isMboxSeparatorLine,
  ItemSkipError,
  mailDeriver,
  mailImporter,
  normalizeTimestamp,
  parseContentLine,
  parseIcalendar,
  parseVcard,
  syntheticEmail,
} from '../dist/index.js';

async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function entryFromBuffer(path, buf, chunkSize = 64 * 1024) {
  return {
    path,
    size: buf.length,
    compressedSize: buf.length,
    open() {
      let off = 0;
      return new Readable({
        read() {
          if (off >= buf.length) {
            this.push(null);
            return;
          }
          const end = Math.min(off + chunkSize, buf.length);
          this.push(buf.subarray(off, end));
          off = end;
        },
      });
    },
  };
}

test('contacts importer splits vCards losslessly and deriver extracts structured fields and graph evidence', async () => {
  const vcf = generateSyntheticVcards(5, 111);
  const entry = entryFromBuffer('Takeout/Contacts/All Contacts/All Contacts.vcf', vcf, 37);
  assert.equal(contactsImporter.matches(entry), true);
  assert.equal(calendarImporter.matches(entry), false);
  assert.equal(mailImporter.matches(entry), false);

  const cards = [];
  for await (const rawItem of contactsImporter.split(entry)) {
    const rawBytes = await streamToBuffer(rawItem.bytes);
    cards.push({ rawItem, rawBytes });
  }

  assert.equal(cards.length, 5);
  assert.ok(Buffer.concat(cards.map(c => c.rawBytes)).equals(vcf), 'concatenated vCards must match input byte-for-byte');
  assert.equal(cards[0].rawItem.path, 'Takeout/Contacts/All Contacts/All Contacts.vcf#1');
  assert.equal(cards[0].rawItem.mime, 'text/vcard');
  assert.ok(cards[0].rawItem.sourceTs?.endsWith('Z'));

  // Derive card #1 (full structured card with folded NOTE) and card #5 (ORG fallback + quoted-printable)
  const derived1 = [];
  for await (const d of contactsDeriver.derive(
    {
      source: contactsImporter.id,
      path: cards[0].rawItem.path,
      mime: cards[0].rawItem.mime,
      size: cards[0].rawBytes.length,
      blobId: '0'.repeat(64),
      profile: 'me',
      collection: 'google-takeout/contacts/2023',
      sensitivity: 'personal',
      sourceTs: cards[0].rawItem.sourceTs,
      tags: cards[0].rawItem.tags,
    },
    Readable.from([cards[0].rawBytes]),
  )) {
    derived1.push(d);
  }
  const text1 = derived1.find(d => d.kind === 'text');
  assert.ok(text1);
  assert.equal(text1.title, 'Contact: Given1 Family1');
  assert.equal(text1.structured.emails[0].address, syntheticEmail('contact1'));
  assert.ok(text1.text.includes('continued '));
  const graph1 = derived1.find(d => d.kind === 'graph_evidence');
  assert.ok(graph1 && graph1.nodes.length === 2 && graph1.edges.length === 1);

  const derived5 = [];
  for await (const d of contactsDeriver.derive(
    {
      source: contactsImporter.id,
      path: cards[4].rawItem.path,
      mime: cards[4].rawItem.mime,
      size: cards[4].rawBytes.length,
      blobId: '1'.repeat(64),
      profile: 'me',
      collection: 'google-takeout/contacts/undated',
      sensitivity: 'personal',
      tags: cards[4].rawItem.tags,
    },
    Readable.from([cards[4].rawBytes]),
  )) {
    derived5.push(d);
  }
  const text5 = derived5.find(d => d.kind === 'text');
  assert.ok(text5);
  assert.ok(text5.structured.name.startsWith('Synthetic Org '));
  assert.ok(text5.structured.notes.includes('TEST ONLY synthetic\nfolded'));
});

test('calendar importer stores lossless iCalendar and deriver emits events, places, and graph evidence', async () => {
  const ics = generateSyntheticIcalendar(4, 222, 'Synthetic Work');
  const entry = entryFromBuffer('Takeout/Calendar/Synthetic Work.ics', ics, 53);
  assert.equal(calendarImporter.matches(entry), true);

  const items = [];
  for await (const rawItem of calendarImporter.split(entry)) {
    const rawBytes = await streamToBuffer(rawItem.bytes);
    items.push({ rawItem, rawBytes });
  }
  assert.equal(items.length, 1);
  assert.ok(items[0].rawBytes.equals(ics));
  assert.equal(items[0].rawItem.mime, 'text/calendar');
  assert.ok(items[0].rawItem.tags.includes('synthetic work'));

  const derived = [];
  for await (const d of calendarDeriver.derive(
    {
      source: calendarImporter.id,
      path: items[0].rawItem.path,
      mime: items[0].rawItem.mime,
      size: items[0].rawBytes.length,
      blobId: '2'.repeat(64),
      profile: 'me',
      collection: 'google-takeout/calendar/2023',
      sensitivity: 'personal',
      sourceTs: items[0].rawItem.sourceTs,
      tags: items[0].rawItem.tags,
    },
    Readable.from([items[0].rawBytes]),
  )) {
    derived.push(d);
  }

  const textEvents = derived.filter(d => d.kind === 'text');
  const places = derived.filter(d => d.kind === 'place');
  const graphs = derived.filter(d => d.kind === 'graph_evidence');
  assert.equal(textEvents.length, 4);
  assert.equal(places.length, 4);
  assert.equal(graphs.length, 4);
  assert.ok(textEvents[0].structured.description.includes('milestones\nLine two.'));
  assert.equal(textEvents[0].structured.attendees[0].address, syntheticEmail('attendee1'));
  assert.equal(typeof places[0].latE7, 'number');
  assert.equal(graphs[0].edges[0].kind, 'invited');
});

test('mail importer splits mbox streaming byte-for-byte across tiny chunks and derives RFC 5322/MIME', async () => {
  const mbox = generateSyntheticMbox(6, 333, {
    includeMultipart: true,
    includeRfc2047: true,
    includeEscapedFrom: true,
    includeUnescapedFromProse: true,
  });

  // Use tiny prime chunk size (17 bytes) to stress-test `From ` boundary detection across chunk splits.
  const entry = entryFromBuffer('Takeout/Mail/All mail.mbox', mbox, 17);
  assert.equal(mailImporter.matches(entry), true);

  assert.equal(isMboxSeparatorLine(Buffer.from('From 12345@xxx Mon Jan 01 12:00:00 +0000 2024\r\n')), true);
  assert.equal(isMboxSeparatorLine(Buffer.from('From time to time prose appears.\r\n')), false);

  const messages = [];
  for await (const rawItem of mailImporter.split(entry)) {
    const rawBytes = await streamToBuffer(rawItem.bytes);
    messages.push({ rawItem, rawBytes });
  }

  assert.equal(messages.length, 6);
  assert.ok(
    Buffer.concat(messages.map(m => m.rawBytes)).equals(mbox),
    'concatenation of split mbox messages must equal original mbox byte-for-byte',
  );

  for (let i = 0; i < messages.length; i++) {
    assert.equal(messages[i].rawItem.path, `Takeout/Mail/All mail.mbox#${i + 1}`);
    assert.equal(messages[i].rawItem.mime, 'message/rfc822');
    assert.ok(typeof messages[i].rawItem.meta?.mbox_separator === 'string');
    assert.ok(messages[i].rawItem.meta.mbox_separator.startsWith('From '));
    assert.ok(messages[i].rawItem.sourceTs?.endsWith('Z'));
  }

  // Derive message #1 (RFC 2047 subject + >From unescaping + unescaped From prose)
  const derived1 = [];
  for await (const d of mailDeriver.derive(
    {
      source: mailImporter.id,
      path: messages[0].rawItem.path,
      mime: messages[0].rawItem.mime,
      size: messages[0].rawBytes.length,
      blobId: '3'.repeat(64),
      profile: 'me',
      collection: 'google-takeout/mail/2023',
      sensitivity: 'personal',
      sourceTs: messages[0].rawItem.sourceTs,
      tags: messages[0].rawItem.tags,
      meta: messages[0].rawItem.meta,
    },
    Readable.from([messages[0].rawBytes]),
  )) {
    derived1.push(d);
  }
  const text1 = derived1.find(d => d.kind === 'text');
  assert.ok(text1);
  assert.ok(text1.title.includes('Synthetic ') && text1.title.includes('#1'));
  assert.ok(text1.text.includes('From an escaped mbox line inside the message body.'));
  assert.ok(text1.text.includes('From time to time prose starts with From without a timestamp.'));
  const graph1 = derived1.find(d => d.kind === 'graph_evidence');
  assert.ok(graph1 && graph1.edges.some(e => e.kind === 'emailed'));

  // Derive message #2 (multipart/mixed with plain + html + attachment + quoted Gmail label)
  const derived2 = [];
  for await (const d of mailDeriver.derive(
    {
      source: mailImporter.id,
      path: messages[1].rawItem.path,
      mime: messages[1].rawItem.mime,
      size: messages[1].rawBytes.length,
      blobId: '4'.repeat(64),
      profile: 'me',
      collection: 'google-takeout/mail/2023',
      sensitivity: 'personal',
      sourceTs: messages[1].rawItem.sourceTs,
      tags: messages[1].rawItem.tags,
      meta: messages[1].rawItem.meta,
    },
    Readable.from([messages[1].rawBytes]),
  )) {
    derived2.push(d);
  }
  const text2 = derived2.find(d => d.kind === 'text');
  assert.ok(text2);
  assert.ok(text2.tags.includes('synthetic label'));
  assert.deepEqual(text2.structured.attachments, [{ filename: 'report.bin', mime: 'application/octet-stream' }]);
});

test('contacts splitter handles folded END:VCARD continuation, unfinished final card, and nested BEGIN (Ruling 10)', async () => {
  // 1. Folded END:VCARD continuation inside a NOTE must NOT terminate the card early
  const email = syntheticEmail('folded-end');
  const foldedCard = Buffer.from(
    [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Folded Continuation Contact',
      'NOTE:First line',
      ' END:VCARD',
      `EMAIL;TYPE=HOME:${email}`,
      'END:VCARD',
      '',
    ].join('\r\n'),
    'utf8',
  );
  const foldedErrors = [];
  const foldedItems = [];
  for await (const rawItem of contactsImporter.split(
    entryFromBuffer('Takeout/Contacts/folded.vcf', foldedCard, 13),
    { onItemError: err => foldedErrors.push(err) },
  )) {
    foldedItems.push(await streamToBuffer(rawItem.bytes));
  }
  assert.equal(foldedErrors.length, 0);
  assert.equal(foldedItems.length, 1);
  assert.ok(foldedItems[0].equals(foldedCard), 'folded card physical bytes must be preserved verbatim');
  const parsedFolded = parseVcard(foldedItems[0].toString('utf8'));
  assert.ok(parsedFolded);
  assert.equal(parsedFolded.emails[0]?.address, email);
  assert.ok(parsedFolded.notes?.includes('END:VCARD'));

  // 2. Unfinished final card -> typed VCARD_UNFINISHED error (reported via callback, or throws ItemSkipError without callback)
  const unfinishedBuf = Buffer.from(
    [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Complete First',
      'END:VCARD',
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Unfinished Second',
      '',
    ].join('\r\n'),
    'utf8',
  );
  const unfinishedErrors = [];
  const unfinishedCards = [];
  for await (const rawItem of contactsImporter.split(
    entryFromBuffer('Takeout/Contacts/unfinished.vcf', unfinishedBuf, 19),
    { onItemError: err => unfinishedErrors.push(err) },
  )) {
    unfinishedCards.push(await streamToBuffer(rawItem.bytes));
  }
  assert.equal(unfinishedCards.length, 1);
  assert.equal(unfinishedErrors.length, 1);
  assert.equal(unfinishedErrors[0].code, 'VCARD_UNFINISHED');

  await assert.rejects(
    async () => {
      for await (const rawItem of contactsImporter.split(entryFromBuffer('Takeout/Contacts/unfinished.vcf', unfinishedBuf))) {
        await streamToBuffer(rawItem.bytes);
      }
    },
    err => err instanceof ItemSkipError && err.code === 'VCARD_UNFINISHED',
  );

  // 3. Nested BEGIN:VCARD -> typed VCARD_NESTED_BEGIN error, while subsequent complete card still yields
  const nestedBuf = Buffer.from(
    [
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Outer Incomplete',
      'BEGIN:VCARD',
      'VERSION:3.0',
      'FN:Inner Complete',
      'END:VCARD',
      '',
    ].join('\r\n'),
    'utf8',
  );
  const nestedErrors = [];
  const nestedCards = [];
  for await (const rawItem of contactsImporter.split(
    entryFromBuffer('Takeout/Contacts/nested.vcf', nestedBuf, 11),
    { onItemError: err => nestedErrors.push(err) },
  )) {
    nestedCards.push(await streamToBuffer(rawItem.bytes));
  }
  assert.equal(nestedErrors.length, 1);
  assert.equal(nestedErrors[0].code, 'VCARD_NESTED_BEGIN');
  assert.equal(nestedCards.length, 1);
  assert.equal(parseVcard(nestedCards[0].toString('utf8'))?.name, 'Inner Complete');
});

test('calendar and contacts property-parameter scanners reject 100 KB of semicolons without colon in under 1 s (Ruling 11)', () => {
  const pathological = 'X' + ';'.repeat(100 * 1024);

  const t0 = performance.now();
  const parsedLine = parseContentLine(pathological, { allowGroup: true });
  const cal = parseIcalendar(`BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n${pathological}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n`);
  const card = parseVcard(`BEGIN:VCARD\r\nVERSION:3.0\r\n${pathological}\r\nEND:VCARD\r\n`);
  const elapsedMs = performance.now() - t0;

  assert.equal(parsedLine, null);
  assert.equal(cal.events.length, 1);
  assert.equal(cal.events[0].summary, undefined);
  assert.equal(card, null);
  assert.ok(elapsedMs < 1000, `100 KB semicolon scan took ${elapsedMs.toFixed(1)} ms (limit 1000 ms)`);
});

test('calendar and contacts importers enforce per-item size cap before buffering and skip over-limit items (Ruling 6)', async () => {
  const limit = 4096;

  // Over-limit calendar entry
  const bigIcs = Buffer.concat([
    Buffer.from('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nSUMMARY:'),
    Buffer.alloc(limit + 2048, 0x41),
    Buffer.from('\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n'),
  ]);
  const calErrors = [];
  const calItems = [];
  for await (const item of calendarImporter.split(entryFromBuffer('Takeout/Calendar/big.ics', bigIcs, 512), {
    maxItemBytes: limit,
    onItemError: e => calErrors.push(e),
  })) {
    calItems.push(item);
  }
  assert.equal(calItems.length, 0);
  assert.equal(calErrors.length, 1);
  assert.equal(calErrors[0].code, 'ITEM_TOO_LARGE');

  // Over-limit vCard followed by a valid vCard + unterminated over-limit line
  const vcfMix = Buffer.concat([
    Buffer.from('BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Too Large\r\nNOTE:'),
    Buffer.alloc(limit + 1024, 0x42),
    Buffer.from('\r\nEND:VCARD\r\n'),
    Buffer.from('BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Small Valid\r\nEND:VCARD\r\n'),
  ]);
  const vcfErrors = [];
  const vcfItems = [];
  for await (const item of contactsImporter.split(entryFromBuffer('Takeout/Contacts/mix.vcf', vcfMix, 512), {
    maxItemBytes: limit,
    onItemError: e => vcfErrors.push(e),
  })) {
    vcfItems.push(await streamToBuffer(item.bytes));
  }
  assert.equal(vcfErrors.length, 1);
  assert.equal(vcfErrors[0].code, 'ITEM_TOO_LARGE');
  assert.equal(vcfItems.length, 1);
  assert.equal(parseVcard(vcfItems[0].toString('utf8'))?.name, 'Small Valid');
});

test('normalizeTimestamp interprets zone-less date-times as UTC deterministically (Ruling 12)', () => {
  assert.equal(normalizeTimestamp('2024-12-31T23:30:00'), '2024-12-31T23:30:00Z');
  assert.equal(normalizeTimestamp('2024-12-31 23:30:00'), '2024-12-31T23:30:00Z');
  assert.equal(normalizeTimestamp('20241231T233000'), '2024-12-31T23:30:00Z');
  assert.equal(normalizeTimestamp('Tue, 31 Dec 2024 23:30:00'), '2024-12-31T23:30:00Z');
  assert.equal(normalizeTimestamp('Tue Dec 31 23:30:00 2024'), '2024-12-31T23:30:00Z');
  assert.equal(normalizeTimestamp('2024-12-31T23:30:00-05:00'), '2025-01-01T04:30:00Z');
});

test('importers and derivers never import network modules or invoke fetch (Product 6.3 rule 4)', () => {
  const distRoot = fileURLToPath(new URL('../dist', import.meta.url));
  const forbidden = /\b(?:node:http|node:https|node:http2|node:net|node:tls|node:dns|node:dgram|fetch\s*\(|WebSocket)\b/;

  const walk = dir => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && entry.name.endsWith('.js')) {
        const src = readFileSync(full, 'utf8');
        assert.equal(forbidden.test(src), false, `Forbidden network reference in ${full}`);
      }
    }
  };
  walk(distRoot);
});

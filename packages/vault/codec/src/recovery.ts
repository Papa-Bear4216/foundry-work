import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { check } from './bytes.ts';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const VERSION = '1';

function base32(bytes: Buffer): string {
  let text = '';
  let held = 0;
  let bits = 0;
  for (const byte of bytes) {
    held = (held << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      text += ALPHABET[(held >> bits) & 31];
    }
    held &= (1 << bits) - 1;
  }
  if (bits > 0) text += ALPHABET[held << (5 - bits)];
  return text;
}

function checksum(payload: string): string {
  return base32(createHash('sha256').update(Buffer.from(VERSION + payload)).digest()).slice(0, 4);
}

export function formatRecoveryKey(key: Buffer): string {
  check(key.length === 32, 'KEY');
  const payload = base32(key);
  const groups = (payload + checksum(payload)).match(/.{4}/gu)!;
  return VERSION + '-' + groups.join('-');
}

/** Parse the printed recovery key into the 32 bytes used by the keyring codec. */
export function decodeRecoveryKey(text: string): Buffer {
  if (typeof text !== 'string' || text.length !== 71 || !/^1(?:-[A-Z2-7]{4}){14}$/u.test(text)) {
    throw new Error('Invalid recovery key format.');
  }
  const symbols = text.slice(2).replaceAll('-', '');
  const payload = symbols.slice(0, 52);
  if (symbols.slice(52) !== checksum(payload)) throw new Error('Recovery key checksum mismatch.');

  const key = Buffer.alloc(32);
  let offset = 0;
  let held = 0;
  let bits = 0;
  for (const symbol of payload) {
    held = (held << 5) | ALPHABET.indexOf(symbol);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      key[offset++] = held >> bits;
      held &= (1 << bits) - 1;
    }
  }
  if (held !== 0) {
    key.fill(0);
    throw new Error('Invalid recovery key padding.');
  }
  return key;
}

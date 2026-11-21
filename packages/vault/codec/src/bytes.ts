import { Buffer, isUtf8 } from 'node:buffer';
import { createCipheriv, createDecipheriv, createHash, hkdfSync } from 'node:crypto';

export type ErrorCode = 'VERSION' | 'SCHEMA' | 'CANONICAL' | 'LENGTH' | 'AUTH' | 'SIGNATURE'
  | 'CHAIN' | 'FILE' | 'SEQUENCE' | 'KEY' | 'ERASED' | 'KDF' | 'MAC';

export class VaultFormatError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode) {
    super(code);
    this.code = code;
    this.name = 'VaultFormatError';
  }
}

export function check(condition: unknown, code: ErrorCode = 'SCHEMA'): asserts condition {
  if (!condition) throw new VaultFormatError(code);
}

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export function canonical(value: Json): string {
  if (typeof value === 'number') check(Number.isSafeInteger(value));
  if (typeof value === 'string') check(value.isWellFormed());
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key => canonical(key) + ':' + canonical(value[key])).join(',') + '}';
}

export function parseCanonical(raw: Buffer): Json {
  check(isUtf8(raw), 'CANONICAL');
  let value: Json;
  try {
    value = JSON.parse(raw.toString());
    check(Buffer.from(canonical(value)).equals(raw), 'CANONICAL');
  } catch {
    throw new VaultFormatError('CANONICAL');
  }
  return value;
}

export function object(value: unknown, fields: string): asserts value is Record<string, Json> {
  check(value !== null && typeof value === 'object' && !Array.isArray(value));
  check(Object.keys(value).sort().join(' ') === fields.split(' ').sort().join(' ')
    && fields.split(' ').every(field => Object.hasOwn(value, field)));
}

export function integer(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): asserts value is number {
  check(typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max);
}

export function hex(value: unknown, size: number): asserts value is string {
  check(typeof value === 'string' && value.length === size * 2 && !/[^0-9a-f]/u.test(value));
}

export function timestamp(value: unknown): asserts value is string {
  check(typeof value === 'string' && value.length === 20
    && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/u.test(value) && !value.startsWith('0000'));
  const date = new Date(value);
  check(Number.isFinite(date.valueOf()) && date.toISOString() === value.slice(0, -1) + '.000Z');
}

export function base64(value: unknown, size?: number): Buffer {
  check(typeof value === 'string');
  const bytes = Buffer.from(value, 'base64');
  check(bytes.toString('base64') === value && (size === undefined || bytes.length === size));
  return bytes;
}

export function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function derive(key: Buffer, label: string, salt = Buffer.alloc(0)): Buffer {
  check(key.length === 32, 'KEY');
  return Buffer.from(hkdfSync('sha256', key, salt, Buffer.from('foundry/' + label + '/v1'), 32));
}

export function seal(key: Buffer, nonce: Buffer, aad: Buffer, plaintext: Buffer): Buffer {
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

export function open(key: Buffer, nonce: Buffer, aad: Buffer, sealed: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(-16));
  try {
    return Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
  } catch {
    throw new VaultFormatError('AUTH');
  }
}

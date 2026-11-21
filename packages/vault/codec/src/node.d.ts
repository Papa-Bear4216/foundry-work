// Narrow built-in declarations for the dependency-free vault workspace.
declare module 'node:buffer' {
  export interface Buffer extends Uint8Array<ArrayBuffer> {
    subarray(start?: number, end?: number): Buffer;
    toString(encoding?: 'utf8' | 'hex' | 'base64'): string;
    equals(other: Uint8Array): boolean;
    readBigUInt64BE(offset: number): bigint;
    writeBigUInt64BE(value: bigint, offset: number): number;
    readUInt32BE(offset: number): number;
    writeUInt32BE(value: number, offset: number): number;
  }

  export const Buffer: {
    alloc(size: number): Buffer;
    from(value: string, encoding?: 'utf8' | 'hex' | 'base64'): Buffer;
    from(value: ArrayBuffer | Uint8Array | readonly number[]): Buffer;
    concat(values: readonly Uint8Array[]): Buffer;
  };

  export function isUtf8(value: Uint8Array): boolean;
}

declare module 'node:crypto' {
  import type { Buffer } from 'node:buffer';

  interface Digest {
    update(data: Uint8Array): this;
    digest(): Buffer;
    digest(encoding: 'hex'): string;
  }

  interface Gcm {
    setAAD(data: Uint8Array): this;
    update(data: Uint8Array): Buffer;
    final(): Buffer;
  }

  interface KeyObject {
    export(options: { type: 'spki'; format: 'der' }): Buffer;
  }

  export function createHash(algorithm: 'sha256'): Digest;
  export function createHmac(algorithm: 'sha256', key: Uint8Array): Digest;
  export function createCipheriv(
    algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array, options: { authTagLength: 16 },
  ): Gcm & { getAuthTag(): Buffer };
  export function createDecipheriv(
    algorithm: 'aes-256-gcm', key: Uint8Array, iv: Uint8Array, options: { authTagLength: 16 },
  ): Gcm & { setAuthTag(tag: Uint8Array): Gcm };
  export function hkdfSync(
    digest: 'sha256', ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number,
  ): ArrayBuffer;
  export function scryptSync(
    passphrase: Uint8Array, salt: Uint8Array, length: number,
    options: { N: number; r: number; p: number; maxmem: number },
  ): Buffer;
  export function randomBytes(size: number): Buffer;
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
  export function createPrivateKey(options: { key: Uint8Array; format: 'der'; type: 'pkcs8' }): KeyObject;
  export function createPublicKey(options: { key: Uint8Array; format: 'der'; type: 'spki' } | KeyObject): KeyObject;
  export function sign(algorithm: null, data: Uint8Array, key: KeyObject): Buffer;
  export function verify(algorithm: null, data: Uint8Array, key: KeyObject, signature: Uint8Array): boolean;
}

declare module 'node:fs' {
  import type { Buffer } from 'node:buffer';

  export function readFileSync(pathOrFd: string | number): Buffer;
  export function openSync(path: string, flags: 'wx', mode: number): number;
  export function writeFileSync(fd: number, data: Uint8Array): void;
  export function fsyncSync(fd: number): void;
  export function closeSync(fd: number): void;
  export function renameSync(source: string, target: string): void;
  export function unlinkSync(path: string): void;
}

declare module 'node:process' {
  export const platform: string;
}

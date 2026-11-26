// Narrow Node 24 built-in declarations for the dependency-free profiles workspace.
declare module 'node:buffer' {
  export interface Buffer extends Uint8Array<ArrayBuffer> {
    subarray(start?: number, end?: number): Buffer;
    toString(encoding?: 'utf8' | 'latin1' | 'ascii' | 'hex' | 'base64', start?: number, end?: number): string;
    equals(other: Uint8Array): boolean;
  }
  export const Buffer: {
    alloc(size: number, fill?: number): Buffer;
    byteLength(value: string, encoding?: 'utf8'): number;
    from(value: string, encoding?: 'utf8' | 'hex' | 'base64'): Buffer;
    from(value: ArrayBuffer, byteOffset?: number, length?: number): Buffer;
    from(value: Uint8Array | readonly number[]): Buffer;
    isBuffer(value: unknown): value is Buffer;
  };
}

declare module 'node:crypto' {
  import type { Buffer } from 'node:buffer';
  interface Digest {
    update(data: Uint8Array | string): this;
    digest(): Buffer;
    digest(encoding: 'hex'): string;
  }
  export function createHash(algorithm: 'sha256'): Digest;
  export function createHmac(algorithm: 'sha256', key: Uint8Array): Digest;
  export function hkdfSync(
    digest: 'sha256',
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
  ): ArrayBuffer;
  export function randomBytes(size: number): Buffer;
}

declare module 'node:fs' {
  import type { Buffer } from 'node:buffer';
  export interface Stats {
    size: number;
    mode?: number;
    isFile(): boolean;
    isDirectory(): boolean;
  }
  export function lstatSync(path: string): Stats;
  export function readFileSync(path: string): Buffer;
  export function readFileSync(path: string, encoding: 'utf8'): string;
}

declare module 'node:path' {
  export function join(...parts: string[]): string;
  export function resolve(...parts: string[]): string;
}

declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string, options?: Record<string, unknown>);
    close(): void;
  }
}

declare class TextDecoder {
  constructor(label?: string, options?: { fatal?: boolean; ignoreBOM?: boolean });
  decode(bytes?: Uint8Array, options?: { stream?: boolean }): string;
}

declare module 'node:module' {
  export function createRequire(url: string): (id: string) => unknown;
}
declare module 'node:sqlite' {
  export const DatabaseSync: new (path: string, options?: Record<string, unknown>) =>
    import('./driver.ts').SqlDriver;
}
declare module 'node:buffer' {
  export interface Buffer extends Uint8Array<ArrayBuffer> {
    toString(encoding?: 'hex' | 'utf8'): string;
  }
  export const Buffer: { from(value: Uint8Array): Buffer };
}
declare module 'node:crypto' {
  interface Digest {
    update(value: Uint8Array | string): this;
    digest(encoding: 'hex'): string;
  }
  export function randomBytes(count: number): import('node:buffer').Buffer;
  export function createHash(name: 'sha256'): Digest;
  export function createHmac(name: 'sha256', key: Uint8Array): Digest;
  export function hkdfSync(
    digest: 'sha256', key: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number,
  ): ArrayBuffer;
}
declare module 'node:fs' {
  export function lstatSync(path: string): { size: number; isFile(): boolean; isDirectory(): boolean };
  export function existsSync(path: string): boolean;
  export function mkdirSync(path: string, options: { recursive: true; mode: number }): string | undefined;
  export function readFileSync(path: string): import('node:buffer').Buffer;
  export function openSync(path: string, mode: 'r' | 'r+'): number;
  export function fsyncSync(fd: number): void;
  export function closeSync(fd: number): void;
  export function unlinkSync(path: string): void;
}
declare module 'node:path' {
  export function dirname(path: string): string;
  export function join(...parts: string[]): string;
  export function resolve(...parts: string[]): string;
  export function relative(from: string, to: string): string;
  export function isAbsolute(path: string): boolean;
  export const sep: string;
}
interface ImportMeta {
  readonly url: string;
}
declare class TextDecoder {
  decode(bytes?: Uint8Array, options?: { stream: boolean }): string;
}

declare class TextEncoder { encode(value: string): Uint8Array<ArrayBuffer>; }

declare module 'node:process' { export const platform: string; }

// Narrow declarations for the built-ins used by this package.
declare module 'node:crypto' {
  export function randomUUID(): string;
}

declare module 'node:fs' {
  export function openSync(path: string, flags: string, mode?: number): number;
  export function closeSync(fd: number): void;
  export function fstatSync(fd: number): { size: number };
  export function fsyncSync(fd: number): void;
  export function mkdirSync(path: string, options: { recursive: true }): string | undefined;
  export function readSync(
    fd: number, buffer: Uint8Array, offset: number, length: number, position: number | null,
  ): number;
  export function writeSync(fd: number, buffer: Uint8Array): number;
}

declare module 'node:path' {
  export function dirname(path: string): string;
}

declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string, options: { timeout: number });
    exec(sql: string): void;
    close(): void;
  }
}

declare module 'node:util' {
  export class TextDecoder {
    constructor(encoding: string, options: { fatal: boolean });
    decode(bytes: Uint8Array): string;
  }
  export class TextEncoder {
    encode(text: string): Uint8Array;
  }
}

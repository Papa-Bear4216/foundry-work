// Narrow Node 24 built-in declarations for the dependency-free importers workspace.
declare module 'node:buffer' {
  export interface Buffer extends Uint8Array<ArrayBuffer> {
    subarray(start?: number, end?: number): Buffer;
    toString(encoding?: 'utf8' | 'latin1' | 'ascii' | 'hex' | 'base64', start?: number, end?: number): string;
    equals(other: Uint8Array): boolean;
    indexOf(value: string | number | Uint8Array, byteOffset?: number): number;
    readUInt16LE(offset: number): number;
    readUInt32LE(offset: number): number;
    readBigUInt64LE(offset: number): bigint;
    readBigUInt64BE(offset: number): bigint;
    writeUInt16LE(value: number, offset: number): number;
    writeUInt32LE(value: number, offset: number): number;
    writeBigUInt64LE(value: bigint, offset: number): number;
    copy(target: Uint8Array, targetStart?: number, sourceStart?: number, sourceEnd?: number): number;
  }

  export const Buffer: {
    alloc(size: number, fill?: number): Buffer;
    allocUnsafe(size: number): Buffer;
    byteLength(value: string, encoding?: 'utf8' | 'latin1' | 'ascii' | 'hex' | 'base64'): number;
    from(value: string, encoding?: 'utf8' | 'latin1' | 'ascii' | 'hex' | 'base64'): Buffer;
    from(value: ArrayBuffer | Uint8Array | readonly number[]): Buffer;
    concat(values: readonly Uint8Array[], totalLength?: number): Buffer;
    isBuffer(value: unknown): value is Buffer;
  };
}

declare module 'node:crypto' {
  import type { Buffer } from 'node:buffer';

  interface HashLike {
    update(data: Uint8Array | string): this;
    digest(): Buffer;
    digest(encoding: 'hex'): string;
  }

  export function createHash(algorithm: 'sha256'): HashLike;
  export function createHmac(algorithm: 'sha256', key: Uint8Array): HashLike;
  export function hkdfSync(
    digest: 'sha256',
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
  ): ArrayBuffer;
}

declare module 'node:fs' {
  import type { Buffer } from 'node:buffer';

  export interface Stats {
    size: number;
    isFile(): boolean;
    isDirectory(): boolean;
  }

  export interface BigIntStats {
    size: bigint;
    isFile(): boolean;
    isDirectory(): boolean;
  }

  export interface Dirent {
    name: string;
    isFile(): boolean;
    isDirectory(): boolean;
  }

  export function openSync(path: string, flags: 'r' | 'w' | 'wx'): number;
  export function closeSync(fd: number): void;
  export function readSync(
    fd: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | bigint | null,
  ): number;
  export function writeSync(
    fd: number,
    buffer: Uint8Array,
    offset?: number,
    length?: number,
    position?: number | bigint | null,
  ): number;
  export function fstatSync(fd: number): Stats;
  export function fstatSync(fd: number, options: { bigint: true }): BigIntStats;
  export function lstatSync(path: string): Stats;
  export function lstatSync(path: string, options: { bigint: true }): BigIntStats;
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  export function mkdirSync(path: string, options?: { recursive?: boolean }): string | undefined;
  export function existsSync(path: string): boolean;
}

declare module 'node:fs/promises' {
  import type { Buffer } from 'node:buffer';
  import type { BigIntStats, Dirent } from 'node:fs';

  export interface FileHandle {
    readonly fd: number;
    stat(options: { bigint: true }): Promise<BigIntStats>;
    read(
      buffer: Buffer,
      offset: number,
      length: number,
      position: number | bigint | null,
    ): Promise<{ bytesRead: number; buffer: Buffer }>;
    close(): Promise<void>;
  }

  export function open(path: string, flags: 'r' | 'w' | 'wx'): Promise<FileHandle>;
  export function lstat(path: string, options: { bigint: true }): Promise<BigIntStats>;
  export function readdir(path: string, options: { withFileTypes: true }): Promise<Dirent[]>;
}

declare module 'node:path' {
  export function basename(path: string): string;
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
}

declare module 'node:stream' {
  import type { Buffer } from 'node:buffer';

  export interface ReadableOptions {
    highWaterMark?: number;
    read?(this: Readable, size: number): void;
    destroy?(this: Readable, error: Error | null, callback: (error?: Error | null) => void): void;
  }

  export class Readable {
    constructor(options?: ReadableOptions);
    push(chunk: Buffer | Uint8Array | string | null): boolean;
    destroy(error?: Error): this;
    pipe<T extends Transform>(destination: T): T;
    on(event: 'data', listener: (chunk: Buffer) => void): this;
    on(event: 'end' | 'close', listener: () => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
    [Symbol.asyncIterator](): AsyncIterableIterator<Buffer>;
    static from(iterable: Iterable<Buffer | Uint8Array | string> | AsyncIterable<Buffer | Uint8Array | string>): Readable;
  }

  export interface TransformOptions {
    highWaterMark?: number;
    transform?(
      this: Transform,
      chunk: Buffer,
      encoding: string,
      callback: (error?: Error | null, data?: Buffer) => void,
    ): void;
    flush?(this: Transform, callback: (error?: Error | null, data?: Buffer) => void): void;
  }

  export class Transform extends Readable {
    constructor(options?: TransformOptions);
    write(chunk: Buffer | Uint8Array): boolean;
    once(event: 'drain', listener: () => void): this;
    end(): this;
  }
}

declare module 'node:zlib' {
  import type { Buffer } from 'node:buffer';
  import type { Transform } from 'node:stream';

  export interface ZlibOptions {
    level?: number;
    chunkSize?: number;
  }

  export function createInflateRaw(options?: ZlibOptions): Transform;
  export function createDeflateRaw(options?: ZlibOptions): Transform;
  export function deflateRawSync(buf: Uint8Array, options?: ZlibOptions): Buffer;
  export function crc32(data: Uint8Array | string, value?: number): number;
}

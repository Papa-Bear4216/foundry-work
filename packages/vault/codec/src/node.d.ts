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
    allocUnsafe(size: number): Buffer;
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
  interface Stats {
    size: number;
    mode: number;
    isFile(): boolean;
    isDirectory(): boolean;
  }
  interface Dirent {
    name: string;
    isFile(): boolean;
    isDirectory(): boolean;
  }
  export function lstatSync(path: string): Stats;
  export function fstatSync(fd: number): Stats;
  export function readSync(fd: number, buffer: Buffer, offset: number, length: number, position: number | null): number;
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  export function openSync(path: string, flags: 'r' | 'r+'): number;
  export function openSync(path: string, flags: 'wx', mode: number): number;
  export function writeSync(fd: number, data: Uint8Array, offset: number, length: number, position: number): number;
  export function writeFileSync(fd: number, data: Uint8Array): void;
  export function ftruncateSync(fd: number, size: number): void;
  export function mkdirSync(path: string, options?: { recursive?: boolean; mode?: number }): string | undefined;
  export function chmodSync(path: string, mode: number): void;
  export function fsyncSync(fd: number): void;
  export function closeSync(fd: number): void;
  export function renameSync(source: string, target: string): void;
  export function unlinkSync(path: string): void;
  // P-3 second copy, ISO export and scheduler.
  export function rmdirSync(path: string): void;
  export function readFileSync(path: string, encoding: 'utf8'): string;
  export function writeFileSync(path: string, data: Uint8Array | string): void;
  export function statSync(path: string): Stats;
  export function statSync(path: string, options: { bigint: true }): { dev: bigint };
  export function statfsSync(path: string): { type: number };
  export const realpathSync: { (path: string): string; native(path: string): string };
  export function openSync(path: string, flags: 'w' | 'wx' | 'wx+' | 'r', mode?: number): number;
}

declare module 'node:path' {
  export function basename(path: string): string;
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
  export function relative(from: string, to: string): string;
  export function isAbsolute(path: string): boolean;
  export function parse(path: string): { root: string; dir: string; base: string; name: string; ext: string };
  export const sep: string;
  /** One platform's path rules (P-3: `win32` and `posix` are chosen by the injected platform, not the host). */
  export interface PlatformPath {
    basename(path: string): string;
    dirname(path: string): string;
    join(...paths: string[]): string;
    resolve(...paths: string[]): string;
    relative(from: string, to: string): string;
    isAbsolute(path: string): boolean;
    parse(path: string): { root: string };
    readonly sep: string;
  }
  export const win32: PlatformPath;
  export const posix: PlatformPath;
}

declare module 'node:os' {
  export function homedir(): string;
}

declare module 'node:child_process' {
  export interface SpawnSyncResult {
    status: number | null;
    signal: string | null;
    stdout: string;
    stderr: string;
    error?: Error;
  }
  export function spawnSync(command: string, args: readonly string[], options: {
    shell: false;
    encoding: 'utf8';
    windowsHide?: boolean;
    timeout?: number;
    input?: string;
    env?: Record<string, string | undefined>;
  }): SpawnSyncResult;
}

declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string, options: { timeout: number });
    exec(sql: string): void;
    close(): void;
  }
}

declare module 'node:process' {
  export const platform: string;
}

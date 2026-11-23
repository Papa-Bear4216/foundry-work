// Narrow Node 24 built-in declarations for the dependency-free command-line workspace.
declare module 'node:buffer' {
  export interface Buffer extends Uint8Array<ArrayBuffer> {
    subarray(start?: number, end?: number): Buffer;
    toString(encoding?: 'utf8' | 'latin1' | 'ascii' | 'hex' | 'base64', start?: number, end?: number): string;
    equals(other: Uint8Array): boolean;
    write(value: string, offset?: number): number;
    copy(target: Uint8Array, targetStart?: number, sourceStart?: number, sourceEnd?: number): number;
  }
  export const Buffer: {
    alloc(size: number, fill?: number): Buffer;
    byteLength(value: string, encoding?: 'utf8'): number;
    from(value: string, encoding?: 'utf8' | 'hex' | 'base64'): Buffer;
    from(value: ArrayBuffer, byteOffset?: number, length?: number): Buffer;
    from(value: Uint8Array | readonly number[]): Buffer;
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
  export function randomBytes(count: number): Buffer;
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}

declare module 'node:fs' {
  import type { Buffer } from 'node:buffer';
  export interface Stats {
    size: number;
    mtimeMs: number;
    isFile(): boolean;
    isDirectory(): boolean;
  }
  export function lstatSync(path: string): Stats;
  export function lstatSync(path: string, options: { throwIfNoEntry: false }): Stats | undefined;
  export function statSync(path: string): Stats;
  export function statSync(path: string, options: { throwIfNoEntry: false }): Stats | undefined;
  export function existsSync(path: string): boolean;
  export function readdirSync(path: string): string[];
  export function mkdirSync(path: string, options?: { recursive?: boolean; mode?: number }): string | undefined;
  export function readFileSync(path: string): Buffer;
  export function readFileSync(path: string | URL, encoding: 'utf8'): string;
  export function openSync(path: string, flags: 'r' | 'wx' | 'w', mode?: number): number;
  export function writeSync(fd: number, data: string | Uint8Array): number;
  export function fsyncSync(fd: number): void;
  export function closeSync(fd: number): void;
  export function unlinkSync(path: string): void;
}

declare module 'node:os' {
  export function homedir(): string;
  export function hostname(): string;
}

declare module 'node:path' {
  export function dirname(path: string): string;
  export function basename(path: string): string;
  export function join(...parts: string[]): string;
  export function resolve(...parts: string[]): string;
}

declare module 'node:url' {
  export function fileURLToPath(url: string | URL): string;
}

declare module 'node:stream' {
  export interface Readable extends AsyncIterable<unknown> {
    destroy(error?: Error): this;
  }
}

declare module 'node:sqlite' {
  export class DatabaseSync {
    constructor(path: string, options?: Record<string, unknown>);
    close(): void;
  }
}

declare module 'node:util' {
  export interface ParseArgsOptionConfig {
    type: 'string' | 'boolean';
    short?: string;
    multiple?: boolean;
  }
  export type ParsedToken =
    | { kind: 'option'; name: string; rawName: string; index: number; value: string | undefined; inlineValue: boolean | undefined }
    | { kind: 'positional'; index: number; value: string }
    | { kind: 'option-terminator'; index: number };
  export function parseArgs(config: {
    args: string[];
    options?: Record<string, ParseArgsOptionConfig>;
    strict?: boolean;
    allowPositionals?: boolean;
    tokens?: boolean;
  }): {
    values: Record<string, string | boolean | undefined>;
    positionals: string[];
    tokens?: ParsedToken[];
  };
}

declare module 'node:worker_threads' {
  export const isMainThread: boolean;
  export const workerData: unknown;
  export const parentPort: {
    postMessage(message: unknown): void;
  } | null;
  export class Worker {
    constructor(filename: string | URL, options?: {
      workerData?: unknown;
      transferList?: ArrayBuffer[];
      stdin?: boolean;
      stdout?: boolean;
      stderr?: boolean;
    });
    on(event: 'message', listener: (message: unknown) => void): this;
    on(event: 'error', listener: (error: Error) => void): this;
    on(event: 'exit', listener: (code: number) => void): this;
    terminate(): Promise<number>;
    unref(): void;
  }
}

declare module 'node:process' {
  interface WritableStream {
    write(text: string): boolean;
    isTTY?: boolean;
  }
  interface ReadableTty {
    isTTY?: boolean;
    setRawMode?(mode: boolean): void;
    on(event: 'data', listener: (chunk: Uint8Array) => void): void;
    off(event: 'data', listener: (chunk: Uint8Array) => void): void;
    resume(): void;
    pause(): void;
  }
  const process: {
    argv: string[];
    env: Record<string, string | undefined>;
    pid: number;
    platform: string;
    exitCode: number | undefined;
    stdin: ReadableTty;
    stdout: WritableStream;
    stderr: WritableStream;
    versions: Record<string, string>;
    exit(code?: number): never;
    kill(pid: number, signal?: string | number): boolean;
    on(event: string, listener: (...args: unknown[]) => void): void;
    off(event: string, listener: (...args: unknown[]) => void): void;
  };
  export default process;
}

interface ImportMeta {
  readonly url: string;
}

declare class URL {
  constructor(url: string, base?: string | URL);
  readonly href: string;
}

declare class TextDecoder {
  constructor(label?: string, options?: { fatal?: boolean });
  decode(bytes?: Uint8Array, options?: { stream: boolean }): string;
}

declare function setTimeout(callback: () => void, ms: number): { unref(): void };
declare function setInterval(callback: () => void, ms: number): unknown;
declare function clearTimeout(handle: { unref(): void } | undefined): void;

// Narrow ambient declarations for the Node.js built-ins used by facts-ledger (`types: []`).

declare const console: {
  log(...args: unknown[]): void;
  error(...args: unknown[]): void;
  warn(...args: unknown[]): void;
};

declare const process: {
  readonly argv: string[];
  readonly pid: number;
  readonly env: Record<string, string | undefined>;
  exitCode: number | undefined;
  resourceUsage(): { maxRSS: number };
  readonly hrtime: {
    bigint(): bigint;
  };
  readonly stdout: {
    write(chunk: string): boolean;
  };
  readonly stderr: {
    write(chunk: string): boolean;
  };
};

declare function fetch(
  input: string,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    redirect?: 'error' | 'follow' | 'manual';
    signal?: unknown;
  },
): Promise<{
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

declare const AbortSignal: {
  timeout(ms: number): unknown;
};

declare class URL {
  constructor(input: string);
  readonly protocol: string;
  readonly hostname: string;
}

declare module 'node:child_process' {
  export function execFile(
    file: string,
    args: readonly string[],
    options: {
      encoding: 'utf8';
      maxBuffer?: number;
      timeout?: number;
      windowsHide?: boolean;
    },
    callback: (error: Error | null, stdout: string, stderr: string) => void,
  ): void;
}

declare module 'node:crypto' {
  export function randomUUID(): string;
  export interface Sha256Hash {
    update(data: Uint8Array | string): Sha256Hash;
    digest(encoding: 'hex'): string;
  }
  export function createHash(algorithm: 'sha256'): Sha256Hash;
}

declare module 'node:fs' {
  export function openSync(path: string, flags: string, mode?: number): number;
  export function closeSync(fd: number): void;
  export function fstatSync(fd: number): { size: number };
  export function fstatSync(
    fd: number,
    options: { bigint: true },
  ): { size: bigint; mtimeNs: bigint; ctimeNs: bigint; ino: bigint; dev: bigint };
  export function statSync(
    path: string,
    options: { bigint: true },
  ): { ino: bigint; dev: bigint };
  export function realpathSync(path: string): string;
  export function fsyncSync(fd: number): void;
  export function mkdirSync(path: string, options: { recursive: true }): string | undefined;
  export function readSync(
    fd: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ): number;
  export function writeSync(fd: number, buffer: Uint8Array): number;
  export function renameSync(oldPath: string, newPath: string): void;
  export function unlinkSync(path: string): void;
  export function existsSync(path: string): boolean;
}

declare module 'node:path' {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
  export function basename(path: string): string;
}

declare module 'node:sqlite' {
  export interface SqlStatementSync {
    run(...params: unknown[]): { changes: number; lastInsertRowid: number | bigint };
    get(...params: unknown[]): Record<string, unknown> | undefined;
    all(...params: unknown[]): Record<string, unknown>[];
    iterate(...params: unknown[]): IterableIterator<Record<string, unknown>>;
  }

  export class DatabaseSync {
    constructor(path: string, options?: { timeout?: number; readOnly?: boolean });
    exec(sql: string): void;
    prepare(sql: string): SqlStatementSync;
    close(): void;
  }
}

declare module 'node:util' {
  export class TextDecoder {
    constructor(encoding?: string, options?: { fatal?: boolean; ignoreBOM?: boolean });
    decode(bytes?: Uint8Array, options?: { stream?: boolean }): string;
  }

  export class TextEncoder {
    encode(text: string): Uint8Array;
  }
}

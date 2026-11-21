// Narrow ambient declarations for the Node.js built-ins used by facts-ledger (`types: []`).

declare const console: {
  log(...args: unknown[]): void;
  error(...args: unknown[]): void;
  warn(...args: unknown[]): void;
};

declare const process: {
  readonly argv: string[];
  readonly pid: number;
  readonly platform: string;
  readonly execPath: string;
  readonly env: Record<string, string | undefined>;
  exitCode: number | undefined;
  kill(pid: number, signal?: string | number): boolean;
  nextTick(callback: () => void): void;
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
  readonly headers: {
    get(name: string): string | null;
  };
  readonly body: {
    getReader(): {
      read(): Promise<{ readonly done: boolean; readonly value?: Uint8Array }>;
      cancel(reason?: unknown): Promise<void>;
    };
  } | null;
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

declare function setTimeout(callback: () => void, ms: number): unknown;
declare function clearTimeout(handle: unknown): void;

declare module 'node:child_process' {
  export interface ChildReadable {
    on(event: 'data', listener: (chunk: string | Uint8Array) => void): this;
    on(event: 'error', listener: (err: Error) => void): this;
    destroy(): void;
  }

  export interface ChildWritable {
    readonly errored?: Error | null;
    readonly writableFinished?: boolean;
    on(event: 'error', listener: (err: Error) => void): this;
    on(event: 'finish', listener: () => void): this;
    end(data: string, callback?: () => void): void;
    destroy(): void;
  }

  export interface ChildProcess {
    readonly pid?: number;
    readonly exitCode: number | null;
    readonly signalCode: string | null;
    readonly stdin: ChildWritable | null;
    readonly stdout: ChildReadable | null;
    readonly stderr: ChildReadable | null;
    kill(signal?: string | number): boolean;
    on(event: 'error', listener: (err: Error) => void): this;
    on(event: 'exit', listener: (code: number | null, signal: string | null) => void): this;
    on(event: 'close', listener: (code: number | null, signal: string | null) => void): this;
  }

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

  export interface SpawnSyncResult {
    readonly status: number | null;
    readonly signal: string | null;
    readonly error?: Error;
    readonly stdout: Uint8Array;
    readonly stderr: Uint8Array;
  }

  export function spawnSync(
    file: string,
    args: readonly string[],
    options: {
      cwd?: string;
      env?: Record<string, string>;
      input?: string | Uint8Array;
      timeout?: number;
      maxBuffer?: number;
      windowsHide?: boolean;
      shell?: false;
      killSignal?: string;
    },
  ): SpawnSyncResult;

  export function spawn(
    file: string,
    args: readonly string[],
    options: {
      stdio: readonly ['pipe', 'pipe', 'pipe'];
      cwd?: string;
      env?: Record<string, string | undefined>;
      windowsHide?: boolean;
      shell?: boolean;
      detached?: boolean;
    },
  ): ChildProcess;
}

declare module 'node:crypto' {
  export function randomUUID(): string;
  export interface HashDigest {
    update(data: Uint8Array | string): HashDigest;
    copy(): HashDigest;
    digest(encoding: 'hex'): string;
  }
  export function createHash(algorithm: 'sha256' | 'sha1'): HashDigest;
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
  export function statSync(path: string): { size: number; isFile(): boolean };
  export function realpathSync(path: string): string;
  export function fsyncSync(fd: number): void;
  export function mkdirSync(path: string, options: { recursive: true }): string | undefined;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(
    path: string,
    options?: { recursive?: boolean; force?: boolean; maxRetries?: number },
  ): void;
  export function readSync(
    fd: number,
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null,
  ): number;
  export function writeSync(fd: number, buffer: Uint8Array): number;
  export function writeFileSync(path: string, data: Uint8Array | string): void;
  export function renameSync(oldPath: string, newPath: string): void;
  export function unlinkSync(path: string): void;
  export function existsSync(path: string): boolean;
  export function readFileSync(path: string): Uint8Array;
  export function readFileSync(path: string, encoding: 'utf8'): string;
}

declare module 'node:os' {
  export function homedir(): string;
  export function tmpdir(): string;
}

declare module 'node:path' {
  export const delimiter: string;
  export const sep: string;
  export function isAbsolute(path: string): boolean;
  export function relative(from: string, to: string): string;
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
    setReturnArrays(enabled: boolean): void;
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

declare module 'node:v8' {
  export function setFlagsFromString(flags: string): void;
}

declare module 'node:vm' {
  export function runInNewContext(code: string): unknown;
}

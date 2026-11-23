/**
 * Secret input (design 4.4). A secret never comes from argv or the environment.
 *
 * - Terminal: a prompt on stderr with no echo (raw mode), main thread only.
 * - Stdin: `readStdinText`, an asynchronous read that keeps the watchdog running; exactly one trailing line ending is
 *   removed. Two secrets on stdin: line 1 and line 2. A terminal on stdin is refused for these flags (`cli.ts`).
 *
 * Secrets travel as Buffers that the owner zeroes in `finally`. A Buffer comes from `Buffer.alloc`, never from the
 * shared pool, so it can be transferred to the worker thread without transferring unrelated memory. The decoded
 * string, and the strings the vault API takes, cannot be zeroed (JavaScript strings are immutable).
 */
import { Buffer } from 'node:buffer';
import { createReadStream } from 'node:fs';
import process from 'node:process';
import { CliError, usage } from './errors.ts';

const MAX_SECRET_BYTES = 64 * 1024;

/** An unpooled Buffer holding the UTF-8 bytes of `text`. */
export function secretBuffer(text: string): Buffer {
  const buffer = Buffer.alloc(Buffer.byteLength(text));
  buffer.write(text);
  return buffer;
}

/** Remove exactly one trailing line ending (CRLF, LF or CR). */
export function stripOneLineEnding(text: string): string {
  if (text.endsWith('\r\n')) return text.slice(0, -2);
  if (text.endsWith('\n') || text.endsWith('\r')) return text.slice(0, -1);
  return text;
}

/** A pending stdin read; `cancel` stops it and zeroes what it has read so far. */
export interface StdinRead {
  cancel(): void;
}

interface ChunkSource {
  on(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
  on(event: 'error', listener: (error: Error) => void): unknown;
  off(event: 'data', listener: (chunk: Uint8Array) => void): unknown;
  off(event: 'end', listener: () => void): unknown;
  off(event: 'error', listener: (error: Error) => void): unknown;
  pause(): unknown;
  destroy(error?: Error): unknown;
}

/**
 * Read stdin to its end WITHOUT blocking the main thread, so the wall-clock watchdog keeps running while a pipe stays
 * open without EOF. fd 0 is read through `process.stdin` (a pending read there does not stop `process.exit`; a
 * blocking `readSync`, in this thread or in a worker, does). Another descriptor (tests) is read with a read stream.
 * Same rules as the vault's `readSecretFromFd`: at most 64 KiB, valid UTF-8. Every chunk is zeroed after it is copied.
 */
export function readStdinText(fd: number, track?: (read: StdinRead) => void): Promise<string> {
  const source: ChunkSource = fd === 0 ? process.stdin : createReadStream(null, { fd, autoClose: false });
  const bytes = Buffer.alloc(MAX_SECRET_BYTES);
  let length = 0;
  return new Promise<string>((resolve, reject) => {
    let settled = false;
    const finish = (error: Error | undefined) => {
      if (settled) return;
      settled = true;
      source.off('data', onData);
      source.off('end', onEnd);
      source.off('error', onError);
      if (error) {
        bytes.fill(0);
        source.destroy();
        reject(error);
        return;
      }
      source.pause();
      try {
        resolve(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
      } catch {
        reject(usage('the secret on stdin is not valid UTF-8'));
      } finally {
        bytes.fill(0);
      }
    };
    const onData = (chunk: Uint8Array) => {
      try {
        if (length + chunk.length > MAX_SECRET_BYTES) {
          finish(new CliError('SECRET_TOO_LONG', 'the secret is longer than 64 KiB'));
          return;
        }
        bytes.set(chunk, length);
        length += chunk.length;
      } finally {
        chunk.fill(0);
      }
    };
    const onEnd = () => finish(undefined);
    const onError = (error: Error) => finish(error);
    source.on('data', onData);
    source.on('end', onEnd);
    source.on('error', onError);
    track?.({ cancel: () => finish(new CliError('INTERRUPTED', 'the stdin read was cancelled')) });
  });
}

/** One secret from stdin text: exactly one trailing line ending is removed. */
export function oneSecret(text: string): Buffer {
  return secretBuffer(stripOneLineEnding(text));
}

/** Read one secret from stdin. */
export async function readOneSecret(fd: number, track?: (read: StdinRead) => void): Promise<Buffer> {
  return oneSecret(await readStdinText(fd, track));
}

/** Two secrets from stdin text: line 1 and line 2 (one trailing line ending after line 2 is removed). */
export function twoSecrets(text: string): [Buffer, Buffer] {
  const match = /\r?\n/u.exec(text);
  if (!match) throw usage('stdin must hold the recovery key on line 1 and the new passphrase on line 2');
  const first = text.slice(0, match.index);
  const second = stripOneLineEnding(text.slice(match.index + match[0].length));
  if (/[\r\n]/u.test(second)) throw usage('stdin must hold exactly two lines');
  return [secretBuffer(first), secretBuffer(second)];
}

/** Read two secrets from stdin: line 1 and line 2. */
export async function readTwoSecrets(fd: number, track?: (read: StdinRead) => void): Promise<[Buffer, Buffer]> {
  return twoSecrets(await readStdinText(fd, track));
}

export type EditorResult = 'more' | 'done' | 'abort';

/**
 * Line editing for the no-echo prompt. Handles Enter, Backspace (one UTF-8 code point), Ctrl-C / Ctrl-D (abort),
 * ignores other control bytes and terminal escape sequences. The internal buffer is fixed and zeroed by `wipe`.
 */
export class LineEditor {
  #bytes = Buffer.alloc(MAX_SECRET_BYTES);
  #length = 0;
  #escape: 'none' | 'esc' | 'csi' = 'none';

  feed(chunk: Uint8Array): EditorResult {
    for (const byte of chunk) {
      if (this.#escape === 'esc') {
        this.#escape = byte === 0x5b || byte === 0x4f ? 'csi' : 'none';
        continue;
      }
      if (this.#escape === 'csi') {
        if (byte >= 0x40 && byte <= 0x7e) this.#escape = 'none';
        continue;
      }
      if (byte === 0x0d || byte === 0x0a) return 'done';
      if (byte === 0x03 || (byte === 0x04 && this.#length === 0)) return 'abort';
      if (byte === 0x1b) {
        this.#escape = 'esc';
        continue;
      }
      if (byte === 0x7f || byte === 0x08) {
        while (this.#length > 0) {
          const last = this.#bytes[--this.#length]!;
          this.#bytes[this.#length] = 0;
          if ((last & 0xc0) !== 0x80) break;
        }
        continue;
      }
      if (byte < 0x20) continue;
      if (this.#length >= this.#bytes.length) throw new CliError('SECRET_TOO_LONG', 'the secret is longer than 64 KiB');
      this.#bytes[this.#length++] = byte;
    }
    return 'more';
  }

  /** Copy the typed bytes into a new unpooled Buffer and zero the internal buffer. */
  take(): Buffer {
    const out = Buffer.alloc(this.#length);
    this.#bytes.copy(out, 0, 0, this.#length);
    this.wipe();
    return out;
  }

  wipe(): void {
    this.#bytes.fill(0);
    this.#length = 0;
  }
}

export interface PromptIo {
  input: typeof process.stdin;
  output: { write(text: string): boolean };
}

/** Ask for a secret on the terminal without echo. Main thread only. */
export function promptHidden(label: string, io: PromptIo = { input: process.stdin, output: process.stderr }): Promise<Buffer> {
  const { input, output } = io;
  if (!input.isTTY || typeof input.setRawMode !== 'function') {
    return Promise.reject(usage('no terminal for a prompt; use --passphrase-stdin or --recovery-key-stdin'));
  }
  const editor = new LineEditor();
  output.write(label);
  return new Promise((resolve, reject) => {
    const finish = () => {
      input.off('data', onData);
      input.setRawMode!(false);
      input.pause();
      output.write('\n');
    };
    const onData = (chunk: Uint8Array) => {
      let result: EditorResult;
      try {
        result = editor.feed(chunk);
      } catch (error) {
        finish();
        editor.wipe();
        reject(error);
        return;
      } finally {
        chunk.fill(0);
      }
      if (result === 'done') {
        finish();
        resolve(editor.take());
      } else if (result === 'abort') {
        finish();
        editor.wipe();
        reject(new CliError('INTERRUPTED', 'the prompt was cancelled'));
      }
    };
    input.setRawMode!(true);
    input.on('data', onData);
    input.resume();
  });
}

/** Restore the terminal after an abnormal end (timeout, signal). Safe to call at any time. */
export function restoreTerminal(): void {
  try {
    if (process.stdin.isTTY) process.stdin.setRawMode?.(false);
  } catch {
    // Best effort only.
  }
}

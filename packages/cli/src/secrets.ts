/**
 * Secret input (design 4.4). A secret never comes from argv or the environment.
 *
 * - Terminal: a prompt on stderr with no echo (raw mode), main thread only.
 * - Stdin: `readSecretFromFd`; exactly one trailing line ending is removed. Two secrets on stdin: line 1 and line 2.
 *
 * Secrets travel as Buffers that the owner zeroes in `finally`. A Buffer comes from `Buffer.alloc`, never from the
 * shared pool, so it can be transferred to the worker thread without transferring unrelated memory. The string that
 * `readSecretFromFd` returns, and the strings the vault API takes, cannot be zeroed (JavaScript strings are immutable).
 */
import { Buffer } from 'node:buffer';
import process from 'node:process';
import { readSecretFromFd } from 'vault';
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

/** Read one secret from stdin. */
export function readOneSecret(fd: number): Buffer {
  return secretBuffer(stripOneLineEnding(readSecretFromFd(fd)));
}

/** Read two secrets from stdin: line 1 and line 2 (one trailing line ending after line 2 is removed). */
export function readTwoSecrets(fd: number): [Buffer, Buffer] {
  const text = readSecretFromFd(fd);
  const match = /\r?\n/u.exec(text);
  if (!match) throw usage('stdin must hold the recovery key on line 1 and the new passphrase on line 2');
  const first = text.slice(0, match.index);
  const second = stripOneLineEnding(text.slice(match.index + match[0].length));
  if (/[\r\n]/u.test(second)) throw usage('stdin must hold exactly two lines');
  return [secretBuffer(first), secretBuffer(second)];
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

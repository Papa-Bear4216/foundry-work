import { isUtf8 } from 'node:buffer';
import { readFileSync } from 'node:fs';

const SECRET_VARIABLE = /(?:^|_)(?:PASS(?:PHRASE|WORD)?|PASS_PHRASE|RECOVERY(?:_?KEY)?)(?:_|$)/iu;

/** Call after consuming fixed command words, before prompting or reading a descriptor. */
export function guardSecretInput(args: readonly string[], env: Readonly<Record<string, string | undefined>>): void {
  if (args.length !== 0) throw new Error('Unexpected command-line arguments. Read secrets from a prompt or stdin.');
  if (Object.keys(env).some(name => SECRET_VARIABLE.test(name))) {
    throw new Error('Secret environment variables are refused. Read secrets from a prompt or stdin.');
  }
}

/** Read exact UTF-8 bytes to EOF from an already-open descriptor, including any newline. */
export function readSecretFromFd(fd = 0): string {
  const bytes = readFileSync(fd);
  try {
    if (!isUtf8(bytes)) throw new Error('Secret input must be valid UTF-8.');
    return bytes.toString();
  } finally {
    bytes.fill(0);
  }
}

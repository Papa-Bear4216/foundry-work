import { Buffer, isUtf8 } from 'node:buffer';
import { readSync } from 'node:fs';

const SECRET_VARIABLE = /^(?:FOUNDRY_|VAULT_).*(?:PASS|SECRET|KEY|RECOVERY|TOKEN)/iu;
const SECRET_OPTION = /^(?:passphrase|password|recovery-key|secret)$/iu;
const MAX_SECRET_BYTES = 64 * 1024;
type ArgumentToken = { kind: 'option'; name: string } | { kind: 'positional' | 'option-terminator' };

/** Inspect the command's parseArgs tokens before reading secrets. Declare its positional count separately. */
export function guardSecretInput(
  args: { tokens: readonly ArgumentToken[] },
  env: Readonly<Record<string, string | undefined>>,
  declaredPositionals = 0,
): void {
  if (args.tokens.some(token => token.kind === 'option' && SECRET_OPTION.test(token.name))
    || args.tokens.filter(token => token.kind === 'positional').length > declaredPositionals) {
    throw new Error('Unexpected command-line arguments. Read secrets from a prompt or stdin.');
  }
  if (Object.entries(env).some(([name, value]) => value !== undefined && SECRET_VARIABLE.test(name))) {
    throw new Error('Secret environment variables are refused. Read secrets from a prompt or stdin.');
  }
}

/** Read exact UTF-8 bytes to EOF from an already-open descriptor, including any newline. */
export function readSecretFromFd(fd = 0): string {
  const chunks: Buffer[] = [];
  const parts: Buffer[] = [];
  let length = 0;
  try {
    for (;;) {
      const chunk = Buffer.alloc(Math.min(4096, MAX_SECRET_BYTES + 1 - length));
      chunks.push(chunk);
      const count = readSync(fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      length += count;
      if (length > MAX_SECRET_BYTES) throw new Error('Secret input exceeds 64 KiB.');
      parts.push(chunk.subarray(0, count));
    }
    const bytes = Buffer.concat(parts);
    try {
      if (!isUtf8(bytes)) throw new Error('Secret input must be valid UTF-8.');
      return bytes.toString();
    } finally {
      bytes.fill(0);
    }
  } finally {
    for (const chunk of chunks) chunk.fill(0);
  }
}

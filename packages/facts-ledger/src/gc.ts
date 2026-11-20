import { setFlagsFromString } from 'node:v8';
import { runInNewContext } from 'node:vm';

let collector: (() => void) | null | undefined;

/**
 * Run a full garbage collection between pages of a long scan (`facts verify --all`, the
 * digest). V8 otherwise lets short-lived per-page objects reach the old generation and grows
 * the heap before collecting them; on Linux that alone put `verify --all` over the 96 MiB
 * budget on the 10,000-block fixture (Step Zero 10.4, A-28). Enabling `--expose-gc` at run
 * time is the standard way to reach the collector without a command-line flag; if the
 * runtime refuses, this does nothing and the budget check in CI reports the cost.
 */
export function collectGarbage(): void {
  if (collector === undefined) {
    try {
      setFlagsFromString('--expose-gc');
      const fn = runInNewContext('gc') as unknown;
      collector = typeof fn === 'function' ? (fn as () => void) : null;
    } catch {
      collector = null;
    }
  }
  collector?.();
}

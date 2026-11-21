// Preload for the budget check (Step Zero 10.4): when the CLI has finished its work, print a
// marker and block until the parent closes stdin, so the parent can read this process's
// peak memory counter from outside while the process still exists.
import { readSync, writeSync } from 'node:fs';

let held = false;
process.on('beforeExit', () => {
  if (held) return;
  held = true;
  writeSync(2, `BUDGET-HOLD ${process.pid}\n`);
  const buf = new Uint8Array(64);
  try {
    while (readSync(0, buf, 0, buf.length, null) > 0) {
      // Drain until the parent closes stdin.
    }
  } catch {
    // EOF reported as an error on some platforms.
  }
});

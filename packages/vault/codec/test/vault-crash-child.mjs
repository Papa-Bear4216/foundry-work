import { writeSync } from 'node:fs';
import { VaultWriter } from '../src/index.ts';
import { event, unlockFixture } from './vault-fixture.mjs';

const [directory, operation, target] = process.argv.slice(2);
const writer = VaultWriter.open(directory, unlockFixture(directory), {
  checkpoint(point) {
    if (point !== target) return;
    writeSync(1, point + '\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  },
});
try {
  if (operation === 'append') writer.appendBatch([event('TEST ONLY interrupted append')]);
  if (operation === 'close') writer.closeSegment();
  if (operation === 'hold') {
    writeSync(1, 'locked\n');
    await new Promise(resolve => setTimeout(resolve, 750));
  }
} finally {
  writer.release();
}

// TEST ONLY: preloaded with `--import` by p3-isolation.test.mjs (R19-9). Every thread (the bin's main thread and the
// command's worker thread, which inherits the flag) appends "<threadId> <module URL>" for each module it loads to the
// file named by P3_TEST_MODULE_TRACE. No data is read or written apart from that synthetic trace file.
import { appendFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { threadId } from 'node:worker_threads';

const file = process.env.P3_TEST_MODULE_TRACE;
if (file) {
  registerHooks({
    load(url, context, nextLoad) {
      appendFileSync(file, `${threadId} ${url}\n`);
      return nextLoad(url, context);
    },
  });
}

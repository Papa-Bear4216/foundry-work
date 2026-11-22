/** Worker-thread entry: runs one command body and reports output, errors and the exit code to the main thread. */
import { parentPort, workerData } from 'node:worker_threads';
import { executeCommand } from './commands.ts';
import type { CommandRequest, TestHooks } from './commands.ts';

const { request, hooks } = workerData as { request: CommandRequest; hooks: TestHooks };
const port = parentPort!;
const code = await executeCommand(request, {
  out: text => port.postMessage({ type: 'out', text }),
  err: text => port.postMessage({ type: 'err', text }),
}, hooks);
port.postMessage({ type: 'done', code });

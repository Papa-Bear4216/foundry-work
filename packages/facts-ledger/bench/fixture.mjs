import { closeSync, openSync, writeFileSync } from 'node:fs';

export const blockCount = 10_000;
export const project = 'fixture';

function blockId(number) {
  return number.toString(16).padStart(12, '0');
}

export function block(number, parent = number === 1 ? null : blockId(number - 1)) {
  const id = blockId(number);
  const ts = new Date(Date.UTC(2026, 0, 1, 0, number)).toISOString();
  const component = `component-${number % 100}`;
  const path = `fixtures/${component}.txt`;
  return {
    id, ts, agent: 'fixture-builder', project, parent, trace_id: id,
    status: number % 101 === 0 ? 'proposed' : 'done',
    intent: `Record calibration for ${component} at sample ${number}`,
    reasoning: 'A deterministic sample exercises the ledger index and summary.',
    actions: [], verification: 'Synthetic fixture', touches: [path], supersedes: null,
    schema: 2,
    facts: [{
      fact_id: `${id}.0`, tier: 'asserted', scope: 'at-commit',
      claim: `Calibration sample ${number} passed for ${component}.`,
      note: 'The synthetic test fixture uses a constant reference signal.',
      tags: ['calibration', number % 101 === 0 ? 'pinned' : component],
      sensitivity: 'public', verified_at: ts, supersedes: null,
      evidence: [{
        type: 'file', repo: project, path, commit: id.padStart(40, '0'),
        blob: id.padEnd(40, '0'), lines: '1', quote: 'Reference signal is stable.',
      }],
    }],
    retracted_facts: [],
    token_usage: { model: 'fixture-model', task: 'calibration', input: 500, output: 120, measured: false },
  };
}

export function line(record) {
  return `${JSON.stringify(record)}\n`;
}

export function generateFixture(directory) {
  const fd = openSync(`${directory}/ledger.jsonl`, 'wx');
  try {
    for (let number = 1; number <= blockCount; number++) writeFileSync(fd, line(block(number)));
  } finally {
    closeSync(fd);
  }
}

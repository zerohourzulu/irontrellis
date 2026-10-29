// Differential-test helper: answers a batch of authorize/survives questions with the
// TypeScript engine. Reads {histories, requests} JSON on stdin, writes one JSON array.
// Not a conformance adapter; the pytest suite spawns it once per session.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const core = await import(join(here, '..', '..', 'packages', 'core', 'dist', 'index.js'));
const encode = (_k, v) => (typeof v === 'bigint' ? { '$continuity.bigint': v.toString() } : v);
const plain = (v) => JSON.parse(JSON.stringify(v, encode));
const revive = (v) => core.jsonParseWithBigints(JSON.stringify(v));

const input = JSON.parse(readFileSync(0, 'utf8'));
const states = new Map();
for (const [name, events] of Object.entries(input.histories)) {
  const result = core.replay(revive(events));
  states.set(name, result.status === 'ACCEPTED' ? result.state : null);
}
const stripEvidence = (value) => {
  if (Array.isArray(value)) return value.map(stripEvidence);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) if (k !== 'evidence') out[k] = stripEvidence(v);
    return out;
  }
  return value;
};
const out = input.requests.map((request) => {
  const state = states.get(request.history);
  if (state === null) return { replay: 'REJECTED' };
  if (request.op === 'authorize') return plain(core.authorizeState(state, revive(request.body)));
  const answer = core.survivesState(state, { targetAgentId: request.agent, evaluationTime: request.at, disclosure: core.publicQueryDisclosure('SURVIVES') });
  return Object.hasOwn(answer, 'answer') ? { established: true, answer: stripEvidence(plain(answer.answer)) } : { established: false, code: answer.code };
});
process.stdout.write(JSON.stringify(out));

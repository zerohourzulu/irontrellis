import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { LIMITS, fail, encode, validateOptions } from './reader-contract.mjs';
const worker = fileURLToPath(new URL('./reader-worker.mjs', import.meta.url));

// Synchronous child execution bounds one active request. Hard timeout and
// maxBuffer also cover Core/import failures; no client-selectable executable.
export function runObservation(source, operation, args = {}) {
  validateOptions(operation, args);
  const input = encode({ source, operation, args });
  if (Buffer.byteLength(input) > LIMITS.config) fail('REQUEST_LIMIT_EXCEEDED');
  return runReaderChild(worker, input);
}

// Internal trusted executable boundary, exported for actual-process fault tests.
// Never populated from MCP input or source configuration.
export function runReaderChild(workerPath, input, timeoutMs = LIMITS.workerMs) {
  const child = spawnSync(process.execPath, ['--max-old-space-size=256', workerPath], {
    input, encoding: 'utf8', timeout: timeoutMs, killSignal: 'SIGKILL',
    maxBuffer: LIMITS.output + 4096, env: {}, stdio: ['pipe', 'pipe', 'pipe'],
  });
  if (child.error?.code === 'ETIMEDOUT') fail('READER_TIMEOUT');
  if (child.error?.code === 'ENOBUFS') fail('OUTPUT_LIMIT_EXCEEDED');
  if (child.error || child.status !== 0) fail('READER_FAILED');
  let reply;
  try { reply = JSON.parse(child.stdout); } catch { fail('READER_FAILED'); }
  if (reply.ok !== true) fail(reply.code ?? 'READER_FAILED');
  return reply.value;
}

// Internal child entry. Its stdin is supplied only by the local trusted runner,
// never directly by MCP. A child can read only; it is not an OS sandbox.
import { readFileSync } from 'node:fs';
import { openObservation } from './lens.mjs';
import { parseStrictJson } from '../integrations/retained-evidence-mcp/src/strict-json.mjs';
import { ReaderError, LIMITS, encode } from './reader-contract.mjs';
try {
  const input = parseStrictJson(readFileSync(0), { maxBytes: LIMITS.config });
  const value = openObservation(input.source.path, input.source).observe(input.operation, input.args);
  process.stdout.write(encode({ ok: true, value }) + '\n');
} catch (error) {
  process.stdout.write(encode({ ok: false, code: error instanceof ReaderError ? error.code : 'READER_FAILED' }) + '\n');
}

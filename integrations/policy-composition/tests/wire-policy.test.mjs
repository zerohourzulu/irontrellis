import { preserveHistories } from './preserve.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createDemo } from '@ramex-labs/irontrellis-protected-evidence-mcp/setup';
const require = createRequire(import.meta.resolve('@ramex-labs/irontrellis-protected-evidence-mcp/package.json'));
const { Client } = await import(require.resolve('@modelcontextprotocol/client'));
const { StdioClientTransport } = await import(require.resolve('@modelcontextprotocol/client/stdio'));
for (const allow of [true, false]) test(`real MCP transport applies Cedar ${allow ? 'permit' : 'denial'}`, async t => {
  const root = mkdtempSync(join(tmpdir(), 'irontrellis-policy-wire-'));
  t.after(() => { preserveHistories(root); rmSync(root, {recursive:true,force:true}); });
  const demo = await createDemo(join(root, 'case')), source = join(root, 'policy.cedar'), journal = join(root, 'audit.jsonl');
  writeFileSync(source, `${allow ? 'permit' : 'forbid'}(principal, action, resource);`);
  const client = new Client({ name: 'policy-integration-test', version: '1' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [fileURLToPath(new URL('../cedar-gateway.mjs', import.meta.url)), demo.configFile, source, journal], stderr: 'pipe' });
  t.after(() => client.close()); await client.connect(transport);
  const result = await client.callTool({ name: 'irontrellis_collect_evidence', arguments: { operationId: 'policy-wire', resource: 'incident:42' } });
  assert.equal(result.structuredContent.status, allow ? 'RECORDED' : 'DENIED');
  assert.equal(readdirSync(demo.config.outputDirectory).length, allow ? 1 : 0);
  assert.equal(JSON.parse(readFileSync(journal, 'utf8')).result.decision, allow ? 'ALLOW' : 'DENY');
  assert.equal(JSON.stringify(result).includes(journal), false);
});

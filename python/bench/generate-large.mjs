#!/usr/bin/env node
// Builds a large format-1 history with the TypeScript core for the Python replay benchmark.
//   node python/bench/generate-large.mjs [events=2000] [out=python/bench/large-v1.jsonl]
import { rmSync, existsSync, copyFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const core = await import(join(here, '..', '..', 'packages', 'core', 'dist', 'index.js'));
const signer = await import(join(here, '..', '..', 'packages', 'core', 'dist', 'signer.js'));
const target = Number(process.argv[2] ?? 2000);
const out = resolve(process.argv[3] ?? join(here, 'large-v1.jsonl'));
const dir = mkdtempSync(join(tmpdir(), 'irontrellis-bench-'));
const historyFile = join(dir, 'large.jsonl');
let tick = 1000, counter = 0;
const pair = core.keyPairFromPrivateKey('ed25519', 'owner:bench', `0x${'7'.repeat(64)}`);
const owner = await core.createLocalOwner({
  historyFile, domain: { protocol: 'irontrellis', version: '1', deploymentId: 'bench' }, owner: 'operations', controller: 'operator',
  format: core.TRELLIS_FORMAT, now: () => tick, ids: () => `bench:${(counter += 1)}`, signer: signer.signerFromKeyPair(pair),
});
const agents = 50;
for (let n = 0; n < agents; n += 1) { await owner.createAgent({ id: `agent-${n}` }); tick += 1; }
let grants = 0, revokes = 0;
const live = [];
let count = 1 + agents;
while (count < target) {
  count += 1;
  if (live.length > 10 && Math.random() < 0.45) { await owner.revoke(live.shift()); revokes += 1; }
  else {
    const id = `grant-${grants}`;
    await owner.grant({ id, to: `agent-${grants % agents}`, actions: ['read', 'write'], resources: [`resource-${grants % 97}`], expiresAt: 10_000_000, maxAmount: BigInt(1000 + grants) });
    live.push(id); grants += 1;
  }
  tick += 1;
}
const total = owner.exportHistory().length;
copyFileSync(historyFile, out);
rmSync(dir, { recursive: true, force: true });
console.log(`wrote ${total} events (${agents} agents, ${grants} grants, ${revokes} revocations) to ${out}`);

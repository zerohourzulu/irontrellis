// Performance sanity: 1,000 sequential head appends over HTTP, each one
// written and fsynced (log and checkpoint) before its reply. The number is
// reported, not asserted tightly: fsync latency depends on the disk.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildHistory, startWitness, t, tempDir } from "./helpers.mjs";

test("1,000 sequential head appends over HTTP", { timeout: 600_000 }, async (context) => {
  const { dir, cleanup } = tempDir();
  const handle = await startWitness({ dir });
  try {
    const h = await buildHistory({ name: "perf", agents: 999 });
    assert.equal(h.heads.length, 1001);
    const statements = [await h.statement(0, null)];
    for (let position = 1; position <= 999; position += 1) statements.push(await h.statement(position, position - 1));
    const post = (path, body, headers = {}) => fetch(`${handle.url}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
    assert.equal((await post("/v1/histories", { genesis: h.genesis }, { authorization: "Bearer itw_test-admin-token-0123456789" })).status, 201);
    const started = performance.now();
    let last;
    for (const statement of statements) {
      const response = await post(`/v1/histories/${h.historyId}/heads`, statement);
      assert.equal(response.status, 201);
      last = await response.json();
    }
    const seconds = (performance.now() - started) / 1000;
    const perSecond = Math.round(statements.length / seconds);
    context.diagnostic(`1000 sequential head appends: ${seconds.toFixed(2)} s (${perSecond}/s, ${(seconds).toFixed(2)} ms mean per append)`);
    console.log(`# perf: 1000 sequential head appends over HTTP in ${seconds.toFixed(2)} s (${perSecond} appends/s)`);
    assert.equal(t.verifyWitnessReceipt(last.receipt, [handle.witness.verifierKey]).ok, true);
    assert.equal(handle.witness.size, 1001);
    assert.ok(seconds < 300, "1,000 appends within five minutes even on a slow disk");
  } finally {
    await handle.close();
    cleanup();
  }
});

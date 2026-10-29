// GATEWAY-RATE-01: the stdio bounds are rates, not lifetime totals. The client guard admits at most 1,024 frames in any 60 s
// (a long session of ordinary calls never reaches it; a flood is refused), the upstream transport the same per connection,
// and a closed upstream connection is evicted from the pool, so the next governed call reconnects and is verified again,
// while a call whose reply was lost stays OUTCOME_UNKNOWN and is never re-dispatched.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setup } from "./fixtures.mjs";
import { guardedInput, rateWindow } from "../dist/guard.js";
import { ProtectedStdioTransport } from "../dist/stdio.js";
import { createGateway } from "../dist/gateway.js";

const ping = (id) => JSON.stringify({ jsonrpc: "2.0", id, method: "ping" }) + "\n";
/** Feeds `count` frames through the guard, the clock advancing `stepMs` per frame; returns frames passed and the refusal. */
async function feed(count, stepMs) {
  let t = 0, passed = 0, refused = null;
  const source = new PassThrough();
  const input = guardedInput(source, { now: () => t, onRefused: (reason) => { refused ??= { reason, passed }; } });
  input.on("data", (b) => { passed += b.toString().split("\n").filter(Boolean).length; });
  for (let i = 1; i <= count && refused === null; i++) { t += stepMs; source.write(ping(i)); await new Promise((r) => setImmediate(r)); }
  await new Promise((r) => setTimeout(r, 20));
  return { passed, refused };
}

test("the window: at most max admissions in any windowMs, and admission resumes as old ones age out", () => {
  let t = 0;
  const admit = rateWindow(3, 1000, () => t);
  assert.deepEqual([admit(), admit(), admit(), admit()], [true, true, true, false]);
  t = 999; assert.equal(admit(), false, "still inside the window of the first");
  t = 1000; assert.equal(admit(), true, "the first has aged out");
});

test("5,000 client frames spread over time all pass (no lifetime cap)", async () => {
  const r = await feed(5000, 100); // 600 a minute
  assert.deepEqual(r, { passed: 5000, refused: null });
});

test("a flood of 1,025 client frames inside one window is refused (INPUT_REFUSED) after 1,024", async () => {
  const r = await feed(1100, 1);
  assert.deepEqual(r, { passed: 1024, refused: { reason: "INPUT_REFUSED", passed: 1024 } });
});

/** An upstream child that writes `count` JSON-RPC notifications, one per line, then waits. */
function chatty(count) {
  return { id: "chatty", command: process.execPath, args: ["-e", `let s="";for(let i=0;i<${count};i++)s+=JSON.stringify({jsonrpc:"2.0",method:"notifications/message",params:{n:i}})+"\\n";process.stdout.write(s);setInterval(()=>{},1000);`] };
}
async function upstreamFrames(count, stepMs) {
  let t = 0, received = 0, error = null, closed = false;
  const transport = new ProtectedStdioTransport(chatty(count), { now: () => (t += stepMs) });
  transport.onmessage = () => { received++; };
  transport.onerror = (e) => { error ??= e.message; };
  transport.onclose = () => { closed = true; };
  await transport.start();
  for (let i = 0; i < 300 && received + (error ? 1 : 0) < count && !closed; i++) await new Promise((r) => setTimeout(r, 10));
  await transport.close();
  return { received, error };
}

test("1,500 upstream frames over time keep the connection; a burst inside one window closes it", async () => {
  assert.deepEqual(await upstreamFrames(1500, 100), { received: 1500, error: null });
  const burst = await upstreamFrames(1100, 0);
  assert.deepEqual(burst, { received: 1024, error: "UPSTREAM_INVALID_FRAME" });
});

test("after an upstream closes, the next governed call reconnects and verifies; the lost-reply call stays OUTCOME_UNKNOWN, never re-dispatched", async (t) => {
  const root = mkdtempSync(join(tmpdir(), "irontrellis-gateway-rate-")), f = await setup(join(root, "case"));
  const dir = join(root, "case"), gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  const count = () => (existsSync(join(dir, "tickets.calls.jsonl")) ? readFileSync(join(dir, "tickets.calls.jsonl"), "utf8").trim().split("\n").length : 0);
  // A second job on the same upstream server ("tickets"), with its own business key, to show the reconnect.
  const ticket = f.config.operations.find((o) => o.name === "create_incident_ticket");
  const followUp = { ...ticket, name: "create_followup_ticket", businessKey: "incident:42:follow-up" };
  const g = await createGateway({ ...f.config, operations: [...f.config.operations, followUp], local: f.local }); gateways.push(g);
  writeFileSync(join(dir, "tickets.control.json"), JSON.stringify({ crash: true }), { mode: 0o600 });
  assert.equal((await g.run("create_incident_ticket", { title: "First" })).status, "OUTCOME_UNKNOWN", "the reply is lost with the upstream");
  writeFileSync(join(dir, "tickets.control.json"), JSON.stringify({}), { mode: 0o600 });
  const second = await g.run("create_followup_ticket", { title: "Follow-up" });
  assert.equal(second.status, "RESPONSE_RETAINED", "a new call reconnects through the verify path and runs");
  assert.equal((await g.run("create_incident_ticket", { title: "First" })).status, "OUTCOME_UNKNOWN", "the lost-reply call stays unknown");
  assert.equal(g.status("create_incident_ticket").dispatchPerformed, false, "and is never dispatched again");
  assert.equal(count(), 2, "the lost-reply call was dispatched once only");
});

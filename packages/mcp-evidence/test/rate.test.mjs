// GATEWAY-RATE-01: the evidence server's stdin guard bounds the message rate, not the session's total: at most 1,024 frames
// in any 60 s. A long session of ordinary calls passes; a flood is refused (INPUT_REFUSED), as before.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { guardedInput } from "../dist/guard.js";

async function feed(count, stepMs) {
  let t = 0, passed = 0, refused = null;
  const source = new PassThrough();
  const input = guardedInput(source, { now: () => t, onRefused: (reason) => { refused ??= { reason, passed }; } });
  input.on("data", (b) => { passed += b.toString().split("\n").filter(Boolean).length; });
  for (let i = 1; i <= count && refused === null; i++) { t += stepMs; source.write(JSON.stringify({ jsonrpc: "2.0", id: i, method: "ping" }) + "\n"); await new Promise((r) => setImmediate(r)); }
  await new Promise((r) => setTimeout(r, 20));
  return { passed, refused };
}

test("5,000 frames spread over time pass; a flood of 1,025 inside one window is refused after 1,024", async () => {
  assert.deepEqual(await feed(5000, 100), { passed: 5000, refused: null });
  assert.deepEqual(await feed(1100, 1), { passed: 1024, refused: { reason: "INPUT_REFUSED", passed: 1024 } });
});

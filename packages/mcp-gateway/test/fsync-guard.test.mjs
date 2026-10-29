// Access is rechecked after the attempt is durably retained and before the upstream is entered (R6 builder guard).
// Retaining the attempt ends in an fsync; a revocation or an expiry that lands while that sync runs must not reach the
// upstream effect. The admitted attempt then stays OUTCOME_UNKNOWN (the Core cannot tell whether the adapter started),
// and a repeat reconciles without dispatching. Ported from Astra's R6 reproduction (verify-builder-guard.py and
// builder-guard-regression.mjs), which showed effect=true on the unguarded gateway.
//
// This file replaces node:fs functions for its own process (node --test runs each file in a separate process).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { syncBuiltinESMExports } from "node:module";
import { openHistoryStore } from "@ramex-labs/irontrellis";
import { setup } from "./fixtures.mjs";
import { createGateway } from "../dist/gateway.js";

/** Calls `onAttemptSynced` right after the fsync of an `*.attempt.json` file returns, while the attempt write is still in progress. */
function hookAttemptFsync(t, onAttemptSynced) {
  const realOpen = fs.openSync, realFsync = fs.fsyncSync, realClose = fs.closeSync, files = new Map();
  let synced = 0;
  fs.openSync = function (path, ...rest) { const fd = realOpen(path, ...rest); files.set(fd, String(path)); return fd; };
  fs.fsyncSync = function (fd) {
    const result = realFsync(fd);
    if (files.get(fd)?.endsWith(".attempt.json")) { synced += 1; onAttemptSynced(); }
    return result;
  };
  fs.closeSync = function (fd) { files.delete(fd); return realClose(fd); };
  syncBuiltinESMExports();
  t.after(() => { fs.openSync = realOpen; fs.fsyncSync = realFsync; fs.closeSync = realClose; syncBuiltinESMExports(); });
  return { synced: () => synced };
}

async function fixture(t, options) {
  const root = fs.mkdtempSync(join(tmpdir(), "irontrellis-gateway-fsync-guard-")), dir = join(root, "case"), f = await setup(dir, options), gateways = [];
  t.after(async () => { for (const g of gateways) await g.close(); fs.rmSync(root, { recursive: true, force: true, maxRetries: 10 }); });
  return {
    ...f, dir,
    count: (kind) => (fs.existsSync(join(dir, kind + ".calls.jsonl")) ? fs.readFileSync(join(dir, kind + ".calls.jsonl"), "utf8").trim().split("\n").length : 0),
    state: () => openHistoryStore(f.config.historyFile).state(),
    async open() { const g = await createGateway({ ...f.config, local: f.local, connectorSigner: f.connectorSigner }); gateways.push(g); return g; },
  };
}
const notCurrent = () => Object.assign(new Error("ACCESS_NOT_CURRENT"), { code: "ACCESS_NOT_CURRENT" });
const title = { title: "Do not dispatch after a revocation during the attempt sync" };

test("exactly-once job: a revocation landing during the attempt fsync does not reach the upstream; the admitted attempt stays OUTCOME_UNKNOWN and a repeat does not dispatch", async (t) => {
  const f = await fixture(t);
  const g = await f.open();
  let revoked = false;
  const hook = hookAttemptFsync(t, () => { revoked = true; });
  const access = { assertCurrent() { if (revoked) throw notCurrent(); } };
  const result = await g.run("create_incident_ticket", title, access);
  assert.equal(hook.synced(), 1, "the revocation landed during the attempt's storage sync");
  assert.equal(f.count("tickets"), 0, "no upstream effect");
  assert.equal(result.status, "OUTCOME_UNKNOWN");
  assert.equal(result.canonicalDisposition, "OUTCOME_UNKNOWN");
  assert.equal(result.upstreamResult, undefined);
  // The admission and the attempt are durable; nothing was consumed.
  const state = f.state();
  assert.equal(state.intentAdmissions.has(result.operationId), true);
  assert.equal(state.intentConsumptions.has(result.operationId), false);
  // Even with access current again, recovery reconciles and never redispatches.
  revoked = false;
  const again = await g.run("create_incident_ticket", title, { assertCurrent() {} });
  assert.equal(again.status, "OUTCOME_UNKNOWN");
  assert.equal(g.status("create_incident_ticket").dispatchPerformed, false);
  assert.equal(f.count("tickets"), 0);
});

test("recorded per-call tool: an access expiry passing during the attempt fsync does not reach the upstream; the call is OUTCOME_UNKNOWN", async (t) => {
  const f = await fixture(t, { mode: "per-call", recordCalls: true });
  const g = await f.open();
  let expiresAt = Date.now() + 3_600_000;
  const hook = hookAttemptFsync(t, () => { expiresAt = Date.now(); });
  const result = await g.run("create_incident_ticket", { title: "expiry during the attempt sync" }, { assertCurrent() { if (Date.now() >= expiresAt) throw notCurrent(); } });
  assert.equal(hook.synced(), 1);
  assert.equal(f.count("tickets"), 0, "no upstream effect");
  assert.equal(result.status, "OUTCOME_UNKNOWN");
  assert.equal(result.recorded, true);
  assert.equal(f.state().intentConsumptions.has(result.operationId), false);
});

test("control: with access current through the attempt fsync, the same hook lets the job reach the upstream once", async (t) => {
  const f = await fixture(t);
  const g = await f.open();
  const hook = hookAttemptFsync(t, () => {});
  const result = await g.run("create_incident_ticket", title, { assertCurrent() {} });
  assert.equal(hook.synced(), 1);
  assert.equal(result.status, "RESPONSE_RETAINED");
  assert.equal(f.count("tickets"), 1);
});

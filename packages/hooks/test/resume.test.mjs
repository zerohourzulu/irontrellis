/**
 * BUILD §6: the hook's PreToolUse check on a format-2 history never replays the history in full while a valid snapshot
 * exists — the owner handle resumes from it (SPEC §7.5: the root is still recomputed from the snapshot's records and the
 * tail replayed with full validation), and nothing else on the path replays (the format and domain come from line 0,
 * the session check from the replayed state). Asserted with the store's replay counters.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLocalDomain, createLocalOwner, keyPairFromPrivateKey, openLocalRuntime, signHashWith, storeCounters, resetStoreCountersForTests } from "@ramex-labs/irontrellis";
import { readFileSync } from "node:fs";
import { admitSession, decideTool, openOwner, sessionKeyFile, sessionStatus, validateConfig } from "../dist/index.js";

test("PreToolUse on a format-2 history resumes from the snapshot: no full replay (replay-call counter), the decision unchanged", async () => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-hook-resume-"));
  try {
    let clock = 1_000_000, n = 0;
    const now = () => (clock += 1);
    const history = join(dir, "history.jsonl"), domain = createLocalDomain();
    const owner = await createLocalOwner({ historyFile: history, domain, owner: "ops", controller: "operator", now, ids: () => `e:${(n += 1)}`, witness: false });
    await owner.createAgent({ id: "bot" });
    await owner.createRole({ id: "worker" });
    await owner.appoint({ agent: "bot", role: "worker", tenure: "t:1", number: 1 });
    await owner.grant({ id: "g", to: "bot", actions: ["write"], resources: ["doc:1"], expiresAt: 1e13 });
    for (let i = 0; i < 300; i += 1) await owner.grant({ id: `g:${i}`, to: "bot", actions: ["read"], resources: [`doc:${i}`], expiresAt: 1e13 });
    const config = validateConfig({
      history, owner: "ops", controller: "operator", domain, agentId: "bot", roleId: "worker", protocol: "claude-code", sessionTtlMs: 86_400_000,
      decisions: { onAllow: "allow", onReadOnly: "defer" }, policy: { sideEffecting: [{ tool: "Write", action: "write", resource: "doc:1" }], readOnly: ["Read"], unmapped: "ask" },
    }, join(dir, "irontrellis-hook.json"));
    const host = "host-1";
    assert.equal((await admitSession(openOwner(config, now), config, host, clock)).admitted, true);
    const event = { kind: "tool", sessionId: host, cwd: dir, toolName: "Write", toolInput: { file_path: join(dir, "x"), content: "x" }, toolUseId: "t", canAsk: true, mcpServer: undefined, deferTo: undefined };
    const check = () => {
      const handle = openOwner(config, now);
      const decision = decideTool(handle, config, event, clock);
      handle.close();
      return decision;
    };
    // Settle: the first open after the writes may still find the snapshot behind and rebuild it.
    assert.equal(check().verdict, "allow");

    resetStoreCountersForTests();
    for (let i = 0; i < 5; i += 1) assert.equal(check().verdict, "allow");
    assert.equal(storeCounters.fullReplays, 0, "no full replay while the snapshot is valid");
    assert.equal(storeCounters.resumes, 5);
    assert.equal(storeCounters.rootRecomputations, 5, "the §7.5 root recomputation is never skipped");

    // Runtime-signed events after the owner-signed root (no owner attestation of them): still a resume, the tail replayed.
    const key = JSON.parse(readFileSync(sessionKeyFile(config, host), "utf8"));
    const runtime = openLocalRuntime({ historyFile: history, domain, owner: "ops", controller: "operator", now, ids: () => `r:${(n += 1)}`, witness: false, session: key.sessionId, signHash: signHashWith(keyPairFromPrivateKey(key.scheme, key.keyId, key.privateKey)) });
    for (let i = 0; i < 20; i += 1) await runtime.recordRefusal({ refusalId: `refusal:${i}`, request: { actorId: "bot", action: "delete", resource: `doc:${i}`, claimedAt: clock } });
    assert.equal(check().verdict, "allow");
    resetStoreCountersForTests();
    for (let i = 0; i < 3; i += 1) assert.equal(check().verdict, "allow");
    assert.deepEqual({ fullReplays: storeCounters.fullReplays, resumes: storeCounters.resumes }, { fullReplays: 0, resumes: 3 });

    // The counter does count: without the snapshot the check replays in full once, then the rebuilt snapshot is used again.
    for (const file of [`${history}.state`, `${history}.state.journal`]) { try { unlinkSync(file); } catch { /* absent */ } }
    resetStoreCountersForTests();
    assert.equal(check().verdict, "allow");
    assert.equal(storeCounters.fullReplays, 1);
    assert.equal(check().verdict, "allow");
    assert.equal(storeCounters.fullReplays, 1);
    assert.equal(storeCounters.resumes, 1);

    // The session check reads the replayed state: fenced by a newer epoch (the decision is a DENY with the same code as before).
    const handle = openOwner(config, now);
    assert.deepEqual(sessionStatus(handle, config, host, clock), { ok: true, sessionId: key.sessionId });
    await handle.advanceEpoch({ agent: "bot", from: 1, to: 2 });
    const fenced = sessionStatus(openOwner(config, now), config, host, clock);
    assert.equal(fenced.ok, false);
    assert.equal(fenced.code, "SESSION_FENCED");
    assert.match(fenced.reason, /\(epoch 1\) was fenced by a newer session of bot/);
    assert.equal(sessionStatus(openOwner(config, now), config, "unknown-host", clock).code, "SESSION_NOT_FOUND");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

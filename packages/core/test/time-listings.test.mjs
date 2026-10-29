// A-180.1 (A-22.5): the two file-only time listings `verify` renders (A-196: one Core function, `timeListings`): every ◇ or ▲
// event outside a migrated prefix that advanced history time by more than TIME_LISTING_SKEW_MS = 300,000 ms over the event before
// it ("session time advance"), and every ◆ event dated at its non-control predecessor's time ("owner event at head time").
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, commitTerms, replay, timeListings, TIME_LISTING_SKEW_MS } = core;
const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");

test("A-180.1: TIME_LISTING_SKEW_MS is the fixed 300,000 ms; a session advance past it and a clamped owner event are listed and rendered by verify", async (t) => {
  assert.equal(TIME_LISTING_SKEW_MS, 300_000);
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-listings-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 1000;
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, witness: false };
  const owner = await createLocalOwner(config);
  await owner.createAgent({ id: "bea" });
  await owner.createRole({ id: "reviewer" });
  await owner.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1 });
  const pair = generateKeyPair("ed25519", "key:1");
  await owner.admitRuntime({ session: "session:1", agent: "bea", epoch: 1, key: "key:1", credential: pair.credential, expiresAt: 10_000_000 });
  await owner.grant({ id: "read", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 10_000_000 });
  const sim = core.openLocalSimulation({ ...config, session: "session:1", signHash: signHashWith(pair) });
  const op = (id) => ({ id, intentId: id, action: "read", resource: "incident:42", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ subject: id }) });
  tick = 1000 + TIME_LISTING_SKEW_MS; // exactly the skew: not listed
  await sim.run(op("op:1"));
  const quiet = timeListings(replay(owner.exportHistory()).state);
  assert.deepEqual(quiet.sessionTimeAdvances, []);
  tick = 1000 + 2 * TIME_LISTING_SKEW_MS + 1; // one ms more than the skew over the previous event
  await sim.run(op("op:2"));
  tick = 5; // the owner's clock is behind: the power-reducing fence is written at the head's time (A-22.3)
  await owner.advanceEpoch({ agent: "bea", from: 1, to: 2 });
  const events = owner.exportHistory(), state = replay(events).state;
  const listings = timeListings(state);
  const first = events.findIndex((e) => e.timestamp === 1000 + 2 * TIME_LISTING_SKEW_MS + 1);
  assert.deepEqual(listings.sessionTimeAdvances, [{ position: first, type: events[first].type, sessionId: "session:1", advanceMs: TIME_LISTING_SKEW_MS + 1 }]);
  assert.deepEqual(listings.ownerEventsAtHeadTime, [{ position: events.length - 1, type: "CONTROL_EPOCH_ADVANCED" }]);
  const notes = owner.verify().notes;
  assert.ok(notes.some((n) => n.startsWith(`SESSION_TIME_ADVANCE: position ${first} `) && n.includes("session:1")), notes.join("\n"));
  assert.ok(notes.some((n) => n.startsWith(`OWNER_EVENT_AT_HEAD_TIME: position ${events.length - 1} `)), notes.join("\n"));
  // Owner events right after the genesis at its time are not listed (the genesis is not a session event).
  assert.equal(listings.ownerEventsAtHeadTime.some((o) => o.position === 1), false);
});

test("A-180.1: events inside a migrated prefix are not listed (¬inPrefix)", () => {
  const prefixEnd = 3;
  const events = [
    { id: "g", type: "DEPLOYMENT_INITIALIZED", timestamp: 0, data: { migratedFrom: { position: prefixEnd } } },
    { id: "a", type: "PRINCIPAL_CREATED", timestamp: 0, data: {} },
    { id: "b", type: "TRANSACTION_INTENT_DECLARED", timestamp: 10 * TIME_LISTING_SKEW_MS, data: { declarationAuthorization: { runtimeSessionId: "s" } } },
    { id: "c", type: "TRANSACTION_INTENT_DECLARED", timestamp: 20 * TIME_LISTING_SKEW_MS, data: { declarationAuthorization: { runtimeSessionId: "s" } } },
    { id: "d", type: "TRANSACTION_INTENT_DECLARED", timestamp: 30 * TIME_LISTING_SKEW_MS, data: { declarationAuthorization: { runtimeSessionId: "s" } } },
  ];
  const listings = timeListings({ events, genesis: events[0].data });
  assert.deepEqual(listings.sessionTimeAdvances.map((a) => a.position), [4], "positions 2 and 3 are prefix events");
  assert.equal(listings.sessionTimeAdvances[0].sessionId, "s");
});

// Post-E5: tests for the G4 and G5 rulings that touch the engine (ADDENDA-G4 A-78…A-85, ADDENDA-G5 A-88, A-89.2).
// Type 42 (A-71 with A-86, A-87, A-89, A-90) has its own file, format2-observation.test.mjs.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling

const core = await import("../src/index.ts");
const { createLocalDomain, createLocalOwner, openLocalSimulation, commitTerms, replay } = core;
const { generateKeyPair, keyPairFromPrivateKey, signHashWith } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const { migrateHistory } = await import("../src/migrate.ts");
const { openHistoryStore } = await import("../src/store.ts");
const E = await import("../src/crypto/ed25519-point.ts");
const { RecordChain } = await import("../src/hash.ts");

const ROOT = join(import.meta.dirname, "..", "..", "..");
const ARCHITECT = JSON.parse(readFileSync(join(ROOT, "conformance", "v2-g3", "histories", "budget-v2.json"), "utf8"));
const seed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const ARCHITECT_OWNER = signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:1", seed(0x1001)));
const MIGRATION_ID = `0x${"4d".repeat(32)}`;
const migrationOwner = () => signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:1", `0x${"7e".repeat(32)}`));
const SOURCE_OWNER = keyPairFromPrivateKey("ed25519", "owner:src", `0x${"5a".repeat(32)}`);
const clone = (value) => JSON.parse(JSON.stringify(value));
const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const SMALL_ORDER_KEY = hex(E.ed25519PointOps.identity());

const rejectsAt = (events, position, expected) => {
  const r = replay(events);
  assert.equal(r.status, "REJECTED", `expected ${expected} at ${position}`);
  assert.equal(r.code, expected, r.reason);
  assert.equal(r.position, position, r.reason);
  return r;
};

/** Re-signs every format-2 control event's `/2` authorization from `from` on, over the record chain as it now stands (SPEC §4.3). */
const resignControl = async (events, signer, from = 1) => {
  const out = clone(events);
  const chain = new RecordChain();
  for (let p = 0; p < out.length; p += 1) {
    if (p >= from && core.CONTROL_EVENT_TYPES.has(out[p].type)) {
      out[p] = clone(await core.signControlEvent(signer, out[p], out[0].data.domain, { hash: chain.head, position: p - 1, canonicalTime: out[p - 1].timestamp }, "sha256"));
    }
    chain.head = chain.push(out[p]);
  }
  return out;
};

/** A pinned format-1 source written by the owner API under SOURCE_OWNER: a session, a grant, a run and an owner write at the head. */
async function formatOneSource(t, { sessionCredential } = {}) {
  const sessionKey = generateKeyPair("ed25519", "key:a");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g4-f1-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100, n = 0;
  const config = { historyFile: join(dir, "f1.jsonl"), domain: createLocalDomain({ format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true }), owner: "operations", controller: "operator", now: () => tick, format: "irontrellis-event/1", [FORMAT1_TEST_TOOLING]: true, nextKey: false, signer: signerFromKeyPair(SOURCE_OWNER), ids: () => `e:${(n += 1)}`, witness: false };
  const c = await createLocalOwner(config);
  await c.createAgent({ id: "a" });
  await c.createRole({ id: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1 });
  await c.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", credential: sessionCredential ?? sessionKey.credential, expiresAt: 100_000 });
  await c.grant({ id: "pay", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 100_000 });
  const sim = openLocalSimulation({ ...config, session: "s:a", signHash: signHashWith(sessionKey) });
  if (sessionCredential === undefined) {
    tick = 102;
    await sim.run({ id: "op:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ n: 1 }) });
  }
  tick = 104; await c.createRole({ id: "auditor" });
  c.close();
  return { dir, source: config.historyFile, domain: config.domain };
}
async function migratedEvents(t) {
  const f = await formatOneSource(t);
  const target = join(f.dir, "f2.jsonl");
  await migrateHistory({ source: f.source, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID });
  const events = openHistoryStore(target).state().events.map((e) => clone(e));
  const sourceHeads = openHistoryStore(f.source, { allowUnpinned: true }).state().eventHistoryHashes;
  return { ...f, events, sourceHeads };
}

// ---------------------------------------------------------------- A-78

test("A-78.1: inside a migrated prefix types 26–28 and 32–40 are EVENT_DATA_INVALID at the schema stage (both source formats); 29–31 too in a format-1 prefix, while a legacy prefix reads them (A-28)", async (t) => {
  const { events } = await migratedEvents(t);
  const until = events[0].data.migratedFrom.position;
  const control = events.findIndex((e, p) => p > 0 && core.CONTROL_EVENT_TYPES.has(e.type));
  assert.ok(control > 0 && control <= until);
  const forbidden = [...core.EVENT_TYPES.slice(26, 29), ...core.EVENT_TYPES.slice(29, 32), ...core.EVENT_TYPES.slice(32)];
  assert.equal(forbidden.length, core.EVENT_TYPES.length - 26);
  for (const type of forbidden) {
    const forged = clone(events);
    forged[control] = { ...forged[control], type };
    const r = rejectsAt(forged, control, "EVENT_DATA_INVALID");
    assert.match(r.reason, /cannot occur inside a migrated prefix/, type);
  }
  // At the validator: the same types after the prefix are a schema question of their own; in a legacy prefix 29–31 are read.
  // (A format-1 prefix control event also needs its source authorization, A-52.1, which would otherwise answer first.)
  const planted = (type, f1 = false) => ({ id: `planted:${type}`, type, timestamp: 1, data: f1 && core.CONTROL_EVENT_TYPES.has(type) ? { sourceControlAuthorization: { keyId: "k", signature: `0x${"11".repeat(64)}` } } : {} });
  for (const type of core.EVENT_TYPES.slice(26)) {
    const inF1 = core.validateEvent(planted(type, true), core.TRELLIS2_FORMAT, 3, { shadow: core.TRELLIS_FORMAT, migratedUntil: 5 });
    assert.equal(inF1.code, "EVENT_DATA_INVALID", type);
    assert.match(inF1.reason, /inside a migrated prefix/, type);
    const after = core.validateEvent(planted(type), core.TRELLIS2_FORMAT, 6, { migratedUntil: 5 });
    assert.doesNotMatch(after.reason, /inside a migrated prefix/, `${type} after the prefix`);
    const inLegacy = core.validateEvent(planted(type), core.TRELLIS2_FORMAT, 3, { shadow: core.LEGACY_FORMAT, migratedUntil: 5 });
    if (core.DUTY_POLICY_EVENT_TYPES.has(type)) assert.doesNotMatch(inLegacy.reason, /inside a migrated prefix/, `${type} in a legacy prefix is read as the oracle reads it`);
    else assert.match(inLegacy.reason, /inside a migrated prefix/, `${type} in a legacy prefix`);
  }
});

// ---------------------------------------------------------------- A-79 (and A-90.4)

test("A-79.1: migrate refuses at plan time a source with a key failing the §3.3 declaration test (MIGRATION_UNSUPPORTED {reason: SOURCE_KEY_INVALID}, nothing written); the source stays readable and verify reports the key", async (t) => {
  const f = await formatOneSource(t, { sessionCredential: SMALL_ORDER_KEY });
  const target = join(f.dir, "f2.jsonl");
  await assert.rejects(migrateHistory({ source: f.source, target, now: () => 5000, signer: migrationOwner(), nextKey: false, migrationId: MIGRATION_ID, acceptUnpinnedSource: true }),
    (e) => e.code === "MIGRATION_UNSUPPORTED" && e.detail.reason === "SOURCE_KEY_INVALID" && e.detail.role === "session" && e.detail.id === "s:a" && e.detail.check === "SMALL_ORDER");
  assert.equal(readdirSync(f.dir).some((name) => name.startsWith("f2")), false, "nothing written");
  const store = openHistoryStore(f.source, { allowUnpinned: true });
  assert.equal(store.state().format, core.TRELLIS_FORMAT);
  assert.ok(store.verify().notes.some((note) => /^KEY_CHECK: session s:a/.test(note)));
});

test("A-79.1 / A-79.2: on replay a prefix session key failing the test is EVENT_DATA_INVALID, checked after control authorization (source and /2) — the dual fault is CONTROL_AUTHORIZATION_INVALID", async (t) => {
  const { events, domain, sourceHeads } = await migratedEvents(t);
  const p = events.findIndex((e) => e.type === "RUNTIME_SESSION_ADMITTED");
  assert.ok(p > 0 && p <= events[0].data.migratedFrom.position);
  const forged = clone(events);
  forged[p].data.credentialPublicKey = SMALL_ORDER_KEY;
  // Unsigned change: the /2 control authorization fails first.
  rejectsAt(forged, p, "CONTROL_AUTHORIZATION_INVALID");
  // Re-signed under the new key only: the source's /1 authorization (verified in the shadow) still fails first.
  const resigned = await resignControl(forged, migrationOwner(), p);
  rejectsAt(resigned, p, "CONTROL_AUTHORIZATION_INVALID");
  // Both authorizations valid: the key test decides, at the session's position (before the prefix hash check at its end).
  const { sourceControlAuthorization: _s, controlAuthorization: _c, ...effect } = forged[p].data;
  const source = await core.signControlEvent(signerFromKeyPair(SOURCE_OWNER), { ...forged[p], data: effect }, domain, { hash: sourceHeads[p - 1], position: p - 1, canonicalTime: 0 }, "sha256");
  forged[p].data.sourceControlAuthorization = source.data.controlAuthorization;
  const r = rejectsAt(await resignControl(forged, migrationOwner(), p), p, "EVENT_DATA_INVALID");
  assert.match(r.reason, /credentialPublicKey: is not a usable Ed25519 key \(SMALL_ORDER/);
});

test("A-79.2 / A-90.4: a native session key (8) and a rotated owner key (26) are tested after control authorization; the genesis owner keys and counterparty keys (36) at the schema stage", async () => {
  const p = ARCHITECT.findIndex((e) => e.type === "RUNTIME_SESSION_ADMITTED");
  const events = clone(ARCHITECT.slice(0, p + 1));
  events[p].data.credentialPublicKey = SMALL_ORDER_KEY;
  rejectsAt(events, p, "CONTROL_AUTHORIZATION_INVALID");
  const signed = await resignControl(events, ARCHITECT_OWNER, p);
  assert.match(rejectsAt(signed, p, "EVENT_DATA_INVALID").reason, /credentialPublicKey/);
  // A rotation to a small-order key, signed by the genesis key: EVENT_DATA_INVALID after its signature verifies; unsigned → CONTROL_AUTHORIZATION_INVALID.
  const rotation = { id: "rotate:bad", type: "OWNER_KEYS_ROTATED", timestamp: ARCHITECT[p].timestamp, data: { ownerKeys: [{ keyId: "owner:9", scheme: "ed25519", credential: SMALL_ORDER_KEY }] } };
  const base = ARCHITECT.slice(0, p + 1);
  const unsigned = [...clone(base), { ...rotation, data: { ...rotation.data, controlAuthorization: { keyId: "owner:1", signature: `0x${"11".repeat(64)}` } } }];
  rejectsAt(unsigned, p + 1, "CONTROL_AUTHORIZATION_INVALID");
  const rotated = await resignControl(unsigned, ARCHITECT_OWNER, p + 1);
  assert.match(rejectsAt(rotated, p + 1, "EVENT_DATA_INVALID").reason, /ownerKeys\[0\]\.credential/);
  // Schema stage: a genesis owner key and a counterparty key (unsigned edits still answer EVENT_DATA_INVALID).
  const genesis = clone(ARCHITECT.slice(0, 1));
  genesis[0].data.ownerKeys = [{ ...genesis[0].data.ownerKeys[0], credential: SMALL_ORDER_KEY }];
  rejectsAt(genesis, 0, "EVENT_DATA_INVALID");
  const c = ARCHITECT.findIndex((e) => e.type === "COUNTERPARTY_REGISTERED");
  const counterparty = clone(ARCHITECT.slice(0, c + 1));
  counterparty[c].data.keys[0].credential = SMALL_ORDER_KEY;
  rejectsAt(counterparty, c, "EVENT_DATA_INVALID");
});

// ---------------------------------------------------------------- A-80

test("A-80: the /1 source attestation — object as written (domain optional, equal to the source domain), head = migratedFrom's; canonicalTime is checked after the prefix replay, EVENT_DATA_INVALID at migratedFrom.position", async (t) => {
  const { events, domain } = await migratedEvents(t);
  const migrated = events[0].data.migratedFrom;
  const until = migrated.position;
  assert.equal(migrated.sourceAttestation.head.canonicalTime, events[until].timestamp, "rc.1-final: the head event's timestamp");
  assert.equal("domain" in migrated.sourceAttestation, false, "the rc.1-final writer omits domain");
  const withGenesis = async (mutate) => {
    const forged = clone(events);
    forged[0].data.migratedFrom.sourceAttestation = await mutate(forged[0].data.migratedFrom.sourceAttestation);
    return resignControl(forged, migrationOwner());
  };
  const reattest = (head) => core.attestHead(signerFromKeyPair(SOURCE_OWNER), domain, head, "sha256");
  // A well-signed attestation of the right hash and position but another time: refused once the prefix is replayed.
  const late = await withGenesis(async (a) => clone(await reattest({ ...a.head, canonicalTime: a.head.canonicalTime + 1 })));
  assert.match(rejectsAt(late, until, "EVENT_DATA_INVALID").reason, /canonicalTime/);
  // `domain` present and equal: accepted; present and different, an unknown key, a /2 version: EVENT_DATA_INVALID at 0.
  assert.equal(replay(await withGenesis((a) => ({ ...a, domain }))).status, "ACCEPTED");
  for (const mutate of [(a) => ({ ...a, domain: { ...domain, deploymentId: "elsewhere" } }), (a) => ({ ...a, extra: true }), (a) => ({ ...a, head: { ...a.head, extra: 1 } }), (a) => ({ ...a, version: "irontrellis-head-attestation/2" })]) {
    rejectsAt(await withGenesis(mutate), 0, "EVENT_DATA_INVALID");
  }
});

// ---------------------------------------------------------------- A-72 / A-88

const S = (state) => { const c = core.capacityOf(state); return c.eventCount + c.lifecycleReserved + c.dutyReserved; };
/** The ▲ event `transition` as the next event of `state`, signed by `signHash` (no writer pre-check, no dry run). */
const signedAdministrative = async (state, sessionId, signHash, transition) => {
  const prepared = core.prepareAdministrativeEventState(state, { expectedDomain: state.genesis.domain, expectedHistoryHead: state.head, transition, runtimeSessionId: sessionId });
  const runtimeSignature = await signHash(prepared.signingHash);
  return clone({ ...transition, data: { ...transition.data, administrativeAuthorization: { challenge: prepared.challenge, authorityProof: prepared.authorityProof, runtimeSignature } } });
};

/** A format-2 obligation case (format2-migrate's, natively): a run with a receipt, then `obligate` — under `maxEvents`. */
async function obligationCase(t, maxEvents) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g4-a88-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => tick, nextKey: false, witness: false, ...(maxEvents === undefined ? {} : { maxEvents }) };
  const c = await createLocalOwner(config);
  const pair = keyPairFromPrivateKey("ed25519", "k:a", `0x${"3c".repeat(32)}`);
  for (const id of ["a", "b"]) await c.createAgent({ id });
  await c.createRole({ id: "reviewer" });
  await c.declareSuccession({ id: "handover", from: "a", to: "b", role: "reviewer" });
  await c.appoint({ agent: "a", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
  await c.admitRuntime({ session: "s:a", agent: "a", epoch: 1, key: "k:a", credential: pair.credential, expiresAt: 1000 });
  await c.grant({ id: "quant", to: "a", actions: ["pay"], resources: ["vendor"], expiresAt: 900 });
  await c.grant({ id: "collect", to: "a", actions: ["OBLIGATE"], resources: ["vendor"], expiresAt: 900 });
  await c.grant({ id: "review", to: "b", actions: ["record-collection-disposition"], resources: ["duty:42", "duty:43"], expiresAt: 900 });
  const a = { ...config, session: "s:a", signHash: signHashWith(pair) };
  const op = { id: "op:1", action: "pay", resource: "vendor", role: "reviewer", tenure: "shift:1", termsCommitment: commitTerms({ invoice: 1 }) };
  const sim = openLocalSimulation(a);
  tick = 102; await sim.run(op);
  tick = 103; await sim.recordReceipt(op);
  tick = 104;
  const before = replay(c.exportHistory()).state;
  const { openLocalRuntime } = await import("../src/runtime.ts");
  await openLocalRuntime(a).obligate({ id: "duty:42", operation: op.id, description: "Review.", deadline: 800, succession: "handover", reviewAuthority: "review" });
  return { owner: c, a, before, events: c.exportHistory() };
}

test("A-72 / A-88: at maxEvents the first OBLIGATION_CREATED (17) and ATTEMPT_DUTY_ASSIGNED (23) of a source intent spend its reservation; a repeat 17 or ATTEMPT_DUTY_CREATED (22) is TRANSITION_INVALID and never reaches capacity; only a repeat 23 is growth (CAPACITY_CONTROL_ONLY)", async (t) => {
  // 17: the cap is S before the first obligation; it is admitted there (ΔS = 0).
  const free = await obligationCase(t);
  const capped = await obligationCase(t, S(free.before));
  const obligated = replay(capped.events).state;
  assert.equal(capped.events.at(-1).type, "OBLIGATION_CREATED");
  assert.equal(S(obligated), obligated.genesis.capacity.maxEvents, "the first 17 for the intent: ΔS = 0, admitted at S(p) = M");
  const { administrativeAuthorization: _a, ...first17 } = clone(capped.events.at(-1).data);
  const repeat17 = await signedAdministrative(obligated, "s:a", capped.a.signHash, { id: "obligation:repeat", type: "OBLIGATION_CREATED", timestamp: capped.events.at(-1).timestamp, data: { ...first17, record: { ...first17.record, obligationId: "duty:43" } } });
  assert.match(rejectsAt([...capped.events, repeat17], capped.events.length, "TRANSITION_INVALID").reason, /obligation/i);
  await assert.rejects(core.openLocalRuntime(capped.a).obligate({ id: "duty:43", operation: "op:1", description: "Review.", deadline: 800, succession: "handover", reviewAuthority: "review" }), (e) => e.code !== "CAPACITY_CONTROL_ONLY");

  // 22 and 23 (the E5 duty fixture; its duty "duty" over the job "job" is the last event): the cap is S after the first 22.
  // (Not growth means admitted even with S(p) > M; growth there is refused.)
  const { fixture, SECOND_KEY, signHashSecond } = await import("./helpers/duty-fixture.mjs");
  const plain = await fixture(t);
  const d = await fixture(t, { maxEvents: S(plain.state()) });
  // The role moves by REASSIGNMENT (owner-signed, admitted at the cap like every control event), so the duty can be assigned.
  await d.owner.admitRuntime({ agent: "replacement", session: "replacement-session", epoch: 1, key: "replacement-key", address: SECOND_KEY.credential, scheme: "eip191-personal-sign-keccak256", expiresAt: 1000 });
  await d.owner.grant({ id: "assign-new", to: "replacement", actions: ["ASSIGN_ATTEMPT_DUTY"], resources: ["job"], expiresAt: 1000 });
  const ownerSigner = core.loadOwnerKeyFile(core.ownerKeyPathFor(d.config.historyFile));
  let events = d.events;
  const append = async (event) => { events = [...events, event]; const r = replay(events); assert.equal(r.status, "ACCEPTED", `${event.type}: ${r.code} ${r.reason}`); return r.state; };
  const transfer = async (id, from, fromTenure, to, toTenure, number) => clone(await core.signControlEvent(ownerSigner, { id, type: "ROLE_TRANSFERRED", timestamp: 200, data: { roleId: "role", fromAgentId: from, fromRoleTenureId: fromTenure, toAgentId: to, toRoleTenureId: toTenure, toTenureNumber: number, principalId: "owner", transferKind: "REASSIGNMENT" } }, events[0].data.domain, replay(events).head, "sha256"));
  const assign = (state, id, from, to, session, signHash) => signedAdministrative(state, session, signHash, { id, type: "ATTEMPT_DUTY_ASSIGNED", timestamp: 200, data: { dutyId: "duty", fromAgentId: from, toAgentId: to, actorId: to } });
  let state = await append(await transfer("to-replacement", "worker", "tenure", "replacement", "replacement-tenure", 2));
  const atCap = S(state);
  assert.ok(atCap > state.genesis.capacity.maxEvents, "the three control events went past the cap (never refused, A-1.3)");
  state = await append(await assign(state, "attempt-duty-assignment:to-replacement", "worker", "replacement", "replacement-session", signHashSecond));
  assert.equal(S(state), atCap, "the first 23 for the intent: ΔS = 0, admitted with S(p) > M");
  state = await append(await transfer("back-to-worker", "replacement", "replacement-tenure", "worker", "return-tenure", 3));
  // A repeat 23 is growth (ΔS = +1): CAPACITY_CONTROL_ONLY at the cap.
  const repeat23 = await assign(state, "attempt-duty-assignment:back-to-worker", "replacement", "worker", "session", d.setupOptions.signHash);
  rejectsAt([...events, repeat23], events.length, "CAPACITY_CONTROL_ONLY");
  // A repeat 22 for the same intent: TRANSITION_INVALID (the rc.1 precondition, before capacity), though ΔS would be +1.
  const created = events.find((e) => e.type === "ATTEMPT_DUTY_CREATED");
  const repeat22 = await signedAdministrative(state, "session", d.setupOptions.signHash, { id: "attempt-duty:duty2:create", type: "ATTEMPT_DUTY_CREATED", timestamp: 200, data: { actorId: "worker", record: { ...clone(created.data.record), dutyId: "duty2", creationRoleTenureId: "return-tenure" } } });
  assert.match(rejectsAt([...events, repeat22], events.length, "TRANSITION_INVALID").reason, /attempt duty cannot be created/);
  // The census (A-72.1): ΔS = 1 + ΔlifecycleReserved, so +1 for the repeat 23 and 0 for the first 17.
  const { reservationDelta } = await import("../src/capacity.ts");
  assert.equal(reservationDelta(state, repeat23), 0, "repeat 23: ΔlifecycleReserved = 0, so ΔS = 1");
  assert.equal(reservationDelta(replay(capped.events.slice(0, -1)).state, capped.events.at(-1)), -1, "first 17: ΔlifecycleReserved = −1, so ΔS = 0");
  // A-171.1 case (a): ATTEMPT_DUTY_CREATED is one of the 11 LIFECYCLE types (capacity.ts), so the first 22 for its source
  // intent spends that intent's reservation like the first 17 and 23.
  const at22 = events.indexOf(created);
  assert.equal(reservationDelta(replay(events.slice(0, at22)).state, created), -1, "first 22: ΔlifecycleReserved = −1, so ΔS = 0");
});

// ---------------------------------------------------------------- A-89.2

test("A-89.2: '≤ 128 chars' counts code points — a surrogate pair is one character — for API identifiers such as a refusal's request.resource (the CONNECTOR template), at 128 and 129", async (t) => {
  const { codePointLength } = core;
  const astral = "😀"; // U+1F600: two UTF-16 units, four UTF-8 bytes
  assert.equal(codePointLength("a".repeat(128)), 128);
  assert.equal(codePointLength(astral.repeat(128)), 128);
  assert.equal(astral.repeat(128).length, 256);
  assert.ok(codePointLength(astral.repeat(129), 128) > 128, "counting stops past the limit");
  assert.equal(codePointLength(`x${astral}y`), 3);
  assert.equal(codePointLength("\ud800x"), 2, "a lone surrogate counts as one (it is refused elsewhere)");
  const { identifier } = await import("../src/input.ts");
  // 100 ASCII + 28 astral: 128 code points, 156 UTF-16 units, 212 UTF-8 bytes (inside the event grammar's 256-byte Identifier).
  const at128 = `${"r".repeat(100)}${astral.repeat(28)}`, at129 = `r${at128}`;
  assert.equal(identifier(at128), at128);
  assert.throws(() => identifier(at129), (e) => e.code === "INVALID_INPUT");
  // End to end: a CONNECTOR refusal whose request.resource is the unrendered template (A-42) of 128 code points.
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-g4-a89-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = { historyFile: join(dir, "h.jsonl"), domain: createLocalDomain(), owner: "operations", controller: "operator", now: () => 100, nextKey: false, witness: false };
  const owner = await createLocalOwner(config);
  const pair = generateKeyPair("ed25519", "k:gw");
  await owner.createAgent({ id: "gateway" });
  await owner.admitRuntime({ session: "s:gw", agent: "gateway", epoch: 1, key: "k:gw", credential: pair.credential, expiresAt: 10_000 });
  const runtime = core.openLocalRuntime({ ...config, session: "s:gw", signHash: signHashWith(pair) });
  const connector = { connectorId: "gateway", refusalCode: "NO_AUTHORITY", detailDigest: `0x${"ab".repeat(32)}` };
  const recorded = await runtime.recordRefusal({ request: { actorId: "bea", action: "read", resource: at128, claimedAt: 100 }, connector });
  assert.equal(typeof recorded.eventId, "string");
  assert.equal(owner.exportHistory().at(-1).data.request.resource, at128);
  await assert.rejects(runtime.recordRefusal({ request: { actorId: "bea", action: "read", resource: at129, claimedAt: 100 }, connector }), (e) => e.code === "INVALID_INPUT");
  assert.equal(replay(owner.exportHistory()).status, "ACCEPTED");
});

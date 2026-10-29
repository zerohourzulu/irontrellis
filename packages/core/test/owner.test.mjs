import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { referenceCore as ref, referenceCore03, fixturePath } from "./reference.mjs";
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts"); // A-185.3 / A-194: older formats are test tooling
const { createLocalDomain, createLocalOwner, openLocalOwner, verifyHistory } = await import("../src/owner.ts");
const { observeHistory, ContinuityError, IronTrellisError } = await import("../src/local.ts");
const { openHistoryStore } = await import("../src/store.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT } = await import("../src/events.ts");

// ---------------------------------------------------------------- helpers
const q = { actor: "bea", action: "read", resource: "incident:42" };
const norm = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? { $bigint: x.toString() } : x)));
const same = (actual, expected) => assert.deepEqual(norm(actual), norm(expected));
const hasCode = (code) => (e) => e instanceof ContinuityError && e.code === code;
const rejects = (promise, code) => assert.rejects(promise, hasCode(code));
const LEGACY_DOMAIN = { protocol: "continuity", version: "0.2", deploymentId: "own-case", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000000" };
const TRELLIS_DOMAIN = { protocol: "irontrellis", version: "1", deploymentId: "own-case" };

/** A fresh owner with agents bea and alex; `format` selects the history format under test. */
async function setup(t, format = LEGACY_FORMAT) {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-owner-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let tick = 100;
  const config = { historyFile: join(dir, "history.jsonl"), owner: "operations", controller: "operator", now: () => tick, format, [FORMAT1_TEST_TOOLING]: true, domain: format === LEGACY_FORMAT ? LEGACY_DOMAIN : TRELLIS_DOMAIN };
  const c = await createLocalOwner(config);
  await c.createAgent({ id: "bea" });
  await c.createAgent({ id: "alex" });
  return { c, config, dir, now: (n) => (tick = n) };
}
const grant = (c, extra = {}) => c.grant({ id: "access", to: "bea", actions: ["read"], resources: ["incident:42"], expiresAt: 200, ...extra });
/** The reference engine's raw authorize input for the same question. */
function raw(c, action = q) {
  const events = c.exportHistory();
  return {
    operationVersion: ref.PORTABLE_AUTHORIZATION_VERSION, events, expectedHistoryHead: c.observe().head, domain: events[0].data.domain, policyVersion: events[0].data.policyVersion,
    rootRecognitionPolicy: ref.PORTABLE_ROOT_RECOGNITION_POLICY,
    request: { actorId: action.actor, action: action.action, resource: action.resource, claimedAt: 100, ...(Object.hasOwn(action, "amount") ? { amount: action.amount } : {}) },
    evaluationTime: 100, authoritative: true, consequential: false,
  };
}

// ---------------------------------------------------------------- ported Core 0.3 owner tests (both formats where the reference engine is not involved)
for (const format of [LEGACY_FORMAT, TRELLIS_FORMAT]) {
  const label = format === LEGACY_FORMAT ? "legacy" : "format 1";

  test(`${label}: fresh case grant/revoke and reopened history preserve withdrawal`, async (t) => {
    const { c, config } = await setup(t, format);
    assert.equal(c.format, format);
    assert.equal(c.authorize(q).decision, "DENY");
    await grant(c);
    assert.equal(c.authorize(q).decision, "ALLOW");
    assert.equal(c.authorize({ ...q, resource: "incident:43" }).decision, "DENY");
    assert.equal(c.authorize({ ...q, actor: "alex" }).decision, "DENY");
    await c.revoke("access");
    assert.equal(c.authorize(q).decision, "DENY");
    assert.equal(openLocalOwner(config).authorize(q).decision, "DENY");
    if (process.platform !== "win32") assert.equal(statSync(config.historyFile).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
    if (format === TRELLIS_FORMAT) {
      if (process.platform !== "win32") assert.equal(statSync(`${config.historyFile}.owner-key.json`).mode & 0o777, 0o600); // POSIX modes (Windows: ACLs, docs/PLATFORMS.md §3)
      assert.equal(c.exportHistory()[0].data.ownerKeys.length, 1);
      assert.equal(c.exportHistory().at(-1).data.controlAuthorization.keyId, c.exportHistory()[0].data.ownerKeys[0].keyId);
    }
  });

  test(`${label}: frozen observation stays historical while owner refreshes file and clock`, async (t) => {
    const { c, now } = await setup(t, format);
    await grant(c);
    const snapshot = c.observe();
    await c.revoke("access");
    assert.equal(snapshot.authorize(q).decision, "ALLOW");
    assert.equal(c.authorize(q).decision, "DENY");
    assert.equal(snapshot.authorize(q).executionCapability, false);
    assert.equal(snapshot.scope, "CAPTURED_HISTORY_ONLY");
    assert.notEqual(c.observe().head.hash, snapshot.head.hash);
    await grant(c, { id: "second" });
    now(201);
    assert.equal(c.authorize(q).decision, "DENY");
    // observe() defaults `at` to the host clock (DESIGN §6 deviation c); the head time is available explicitly.
    assert.equal(c.observe().authorize(q).decision, "DENY");
    assert.equal(c.observe({ at: c.observe().head.canonicalTime }).authorize(q).decision, "ALLOW");
    assert.equal(observeHistory(c.exportHistory()).authorize(q).decision, "ALLOW");
  });

  test(`${label}: alternate grants remain effective after one withdrawal; notBefore and expiry apply`, async (t) => {
    const { c, now } = await setup(t, format);
    await grant(c);
    await grant(c, { id: "other", notBefore: 101, expiresAt: 150 });
    await c.revoke("access");
    assert.equal(c.authorize(q).decision, "DENY");
    now(101);
    assert.equal(c.authorize(q).decision, "ALLOW");
    now(151);
    assert.equal(c.authorize(q).decision, "DENY");
  });

  test(`${label}: duplicate/malformed commands and mismatched identity/domain cannot append`, async (t) => {
    const { c, config } = await setup(t, format);
    await grant(c);
    const before = readFileSync(config.historyFile);
    await rejects(grant(c), "TRANSITION_REJECTED");
    await rejects(c.grant({ id: "evil", to: "alex", actions: ["read"], resources: ["incident:42"], expiresAt: 200, grantor: "other" }), "INVALID_INPUT");
    await rejects(c.revoke("missing"), "TRANSITION_REJECTED");
    assert.throws(() => openLocalOwner({ ...config, owner: "intruder" }), hasCode("PROFILE_MISMATCH"));
    assert.throws(() => openLocalOwner({ ...config, domain: { ...config.domain, deploymentId: "elsewhere" } }), hasCode("PROFILE_MISMATCH"));
    await rejects(createLocalOwner(config), "HISTORY_EXISTS");
    assert.deepEqual(readFileSync(config.historyFile), before);
  });

  test(`${label}: accessors and proxies are rejected without invoking user code`, async (t) => {
    const { c, config } = await setup(t, format);
    let invoked = 0;
    const before = readFileSync(config.historyFile);
    const malicious = { ...q };
    Object.defineProperty(malicious, "actor", { enumerable: true, get() { invoked++; return "bea"; } });
    assert.throws(() => c.authorize(malicious), hasCode("INVALID_INPUT"));
    await rejects(c.createAgent(new Proxy({ id: "danger" }, { ownKeys() { invoked++; return ["id"]; } })), "INVALID_INPUT");
    assert.equal(invoked, 0);
    assert.deepEqual(readFileSync(config.historyFile), before);
  });

  test(`${label}: captured history and returned evidence resist caller mutation`, async (t) => {
    const { c } = await setup(t, format);
    await grant(c);
    const events = structuredClone(c.exportHistory()), snapshot = observeHistory(events);
    events.length = 0;
    assert.equal(snapshot.authorize(q).decision, "ALLOW");
    assert.throws(() => { snapshot.head.hash = "0x00"; }, TypeError);
    assert.throws(() => { snapshot.authorize(q).evidence.decision = "DENY"; }, TypeError);
  });

  test(`${label}: quantities retain bigint zero/absence; malformed values and extra control flags fail`, async (t) => {
    const { c } = await setup(t, format);
    await grant(c);
    assert.equal(c.authorize(q).decision, "ALLOW");
    assert.ok(["ALLOW", "DENY"].includes(c.authorize({ ...q, amount: 0n }).decision));
    for (const amount of [0, "0", -1n, 1n << 256n, undefined]) assert.throws(() => c.authorize({ ...q, amount }), hasCode("INVALID_INPUT"));
    assert.throws(() => c.authorize({ ...q, consequential: true }), hasCode("INVALID_INPUT"));
  });

  test(`${label}: bad clocks and rejected setup do not silently produce writes`, async (t) => {
    const { c, config, now } = await setup(t, format);
    const before = readFileSync(config.historyFile);
    now(99);
    await rejects(grant(c), "CLOCK_INVALID");
    assert.deepEqual(readFileSync(config.historyFile), before);
    now(NaN);
    assert.throws(() => c.authorize(q), hasCode("CLOCK_INVALID"));
    const path = config.historyFile + "-invalid";
    const bad = format === LEGACY_FORMAT ? { ...config.domain, verifyingContract: "not-an-address" } : { ...config.domain, deploymentId: "\u0000" };
    await assert.rejects(createLocalOwner({ ...config, historyFile: path, now: () => 100, domain: bad }));
    assert.equal(existsSync(path), false);
  });

  test(`${label}: invalid histories and option shapes cannot become ALLOW`, async (t) => {
    const { c } = await setup(t, format);
    const events = structuredClone(c.exportHistory());
    events[1].data.principalId = "changed";
    assert.throws(() => observeHistory(events), hasCode("INVALID_HISTORY"));
    // HISTORY_LIMIT is gone (DESIGN §7): an empty history is simply invalid.
    assert.throws(() => observeHistory([]), hasCode("INVALID_HISTORY"));
    assert.throws(() => observeHistory(c.exportHistory(), { at: -0 }), hasCode("INVALID_INPUT"));
    assert.throws(() => c.observe({ expectHead: { ...c.observe().head, position: 99 } }), hasCode("HISTORY_CONFLICT"));
    assert.equal(c.observe({ expectHead: c.observe().head }).eventCount, c.exportHistory().length);
  });

  test(`${label}: another writer advancing the head during clock lookup prevents stale append`, async (t) => {
    const { config } = await setup(t, format);
    let competingWrite;
    const first = openLocalOwner({ ...config, now: () => { const f = competingWrite; competingWrite = undefined; f?.(); return 100; } });
    const second = openLocalOwner(config);
    competingWrite = () => { second.createAgent({ id: "concurrent" }).catch(() => {}); };
    await rejects(grant(first), "HISTORY_CONFLICT");
    assert.equal(first.authorize(q).decision, "DENY");
    assert.equal(first.exportHistory().filter((e) => e.type === "AGENT_CREATED" && e.data.agentId === "concurrent").length, 1);
    assert.equal(first.exportHistory().filter((e) => e.type === "AUTHORITY_GRANTED").length, 0);
  });

  test(`${label}: request shape bounds reject symbols, hidden fields, cycles and sparse lists`, async (t) => {
    const { c, config } = await setup(t, format);
    const before = readFileSync(config.historyFile);
    const hidden = { id: "new" };
    Object.defineProperty(hidden, "hidden", { value: true });
    const cycle = { id: "new" };
    cycle.extra = cycle;
    for (const input of [hidden, cycle, { id: "x".repeat(129) }, { id: "new", [Symbol("hidden")]: true }]) await rejects(c.createAgent(input), "INVALID_INPUT");
    const sparse = [];
    sparse.length = 1;
    await rejects(grant(c, { actions: sparse }), "INVALID_INPUT");
    await rejects(grant(c, { actions: ["read", "read"] }), "INVALID_INPUT");
    await rejects(c.createAgent({ id: "new", owner: undefined }), "INVALID_INPUT");
    const events = structuredClone(c.exportHistory());
    let calls = 0;
    Object.defineProperty(events[0].data, "domain", { enumerable: true, get() { calls++; throw Error("must not run"); } });
    assert.throws(() => observeHistory(events), hasCode("INVALID_HISTORY"));
    assert.equal(calls, 0);
    assert.deepEqual(readFileSync(config.historyFile), before);
  });

  test(`${label}: fresh local namespaces work without configuring a chain and cannot reopen a different domain`, async (t) => {
    const { config } = await setup(t, format);
    const first = createLocalDomain({ format }), second = createLocalDomain({ format });
    assert.notEqual(first.deploymentId, second.deploymentId);
    assert.equal(first.protocol, format === LEGACY_FORMAT ? "continuity" : "irontrellis");
    const selected = { ...config, historyFile: config.historyFile + "-local", domain: first };
    const owner = await createLocalOwner(selected);
    await owner.createAgent({ id: "bea" });
    await grant(owner);
    assert.equal(openLocalOwner(selected).authorize(q).decision, "ALLOW");
    assert.throws(() => openLocalOwner({ ...selected, domain: second }), hasCode("PROFILE_MISMATCH"));
  });

  test(`${label}: delegations, prohibitions, terminations and unappointments (DESIGN §6 additions)`, async (t) => {
    const { c, now } = await setup(t, format);
    await grant(c, { delegable: 1 });
    await c.delegate({ id: "sub", to: "alex", from: "bea", parent: "access", actions: ["read"], resources: ["incident:42"], expiresAt: 150 });
    assert.equal(c.authorize({ ...q, actor: "alex" }).decision, "ALLOW");
    const sub = c.exportHistory().at(-1).data.grant;
    assert.equal(sub.parentAuthorityId, "access");
    assert.equal(sub.rootAuthorityId, "access");
    assert.equal(sub.grantorId, "bea");
    await rejects(c.delegate({ id: "deep", to: "alex", from: "alex", parent: "sub", actions: ["read"], resources: ["incident:42"], expiresAt: 150 }), "TRANSITION_REJECTED");
    await rejects(c.prohibit({ id: "no-alex", actions: ["read"], resources: ["incident:42"], subject: "alex", root: "access" }), "TRANSITION_REJECTED");
    await c.prohibit({ id: "no-alex", actions: ["read"], resources: ["incident:42"], subject: "alex", root: "access", expiresAt: 200 });
    assert.equal(c.authorize({ ...q, actor: "alex" }).decision, "DENY");
    assert.equal(c.authorize({ ...q, actor: "alex" }).evidence.code, "PROHIBITED");
    assert.equal(c.authorize(q).decision, "ALLOW");
    await c.prohibit({ id: "freeze", actions: ["read"], resources: ["incident:42"], global: true, notBefore: 300 });
    assert.equal(c.exportHistory().at(-1).data.grant.grantorId, c.exportHistory()[0].data.globalPolicySourceId);
    assert.equal(c.authorize(q).decision, "ALLOW");
    now(300);
    assert.equal(c.authorize(q).decision, "DENY");
    now(100);
    await c.createRole({ id: "reviewer" });
    await c.declareSuccession({ id: "handover", from: "bea", to: "alex", role: "reviewer" });
    await c.appoint({ agent: "bea", role: "reviewer", tenure: "shift:1", number: 1, succession: "handover" });
    await rejects(c.unappoint({ agent: "alex", role: "reviewer", tenure: "shift:1" }), "TRANSITION_REJECTED");
    await c.unappoint({ agent: "bea", role: "reviewer", tenure: "shift:1" });
    await c.appoint({ agent: "bea", role: "reviewer", tenure: "shift:2", number: 2, succession: "handover" });
    const report = c.handover("bea");
    assert.deepEqual(report.tenures.map((x) => x.tenureId), ["shift:2"]);
    assert.deepEqual(report.liveGrants.map((x) => x.authorityId), ["access"]);
    assert.deepEqual(report.delegationsIssued.map((x) => x.authorityId), ["sub"]);
    assert.equal(report.terminated, false);
    assert.equal(report.survives.kind, "SURVIVES");
    await c.terminate({ agent: "bea", succession: "handover", role: "reviewer", tenure: "shift:2" });
    assert.equal(c.handover("bea").terminated, true);
    assert.equal(c.authorize(q).decision, "DENY");
    assert.equal(c.authorize(q).evidence.code, "AGENT_INACTIVE");
    assert.throws(() => c.handover("nobody"), hasCode("INVALID_INPUT"));
  });

  test(`${label}: verify reports the chain, the pinned head and no rollback`, async (t) => {
    const { c, config } = await setup(t, format);
    await grant(c);
    const report = c.verify();
    assert.equal(report.chain, "OK");
    assert.equal(report.rollback, false);
    assert.equal(report.pinnedHeadStatus, "MATCHES");
    assert.equal(report.head.position, c.observe().head.position);
    assert.equal(report.controlSignatures, format === LEGACY_FORMAT ? "NOT_APPLICABLE" : "VERIFIED");
    assert.deepEqual(verifyHistory(config.historyFile).head, report.head);
    assert.deepEqual(openHistoryStore(config.historyFile).verify().head, report.head);
  });

  test(`${label}: errors are IronTrellisError (ContinuityError alias) with code and mayHaveCommitted`, async (t) => {
    const { c } = await setup(t, format);
    try { await c.revoke("missing"); assert.fail("expected rejection"); } catch (error) {
      assert.ok(error instanceof IronTrellisError && error instanceof ContinuityError);
      assert.equal(error.name, "IronTrellisError");
      assert.equal(error.code, "TRANSITION_REJECTED");
      assert.equal(error.mayHaveCommitted, false);
    }
  });
}

// ---------------------------------------------------------------- reference-engine parity (legacy format only: the reference has no format 1)
test("legacy: appointment grants no permission; facade retains exact original decision and query evidence", async (t) => {
  const { c } = await setup(t);
  await c.createRole({ id: "investigator" });
  await c.appoint({ agent: "bea", role: "investigator", tenure: "shift1", number: 1 });
  assert.equal(c.authorize(q).decision, "DENY");
  await grant(c);
  const r = raw(c);
  same(c.authorize(q).evidence, ref.authorizePortable(r));
  for (const kind of ["why", "responsible"]) {
    same(c[kind](q), ref[`${kind}Portable`]({
      operationVersion: ref.PORTABLE_QUERY_VERSION, evaluationEvents: r.events, observedEvents: r.events, authorizationDomain: r.domain, request: r.request, evaluationTime: 100,
      disclosure: ref.portablePublicQueryDisclosure(kind.toUpperCase()),
    }));
  }
  same(c.survives("bea"), ref.survivesPortable({
    operationVersion: ref.PORTABLE_QUERY_VERSION, observedEvents: r.events, targetAgentId: "bea", evaluationTime: 100, disclosure: ref.portablePublicQueryDisclosure("SURVIVES"),
  }));
  same(c.authorize({ ...q, amount: 0n }).evidence, ref.authorizePortable(raw(c, { ...q, amount: 0n })));
});

test("legacy: the reference Core 0.3 SDK reopens a history written by the port and reads every event", async (t) => {
  const { c, config } = await setup(t);
  await grant(c);
  const legacy = await referenceCore03("local-owner.ts");
  const theirs = legacy.openLocalOwner({ ...config, format: undefined });
  same(theirs.exportHistory(), c.exportHistory());
  assert.equal(theirs.authorize(q).decision, "ALLOW");
  theirs.revoke("access");
  assert.equal(c.authorize(q).decision, "DENY");
  same(c.exportHistory(), theirs.exportHistory());
});

test("legacy: captured historical handover retains original SURVIVES and assignment evidence", () => {
  const path = fixturePath("handover-history.jsonl");
  const events = openHistoryStore(path).readAll(), observation = observeHistory(events);
  for (const agent of ["a:first-look", "b:first-look"]) {
    same(observation.survives(agent), ref.survivesPortable({
      operationVersion: ref.PORTABLE_QUERY_VERSION, observedEvents: events, targetAgentId: agent, evaluationTime: observation.evaluationTime, disclosure: ref.portablePublicQueryDisclosure("SURVIVES"),
    }));
  }
});

// ---------------------------------------------------------------- format 1 specifics
test("format 1: a caller-provided signer replaces the key file; a missing key makes control writes KEY_UNAVAILABLE", async (t) => {
  const { generateKeyPair } = await import("../src/crypto/suites.ts");
  const { signerFromKeyPair } = await import("../src/signer.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-owner-key-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const signer = signerFromKeyPair(generateKeyPair("ed25519", "kms:1"));
  // Format 1 by name: the owner API writes format 2 by default (SPEC §19); these tests cover the format-1 writer.
  const config = { historyFile: join(dir, "h.jsonl"), domain: TRELLIS_DOMAIN, owner: "operations", controller: "operator", now: () => 100, signer, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const c = await createLocalOwner(config);
  assert.equal(existsSync(`${config.historyFile}.owner-key.json`), false);
  assert.deepEqual(c.exportHistory()[0].data.ownerKeys, [{ keyId: "kms:1", scheme: "ed25519", credential: signer.credential }]);
  await c.createAgent({ id: "bea" });
  const readOnly = openLocalOwner({ ...config, signer: undefined });
  assert.equal(readOnly.authorize(q).decision, "DENY");
  await rejects(readOnly.createAgent({ id: "alex" }), "KEY_UNAVAILABLE");
  const wrong = openLocalOwner({ ...config, signer: signerFromKeyPair(generateKeyPair("ed25519", "kms:1")) });
  await rejects(wrong.createAgent({ id: "alex" }), "CONTROL_AUTHORIZATION_INVALID");
  // Genesis (committed to a next key: a caller's signer gets a next-key file by default too), principal and bea.
  assert.equal(c.exportHistory().length, 3);
  assert.equal(c.exportHistory()[0].data.nextKeyDigests.length, 1);
  assert.equal(existsSync(`${config.historyFile}.owner-next-key.json`), true);
});

test("format 1: genesis capacity, ed25519 and eip191 runtime credentials, legacy address still accepted", async (t) => {
  const { generateKeyPair } = await import("../src/crypto/suites.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-owner-cap-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = { historyFile: join(dir, "h.jsonl"), domain: TRELLIS_DOMAIN, owner: "operations", controller: "operator", now: () => 100, maxEvents: 40, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const c = await createLocalOwner(config);
  assert.deepEqual(c.exportHistory()[0].data.capacity, { maxEvents: 40 });
  assert.equal(c.capacity().maxEvents, 40);
  assert.equal(c.exportHistory()[0].data.versions.signatureScheme, "ed25519");
  for (const id of ["bea", "alex", "carl"]) await c.createAgent({ id });
  const ed = generateKeyPair("ed25519", "k:ed"), ec = generateKeyPair("eip191-personal-sign-keccak256", "k:ec");
  await c.admitRuntime({ session: "s:ed", agent: "bea", epoch: 1, key: "k:ed", credential: ed.credential, expiresAt: 500 });
  await c.admitRuntime({ session: "s:ec", agent: "alex", epoch: 1, key: "k:ec", credential: ec.credential, expiresAt: 500 });
  await c.admitRuntime({ session: "s:legacy", agent: "carl", epoch: 1, key: "k:legacy", address: generateKeyPair("eip191-personal-sign-keccak256", "x").credential, expiresAt: 500 });
  const sessions = c.exportHistory().filter((e) => e.type === "RUNTIME_SESSION_ADMITTED").map((e) => [e.data.credentialScheme, "credentialPublicKey" in e.data]);
  assert.deepEqual(sessions, [["ed25519", true], ["eip191-personal-sign-keccak256", false], ["eip191-personal-sign-keccak256", false]]);
  await rejects(c.admitRuntime({ session: "s:bad", agent: "bea", epoch: 2, key: "k:bad", credential: ed.credential, scheme: "eip191-personal-sign-keccak256", expiresAt: 500 }), "INVALID_INPUT");
  await rejects(c.admitRuntime({ session: "s:bad", agent: "bea", epoch: 2, key: "k:bad", credential: ed.credential, address: ec.credential, expiresAt: 500 }), "INVALID_INPUT");
  const legacyOwner = await createLocalOwner({ ...config, historyFile: join(dir, "legacy.jsonl"), format: LEGACY_FORMAT, [FORMAT1_TEST_TOOLING]: true, domain: LEGACY_DOMAIN, maxEvents: undefined });
  await legacyOwner.createAgent({ id: "bea" });
  await rejects(legacyOwner.admitRuntime({ session: "s:ed", agent: "bea", epoch: 1, key: "k:ed", credential: ed.credential, expiresAt: 500 }), "INVALID_INPUT");
  await legacyOwner.admitRuntime({ session: "s:ec", agent: "bea", epoch: 1, key: "k:ec", credential: ec.credential, expiresAt: 500 });
  assert.equal("credentialScheme" in legacyOwner.exportHistory().at(-1).data, false);
});

test("format 1: rollback of the file behind its pinned head is detected on open and can be accepted explicitly", async (t) => {
  const { writeFileSync } = await import("node:fs");
  const { c, config } = await setup(t, TRELLIS_FORMAT);
  await grant(c);
  const lines = readFileSync(config.historyFile, "utf8").split("\n").filter(Boolean);
  const pinBefore = JSON.parse(readFileSync(`${config.historyFile}.head`, "utf8"));
  writeFileSync(config.historyFile, lines.slice(0, -1).join("\n") + "\n");
  assert.throws(() => openLocalOwner(config), (e) => hasCode("ROLLBACK_DETECTED")(e) && e.detail.reason === "BEHIND_PIN");
  // verifyHistory reports the rollback (it does not throw), and it changes nothing.
  const report = verifyHistory(config.historyFile);
  assert.equal(report.ok, false);
  assert.equal(report.rollback, true);
  assert.equal(report.pinnedHeadStatus, "ROLLBACK");
  assert.ok(report.failures[0].startsWith("PIN_ROLLBACK: "));
  assert.deepEqual(JSON.parse(readFileSync(`${config.historyFile}.head`, "utf8")), pinBefore);
  // Accepting re-pins with the owner key (attested) and leaves the acceptance visible to verify().
  const accepted = openLocalOwner({ ...config, acceptRollback: true });
  assert.equal(accepted.authorize(q).decision, "DENY");
  assert.equal(accepted.exportHistory().length, lines.length - 1);
  // The re-pin happens inside the synchronous open; an asynchronous signer (KMS, ssh-agent, test mode) attests it after: flush() waits.
  await accepted.flush();
  const after = verifyHistory(config.historyFile);
  assert.equal(after.ok, true, after.failures.join("; "));
  assert.equal(after.pinnedAttestation, "VERIFIED");
  assert.equal(typeof after.rollbackAcceptedAt, "number");
  assert.equal(after.previousPin.position, pinBefore.position);
});

test("format 1 (B1): a deleted pin makes the owner refuse the history; revoked authority does not come back", async (t) => {
  const { writeFileSync, rmSync: remove } = await import("node:fs");
  const { c, config } = await setup(t, TRELLIS_FORMAT);
  await grant(c);
  await c.revoke("access");
  assert.equal(c.authorize(q).decision, "DENY");
  // Cut the revocation and delete the pin: every opener refuses instead of answering ALLOW.
  const lines = readFileSync(config.historyFile, "utf8").split("\n").filter(Boolean);
  writeFileSync(config.historyFile, lines.slice(0, -1).join("\n") + "\n");
  remove(`${config.historyFile}.head`);
  assert.throws(() => openLocalOwner(config), (e) => hasCode("ROLLBACK_DETECTED")(e) && e.detail.reason === "PIN_MISSING" && /pin missing/.test(e.message));
  assert.throws(() => c.authorize(q), hasCode("ROLLBACK_DETECTED"));
  const report = verifyHistory(config.historyFile);
  assert.equal(report.ok, false);
  assert.equal(report.pinnedHeadStatus, "MISSING");
  // allowUnpinned reads it (the operator's explicit choice) but cannot write to it.
  const reader = openLocalOwner({ ...config, allowUnpinned: true });
  assert.equal(reader.authorize(q).decision, "ALLOW");
  await rejects(reader.createAgent({ id: "carl" }), "ROLLBACK_DETECTED");
  assert.equal(verifyHistory(config.historyFile, { allowUnpinned: true }).ok, true);
});

test("format 1 (L2): an owner key file already next to a new history is never adopted silently", async (t) => {
  const { writeFileSync } = await import("node:fs");
  const { createOwnerKeyFile } = await import("../src/signer.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-owner-planted-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const config = { historyFile: join(dir, "h.jsonl"), domain: TRELLIS_DOMAIN, owner: "operations", controller: "operator", now: () => 100, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const planted = createOwnerKeyFile(`${config.historyFile}.owner-key.json`, "owner:planted");
  const before = readFileSync(`${config.historyFile}.owner-key.json`);
  await assert.rejects(createLocalOwner(config), (e) => hasCode("KEY_EXISTS")(e) && e.detail.keyPath === `${config.historyFile}.owner-key.json` && /reuseExistingKey/.test(e.message));
  assert.equal(existsSync(config.historyFile), false);
  assert.deepEqual(readFileSync(`${config.historyFile}.owner-key.json`), before, "the existing key file is left alone");
  // A caller-provided signer does not make the stray key file acceptable either.
  const { generateKeyPair } = await import("../src/crypto/suites.ts");
  const { signerFromKeyPair } = await import("../src/signer.ts");
  await rejects(createLocalOwner({ ...config, signer: signerFromKeyPair(generateKeyPair("ed25519", "kms:1")) }), "KEY_EXISTS");
  // Explicit reuse adopts it.
  const c = await createLocalOwner({ ...config, reuseExistingKey: true });
  assert.deepEqual(c.exportHistory()[0].data.ownerKeys, [{ keyId: "owner:planted", scheme: "ed25519", credential: planted.credential }]);
  // A key file created for a history that could not be written is removed again.
  // (Here a stale pin from an earlier history at that path refuses the creation after the key was made.)
  const second = { ...config, historyFile: join(dir, "second.jsonl") };
  writeFileSync(`${second.historyFile}.head`, readFileSync(`${config.historyFile}.head`));
  await rejects(createLocalOwner(second), "ROLLBACK_DETECTED");
  assert.equal(existsSync(second.historyFile), false);
  assert.equal(existsSync(`${second.historyFile}.owner-key.json`), false);
  // A readable-by-others key is refused with the mode it needs (L3), and the handle says so on its first control write.
  // (POSIX: Windows modes are synthetic and not checked; the ACL protects the key there, docs/PLATFORMS.md §3.)
  if (process.platform !== "win32") {
    const { chmodSync } = await import("node:fs");
    chmodSync(`${config.historyFile}.owner-key.json`, 0o644);
    const loose = openLocalOwner(config);
    await assert.rejects(loose.createAgent({ id: "bea" }), (e) => hasCode("KEY_UNAVAILABLE")(e) && /must be mode 0600/.test(e.message));
  }
  writeFileSync(`${config.historyFile}.owner-key.json`, before, { mode: 0o600 });
});

test("format 1 (M10): a busy writer lock is HISTORY_CONFLICT naming the lock file and its holder", async (t) => {
  const { realpathSync, writeFileSync } = await import("node:fs");
  const { hostname } = await import("node:os");
  const { c, config } = await setup(t, TRELLIS_FORMAT);
  const lock = `${config.historyFile}.writer-lock`;
  writeFileSync(lock, JSON.stringify({ pid: process.pid, hostname: hostname(), createdAt: Date.now() }));
  await assert.rejects(c.createAgent({ id: "carl" }), // A-184.1: a lock path is compared after canonicalising both sides (on macOS a tmpdir path may run through a symlink).
    (e) => hasCode("HISTORY_CONFLICT")(e) && realpathSync(e.detail.lockPath) === realpathSync(lock) && e.message.includes(e.detail.lockPath) && e.detail.holder.pid === process.pid);
  rmSync(lock);
  await c.createAgent({ id: "carl" });
});

test("shared Core preserves the public default and requires explicit E5/E6 new-history selection", async (t) => {
  const { createLocalAttemptOwner, createLocalReviewOwner } = await import("../src/owner.ts");
  const { ADAPTER_POLICY_HASH, ADAPTER_POLICY_E5_HASH, ADAPTER_POLICY_E6_HASH } = await import("../src/adapter-editions.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-policy-compat-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const format of [LEGACY_FORMAT, TRELLIS_FORMAT]) {
    for (const [name, make, hash] of [["existing", createLocalOwner, ADAPTER_POLICY_HASH], ["attempts", createLocalAttemptOwner, ADAPTER_POLICY_E5_HASH], ["review", createLocalReviewOwner, ADAPTER_POLICY_E6_HASH]]) {
      const config = { historyFile: join(dir, `${format.replace("/", "-")}-${name}.jsonl`), domain: createLocalDomain({ format }), owner: "owner", controller: "controller", now: () => 100, format, [FORMAT1_TEST_TOOLING]: true };
      const owner = await make(config);
      assert.equal(owner.exportHistory()[0].data.adapterPolicyHash, hash);
      const before = owner.exportHistory();
      assert.deepEqual(openLocalOwner(config).exportHistory(), before);
      await rejects(createLocalReviewOwner(config), "HISTORY_EXISTS");
      assert.deepEqual(openLocalOwner(config).exportHistory(), before, "creating a different policy must not migrate a history");
    }
  }
});

for (const format of [LEGACY_FORMAT, TRELLIS_FORMAT]) {
  test(`${format}: createRole refuses a shared role up front (both formats require exclusive roles)`, async (t) => {
    const { c } = await setup(t, format);
    const before = c.exportHistory().length;
    await assert.rejects(c.createRole({ id: "shared", exclusive: false }), (e) => e instanceof IronTrellisError && e.code === "INVALID_INPUT" && e.message === "only exclusive roles are supported in this release");
    assert.equal(c.exportHistory().length, before);
    assert.ok((await c.createRole({ id: "exclusive", exclusive: true })).eventId);
    assert.ok((await c.createRole({ id: "default" })).eventId);
    assert.deepEqual(c.exportHistory().slice(before).map((e) => e.data.exclusive), [true, true]);
  });
}

test("format 1: a write with a KMS (async-only) signer returns once its head is attested; a failed attestation surfaces in flush(); close() releases the handle", async (t) => {
  const { generateKeyPair, signHashWith } = await import("../src/crypto/suites.ts");
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-owner-flush-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const pair = generateKeyPair("ed25519", "kms:1"), sign = signHashWith(pair);
  let failing = false;
  const purposes = [];
  // No signHashSync: the store pins each head at once and attests it after the append, as with a remote KMS.
  const signer = Object.freeze({ keyId: "kms:1", scheme: "ed25519", credential: pair.credential, signHash: async (hash, context) => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    purposes.push(context?.purpose);
    if (failing && context?.purpose === "head-attestation") throw new Error("kms unavailable");
    return sign(hash);
  } });
  // Format 1 by name: the owner API writes format 2 by default (SPEC §19); these tests cover the format-1 writer.
  const config = { historyFile: join(dir, "h.jsonl"), domain: TRELLIS_DOMAIN, owner: "operations", controller: "operator", now: () => 100, signer, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true };
  const c = await createLocalOwner(config);
  purposes.length = 0;
  const written = await c.createAgent({ id: "bea" });
  assert.deepEqual(purposes, ["control-authorization", "head-attestation"], "the signer learns why it signs (advisory)");
  const pin = () => JSON.parse(readFileSync(`${config.historyFile}.head`, "utf8"));
  assert.equal(pin().hash, written.head.hash);
  // Block 4 (§4.1): the owner API waits for the attestation, so the pin already carries the owner's word for the new head.
  assert.equal(pin().attestation.head.hash, written.head.hash, "the write returns once its head is attested");
  assert.equal(c.verify().ok, true);
  await c.flush();
  assert.equal(c.verify().pinnedAttestation, "VERIFIED");
  // A failed attestation surfaces once, as SIGNER_FAILED; the event itself is durable and the pin keeps the previous attestation.
  failing = true;
  const second = await c.createAgent({ id: "alex" });
  await rejects(c.flush(), "SIGNER_FAILED");
  await c.flush();
  failing = false;
  assert.equal(pin().hash, second.head.hash);
  assert.equal(pin().attestation.head.hash, written.head.hash, "the failed attestation leaves the previous one in place");
  assert.deepEqual(c.verify().attestedHead, written.head);
  assert.equal(openLocalOwner({ ...config, signer: undefined }).exportHistory().length, 4, "genesis (with the next-key commitment), principal, bea, alex");
  // close(): idempotent; afterwards every read and write is READ_UNAVAILABLE.
  c.close();
  c.close();
  assert.throws(() => c.authorize(q), hasCode("READ_UNAVAILABLE"));
  assert.throws(() => c.verify(), hasCode("READ_UNAVAILABLE"));
  await rejects(c.createAgent({ id: "cid" }), "READ_UNAVAILABLE");
  assert.equal(openLocalOwner({ ...config, signer: undefined }).exportHistory().length, 4);
});

// Format 2 (SPEC §5–§6, §8): schema refusals, the /2 control challenge against TEST-KEYS, the declaration and runtime
// challenges, the metric and nonce rules, string amounts in proofs, and the untouched behaviour of the format-1 twin.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const core = await import("../src/index.ts");
const { signerFromKeyPair } = await import("../src/signer.ts");
const V2 = join(import.meta.dirname, "..", "..", "..", "conformance", "v2-g3");
const EVENTS = JSON.parse(readFileSync(join(V2, "histories", "budget-v2.json"), "utf8"));
const TWIN = JSON.parse(readFileSync(join(V2, "histories", "budget-v2-twin-format1.json"), "utf8"));
const VECTORS = JSON.parse(readFileSync(join(V2, "vectors.json"), "utf8"));
const vector = (id) => VECTORS.find((v) => v.id === id);
const seed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
const OWNER = core.keyPairFromPrivateKey("ed25519", "owner:1", seed(0x1001));
const SPENDER = core.keyPairFromPrivateKey("ed25519", "key:spender", seed(0x2004));
const DOMAIN = EVENTS[0].data.domain;
const clone = (v) => JSON.parse(JSON.stringify(v));

test("format 2 keys: TEST-KEYS.md credentials derive from the published seeds", () => {
  assert.equal(OWNER.credential, "0x967e264fa6b2e89fcfab4df3d4291cd1482a3a5a9f3836c9ce8f80d112d2ac4d");
  assert.equal(SPENDER.credential, "0xcb75fed9c52f386f38a12a8aaffd593eab63603ae28b8056b894e8d08d53d71f");
  assert.equal(core.ownerKeyDigest(core.keyPairFromPrivateKey("ed25519", "owner:2", seed(0x1102))), EVENTS[0].data.nextKeyDigests[0]);
});

test("format 2 control challenge (SPEC §6.1): /2 literal, chain head, effect hash; re-signing with owner:1 reproduces every recorded signature", async () => {
  const r = core.replay(EVENTS);
  assert.equal(r.status, "ACCEPTED");
  const signer = signerFromKeyPair(OWNER);
  for (const [position, event] of EVENTS.entries()) {
    if (!core.CONTROL_EVENT_TYPES.has(event.type)) continue;
    const previousHead = { hash: r.state.eventHistoryHashes[position - 1], position: position - 1 };
    const challenge = core.controlAuthorizationChallenge({ domain: DOMAIN, eventId: event.id, eventType: event.type, timestamp: event.timestamp, previousHead, effectHash: core.controlEffectHash(event, "sha256") });
    assert.equal(challenge.version, "irontrellis-control-authorization/2");
    assert.deepEqual(challenge.previousHead, previousHead);
    const { controlAuthorization: _a, ...effect } = event.data;
    assert.equal(challenge.effectHash, core.hashCanonical(effect, "sha256"));
    // Ed25519 is deterministic: the same key over the same challenge gives the same bytes.
    const signed = await core.signControlEvent(signer, { ...event, data: effect }, DOMAIN, { ...previousHead, canonicalTime: EVENTS[position - 1].timestamp }, "sha256");
    assert.equal(signed.data.controlAuthorization.signature, event.data.controlAuthorization.signature, `${event.type} at ${position}`);
    assert.equal(core.controlSignatureFailure(event, { domain: DOMAIN, previousHead, keys: core.ownerKeysAt(r.state, position), algorithm: "sha256" }), undefined);
  }
  // A format-1 domain keeps the /1 literal.
  assert.equal(core.controlAuthorizationChallenge({ domain: TWIN[0].data.domain, eventId: "e", eventType: "PRINCIPAL_CREATED", timestamp: 1, previousHead: null, effectHash: `0x${"0".repeat(64)}` }).version, "irontrellis-control-authorization/1");
  assert.equal(core.controlAuthorizationVersionOf(DOMAIN), core.CONTROL_AUTHORIZATION_VERSION_2);
});

test("format 2 declaration challenge (SPEC §8.6) and runtime challenge (SPEC §8.2) reproduce the recorded hashes and signatures", async () => {
  const r = core.replay(EVENTS);
  const sign = core.signHashWith(SPENDER);
  for (const [position, event] of EVENTS.entries()) {
    if (event.type === "TRANSACTION_INTENT_DECLARED") {
      const { declarationAuthorization: a, ...fields } = event.data;
      const previousHead = { hash: r.state.eventHistoryHashes[position - 1], position: position - 1 };
      const hash = core.intentDeclarationHash(DOMAIN, fields, previousHead, a, event);
      assert.equal(hash, a.hash, `declaration at ${position}`);
      assert.equal(await sign(hash), a.signature);
      const challenge = core.intentDeclarationChallenge(DOMAIN, fields, previousHead, a, event);
      assert.equal(challenge.version, "irontrellis-intent-declaration/2");
      // A-54 (profile g3, the default): the challenge binds the final envelope.
      assert.deepEqual([challenge.eventId, challenge.eventType, challenge.timestamp], [event.id, "TRANSACTION_INTENT_DECLARED", event.timestamp]);
    }
    if (event.type === "TRANSACTION_INTENT_ADMITTED") {
      const proof = event.data.authorizationProof;
      const head = r.state.events[position - 1] && { hash: r.state.eventHistoryHashes[position - 1], position: position - 1, canonicalTime: EVENTS[position - 1].timestamp };
      const challenge = core.createRuntimeAuthorizationChallenge({
        domain: DOMAIN, request: proof.request, evaluationTime: event.data.evaluationTime, policyVersion: proof.policyVersion, historyHead: head,
        binding: { runtimeSessionId: proof.runtimeSessionId, credentialKeyId: proof.credentialKeyId, controlEpoch: proof.controlEpoch, roleId: proof.roleId, roleTenureId: proof.roleTenureId, intentId: proof.intentId, nonce: proof.nonce },
      });
      assert.equal(challenge.version, "irontrellis-runtime-authorization/2");
      assert.equal(typeof challenge.request.amount, "string");
      assert.equal(core.hashRuntimeAuthorizationChallenge(challenge, "sha256"), event.data.runtimeAuthorizationHash, `admission at ${position}`);
      assert.equal(proof.proofVersion, "irontrellis-authorization-proof/2");
    }
  }
});

test("format 2 schema refusals (SPEC §3, §5.1): markers, negative and leading-zero amounts, reserved keys, literals, domain version, format-2 types in format 1", () => {
  const code = (events) => { const r = core.replay(events); return r.status === "REJECTED" ? [r.code, r.position] : ["ACCEPTED"]; };
  for (const [id, expected] of [["rejects-bigint-marker-amount", "EVENT_DATA_INVALID"], ["rejects-negative-amount", "EVENT_DATA_INVALID"], ["rejects-leading-zero-amount", "EVENT_DATA_INVALID"],
    ["rejects-format1-literals-in-format2-genesis", "UNSUPPORTED_VERSION"], ["rejects-domain-version-1-in-format2", "EVENT_DATA_INVALID"], ["rejects-unsigned-intent-declaration", "EVENT_DATA_INVALID"],
    ["rejects-intent-declaration-with-wrong-signature", "DECLARATION_AUTHORIZATION_INVALID"], ["rejects-intent-declaration-with-altered-amount", "DECLARATION_AUTHORIZATION_INVALID"],
    ["rejects-duplicate-nonce-declaration", "TRANSITION_INVALID"], ["rejects-admission-metric-mismatch", "TRANSITION_INVALID"], ["rejects-moved-control-event", "CONTROL_AUTHORIZATION_INVALID"],
    ["rejects-format2-event-kind-in-format1-history", "UNSUPPORTED_EVENT_TYPE"]]) {
    assert.equal(code(vector(`replay/v2/${id}`).events)[0], expected, id);
  }
  // A reserved key anywhere in format-2 data, a bigint handed to the engine directly, an oversized amount string.
  const planted = clone(EVENTS.slice(0, 12));
  planted[11].data.adapterProfile = { ...planted[11].data.adapterProfile, "$continuity.note": "x" };
  assert.deepEqual(code(planted), ["EVENT_DATA_INVALID", 11]);
  const asBigint = clone(EVENTS.slice(0, 12));
  asBigint[11].data.amount = 60n;
  assert.deepEqual(code(asBigint), ["EVENT_DATA_INVALID", 11]);
  const tooLong = clone(EVENTS.slice(0, 12));
  tooLong[11].data.amount = "1".repeat(79);
  assert.deepEqual(code(tooLong), ["EVENT_DATA_INVALID", 11]);
  const overMax = clone(EVENTS.slice(0, 12));
  overMax[11].data.amount = ((1n << 256n)).toString();
  assert.deepEqual(code(overMax), ["EVENT_DATA_INVALID", 11]);
  // Genesis: a missing or extra versions key is UNSUPPORTED_VERSION; a format-2 `versions` block with a format-1 schema literal is UNSUPPORTED_EVENT_SCHEMA under format 1 rules.
  const missing = clone(EVENTS.slice(0, 1)); delete missing[0].data.versions.projectionVersion;
  assert.equal(code(missing)[0], "UNSUPPORTED_VERSION");
  const extra = clone(EVENTS.slice(0, 1)); extra[0].data.versions.extra = "x";
  assert.equal(code(extra)[0], "UNSUPPORTED_VERSION");
  // `metric` is a format-2 field: a format-1 intent or request with it is refused.
  const twinDeclaration = core.jsonParseWithBigints(JSON.stringify(TWIN));
  const twinWithMetric = twinDeclaration.map((e) => (e.type === "TRANSACTION_INTENT_DECLARED" ? { ...e, data: { ...e.data, metric: "amount" } } : e));
  assert.equal(code(twinWithMetric)[0], "EVENT_DATA_INVALID");
  // sourceControlAuthorization is only allowed inside a migrated prefix (none here).
  const sourced = clone(EVENTS.slice(0, 2)); sourced[1].data.sourceControlAuthorization = { keyId: "owner:0", signature: `0x${"ab".repeat(64)}` };
  assert.deepEqual(code(sourced), ["EVENT_DATA_INVALID", 1]);
  // Every one of the 42 types (codes 0–40 and 42, A-71.0) is known to format 2; types 29–40 and 42 are unknown to format 1 and legacy.
  assert.equal(core.EVENT_TYPES.length, 42);
  assert.equal(core.EVENT_TYPES.indexOf("COUNTERPARTY_RECEIPT_RECORDED"), 40);
  assert.equal(core.EVENT_TYPE_CODES.get("COUNTERPARTY_RECEIPT_RECORDED"), 40);
  assert.equal(core.EVENT_TYPE_CODES.get("RECONCILIATION_OBSERVED"), 42);
  assert.equal(core.FORMAT2_ONLY_EVENT_TYPES.size, 13);
  for (const type of core.FORMAT2_ONLY_EVENT_TYPES) assert.ok(!core.validateEvent({ id: "x", type, timestamp: 1, data: {} }, core.TRELLIS_FORMAT, 5).ok);
});

test("format 2 authorize: string amounts in and out, metric accepted, budgets consulted after ALLOW; the format-1 twin answers as before", () => {
  const r = core.replay(EVENTS);
  const head = r.head;
  const body = (request, evaluationTime = head.canonicalTime) => ({ expectedHistoryHead: head, domain: DOMAIN, policyVersion: "irontrellis-local-owner/2", rootRecognitionPolicy: core.ROOT_RECOGNITION_POLICY, request, evaluationTime, consequential: false });
  const allow = core.authorizeState(r.state, body({ actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: head.canonicalTime, amount: "10" }));
  assert.equal(allow.decision, "ALLOW");
  assert.equal(allow.proof.proofVersion, "irontrellis-authorization-proof/2");
  assert.equal(allow.proof.request.amount, "10");
  assert.equal(typeof allow.proof.effectiveConstraints.maxAmount, "string");
  assert.equal(typeof allow.proof.permissionPath[0].constraints.maxAmount, "string");
  assert.ok(!core.canonicalEncode(allow.proof).includes("$continuity"));
  // bigint amounts are accepted too, and give the same proof.
  const allowBig = core.authorizeState(r.state, body({ actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: head.canonicalTime, amount: 10n }));
  assert.equal(core.canonicalEncode(allowBig.proof), core.canonicalEncode(allow.proof));
  const deny = core.authorizeState(r.state, body({ actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: head.canonicalTime, amount: "11" }));
  assert.equal(deny.decision, "DENY");
  assert.equal(deny.code, "BUDGET_AMOUNT_EXCEEDED");
  assert.equal(deny.budgetId, "b-amount");
  assert.deepEqual(deny.failures.map((f) => f.code), ["BUDGET_AMOUNT_EXCEEDED"]);
  const other = core.authorizeState(r.state, body({ actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: head.canonicalTime, amount: "5", metric: "bytes" }));
  assert.equal(other.decision, "ALLOW");
  assert.equal(other.proof.request.metric, "bytes");
  const invalid = core.authorizeState(r.state, body({ actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: head.canonicalTime, amount: "-1" }));
  // G6.5 A-134.1: a non-Amount at request.amount is a capture failure in format 2 (INVALID_AMOUNT is unreachable there).
  assert.deepEqual([invalid.decision, invalid.code, invalid.scopeAssurance], ["INDETERMINATE", "INVALID_INPUT", "SUPPLIED_SCOPE"]);
  // The format-1 twin: marker amounts, /0.2 literals, no budgets, no metric.
  const twin = core.replay(core.jsonParseWithBigints(JSON.stringify(TWIN)));
  assert.equal(twin.status, "ACCEPTED");
  assert.equal(twin.stateRoot, undefined);
  const twinBody = { expectedHistoryHead: twin.head, domain: TWIN[0].data.domain, policyVersion: "irontrellis-local-owner/1", rootRecognitionPolicy: core.ROOT_RECOGNITION_POLICY, evaluationTime: twin.head.canonicalTime, consequential: false };
  const twinAllow = core.authorizeState(twin.state, { ...twinBody, request: { actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: twin.head.canonicalTime, amount: 11n } });
  assert.equal(twinAllow.decision, "ALLOW");
  assert.equal(twinAllow.proof.proofVersion, "continuity-authorization-proof/0.2");
  assert.equal(typeof twinAllow.proof.request.amount, "bigint");
  assert.equal(core.authorizeState(twin.state, { ...twinBody, request: { actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: twin.head.canonicalTime, amount: "11" } }).code, "INVALID_AMOUNT");
  assert.equal(core.authorizeState(twin.state, { ...twinBody, request: { actorId: "spender", action: "spend", resource: "petty-cash", claimedAt: twin.head.canonicalTime, metric: "amount" } }).code, "INVALID_INPUT");
});

test("format 2 headroom (SPEC §9.7) answers every headroom vector", () => {
  for (const v of VECTORS.filter((x) => x.kind === "headroom")) {
    const r = core.replay(EVENTS.slice(0, v.history.eventCount));
    assert.equal(r.status, "ACCEPTED");
    assert.deepEqual(core.headroom(r.state, v.input.budgetId, v.input.at), v.expect, v.id);
  }
});

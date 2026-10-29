// Regression tests for engine defects the fuzzer found that its own regression vectors
// (fuzz/regressions, replayed by fuzz-smoke.test.mjs) do not reach directly.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { canonicalEncode, contextKeysAt, jsonParseWithBigints, observeState, ownerKeysAt, replay, verifyHeadAttestationAt, verifyHeadAttestationFacts } from "../src/index.ts";

const handover = () => replay(jsonParseWithBigints(readFileSync(new URL("../../../conformance/v1/histories/handover-v1.json", import.meta.url), "utf8"))).state;

test("owner-API identifiers must be well-formed Unicode: INVALID_INPUT, not a raw CanonicalError from the capture", () => {
  const observation = observeState(handover());
  for (const ask of [() => observation.survives("a\ud800"), () => observation.authorize({ actor: "a\udfff", action: "read", resource: "x" }),
    () => observation.why({ actor: "alex", action: "r\ud800", resource: "x" })]) {
    assert.throws(ask, (error) => error.name === "IronTrellisError" && error.code === "INVALID_INPUT");
  }
  assert.equal(observation.survives("alex").answer.lifecycleStatus, "ACTIVE", "well-formed non-ASCII ids still work");
});

test("a record's keys are all validated before the reserved-prefix rule, the depth bound and any field (spec 01 §A.6, as the reference)", async (t) => {
  const deep = (n, leaf) => { let v = leaf; for (let i = 0; i < n; i += 1) v = [v]; return v; };
  const cases = [
    [{ a: { "$continuity.bigint": 0 }, "\ud800": 1 }, "is not well-formed Unicode"],
    [{ a: { "$continuity.bigint": 0 }, ["é".repeat(2049)]: 1 }, "exceeds the 4096-byte ProtocolString bound"],
    [{ a: deep(40, 0), "\ud800": 1 }, "is not well-formed Unicode"],
    [{ "$continuity.x": 1, "\ud800": 2 }, "is not well-formed Unicode"],
    [deep(32, { "\ud800": 1 }), "is not well-formed Unicode"],
  ];
  for (const [value, message] of cases) assert.throws(() => canonicalEncode(value), (error) => error.name === "CanonicalError" && error.message.includes(message) && error.message.includes(".{key}"));
  // Parity with the frozen reference engine itself, when this Node can load its TypeScript sources.
  let reference;
  try { reference = await import("../../reference-0.2/core-0.2/src/core/canonical.ts"); } catch { t.diagnostic("reference-0.2 not loadable here: parity part skipped"); return; }
  for (const [value] of cases) {
    const message = (f) => { try { f(); return "ok"; } catch (error) { return error.message; } };
    assert.equal(message(() => canonicalEncode(value)), message(() => reference.canonicalEncode(value)));
  }
});

test("jsonParseWithBigints reads valid JSON nested far deeper than a reviver's recursion allows", () => {
  const text = `${"[".repeat(100_000)}{"$continuity.bigint":"7"}${"]".repeat(100_000)}`;
  let value = jsonParseWithBigints(text);
  for (let depth = 0; depth < 100_000; depth += 1) value = value[0];
  assert.equal(value, 7n);
  assert.throws(() => canonicalEncode(jsonParseWithBigints(text)), (error) => error.name === "CanonicalError" && error.limit === true);
});

test("a head position of -0 is not a position (canonical U53): no prefix, no signature check, no keys (a fuzzer finding)", () => {
  const state = handover();
  const attestation = (position) => ({ version: "irontrellis-head-attestation/1",
    head: { hash: state.eventHistoryHashes[0], position, canonicalTime: state.events[0].timestamp }, keyId: "owner:1", scheme: "ed25519", signature: `0x${"00".repeat(64)}` });
  assert.equal(verifyHeadAttestationFacts(attestation(0), state).prefix, true, "position 0 is a prefix");
  // Before the fix, -0 passed Number.isSafeInteger and >= 0 and was taken as 0, so `prefix` was true here while the Python
  // verifier (which reads -0 as negative zero) answered false.
  const facts = verifyHeadAttestationFacts(attestation(-0), state);
  assert.deepEqual([facts.prefix, facts.valid], [false, false]);
  assert.equal(verifyHeadAttestationAt(attestation(-0), state), false);
  assert.ok(ownerKeysAt(state, 0).length > 0);
  assert.deepEqual(ownerKeysAt(state, -0), []);
  assert.deepEqual(contextKeysAt({ ownerKeys: [], ownerKeysAt: (p) => ownerKeysAt(state, p) }, -0), []);
});

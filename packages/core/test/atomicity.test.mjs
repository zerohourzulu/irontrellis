// r4 §5: a rejected event leaves the state unchanged. The coordinator's atomicity finding (20261012T053937Z, probe
// files/atomicity-probe.mjs) rewritten with synthetic keys: the final event of a migrated prefix whose source-head
// attestation names another canonicalTime is rejected (EVENT_DATA_INVALID, A-40.2/A-80) without its transition reaching the
// shared maps; an event failing its transition too still reports the transition's code. Then the genesis whose shadow does
// not open, and a generic check over the rejection vectors: the state dump (every map, the shadow, rootAt(head)) is the
// same before and after each rejected event, and a prospective check never writes to its base.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { stateDump } from "./helpers/state-dump.mjs";

const { replay, applyEvent, createReplayState, detectFormat, withProspectiveEvent } = await import("../src/replay.ts");
const { FORMAT2_VERSIONS, TRELLIS2_FORMAT, TRELLIS_FORMAT, LEGACY_FORMAT } = await import("../src/events.ts");
const { keyPairFromPrivateKey } = await import("../src/crypto/suites.ts");
const { signerFromKeyPair, signControlEvent, attestHead } = await import("../src/signer.ts");
const { HistoryHasher } = await import("../src/hash.ts");
const { setCapacityLimitsForTests } = await import("../src/capacity.ts");

const CONFORMANCE = new URL("../../../conformance/", import.meta.url).pathname;
const read = (path) => JSON.parse(readFileSync(join(CONFORMANCE, path), "utf8"));
const TEMPLATE = read("v2-regenerated/histories/migrated-format1-v2.json")[0];
const signer = signerFromKeyPair(keyPairFromPrivateKey("ed25519", "owner:atomicity", `0x${"5a".repeat(32)}`));
const ownerKeys = [{ keyId: signer.keyId, scheme: signer.scheme, credential: signer.credential }];
const SOURCE = (() => { const data = { ...TEMPLATE.data.migratedFrom.genesis, ownerKeys }; delete data.nextKeyDigests; return data; })();
const SOURCE_GENESIS = { id: "event:atomicity:genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 100, data: SOURCE };
const principal = (n, principalId = `principal:${n}`) => ({ id: `event:atomicity:principal:${n}`, type: "PRINCIPAL_CREATED", timestamp: 100 + n, data: { principalId } });

/**
 * A format-1 source (genesis + `unsigned`, each owner-signed over the source head before it, accepted or not) and its
 * incremental format-2 migration target through the genesis; the attestation signs the source head with `canonicalTime`.
 */
const migration = async (unsigned, canonicalTime) => {
  const hasher = new HistoryHasher(TRELLIS_FORMAT);
  let head = { hash: hasher.push(SOURCE_GENESIS), position: 0 };
  const source = [];
  for (const event of unsigned) {
    const signed = await signControlEvent(signer, event, SOURCE.domain, head, "sha256");
    source.push(signed);
    head = { hash: hasher.push(signed), position: head.position + 1 };
  }
  const sourceAttestation = await attestHead(signer, SOURCE.domain, { ...head, canonicalTime }, "sha256");
  const data = {
    ...TEMPLATE.data, domain: { ...SOURCE.domain, version: "2" }, ownerKeys, versions: { ...FORMAT2_VERSIONS, signatureScheme: SOURCE.versions.signatureScheme },
    migratedFrom: { ...TEMPLATE.data.migratedFrom, format: TRELLIS_FORMAT, historyHash: head.hash, recordHash: head.hash, position: head.position, genesis: SOURCE,
      genesisEventId: SOURCE_GENESIS.id, genesisTimestamp: SOURCE_GENESIS.timestamp, versions: SOURCE.versions, sourceAttestation },
  };
  delete data.nextKeyDigests;
  const state = createReplayState(TRELLIS2_FORMAT);
  const genesis = applyEvent(state, { ...SOURCE_GENESIS, data });
  assert.equal(genesis.ok, true, genesis.reason);
  /** The source event at `position`, transcribed (its /1 authorization kept as sourceControlAuthorization) and signed over the target head. */
  const transcribed = (position) => {
    const { controlAuthorization, ...rest } = source[position - 1].data;
    return signControlEvent(signer, { ...source[position - 1], data: { ...rest, sourceControlAuthorization: controlAuthorization } }, data.domain, state.head, "sha256");
  };
  return { state, transcribed };
};

test("atomicity finding: the final prefix event with a mis-attested source time is rejected without touching the shared maps", async () => {
  const { state, transcribed } = await migration([principal(1, "principal:probe")], 102);
  const event = await transcribed(1);
  const before = stateDump(state);
  const result = applyEvent(state, event);
  assert.equal(result.ok, false);
  assert.equal(result.code, "EVENT_DATA_INVALID");
  assert.match(result.reason, /A-40\.2/);
  assert.equal(state.principals.has("principal:probe"), false);
  assert.equal(state.principals.size, 0);
  assert.equal(stateDump(state), before);
  // The same prefix, correctly attested, applies the principal.
  const good = await migration([principal(1, "principal:probe")], 101);
  assert.equal(applyEvent(good.state, await good.transcribed(1)).ok, true);
  assert.equal(good.state.principals.has("principal:probe"), true);
});

test("atomicity finding: an event failing its transition and the time check reports the transition (first failure wins), state unchanged", async () => {
  const { state, transcribed } = await migration([principal(1, "principal:twice"), principal(2, "principal:twice")], 999);
  assert.equal(applyEvent(state, await transcribed(1)).ok, true);
  const event = await transcribed(2);
  const before = stateDump(state);
  const result = applyEvent(state, event);
  assert.deepEqual([result.ok, result.code], [false, "TRANSITION_INVALID"]);
  assert.equal(stateDump(state), before);
});

test("a genesis whose migrated shadow does not open leaves the empty state as it was (signature scheme included)", () => {
  const data = { ...TEMPLATE.data, canonicalLineageId: "lineage:not-the-source" }; // A-17.2: copied as written, or refused
  const state = createReplayState(TRELLIS2_FORMAT);
  const before = stateDump(state);
  const result = applyEvent(state, { ...TEMPLATE, data });
  assert.deepEqual([result.ok, result.code], [false, "TRANSITION_INVALID"]);
  assert.match(result.reason, /canonicalLineageId/);
  assert.equal(stateDump(state), before);
});

// ---------------------------------------------------------------- generic: every rejection vector of the format-2 suites

const isFormat2 = (events) => events[0]?.data?.versions?.eventSchemaVersion === "irontrellis-event/2";
const reviveTag = (value) => {
  if (value === null || typeof value !== "object") return value;
  if (Object.hasOwn(value, "$continuity.bigint")) return BigInt(value["$continuity.bigint"]);
  return Array.isArray(value) ? value.map(reviveTag) : Object.fromEntries(Object.entries(value).map(([k, v]) => [k, reviveTag(v)]));
};
const rejectionVectors = (suite) => {
  const histories = new Map();
  return read(`${suite}/vectors.json`).filter((v) => v.kind === "replay" && v.expect.status === "REJECTED").map((v) => {
    if (v.events !== undefined) return { id: v.id, events: v.events, limits: v.input?.testCapacityLimits };
    if (!histories.has(v.history.ref)) histories.set(v.history.ref, read(`${suite}/histories/${v.history.ref}.json`));
    return { id: v.id, events: histories.get(v.history.ref).slice(0, v.history.eventCount), limits: v.input?.testCapacityLimits };
  });
};

for (const suite of ["v2-regenerated", "v2-owner-policy", "v2-human-attestation"]) {
  test(`r4 §5 over ${suite}: each rejected event leaves the state dump unchanged, and a prospective check never writes to its base`, () => {
    const vectors = rejectionVectors(suite);
    assert.ok(vectors.length > 30);
    let checked = 0, incomplete = 0;
    for (const { id, events: raw, limits } of vectors) {
      const events = isFormat2(raw) ? raw : reviveTag(raw);
      if (limits !== undefined) setCapacityLimitsForTests(limits);
      try {
        const state = createReplayState(detectFormat(events) ?? LEGACY_FORMAT);
        for (const event of events) {
          const before = stateDump(state);
          if (state.events.length > 0) {
            withProspectiveEvent(state, event);
            assert.equal(stateDump(state), before, `${id}: a prospective check at ${state.events.length} wrote to its base`);
          }
          const result = applyEvent(state, event);
          if (result.ok) continue;
          assert.equal(stateDump(state), before, `${id}: rejected at ${state.events.length} (${result.code}) but the state changed`);
          checked += 1;
          break;
        }
        if (state.events.length === events.length) incomplete += 1; // every event applied: refused once the replay completes
      } finally {
        if (limits !== undefined) setCapacityLimitsForTests();
      }
    }
    // Every vector is rejected by an event, except the migrated prefixes cut short (refused by `incompleteMigration`).
    assert.equal(checked + incomplete, vectors.length);
    assert.equal(incomplete, suite === "v2-regenerated" ? 2 : 0);
  });
}

test("the replay entry point agrees: the mis-attested migration is rejected at the prefix end", async () => {
  const { state, transcribed } = await migration([principal(1)], 50);
  const events = [...state.events, await transcribed(1)];
  const result = replay(events);
  assert.deepEqual([result.status, result.code, result.position], ["REJECTED", "EVENT_DATA_INVALID", 1]);
});

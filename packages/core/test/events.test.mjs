// Event schema differential tests: every closed schema and its rejection code
// against the reference engine's standalone validator, plus adapter editions
// and the format-1 additions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

import { referenceCore as core, referenceCore02, fixturesRoot } from "./reference.mjs";
const refSchema = await referenceCore02("core/event-schema.ts");
const refAdapter = await referenceCore02("core/portable-adapter-engine.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const { hashCanonical } = await import("../src/hash.ts");
const { canonicalEncode } = await import("../src/canonical.ts");

const revive = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;
const load = (name) => JSON.parse(readFileSync(`${fixturesRoot}${name}`, "utf8"), revive);
const FIXTURES = ["handover-history.json", "handover-denied-history.json", "mandate-history.json",
  "original-core/cases/core02-packet-r1/export/history.json", "original-core/cases/core02-simulated-r1/export/history.json"];
const LEGACY = "continuity-event/0.2";

/** Reference standalone result mapped onto replay codes (spec 01 §C, §D.6 step 3). */
const referenceCode = (result) => {
  if (result.ok) return "OK";
  if (result.code === "EVENT_ENVELOPE_INVALID") return "INVALID_INPUT";
  if (result.code === "EVENT_TYPE_UNSUPPORTED") return "UNSUPPORTED_EVENT_TYPE";
  return refSchema.isCoreSchemaLimitFailure(result) ? "INVALID_INPUT" : "EVENT_DATA_INVALID";
};
const mineCode = (result) => (result.ok ? "OK" : result.code);
const compare = (event, label) => {
  const ref = refSchema.validateCanonicalEventShape(event);
  const mine = events.validateEvent(event, LEGACY, 1);
  assert.equal(mineCode(mine), referenceCode(ref), `${label}: ${JSON.stringify({ ref: ref.reason, mine: mine.reason })}`);
  if (!ref.ok && ref.code === "EVENT_DATA_INVALID" && !ref.reason.startsWith("$.data: failed") && !ref.reason.includes("byte limit")) {
    assert.equal(mine.reason, legacyAdministrativeTypes(ref.reason), label);
  }
  return mine;
};
// A-28: legacy reads follow the reference-0.3 oracle (preview.10.2), whose administrative challenge admits the ten
// administrative types (types 29–31 included, `reference-0.3/.../event-schema.ts:1166-1177`); the Continuity 0.2 reference
// used here lists the seven it knew. Same code, one literal list in the reason.
const SEVEN = "must be one of OBLIGATION_CREATED, OBLIGATION_PERFORMANCE_ASSIGNED, OBLIGATION_STATUS_RECORDED, OUTCOME_OBSERVATION_RECORDED, ATTEMPT_DUTY_CREATED, ATTEMPT_DUTY_ASSIGNED, ATTEMPT_DUTY_REVIEW_CLOSED";
const legacyAdministrativeTypes = (reason) =>
  (reason.includes(".transitionEventType: ") && reason.endsWith(SEVEN) ? `${reason}, ATTEMPT_DUTY_POLICY_ACTIVATED, ATTEMPT_DUTY_DISPOSITION_RECORDED, ATTEMPT_DUTY_CONTEST_RECORDED` : reason);

test("adapter policy hashes, descriptors and profiles equal the reference constants", () => {
  assert.deepEqual(editions.ADAPTER_POLICY_HASHES, {
    E1: refAdapter.PORTABLE_ADAPTER_POLICY_HASH, E2: refAdapter.PORTABLE_ADAPTER_POLICY_E2_HASH, E3: refAdapter.PORTABLE_ADAPTER_POLICY_E3_HASH,
    E4: refAdapter.PORTABLE_ADAPTER_POLICY_E4_HASH, E5: refAdapter.PORTABLE_ADAPTER_POLICY_E5_HASH, E6: refAdapter.PORTABLE_ADAPTER_POLICY_E6_HASH,
  });
  assert.equal(events.ADAPTER_POLICY_HASHES.E1, "0x00c3498e2744943663475d0187ca979cdd09763b88427781883693c4b8c163a7");
  for (const id of Object.keys(editions.ADAPTER_DESCRIPTORS)) {
    assert.deepEqual(editions.knownAdapterProfile(id), refAdapter.knownPortableAdapterProfile(id), id);
    assert.equal(editions.knownAdapterAcknowledgmentVersion(editions.knownAdapterProfile(id)), refAdapter.knownPortableAdapterAcknowledgmentVersion(refAdapter.knownPortableAdapterProfile(id)));
  }
  for (const edition of ["E1", "E2", "E3", "E4", "E5", "E6"]) {
    const hash = editions.ADAPTER_POLICY_HASHES[edition];
    const policy = editions.resolveAdapterPolicy(hash), ref = refAdapter.resolvePortableAdapterPolicy(hash);
    assert.equal(policy.edition, ref.edition);
    assert.deepEqual(policy.profiles.map((p) => p.profileId), ref.profiles.map((p) => p.profileId));
    assert.equal(canonicalEncode(policy), canonicalEncode(ref));
  }
  assert.equal(editions.resolveAdapterPolicy(`0x${"1".repeat(64)}`), undefined);
  assert.throws(() => editions.approvedAdapterProfileForPolicy(editions.ADAPTER_POLICY_HASHES.E1, "adapter:remote-service-report"));
});

test("adapter acknowledgments, no-effects and evidence match the reference for every fixture consumption", () => {
  for (const name of FIXTURES) {
    const history = load(name);
    for (const event of history) {
      if (event.type !== "TRANSACTION_INTENT_CONSUMED" && !(event.type === "TRANSACTION_OUTCOME_RECORDED" && event.data.noEffect)) continue;
      const ack = event.data.acknowledgment ?? event.data.noEffect;
      const shape = event.data.acknowledgment ? "validateAdapterAcknowledgmentShape" : "validateAdapterNoEffectShape";
      const refShape = event.data.acknowledgment ? "validatePortableAdapterAcknowledgmentShape" : "validatePortableAdapterNoEffectShape";
      assert.equal(editions[shape](ack), refAdapter[refShape](ack), `${name} ${event.id}`);
      assert.equal(editions[shape](ack), true);
      assert.equal(editions[shape]({ ...ack, extra: 1 }), false);
      assert.equal(editions[shape]({ ...ack, intentId: "other" }), false);
      const identity = { ...ack, adapterProfile: ack.adapterProfile, durableEventHistoryHash: ack.admissionHead.hash,
        adapterNoEffectReference: editions.deriveAdapterNoEffectReference(ack.idempotencyKey, ack.submissionFingerprint, "keccak256") };
      delete identity.schemaVersion; delete identity.kind; delete identity.result;
      if (event.data.acknowledgment) {
        assert.equal(editions.validateAdapterAcknowledgment(ack, identity), true);
        assert.equal(editions.adapterAcknowledgmentTransactionReference(ack, identity), refAdapter.portableAdapterAcknowledgmentTransactionReference(ack, identity));
        assert.deepEqual(editions.adapterAcknowledgmentEvidence(identity, ack), refAdapter.portableAdapterAcknowledgmentEvidence(identity, ack));
        assert.deepEqual(editions.adapterAcknowledgmentEvidence(identity, ack), event.data.evidenceReference);
      } else {
        assert.equal(editions.validateAdapterNoEffect(ack, identity), true);
        assert.deepEqual(editions.adapterNoEffectEvidence(identity, ack), refAdapter.portableAdapterNoEffectEvidence(identity, ack));
        assert.deepEqual(editions.createAdapterNoEffect(identity), refAdapter.createPortableAdapterNoEffect(identity));
      }
    }
  }
});

test("adapter identity derivation matches the reference for every fixture admission", () => {
  for (const name of FIXTURES) {
    const history = load(name);
    const state = core.replayPortable({ operationVersion: core.PORTABLE_REPLAY_VERSION, events: history });
    assert.equal(state.status, "ACCEPTED", name);
    const hashes = refSchemaPrefixes(history);
    const genesis = history[0].data;
    for (const [position, event] of history.entries()) {
      if (event.type !== "TRANSACTION_INTENT_ADMITTED") continue;
      const declaration = history.find((e) => e.type === "TRANSACTION_INTENT_DECLARED" && e.data.intentId === event.data.intentId);
      const head = { hash: hashes[position], position, canonicalTime: event.timestamp };
      const mine = editions.deriveAdapterIdentityForAcceptedAdmission(event, head, declaration.data.adapterProfile, genesis.adapterPolicyHash);
      const ref = refAdapter.derivePortableAdapterIdentityForAcceptedAdmission(event, head, declaration.data.adapterProfile, genesis.adapterPolicyHash);
      assert.equal(canonicalEncode(mine), canonicalEncode(ref), `${name} ${event.id}`);
      assert.equal(editions.createAdapterAcknowledgment(mine, mine.adapterProfile.profileId === "adapter:simulated" ? undefined : `0x${"ab".repeat(32)}`) !== undefined, true);
    }
  }
});
const refCanonical = await referenceCore02("core/canonical.ts");
const refSchemaPrefixes = (history) => refCanonical.hashEventHistoryPrefixes(history);

test("every fixture event passes the closed schema and encodes to the reference canonical text", () => {
  let count = 0;
  for (const name of FIXTURES) {
    for (const event of load(name)) {
      const mine = compare(event, `${name} ${event.id}`);
      assert.equal(mine.ok, true, `${name} ${event.id}: ${mine.reason}`);
      assert.equal(canonicalEncode(mine.event), core.canonicalEncode(event));
      assert.equal(hashCanonical(mine.event, "keccak256"), core.hashCanonical(event));
      count += 1;
    }
  }
  assert.ok(count > 100);
});

/** Structural mutations at every path of a data record: the same code (and reason) as the reference, for each event type. */
const mutations = (value) => [undefined, 5, "", null, "x".repeat(300), { unexpected: true }, -1, 1.5]
  .filter((candidate) => typeof candidate !== typeof value || candidate === "" || candidate === -1 || candidate === 1.5);
const setAt = (root, path, value) => {
  const copy = structuredClone(root);
  let node = copy;
  for (const key of path.slice(0, -1)) node = node[key];
  const last = path[path.length - 1];
  if (value === undefined) { if (Array.isArray(node)) node.splice(last, 1); else delete node[last]; } else node[last] = value;
  return copy;
};
const paths = (value, prefix = []) => {
  if (value === null || typeof value !== "object") return [];
  const out = [];
  const entries = Array.isArray(value) ? value.map((v, i) => [i, v]) : Object.entries(value);
  for (const [key, child] of entries) {
    out.push([...prefix, key]);
    if (Array.isArray(value) && key > 1) continue; // two members per list are enough
    out.push(...paths(child, [...prefix, key]));
  }
  return out;
};

test("mutation differential: every data path of every event type yields the reference code", () => {
  const seen = new Map();
  let checked = 0;
  for (const name of FIXTURES) {
    for (const event of load(name)) {
      if ((seen.get(event.type) ?? 0) >= 2) continue;
      seen.set(event.type, (seen.get(event.type) ?? 0) + 1);
      for (const path of paths(event.data)) {
        const original = path.reduce((node, key) => node[key], event.data);
        for (const candidate of mutations(original)) {
          compare({ ...event, data: setAt(event.data, path, candidate) }, `${event.type} ${event.id} ${path.join(".")}=${String(candidate)}`);
          checked += 1;
        }
      }
      for (const candidate of [{ ...event, extra: 1 }, { ...event, id: "" }, { ...event, id: 5 }, { ...event, timestamp: -1 }, { ...event, timestamp: 1.5 },
        { ...event, type: "" }, { ...event, type: "NOPE" }, { ...event, data: [] }, { ...event, data: null }, { ...event, data: { ...event.data, extra: undefined } }]) {
        compare(candidate, `${event.type} envelope ${JSON.stringify(Object.keys(candidate))}`);
        checked += 1;
      }
    }
  }
  assert.ok(seen.size >= 20, `event types covered: ${[...seen.keys()].join(",")}`);
  assert.ok(checked > 2000);
});

test("named-limit precedence: an identifier overflow beats an earlier semantic defect", () => {
  const genesis = load("handover-history.json")[0];
  const principal = load("handover-history.json")[1];
  const long = "p".repeat(257);
  assert.equal(events.validateEvent({ ...principal, data: { principalId: long } }, LEGACY, 1).code, "INVALID_INPUT");
  assert.equal(events.validateEvent({ ...principal, data: { zzz: 1, principalId: long } }, LEGACY, 1).code, "INVALID_INPUT");
  assert.equal(events.validateEvent({ ...principal, data: { zzz: 1, principalId: "ok" } }, LEGACY, 1).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...principal, data: { principalId: "a".repeat(4097) } }, LEGACY, 1).code, "INVALID_INPUT");
  const grant = load("mandate-history.json").find((e) => e.type === "AUTHORITY_GRANTED" && e.data.grant.constraints.maxAmount !== undefined);
  const huge = { ...grant, data: { grant: { ...grant.data.grant, constraints: { ...grant.data.grant.constraints, maxAmount: 1n << 256n } } } };
  assert.equal(events.validateEvent(huge, LEGACY, 1).code, "INVALID_INPUT"); // replay semantics (spec 01 §C.3), unlike the standalone validator
  // Position 0 rules.
  assert.equal(events.validateEvent(principal, LEGACY, 0).code, "GENESIS_REQUIRED");
  const versions = (patch) => ({ ...genesis, data: { ...genesis.data, versions: { ...genesis.data.versions, ...patch } } });
  // An event schema this engine does not implement is UNSUPPORTED_VERSION before the probe (SPEC-IRONTRELLIS-CORE-v2 §19; parity with the Python verifier), not the fallback schema's UNSUPPORTED_EVENT_SCHEMA.
  assert.equal(events.validateEvent(versions({ eventSchemaVersion: "continuity-event/0.3" }), LEGACY, 0).code, "UNSUPPORTED_VERSION");
  assert.equal(events.validateEvent(versions({ eventSchemaVersion: 3 }), LEGACY, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(versions({ signatureScheme: "ed25519" }), LEGACY, 0).code, "UNSUPPORTED_VERSION");
  assert.equal(events.validateEvent(versions({ signatureScheme: "" }), LEGACY, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, adapterPolicyHash: `0x${"1".repeat(64)}` } }, LEGACY, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(genesis, LEGACY, 0).ok, true);
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, versions: { ...genesis.data.versions, signatureScheme: "ed25519" } } }, LEGACY, 1).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateGenesis(genesis.data, LEGACY).ok, true);
  assert.equal(events.validateGenesis({ ...genesis.data, finality: "GLOBAL" }, LEGACY).ok, false);
});

// ---------------------------------------------------------------- format 1

const ed25519 = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  return { privateKey, credential: `0x${Buffer.from(raw).toString("hex")}` };
};
const TRELLIS = "irontrellis-event/1";
const trellisGenesis = (owner) => ({
  domain: { protocol: "irontrellis", version: "1", deploymentId: "deployment:test" },
  versions: { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" },
  ownerKeys: [{ keyId: "owner:1", scheme: "ed25519", credential: owner.credential }],
  adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: "lineage:test", policyVersion: "policy:test/1",
  rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:test", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
  capacity: { maxEvents: null },
});

test("format-1 genesis declares exactly the version literals used on the wire", async () => {
  const { AUTHORIZATION_PROOF_VERSION, RUNTIME_AUTHORIZATION_VERSION } = await import("../src/authority.ts");
  const { ADMINISTRATIVE_AUTHORIZATION_VERSION } = await import("../src/administration.ts");
  const { QUERY_VERSION } = await import("../src/query-codec.ts");
  assert.deepEqual({ ...events.TRELLIS_VERSIONS }, {
    eventSchemaVersion: TRELLIS, historyHashAlgorithm: "sha256", receiptSchemaVersion: "irontrellis-receipt/1",
    controlAuthorizationVersion: events.CONTROL_AUTHORIZATION_VERSION, queryEnvelopeVersion: QUERY_VERSION,
    authorizationProofVersion: AUTHORIZATION_PROOF_VERSION, runtimeAuthorizationVersion: RUNTIME_AUTHORIZATION_VERSION,
    administrativeAuthorizationVersion: ADMINISTRATIVE_AUTHORIZATION_VERSION,
  });
  const genesis = { id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0, data: trellisGenesis(ed25519()) };
  // The earlier declared-but-unused literals are refused, and the record stays closed.
  for (const [key, value] of [["queryEnvelopeVersion", "irontrellis-query-envelope/1"], ["authorizationProofVersion", "irontrellis-authorization-proof/1"], ["runtimeAuthorizationVersion", "irontrellis-runtime-authorization/1"]]) {
    assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, versions: { ...genesis.data.versions, [key]: value } } }, TRELLIS, 0).code, "UNSUPPORTED_VERSION");
  }
  const { administrativeAuthorizationVersion: _omitted, ...withoutAdministrative } = genesis.data.versions;
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, versions: withoutAdministrative } }, TRELLIS, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, versions: { ...genesis.data.versions, extraVersion: "x/1" } } }, TRELLIS, 0).code, "EVENT_DATA_INVALID");
});

test("format-1 genesis, sessions, anchors and control effects validate; legacy rules reject them", () => {
  const owner = ed25519();
  const genesis = { id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0, data: trellisGenesis(owner) };
  assert.equal(events.validateEvent(genesis, TRELLIS, 0).ok, true);
  assert.equal(events.validateGenesis(genesis.data, TRELLIS).ok, true);
  assert.equal(events.validateEvent(genesis, LEGACY, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, ownerKeys: [] } }, TRELLIS, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, ownerKeys: [genesis.data.ownerKeys[0], genesis.data.ownerKeys[0]] } }, TRELLIS, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, versions: { ...genesis.data.versions, historyHashAlgorithm: "keccak256" } } }, TRELLIS, 0).code, "UNSUPPORTED_VERSION");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, versions: { ...genesis.data.versions, signatureScheme: "rsa" } } }, TRELLIS, 0).code, "UNSUPPORTED_VERSION");
  const legacyGenesis = load("handover-history.json")[0];
  const migratedFrom = { format: LEGACY, historyHash: `0x${"a".repeat(64)}`, position: 3, recordHash: `0x${"b".repeat(64)}`, genesis: legacyGenesis.data, genesisEventId: legacyGenesis.id, genesisTimestamp: legacyGenesis.timestamp };
  const withMigration = (patch) => ({ ...genesis, data: { ...genesis.data, migratedFrom: { ...migratedFrom, ...patch } } });
  assert.equal(events.validateEvent(withMigration({}), TRELLIS, 0).ok, true);
  assert.equal(events.validateEvent(withMigration({ format: TRELLIS }), TRELLIS, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(withMigration({ genesis: { ...legacyGenesis.data, finality: "X" } }), TRELLIS, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(withMigration({ genesis: genesis.data }), TRELLIS, 0).code, "EVENT_DATA_INVALID"); // the source genesis must be legacy-shaped
  assert.equal(events.validateEvent(withMigration({ genesisEventId: "" }), TRELLIS, 0).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ ...genesis, data: { ...genesis.data, migratedFrom: { format: LEGACY, historyHash: `0x${"a".repeat(64)}`, position: 3, recordHash: `0x${"b".repeat(64)}` } } }, TRELLIS, 0).code, "EVENT_DATA_INVALID");
  // Shadow mode: a re-recorded legacy admission keeps its legacy domain and signature shapes.
  const admission = load("handover-history.json").find((e) => e.type === "TRANSACTION_INTENT_ADMITTED");
  assert.equal(events.validateEvent(admission, TRELLIS, 14).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(admission, TRELLIS, 14, { shadow: true }).ok, true);
  assert.equal(events.legacyProjection(admission), admission);
  const auth = { controlAuthorization: { keyId: "owner:1", signature: `0x${"1".repeat(128)}` } };
  const session = { id: "s", type: "RUNTIME_SESSION_ADMITTED", timestamp: 1, data: { sessionId: "session:1", agentId: "a", controllerId: "c", controlEpoch: 1, credentialKeyId: "k", credentialScheme: "ed25519", credentialPublicKey: owner.credential, ...auth } };
  assert.equal(events.validateEvent(session, TRELLIS, 1).ok, true);
  assert.equal(events.validateEvent({ ...session, data: { ...session.data, credentialAddress: `0x${"0".repeat(40)}` } }, TRELLIS, 1).code, "EVENT_DATA_INVALID");
  const eip = { ...session, data: { ...session.data, credentialScheme: "eip191-personal-sign-keccak256", credentialPublicKey: undefined, credentialAddress: `0x${"0".repeat(40)}` } };
  assert.equal(events.validateEvent(eip, TRELLIS, 1).ok, true);
  assert.deepEqual(events.sessionCredential(eip.data, TRELLIS), { scheme: "eip191-personal-sign-keccak256", key: `0x${"0".repeat(40)}` });
  assert.deepEqual(events.sessionCredential(session.data, TRELLIS), { scheme: "ed25519", key: owner.credential.toLowerCase() });
  assert.equal(events.validateEvent(session, LEGACY, 1).code, "EVENT_DATA_INVALID");
  const anchor = { id: "anchor", type: "ANCHOR_RECORDED", timestamp: 2, data: { anchoredHead: { hash: `0x${"a".repeat(64)}`, position: 0, canonicalTime: 0 }, anchor: "local-head-file", receipt: { note: "x" }, anchoredAt: 2, ...auth } };
  assert.equal(events.validateEvent(anchor, TRELLIS, 1).ok, true);
  assert.equal(events.validateEvent({ ...anchor, data: { ...anchor.data, witness: "bogus" } }, TRELLIS, 1).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(anchor, LEGACY, 1).code, "UNSUPPORTED_EVENT_TYPE");
  // Control effect excludes the authorization; the challenge is deterministic and binds the previous head.
  const validated = events.validateEvent(session, TRELLIS, 1);
  assert.equal(events.controlEffectHash(validated.event, "sha256"), hashCanonical({ ...session.data, controlAuthorization: undefined }, "sha256"));
  const challenge = { domain: genesis.data.domain, eventId: "s", eventType: "RUNTIME_SESSION_ADMITTED", timestamp: 1, previousHead: { hash: `0x${"c".repeat(64)}`, position: 0 }, effectHash: `0x${"d".repeat(64)}` };
  assert.equal(events.controlAuthorizationHash(challenge, "sha256"), events.controlAuthorizationHash({ ...challenge }, "sha256"));
  assert.notEqual(events.controlAuthorizationHash(challenge, "sha256"), events.controlAuthorizationHash({ ...challenge, previousHead: null }, "sha256"));
  assert.equal(events.controlAuthorizationChallenge(challenge).version, "irontrellis-control-authorization/1");
  // A legacy control event must not carry a control authorization.
  const principal = { id: "p", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner", ...auth } };
  assert.equal(events.validateEvent(principal, LEGACY, 1).code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent(principal, TRELLIS, 1).ok, true);
  assert.equal(events.validateEvent({ ...principal, data: { principalId: "owner" } }, TRELLIS, 1).ok, true);
  assert.deepEqual(events.legacyProjection(principal), { ...principal, data: { principalId: "owner" } });
  assert.deepEqual(Object.keys(events.legacyProjection(session).data).sort(), ["agentId", "controlEpoch", "controllerId", "credentialKeyId", "credentialPublicKey", "sessionId"]);
});

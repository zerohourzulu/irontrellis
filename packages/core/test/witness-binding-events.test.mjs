// Remote witness bindings as their own owner-signed control events (WITNESSES_BOUND / WITNESSES_UNBOUND; provenance:
// coherence F1, which replaced bindings carried in ANCHOR_RECORDED receipts): the closed schema, the transition rules
// replay enforces (the REGISTERED receipt verified with the bound witness's key against this very genesis, at most 16
// bound, the quorum against the witnesses bound after the event, unbinding only bound witnesses, an accepted loss only of
// a head this copy lacks), the state readers, and that no anchor, whatever its receipt, binds anything. The same cases
// run in Python (python/tests/test_witness_bindings.py).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const { replay } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const signer = await import("../src/signer.ts");
const suites = await import("../src/crypto/suites.ts");
const { boundPolicyOf, boundRegistrationOf, boundWitnessesOf, witnessBindingEvent } = await import("../src/witness-session.ts");
const types = await import("../src/types.ts");

const ROOT = join(import.meta.dirname, "..", "..", "..");
const history = (name) => JSON.parse(readFileSync(join(ROOT, "conformance", "v1", "histories", `${name}.json`), "utf8"));
const base = history("handover-v1");
const bound = history("witness-bound-v1");
const [a, b] = bound[base.length].data.witnesses;
const plainA = Object.fromEntries(Object.entries(a).filter(([key]) => key !== "registration"));
const owner = signer.signerFromKeyPair(suites.keyPairFromPrivateKey("ed25519", "owner:1", `0x${(0x1001).toString(16).padStart(64, "0")}`));
const policy = (quorum = 1) => ({ quorum, requireOnOpen: true, maxUnwitnessedEvents: 100 });
const plain = (value) => JSON.parse(JSON.stringify(value));

/** `event` signed by the conformance owner key as the next control event of `list`. */
async function signed(list, event) {
  const accepted = replay(list);
  assert.equal(accepted.status, "ACCEPTED", `${accepted.code} ${accepted.reason}`);
  const timed = { ...event, timestamp: Math.max(event.timestamp ?? 0, accepted.head.canonicalTime) };
  return [...list, plain(await signer.signControlEvent(owner, timed, accepted.state.genesis.domain, accepted.head, "sha256"))];
}
const bind = (list, witnesses, quorum = 1, id = "binding:ts") => signed(list, { id, type: "WITNESSES_BOUND", data: { witnesses, policy: policy(quorum) } });
const unbind = (list, keys, quorum = 1, extra = {}, id = "unbinding:ts") => signed(list, { id, type: "WITNESSES_UNBOUND", data: { verifierKeys: keys, policy: policy(quorum), ...extra } });
const rejected = (list, code, fragment) => {
  const result = replay(list);
  assert.equal(result.status, "REJECTED");
  assert.equal(result.code, code, result.reason);
  if (fragment !== undefined) assert.ok(result.reason.includes(fragment), result.reason);
};

test("vocabulary: two format-1 control events, always admitted; nothing else binds", () => {
  for (const type of ["WITNESSES_BOUND", "WITNESSES_UNBOUND"]) {
    assert.ok(types.EVENT_TYPES.includes(type) && types.CONTROL_EVENT_TYPES.has(type) && types.TRELLIS_ONLY_EVENT_TYPES.has(type) && types.ALWAYS_ADMITTED_EVENT_TYPES.has(type));
  }
  assert.deepEqual([...events.ANCHOR_NAMES], ["local-head-file", "rekor-v2", "custom"]);
  assert.equal(events.MAX_BOUND_WITNESSES, 16);
});

test("bind, re-bind in place, unbind; the readers report what replay applied", async () => {
  let list = await bind(base, [a, b], 2);
  let state = replay(list).state;
  assert.deepEqual(state.boundWitnesses.map((w) => w.verifierKey), [a.verifierKey, b.verifierKey]);
  assert.equal(state.boundWitnesses[0].registration.index, 0);
  assert.equal(boundRegistrationOf(state, a.verifierKey).index, 0);
  assert.equal(boundRegistrationOf(state, b.verifierKey), undefined);
  assert.deepEqual(boundPolicyOf(state), policy(2));
  assert.deepEqual(plain(boundWitnessesOf(state)), [{ url: a.url, verifierKey: a.verifierKey, name: a.name }, { url: b.url, verifierKey: b.verifierKey }]);
  list = await bind(list, [{ ...plainA, url: "https://witness-a.example.org/v2" }], 2, "binding:again");
  state = replay(list).state;
  assert.deepEqual(state.boundWitnesses.map((w) => w.url), ["https://witness-a.example.org/v2", b.url]);
  assert.equal(state.boundWitnesses[0].registration, undefined);
  list = await unbind(list, [b.verifierKey]);
  assert.deepEqual(replay(list).state.boundWitnesses.map((w) => w.verifierKey), [a.verifierKey]);
  // witnessBindingEvent builds exactly these shapes.
  assert.deepEqual(plain(witnessBindingEvent({ action: "UNBIND", witnesses: [a], policy: policy() })), { type: "WITNESSES_UNBOUND", data: { verifierKeys: [a.verifierKey], policy: policy() } });
  assert.deepEqual(plain(witnessBindingEvent({ action: "BIND", witnesses: [plainA], policy: policy() })), { type: "WITNESSES_BOUND", data: { witnesses: [plainA], policy: policy() } });
  assert.throws(() => witnessBindingEvent({ action: "BIND", witnesses: [plainA], policy: { quorum: 0, requireOnOpen: true, maxUnwitnessedEvents: 1 } }), (e) => e.code === "INVALID_INPUT");
});

test("schema: URL, verifier key, name, allowInsecureHttp, registration record, policy, accepted loss; closed records", () => {
  const check = (data, type = "WITNESSES_BOUND") => events.validateEvent({ id: "x", type, timestamp: 1, data }, "irontrellis-event/1", 5);
  assert.equal(check({ witnesses: [plainA], policy: policy() }).ok, true);
  for (const url of ["ftp://witness", "https://witness/", "https://user@witness", "https://witness?x=1", "https://witness#f", "https://wit ness", "https://wïtness", "https://", ""]) {
    assert.equal(check({ witnesses: [{ ...plainA, url }], policy: policy() }).code, "EVENT_DATA_INVALID", url);
  }
  assert.equal(check({ witnesses: [{ ...plainA, url: "http://127.0.0.1:8080/w" }], policy: policy() }).ok, true);
  assert.equal(check({ witnesses: [{ ...plainA, verifierKey: "not+a+key" }], policy: policy() }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: [{ ...plainA, allowInsecureHttp: false }], policy: policy() }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: [{ ...plainA, registration: "receipt" }], policy: policy() }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: [{ ...plainA, extra: 1 }], policy: policy() }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: [plainA, plainA], policy: policy() }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: [], policy: policy() }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: Array(17).fill(plainA), policy: policy() }).code, "INVALID_INPUT");
  assert.equal(check({ witnesses: [{ ...plainA, name: "n".repeat(257) }], policy: policy() }).code, "INVALID_INPUT");
  for (const bad of [{ quorum: 0, requireOnOpen: true, maxUnwitnessedEvents: 1 }, { quorum: 17, requireOnOpen: true, maxUnwitnessedEvents: 1 },
    { quorum: 1, requireOnOpen: 1, maxUnwitnessedEvents: 1 }, { quorum: 1, requireOnOpen: true, maxUnwitnessedEvents: 0 },
    { quorum: 1, requireOnOpen: true }, { quorum: 1, requireOnOpen: true, maxUnwitnessedEvents: 1, cacheMs: 1 }]) {
    assert.equal(check({ witnesses: [plainA], policy: bad }).code, "EVENT_DATA_INVALID", JSON.stringify(bad));
  }
  assert.equal(check({ witnesses: [plainA] }).code, "EVENT_DATA_INVALID");
  assert.equal(check({ witnesses: [plainA], policy: policy(), acceptedLoss: { reason: "r", heads: [] } }).code, "EVENT_DATA_INVALID", "only an unbinding records a loss");
  const head = { hash: `0x${"ee".repeat(32)}`, position: 40, canonicalTime: 1 };
  const loss = { reason: "restored", heads: [{ verifierKey: a.verifierKey, head }] };
  assert.equal(check({ verifierKeys: [a.verifierKey], policy: policy(), acceptedLoss: loss }, "WITNESSES_UNBOUND").ok, true);
  assert.equal(check({ verifierKeys: [a.verifierKey], policy: policy(), acceptedLoss: { ...loss, reason: "" } }, "WITNESSES_UNBOUND").code, "EVENT_DATA_INVALID");
  assert.equal(check({ verifierKeys: [a.verifierKey], policy: policy(), acceptedLoss: { ...loss, heads: [] } }, "WITNESSES_UNBOUND").code, "EVENT_DATA_INVALID");
  assert.equal(check({ verifierKeys: [], policy: policy() }, "WITNESSES_UNBOUND").code, "EVENT_DATA_INVALID");
  assert.equal(check({ verifierKeys: [a.verifierKey, a.verifierKey], policy: policy() }, "WITNESSES_UNBOUND").code, "EVENT_DATA_INVALID");
  assert.equal(events.validateEvent({ id: "x", type: "WITNESSES_BOUND", timestamp: 1, data: { witnesses: [plainA], policy: policy() } }, "continuity-event/0.2", 5).code, "UNSUPPORTED_EVENT_TYPE");
});

test("transition rules: receipts, quorum, unbinding, accepted loss", async () => {
  rejected(await bind(base, [{ ...b, registration: a.registration }]), "TRANSITION_INVALID", "does not verify");
  rejected(await bind(base, [{ ...a, registration: { ...a.registration, inclusionProof: ["AAAA"] } }]), "TRANSITION_INVALID", "does not verify");
  rejected(await bind([{ ...base[0], id: "another-genesis" }], [a]), "TRANSITION_INVALID", "not the REGISTERED leaf of this history");
  rejected(await bind(base, [a], 2), "TRANSITION_INVALID", "exceeds the 1 witness(es)");
  const list = await bind(base, [a, b], 2);
  rejected(await unbind(list, [b.verifierKey], 2), "TRANSITION_INVALID", "exceeds the 1 witness(es)");
  assert.equal(replay(await unbind(list, [a.verifierKey, b.verifierKey], 1)).status, "ACCEPTED", "unbinding every witness leaves quorum 1");
  rejected(await unbind(base, [a.verifierKey]), "TRANSITION_INVALID", "is not bound");
  const head = replay(list).state.head;
  rejected(await unbind(list, [b.verifierKey], 1, { acceptedLoss: { reason: "restored", heads: [{ verifierKey: b.verifierKey, head }] } }), "TRANSITION_INVALID", "nothing was lost");
  rejected(await unbind(list, [b.verifierKey], 1, { acceptedLoss: { reason: "restored", heads: [{ verifierKey: a.verifierKey, head: { ...head, position: head.position + 3 } }] } }), "TRANSITION_INVALID", "does not unbind");
  assert.equal(replay(await unbind(list, [b.verifierKey], 1, { acceptedLoss: { reason: "restored", heads: [{ verifierKey: b.verifierKey, head: { ...head, hash: `0x${"ee".repeat(32)}` } }] } })).status, "ACCEPTED");
  // More than 16 bound in total (each event names at most 16): refused.
  const tp = await import("../src/transparency/index.ts");
  const many = Array.from({ length: 17 }, (_, n) => {
    const s = tp.noteSignerFromSeed(`w${n}.example`, new Uint8Array(32).fill(n + 1));
    return { url: `https://w${n}.example`, verifierKey: tp.verifierKey(s.name, s.publicKey) };
  });
  const sixteen = await bind(base, many.slice(0, 16));
  assert.equal(replay(sixteen).state.boundWitnesses.length, 16);
  rejected(await bind(sixteen, many.slice(16), 1, "binding:17"), "TRANSITION_INVALID", "at most 16");
});

test("anchors never bind: a binding-shaped receipt is an anchor; \"http-witness\" is not an anchor kind", async () => {
  const list = await bind(base, [a]);
  const head = replay(list).state.head;
  const shaped = { version: "irontrellis-witness-binding/1", action: "UNBIND", witnesses: [{ url: a.url, verifierKey: a.verifierKey }], policy: policy() };
  const anchored = await signed(list, { id: "anchor:ts", type: "ANCHOR_RECORDED", data: { anchoredHead: head, anchor: "custom", receipt: shaped, anchoredAt: head.canonicalTime } });
  const state = replay(anchored).state;
  assert.deepEqual(state.boundWitnesses.map((w) => w.verifierKey), [a.verifierKey]);
  assert.deepEqual(state.boundPolicy, policy());
  assert.equal(state.anchors.length, 1);
  rejected(await signed(list, { id: "anchor:http", type: "ANCHOR_RECORDED", data: { anchoredHead: head, anchor: "http-witness", receipt: shaped, anchoredAt: head.canonicalTime } }), "EVENT_DATA_INVALID");
});

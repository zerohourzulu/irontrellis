// Owner-signed head statements (WITNESS-DESIGN §2.2) and witness log entries (§2.3),
// over a real format-1 history (conformance/transparency/scenario.mjs).
import { test } from "node:test";
import assert from "node:assert/strict";

const { transparency: t, replayModule, hash, signer, suites, buildScenario, keysAt, DOMAIN } = await import("./transparency-scenario.mjs");
const { canonicalEncode } = await import("../src/canonical.ts");

const S = await buildScenario();
const only1 = () => S.ownerKeys1;
const byEpoch = (position) => keysAt(S.ownerKeyEpochs, position);
const clone = (value) => JSON.parse(JSON.stringify(value));

test("the scenario history is a genuine format-1 history (positions 0..6 replay)", () => {
  const result = replayModule.replay(S.events.slice(0, 7));
  assert.equal(result.status, "ACCEPTED", JSON.stringify(result));
  assert.deepEqual(result.state.eventHistoryHashes, S.heads.slice(0, 7).map((head) => head.hash));
  assert.deepEqual(result.state.head, S.heads[6]);
  assert.equal(S.historyId, result.state.eventHistoryHashes[0]);
  assert.notEqual(S.fork.heads[6].hash, S.heads[6].hash);
  assert.equal(S.fork.heads[5].hash, S.heads[5].hash);
});

test("statement hash is hashCanonical of exactly the statement fields (sha256), signed like a head attestation", async () => {
  const statement = S.statement(S.heads[3], S.heads[0]);
  const expected = hash.hashCanonical({ version: "irontrellis-head-statement/1", historyId: S.historyId, domain: DOMAIN, head: S.heads[3], previous: { hash: S.heads[0].hash, position: 0 } }, "sha256");
  assert.equal(t.headStatementHash(statement), expected);
  assert.equal(t.HEAD_STATEMENT_VERSION, "irontrellis-head-statement/1");
  const signed = await t.signHeadStatement(S.owner1, statement);
  assert.deepEqual(Object.keys(signed).sort(), ["keyId", "scheme", "signature", "statement"]);
  assert.equal(signed.keyId, "owner:1");
  assert.equal(signed.scheme, "ed25519");
  assert.equal(suites.suiteFor("ed25519").verify(expected, signed.signature, S.owner1.credential), true);
  assert.deepEqual(signed, S.statements.s3);
  // Extra properties on the input are not signed or carried.
  const withExtra = await t.signHeadStatement(S.owner1, { ...statement, extra: 1 }).catch((error) => error);
  assert.equal(withExtra.code, "INVALID_INPUT");
  // Canonical-JSON encodable, and survives a JSON round trip unchanged.
  assert.equal(canonicalEncode(clone(signed)), canonicalEncode(signed));
  assert.deepEqual(t.verifySignedHeadStatement(clone(signed), only1), { ok: true });
});

test("sync signing matches async signing for local Ed25519 keys", async () => {
  const pair = suites.keyPairFromPrivateKey("ed25519", "owner:1", `0x${(0x3001).toString(16).padStart(64, "0")}`);
  const local = signer.signerFromKeyPair(pair);
  const statement = S.statement(S.heads[6], S.heads[3]);
  assert.deepEqual(t.signHeadStatementSync(local, statement), await t.signHeadStatement(local, statement));
  assert.equal(t.signHeadStatementSync(S.owner1, statement), undefined, "a signer without signHashSync");
});

test("verifySignedHeadStatement: ok, UNKNOWN_KEY, SIGNATURE_INVALID, MALFORMED", async () => {
  const { s0, s3, s6, s8 } = S.statements;
  for (const signed of [s0, s3, s6]) assert.deepEqual(t.verifySignedHeadStatement(signed, only1), { ok: true });
  // Key validity is per head position (the callback receives head.position).
  const seen = [];
  t.verifySignedHeadStatement(s8, (position) => { seen.push(position); return S.ownerKeys2; });
  assert.deepEqual(seen, [8]);
  assert.deepEqual(t.verifySignedHeadStatement(s8, byEpoch), { ok: true });
  assert.deepEqual(t.verifySignedHeadStatement(s8, only1), { ok: false, reason: "UNKNOWN_KEY" });
  assert.deepEqual(t.verifySignedHeadStatement(s6, () => S.ownerKeys2), { ok: false, reason: "UNKNOWN_KEY" });
  assert.deepEqual(t.verifySignedHeadStatement(s6, () => { throw new Error("no epochs"); }), { ok: false, reason: "UNKNOWN_KEY" });
  assert.deepEqual(t.verifySignedHeadStatement(s6, () => [{ ...S.ownerKeys1[0], scheme: "eip191-personal-sign-keccak256" }]), { ok: false, reason: "UNKNOWN_KEY" });
  // Same key id, another credential: the signature does not verify.
  assert.deepEqual(t.verifySignedHeadStatement(s6, () => [{ ...S.ownerKeys2[0], keyId: "owner:1" }]), { ok: false, reason: "SIGNATURE_INVALID" });
  const tampered = (mutate) => { const copy = clone(s6); mutate(copy); return t.verifySignedHeadStatement(copy, only1); };
  assert.deepEqual(tampered((c) => { c.statement.head.canonicalTime += 1; }), { ok: false, reason: "SIGNATURE_INVALID" });
  assert.deepEqual(tampered((c) => { c.statement.domain.deploymentId = "deployment:other"; }), { ok: false, reason: "SIGNATURE_INVALID" });
  assert.deepEqual(tampered((c) => { c.statement.previous = { hash: S.heads[5].hash, position: 5 }; }), { ok: false, reason: "SIGNATURE_INVALID" });
  assert.deepEqual(tampered((c) => { c.signature = `0x${"00".repeat(64)}`; }), { ok: false, reason: "SIGNATURE_INVALID" });
  assert.deepEqual(tampered((c) => { c.signature = c.signature.slice(0, -2); }), { ok: false, reason: "MALFORMED" });
  assert.deepEqual(tampered((c) => { c.extra = 1; }), { ok: false, reason: "MALFORMED" });
  assert.deepEqual(tampered((c) => { c.statement.extra = 1; }), { ok: false, reason: "MALFORMED" });
  assert.deepEqual(tampered((c) => { c.scheme = "rsa"; }), { ok: false, reason: "MALFORMED" });
  assert.deepEqual(tampered((c) => { c.statement.previous.position = 7; }), { ok: false, reason: "MALFORMED" });
  for (const junk of [null, undefined, 1, "x", [], {}]) assert.deepEqual(t.verifySignedHeadStatement(junk, only1), { ok: false, reason: "MALFORMED" });
});

test("validateHeadStatement: structure and the previous/head rules", () => {
  const good = S.statement(S.heads[6], S.heads[3]);
  assert.equal(t.validateHeadStatement(good), null);
  assert.equal(t.validateHeadStatement(S.statement(S.heads[0], null)), null, "first statement");
  assert.equal(t.validateHeadStatement(S.statement(S.heads[6], null)), null, "previous null at any head");
  assert.equal(t.validateHeadStatement(S.statement(S.heads[6], S.heads[6])), null, "re-submission: previous equals head");
  const bad = [
    { ...good, previous: { hash: S.heads[6].hash, position: 7 } },
    { ...good, previous: { hash: S.heads[5].hash, position: 6 } },
    { ...good, previous: { hash: S.heads[3].hash, position: 0 } },
    { ...good, head: { ...S.heads[0], hash: S.heads[1].hash } },
    { ...good, version: "irontrellis-head-statement/2" },
    { ...good, historyId: S.historyId.toUpperCase() },
    { ...good, domain: { protocol: "continuity", version: "0.2", deploymentId: "d", chainId: "1", verifyingContract: `0x${"11".repeat(20)}` } },
    { ...good, domain: { ...DOMAIN, extra: 1 } },
    { ...good, head: { hash: S.heads[6].hash, position: 6 } },
    { ...good, head: { ...S.heads[6], position: -1 } },
    { ...good, head: { ...S.heads[6], position: 1.5 } },
    { ...good, head: { ...S.heads[6], canonicalTime: 2 ** 53 } },
    { ...good, previous: { hash: S.heads[3].hash, position: 3, canonicalTime: 5 } },
    { ...good, previous: undefined },
    (() => { const { previous: _p, ...rest } = good; return rest; })(),
    { ...good, extra: true },
  ];
  for (const [i, statement] of bad.entries()) assert.equal(typeof t.validateHeadStatement(statement), "string", `bad statement ${i}`);
  assert.throws(() => t.headStatementHash(bad[0]), (error) => error.code === "INVALID_INPUT");
});

// ---------------------------------------------------------------- entries

test("entries: canonical encoding, leaf hash, structural validation", () => {
  assert.equal(t.WITNESS_ENTRY_VERSION, "irontrellis-witness-entry/1");
  for (const entry of S.entries) {
    assert.equal(t.validateEntry(entry), null, entry.kind);
    const bytes = t.encodeEntry(entry);
    assert.equal(Buffer.from(bytes).toString("utf8"), canonicalEncode(entry));
    assert.deepEqual(t.entryLeafHash(entry), t.leafHash(bytes));
    assert.deepEqual(t.entryLeafHash(clone(entry)), t.entryLeafHash(entry), "JSON round trip keeps the leaf hash");
  }
  const [registered, head, , , rotated, , equivocation] = S.entries;
  const bad = [
    [null, "record"], [{ ...head, version: "irontrellis-witness-entry/2" }, "version"], [{ ...head, kind: "OTHER" }, "kind"],
    [{ ...head, receivedAt: -1 }, "receivedAt"], [{ ...head, historyId: "0x12" }, "historyId"], [{ ...head, extra: 1 }, "extra field"],
    [{ ...registered, genesis: { ...registered.genesis, timestamp: 1 } }, "genesis does not hash to historyId"],
    [{ ...registered, genesis: [] }, "genesis not a record"],
    [{ ...head, signedStatement: { ...head.signedStatement, signature: "0x00" } }, "signature shape"],
    [{ ...head, historyId: S.heads[1].hash }, "statement for another history"],
    [{ ...rotated, rotation: { ...rotated.rotation, type: "AGENT_CREATED" } }, "rotation type"],
    [{ ...rotated, rotationHead: { ...rotated.rotationHead, canonicalTime: 7 } }, "rotationHead shape"],
    [Object.fromEntries(Object.entries(rotated).filter(([key]) => key !== "previousHead")), "ROTATED without previousHead (§9.2)"],
    [{ ...rotated, previousHead: { ...rotated.previousHead, canonicalTime: 6 } }, "previousHead shape"],
    [{ ...rotated, previousHead: { ...rotated.previousHead, position: 5 } }, "previousHead not right before rotationHead"],
    [{ ...equivocation, second: equivocation.first }, "same head twice"],
    [(({ rotation, rotationHead, ...rest }) => ({ ...rest, kind: "COMMITTED", event: rotation, eventHead: rotationHead }))(rotated), "COMMITTED is not an entry kind (ROTATED is the only key-event leaf)"],
    [{ ...equivocation, second: S.statements.s3 }, "different positions"],
    [{ ...head, receivedAt: 1, signedStatement: { ...head.signedStatement, statement: { ...head.signedStatement.statement, head: { ...head.signedStatement.statement.head, canonicalTime: 1.5 } } } }, "non-U53 inside"],
  ];
  for (const [entry, why] of bad) assert.equal(typeof t.validateEntry(entry), "string", why);
  // Entries with a bigint inside encode identically as bigint or as the canonical marker.
  const withBig = { ...registered, genesis: { ...registered.genesis, data: { ...registered.genesis.data, amount: 5n } } };
  const withMarker = { ...registered, genesis: { ...registered.genesis, data: { ...registered.genesis.data, amount: { "$continuity.bigint": "5" } } } };
  assert.deepEqual(t.entryLeafHash(withBig), t.entryLeafHash(withMarker));
});

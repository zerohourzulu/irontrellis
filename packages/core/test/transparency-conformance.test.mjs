// The TypeScript runner for conformance/transparency/vectors.json (witness wire
// formats): every vector is re-checked against the core sources. The Python
// verifier runs the same file (see conformance/transparency/README.md).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const { transparency: t, conformanceTransparencyRoot, keysAt } = await import("./transparency-scenario.mjs");
const V = JSON.parse(readFileSync(`${conformanceTransparencyRoot}vectors.json`, "utf8"));
const hx = (text) => new Uint8Array(Buffer.from(text, "hex"));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");

test("vector file header", () => {
  assert.equal(V.schemaVersion, "irontrellis-transparency-vectors/1");
  for (const section of ["merkle", "notes", "keys", "checkpoints", "statements", "entries", "receipts", "latestNotes"]) assert.ok(V[section], section);
});

test("merkle: leaf hashes, roots, inclusion and consistency vectors", () => {
  for (const set of [V.merkle.published, V.merkle.generated]) {
    const tree = new t.MerkleTree();
    set.leaves.forEach((leaf, i) => {
      assert.equal(hex(t.leafHash(hx(leaf))), set.leafHashes[i]);
      tree.append(hx(set.leafHashes[i]));
    });
    set.roots.forEach((root, size) => assert.equal(hex(tree.root(size)), root, `${set.source} root ${size}`));
  }
  let valid = 0;
  for (const v of V.merkle.inclusion) {
    assert.equal(t.verifyInclusion(hx(v.leafHash), v.index, v.size, v.proof.map(hx), hx(v.root)), v.valid, `${v.source} ${v.desc ?? ""} ${v.index}/${v.size}`);
    if (v.valid) valid += 1;
  }
  for (const v of V.merkle.consistency) {
    assert.equal(t.verifyConsistency(v.from, v.to, hx(v.fromRoot), hx(v.toRoot), v.proof.map(hx)), v.valid, `${v.source} ${v.desc ?? ""} ${v.from}->${v.to}`);
  }
  assert.ok(valid > 20);
});

test("notes: open with the listed verifier keys", () => {
  for (const v of V.notes) {
    let actual;
    try {
      actual = { ok: true, ...t.openNote(v.note, v.verifierKeys) };
    } catch (error) {
      assert.ok(error instanceof t.NoteError, v.desc);
      actual = { ok: false, error: error.code };
    }
    assert.deepEqual(actual, v.expect, `${v.source}: ${v.desc}`);
  }
});

test("keys and deterministic signing", () => {
  for (const v of V.keys.verifierKeys) {
    let parsed;
    try { parsed = t.parseVerifierKey(v.vkey); } catch { parsed = undefined; }
    assert.equal(parsed !== undefined, v.valid, v.vkey);
    if (parsed) assert.deepEqual({ name: parsed.name, keyHash: hex(parsed.keyHash), publicKey: hex(parsed.publicKey) }, { name: v.name, keyHash: v.keyHash, publicKey: v.publicKey });
  }
  for (const v of V.keys.signerKeys) {
    let parsed;
    try { parsed = t.parseSignerKey(v.skey); } catch { parsed = undefined; }
    assert.equal(parsed !== undefined, v.valid, v.skey);
    if (parsed) assert.equal(t.verifierKey(parsed.name, parsed.publicKey), v.verifierKey);
  }
  for (const v of V.keys.signing) assert.equal(t.signNote(v.body, t.parseSignerKey(v.signerKey)), v.note, v.source);
});

test("checkpoints: strict parse", () => {
  for (const v of V.checkpoints) {
    let parsed;
    try { parsed = t.parseCheckpoint(v.body); } catch { parsed = undefined; }
    assert.equal(parsed !== undefined, v.valid, JSON.stringify(v.body));
    if (parsed) assert.deepEqual({ origin: parsed.origin, size: parsed.size, root: b64(parsed.root), extensions: parsed.extensions }, { origin: v.origin, size: v.size, root: v.root, extensions: v.extensions });
  }
});

test("statements: hash and verification against owner-key epochs", () => {
  for (const v of V.statements) {
    const result = t.verifySignedHeadStatement(v.signed, (position) => keysAt(v.ownerKeyEpochs, position));
    assert.equal(result.ok ? "OK" : result.reason, v.expect, v.desc);
    if (v.statementHash !== null) assert.equal(t.headStatementHash(v.signed.statement), v.statementHash, v.desc);
    else assert.equal(typeof t.validateHeadStatement(v.signed.statement), "string", v.desc);
  }
});

test("entries: validity, canonical text and leaf hash", () => {
  for (const v of V.entries) {
    assert.equal(t.validateEntry(v.entry) === null, v.valid, v.desc);
    if (v.valid) {
      assert.equal(Buffer.from(t.encodeEntry(v.entry)).toString("utf8"), v.canonical, v.desc);
      assert.equal(hex(t.entryLeafHash(v.entry)), v.leafHash, v.desc);
    }
  }
});

test("receipts: verification outcome and reason", () => {
  for (const v of V.receipts) {
    const result = t.verifyWitnessReceipt(v.receipt, v.trustedVerifierKeys);
    const actual = result.ok
      ? { ok: true, index: result.index, checkpoint: { origin: result.checkpoint.origin, size: result.checkpoint.size, root: b64(result.checkpoint.root) } }
      : { ok: false, reason: result.reason };
    assert.deepEqual(actual, v.expect, v.desc);
  }
});

test("latest notes: format, strict parse and verification against the request", () => {
  for (const v of V.latestNotes.format) {
    if (v.valid) assert.equal(t.formatLatestNote(v.fields), v.body, v.desc);
    else assert.throws(() => t.formatLatestNote(v.fields), (e) => e instanceof t.NoteError && e.code === v.error, v.desc);
  }
  for (const v of V.latestNotes.parse) {
    if (v.valid) assert.deepEqual(JSON.parse(JSON.stringify(t.parseLatestNote(v.body))), v.fields, v.desc);
    else assert.throws(() => t.parseLatestNote(v.body), (e) => e instanceof t.NoteError && e.code === v.error, v.desc);
  }
  for (const v of V.latestNotes.verify) {
    const result = t.verifyLatestNote(v.note, v.trustedVerifierKeys, v.expect);
    assert.deepEqual(result.ok ? { ok: true, latest: JSON.parse(JSON.stringify(result.latest)) } : { ok: false, reason: result.reason }, v.result, v.desc);
  }
  assert.ok(V.latestNotes.verify.some((v) => v.result.reason === "NONCE_MISMATCH"), "a replayed answer is among the vectors");
  assert.ok(V.latestNotes.verify.some((v) => v.result.reason === "EXPECTATION_INVALID"), "malformed expectations are among the vectors");
});

test("latest notes: an expectation that is not a well-formed plain object fails closed (review block 3, L2)", () => {
  const v = V.latestNotes.verify[0];
  const good = v.expect, wrong = { ...good, nonce: "A".repeat(43) };
  assert.equal(t.verifyLatestNote(v.note, v.trustedVerifierKeys, good).ok, true);
  assert.equal(t.verifyLatestNote(v.note, v.trustedVerifierKeys, wrong).reason, "NONCE_MISMATCH");
  assert.equal(t.verifyLatestNote(v.note, v.trustedVerifierKeys, Object.assign(Object.create(null), good)).ok, true, "a null-prototype record is plain");
  assert.equal(t.verifyLatestNote(v.note, v.trustedVerifierKeys, { historyId: good.historyId, nonce: good.nonce }).ok, true, "origin is optional");
  class Expectation { constructor(fields) { Object.assign(this, fields); } }
  const getter = { origin: good.origin, historyId: good.historyId, get nonce() { return good.nonce; } };
  const invalid = {
    // The review's PoC (latest-expect.mjs): a Map and an array carrying a wrong nonce used to return ok: true.
    "Map with a wrong nonce": new Map(Object.entries(wrong)), "Map with the right nonce": new Map(Object.entries(good)), "array": ["nonce"],
    "undefined (omitted)": undefined, null: null, "a string": "nonce", "a number": 7, "a class instance": new Expectation(good), "an accessor field": getter,
    "empty object": {}, "no nonce": { origin: good.origin, historyId: good.historyId }, "no history id": { origin: good.origin, nonce: good.nonce },
    "nonce undefined": { ...good, nonce: undefined }, "nonce null": { ...good, nonce: null }, "nonce a number": { ...good, nonce: 7 }, "nonce padded": { ...good, nonce: `${good.nonce}=` },
    "nonce a String object": { ...good, nonce: new String(good.nonce) }, "history id uppercase": { ...good, historyId: good.historyId.toUpperCase() },
    "origin undefined": { ...good, origin: undefined }, "origin empty": { ...good, origin: "" }, "origin two lines": { ...good, origin: `${good.origin}\nx` },
    "origin a version line": { ...good, origin: "irontrellis-witness-latest/1" }, "a misspelt key": { origin: good.origin, historyId: good.historyId, nonce: good.nonce, nonces: good.nonce },
    "a symbol key": { ...good, [Symbol("nonce")]: good.nonce },
  };
  for (const [name, expectation] of Object.entries(invalid)) {
    const result = t.verifyLatestNote(v.note, v.trustedVerifierKeys, expectation);
    assert.deepEqual([result.ok, result.reason], [false, "EXPECTATION_INVALID"], name);
    assert.equal(typeof result.message, "string", name);
  }
  // Checked first: whatever the note, a bad expectation is the reason.
  assert.equal(t.verifyLatestNote(7, v.trustedVerifierKeys, null).reason, "EXPECTATION_INVALID");
  assert.equal(t.verifyLatestNote(7, v.trustedVerifierKeys, good).reason, "NOTE_UNVERIFIED");
});

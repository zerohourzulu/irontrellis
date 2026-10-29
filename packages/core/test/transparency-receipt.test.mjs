// Witness receipts (WITNESS-DESIGN §2.6): a log of real entries, signed
// checkpoints, receipts for every entry, and every rejection reason.
import { test } from "node:test";
import assert from "node:assert/strict";

const { transparency: t, buildScenario, ORIGIN } = await import("./transparency-scenario.mjs");

const S = await buildScenario();
const trusted = [S.witnessVkey];
const clone = (value) => JSON.parse(JSON.stringify(value));
const reasonOf = (receipt, keys = trusted) => {
  const result = t.verifyWitnessReceipt(receipt, keys);
  return result.ok ? "OK" : result.reason;
};

test("a receipt for every entry verifies against the size-7 checkpoint (and survives JSON)", () => {
  assert.equal(S.tree.size, 15, "the main history's 7 leaves, then the pre-rotation history's 8");
  for (const [index, receipt] of S.receipts.entries()) {
    assert.equal(receipt.version, "irontrellis-witness-receipt/1");
    assert.deepEqual(receipt.witness, { origin: ORIGIN, verifierKey: S.witnessVkey });
    const result = t.verifyWitnessReceipt(clone(receipt), trusted);
    assert.equal(result.ok, true, `${index}: ${result.reason} ${result.message}`);
    assert.equal(result.index, index);
    assert.deepEqual(result.checkpoint, { origin: ORIGIN, size: 7, root: S.tree.root(7) });
    assert.deepEqual(result.verifiedBy, [S.witnessVkey]);
  }
  assert.equal(t.verifyReceipt, undefined, "one name for witness receipts: verifyWitnessReceipt");
  // The pre-rotation history's leaves (7..14) against the size-15 checkpoint.
  for (const receipt of S.preRotation.receipts) {
    const result = t.verifyWitnessReceipt(clone(receipt), trusted);
    assert.equal(result.ok, true, `${receipt.index}: ${result.reason} ${result.message}`);
    assert.deepEqual(result.checkpoint, { origin: ORIGIN, size: 15, root: S.tree.root(15) });
  }
});

test("an older checkpoint's receipt verifies, and the log is consistent from 4 to 7", () => {
  const result = t.verifyWitnessReceipt(S.receiptAt4, trusted);
  assert.equal(result.ok, true);
  assert.equal(result.checkpoint.size, 4);
  const at4 = t.parseCheckpoint(t.openNote(S.checkpoint4, trusted).body);
  const at7 = t.parseCheckpoint(t.openNote(S.checkpoint7, trusted).body);
  assert.equal(t.verifyConsistency(at4.size, at7.size, at4.root, at7.root, S.tree.consistencyProof(4, 7)), true);
  // A second key-holder's log would not be consistent with a different root.
  assert.equal(t.verifyConsistency(4, 7, at4.root, S.tree.root(6), S.tree.consistencyProof(4, 7)), false);
});

test("extra trusted keys and extra (unknown) cosignatures do not matter", () => {
  const cosigned = `${S.checkpoint7}${t.signNote(t.openNote(S.checkpoint7, trusted).body, S.other).split("\n\n").at(-1)}`;
  assert.equal(reasonOf({ ...S.receipts[3], checkpoint: cosigned }), "OK");
  assert.equal(reasonOf(S.receipts[3], [t.generateNoteKey("someone-else").verifierKey, S.witnessVkey]), "OK");
});

test("rejections: every reason", () => {
  const good = S.receipts[2];
  const cases = [
    ["RECEIPT_MALFORMED", { ...good, version: "irontrellis-witness-receipt/2" }],
    ["RECEIPT_MALFORMED", { ...good, witness: { origin: ORIGIN } }],
    ["RECEIPT_MALFORMED", { ...good, index: -1 }],
    ["RECEIPT_MALFORMED", { ...good, index: 1.5 }],
    ["RECEIPT_MALFORMED", { ...good, inclusionProof: "x" }],
    ["RECEIPT_MALFORMED", null],
    ["NOTE_UNVERIFIED", { ...good, checkpoint: S.checkpointAt(7, S.other) }, "signed by another key with the same name"],
    ["NOTE_UNVERIFIED", { ...good, checkpoint: good.checkpoint.replace("\n7\n", "\n8\n") }, "checkpoint body altered"],
    ["NOTE_UNVERIFIED", { ...good, checkpoint: good.checkpoint.slice(0, -1) }, "malformed note"],
    ["CHECKPOINT_MALFORMED", { ...good, checkpoint: t.signNote(`${ORIGIN}\n07\n${Buffer.from(S.tree.root(7)).toString("base64")}\n`, S.witness) }],
    ["CHECKPOINT_MALFORMED", { ...good, checkpoint: t.signNote("not a checkpoint\n", S.witness) }],
    ["ORIGIN_MISMATCH", { ...good, witness: { ...good.witness, origin: "irontrellis-witness/other" } }],
    ["ORIGIN_MISMATCH", { ...good, checkpoint: t.signNote(t.formatCheckpoint("irontrellis-witness/other", 7, S.tree.root(7)), S.witness) }],
    ["ENTRY_MALFORMED", { ...good, entry: { ...good.entry, kind: "NOPE" } }],
    ["ENTRY_MALFORMED", { ...good, entry: { ...good.entry, historyId: S.heads[1].hash } }],
    ["INDEX_OUT_OF_RANGE", { ...good, index: 7 }],
    ["INDEX_OUT_OF_RANGE", { ...S.receipts[5], checkpoint: S.checkpoint4 }],
    ["INCLUSION_INVALID", { ...good, index: 3 }],
    ["INCLUSION_INVALID", { ...good, entry: { ...good.entry, receivedAt: good.entry.receivedAt + 1 } }],
    ["INCLUSION_INVALID", { ...good, entry: S.entries[3] }],
    ["INCLUSION_INVALID", { ...good, inclusionProof: good.inclusionProof.slice(0, -1) }],
    ["INCLUSION_INVALID", { ...good, inclusionProof: [...good.inclusionProof, good.inclusionProof[0]] }],
    ["INCLUSION_INVALID", { ...good, inclusionProof: good.inclusionProof.map((p, i) => (i === 0 ? `${p.slice(0, -2)}Q=` : p)) }],
    ["INCLUSION_INVALID", { ...good, inclusionProof: ["AAAA", ...good.inclusionProof.slice(1)] }],
    ["INCLUSION_INVALID", { ...good, checkpoint: S.checkpoint4 }, "the size-7 proof against the size-4 checkpoint"],
  ];
  for (const [reason, receipt, why] of cases) {
    const result = t.verifyWitnessReceipt(receipt, trusted);
    assert.equal(result.ok ? "OK" : result.reason, reason, why ?? reason);
    if (!result.ok) assert.equal(typeof result.message, "string");
  }
  assert.equal(reasonOf(good, [S.otherVkey]), "NOTE_UNVERIFIED", "untrusted witness");
  assert.equal(reasonOf(good, []), "NOTE_UNVERIFIED", "no trusted keys");
  assert.equal(reasonOf(good, ["garbage"]), "NOTE_UNVERIFIED", "malformed trusted key");
  // Flip each inclusion-proof element in turn.
  for (let i = 0; i < good.inclusionProof.length; i += 1) {
    const proof = good.inclusionProof.slice();
    const bytes = Buffer.from(proof[i], "base64"); bytes[7] ^= 1; proof[i] = bytes.toString("base64");
    assert.equal(reasonOf({ ...good, inclusionProof: proof }), "INCLUSION_INVALID", `element ${i}`);
  }
});

test("buildReceipt encodes the proof as base64 and the receipt verifies from its parts", () => {
  const index = 4;
  const receipt = t.buildReceipt({ origin: ORIGIN, verifierKey: S.witnessVkey, entry: S.entries[index], index, checkpoint: S.checkpoint7, inclusionProof: S.tree.inclusionProof(index, 7) });
  assert.deepEqual(receipt.inclusionProof, S.tree.inclusionProof(index, 7).map((p) => Buffer.from(p).toString("base64")));
  assert.deepEqual(receipt, S.receipts[index]);
  assert.equal(reasonOf(receipt), "OK");
});

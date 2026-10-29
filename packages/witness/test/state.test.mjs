// The pure acceptance rules (WITNESS-DESIGN §3.2, §8.1, §9): every branch of
// REGISTER, HEAD (rules 1–6) and KEY EVENT, and the replay (applyEntry) that
// rebuilds the same state from the log. Real owner keys, real events.
import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { buildHistory, buildScenario, core, keyPair, signerOf, t, tempDir, witnessLib, wire } from "./helpers.mjs";

const { emptyState, decideRegister, decideHead, decideKeyEvent, applyEntry, ERROR_CODES } = witnessLib;

/** A pure witness: state + entries array; `run` decides, appends and applies like the server. */
function pureWitness({ maxHistories, now = () => 1_000 } = {}) {
  const state = emptyState();
  const entries = [];
  const lookup = (index) => entries[index];
  const context = () => ({ now: now(), lookup, ...(maxHistories === undefined ? {} : { maxHistories }) });
  const run = (decision) => {
    if (decision.append !== undefined) {
      let index;
      // A decision appends one entry, or several in order (a key event with its head, a supersede: WITNESS-DESIGN §11.3, §11.4).
      for (const entry of decision.append.entries) {
        index = entries.length;
        entries.push(entry);
        assert.equal(applyEntry(state, entry, index, { lookup, verify: true }), null);
      }
      return { ...decision, index };
    }
    return decision;
  };
  return {
    state, entries,
    register: (body) => run(decideRegister(state, wire(body), context())),
    head: (id, body) => run(decideHead(state, id, wire(body), context())),
    keyEvent: (id, body, route) => run(decideKeyEvent(state, id, wire(body), context(), route)),
  };
}

const code = (decision) => decision.error?.code;

test("REGISTER: new, idempotent, bad body, invalid genesis, legacy format, history limit", async () => {
  const h = await buildHistory({ name: "reg" });
  const w = pureWitness({ maxHistories: 2 });
  const first = w.register({ genesis: h.genesis });
  assert.equal(first.status, 201);
  assert.equal(first.historyId, h.historyId);
  assert.equal(first.receipt, "appended");
  assert.equal(first.index, 0);
  assert.equal(w.entries[0].kind, "REGISTERED");
  assert.deepEqual(w.entries[0].genesis, wire(h.genesis), "the genesis is recorded verbatim");

  const again = w.register({ genesis: h.genesis });
  assert.equal(again.status, 200);
  assert.equal(again.receipt, 0);
  assert.equal(again.append, undefined);

  assert.equal(code(w.register({ genesis: h.genesis, extra: 1 })), "INVALID_REQUEST");
  assert.equal(code(w.register([])), "INVALID_REQUEST");
  assert.equal(code(w.register({ genesis: "x" })), "INVALID_GENESIS");
  assert.equal(code(w.register({ genesis: { ...h.genesis, type: "PRINCIPAL_CREATED" } })), "INVALID_GENESIS");
  assert.equal(code(w.register({ genesis: { ...h.genesis, data: { ...h.genesis.data, ownerKeys: [] } } })), "INVALID_GENESIS");
  const legacy = { ...h.genesis, data: { ...h.genesis.data, versions: { ...h.genesis.data.versions, eventSchemaVersion: core.LEGACY_VERSIONS.eventSchemaVersion } } };
  assert.equal(code(w.register({ genesis: legacy })), "UNSUPPORTED_FORMAT");

  const h2 = await buildHistory({ name: "reg2" });
  const h3 = await buildHistory({ name: "reg3" });
  assert.equal(w.register({ genesis: h2.genesis }).status, 201);
  const full = w.register({ genesis: h3.genesis });
  assert.equal(full.status, 503);
  assert.equal(code(full), "HISTORY_LIMIT_REACHED");
  assert.equal(w.register({ genesis: h2.genesis }).status, 200, "an existing history is still answered at the limit");
  assert.ok(ERROR_CODES.includes("HISTORY_LIMIT_REACHED"));
});

test("HEAD rules (§9.1): first head, chain, idempotent, rule 5, stale previous (latest null and not), equivocation as deduped evidence, history stays open", async () => {
  const s = await buildScenario();
  const id = s.historyId;
  const w = pureWitness();
  assert.equal(code(w.head(id, s.statements.s0)), "NOT_REGISTERED");
  w.register({ genesis: s.events[0] });

  // Stale previous with no heads yet: latest is null.
  const stale0 = w.head(id, s.statements.s3);
  assert.equal(stale0.status, 409);
  assert.equal(code(stale0), "STALE_PREVIOUS");
  assert.equal(stale0.latest, true);
  assert.equal(w.state.histories.get(id).latest, undefined);

  // Rule 2: first head.
  const first = w.head(id, s.statements.s0);
  assert.equal(first.status, 201);
  assert.equal(first.result, "APPENDED");
  assert.equal(first.receipt, "appended");
  // Rule 3: chain.
  const chained = w.head(id, s.statements.s3);
  assert.equal(chained.result, "APPENDED");
  assert.equal(w.state.histories.get(id).latest.position, 3);
  // Rule 3 idempotent: the same statement again.
  const idem = w.head(id, s.statements.s3);
  assert.equal(idem.status, 200);
  assert.equal(idem.result, "ALREADY_WITNESSED");
  assert.equal(idem.receipt, chained.index);
  assert.equal(idem.append, undefined);
  // Rule 5: a held head that is not the latest.
  const older = w.head(id, s.statements.s0);
  assert.equal(older.status, 200);
  assert.equal(older.result, "ALREADY_WITNESSED");
  assert.equal(older.receipt, first.index);
  assert.equal(older.latest, true);
  // A differently signed statement of a held head (previous null at position 0 again, re-signed): still rule 5.
  const resigned = await t.signHeadStatement(s.owner1, s.statement(s.heads[0], null));
  assert.equal(w.head(id, resigned).result, "ALREADY_WITNESSED");

  // Rule 6: stale previous with a latest.
  const skip = await t.signHeadStatement(s.owner1, s.statement(s.heads[6], s.heads[0]));
  const stale = w.head(id, skip);
  assert.equal(stale.status, 409);
  assert.equal(code(stale), "STALE_PREVIOUS");
  assert.equal(stale.latest, true);
  // Statement previous null once the witness has heads, for an unheld head: stale.
  const fromNull = await t.signHeadStatement(s.owner1, s.statement(s.heads[5], null));
  assert.equal(code(w.head(id, fromNull)), "STALE_PREVIOUS");

  // Chain to 6, then the fork at 6: EQUIVOCATION evidence (with latest), recorded once; the history stays open.
  assert.equal(w.head(id, s.statements.s6).result, "APPENDED");
  const eq = w.head(id, s.statements.s6fork);
  assert.equal(eq.status, 409);
  assert.equal(code(eq), "EQUIVOCATION");
  assert.equal(eq.receipt, "appended");
  assert.equal(eq.latest, true);
  const evidence = w.entries[eq.index];
  assert.equal(evidence.kind, "EQUIVOCATION");
  assert.deepEqual(evidence.first, wire(s.statements.s6));
  assert.deepEqual(evidence.second, wire(s.statements.s6fork));
  const history = w.state.histories.get(id);
  assert.equal(history.equivocations, 1);
  assert.equal(history.lastEquivocationIndex, eq.index);
  assert.equal(history.latest.position, 6, "the latest head is unchanged");
  assert.equal(w.state.equivocatingHistories, 1);
  const dup = w.head(id, s.statements.s6fork);
  assert.equal(code(dup), "EQUIVOCATION");
  assert.equal(dup.receipt, eq.index, "the same conflicting statement is answered with the recorded evidence");
  assert.equal(dup.append, undefined);
  // Another conflicting statement at the same position (different previous): capped (docs/reference/witness-protocol.md §9.2 rule 4, one
  // entry per position): answered with the recorded evidence, nothing appended.
  const fromZero = await t.signHeadStatement(s.owner1, s.statement(s.fork.heads[6], s.heads[0]));
  const capped = w.head(id, fromZero);
  assert.equal(code(capped), "EQUIVOCATION");
  assert.equal(capped.receipt, eq.index);
  assert.equal(capped.append, undefined);
  assert.equal(capped.capped, true);
  assert.equal(history.equivocations, 1);
  // A conflicting statement at another held position is a second piece of evidence.
  const at3 = await t.signHeadStatement(s.owner1, s.statement({ hash: s.heads[5].hash, position: 3, canonicalTime: s.heads[3].canonicalTime }, s.heads[0]));
  const eq2 = w.head(id, at3);
  assert.equal(code(eq2), "EQUIVOCATION");
  assert.notEqual(eq2.index, eq.index);
  assert.equal(history.equivocations, 2);
  assert.equal(history.lastEquivocationIndex, eq2.index);
  assert.equal(w.state.equivocatingHistories, 1);
  // Not frozen: held heads are still answered, and statements extending the latest are accepted (rotation included).
  for (const body of [s.statements.s6, s.statements.s0]) assert.equal(w.head(id, body).result, "ALREADY_WITNESSED");
  const s7 = await t.signHeadStatement(s.owner1, s.statement(s.heads[7], s.heads[6]));
  assert.equal(w.head(id, s7).result, "APPENDED");
  const rotation = w.keyEvent(id, { event: s.rotation, previousHead: { hash: s.heads[6].hash, position: 6 }, eventHead: { hash: s.heads[7].hash, position: 7 } });
  assert.equal(rotation.status, 201);
  assert.equal(w.head(id, s.statements.s8).status, 409, "s8 names 6 as previous: stale once 7 is held");
  const s8 = await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7]));
  assert.equal(w.head(id, s8).result, "APPENDED");
  assert.ok(!ERROR_CODES.includes("HISTORY_FORKED"), "retired by §9.1");
});

test("HEAD rule 3 (§9.1) applies whatever stale previous the statement names (a fork that claims to extend the latest's predecessor)", async () => {
  const s = await buildScenario();
  const w = pureWitness();
  w.register({ genesis: s.events[0] });
  w.head(s.historyId, s.statements.s0);
  w.head(s.historyId, s.statements.s3);
  w.head(s.historyId, s.statements.s6);
  const fromZero = await t.signHeadStatement(s.owner1, s.statement(s.fork.heads[6], s.heads[0]));
  assert.equal(code(w.head(s.historyId, fromZero)), "EQUIVOCATION");
});

test("HEAD rule 1: malformed, wrong history, wrong domain, position-0 rules, bad signature, unknown key hint", async () => {
  const s = await buildScenario();
  const other = await buildHistory({ name: "other" });
  const id = s.historyId;
  const w = pureWitness();
  w.register({ genesis: s.events[0] });
  w.register({ genesis: other.genesis });

  assert.equal(code(w.head(id, { statement: {} })), "INVALID_STATEMENT");
  assert.equal(code(w.head(id, "x")), "INVALID_STATEMENT");
  const extra = { ...wire(s.statements.s0), extra: true };
  assert.equal(code(w.head(id, extra)), "INVALID_STATEMENT");

  // Another (registered) history's statement posted under this id.
  const otherStatement = await other.statement(0, null);
  const wrongHistory = w.head(id, otherStatement);
  assert.equal(wrongHistory.status, 400);
  assert.equal(code(wrongHistory), "INVALID_STATEMENT");
  assert.match(wrongHistory.error.message, /another|not/);

  // Right history id, wrong domain (validly signed by the owner key).
  const wrongDomain = await t.signHeadStatement(s.owner1, { ...s.statement(s.heads[0], null), domain: { ...s.statement(s.heads[0], null).domain, deploymentId: "deployment:elsewhere" } });
  assert.equal(code(w.head(id, wrongDomain)), "INVALID_STATEMENT");

  // Position 0 must be the history id (head and previous); such statements cannot even be signed, so forge the shape.
  const fake = (statement) => ({ statement, keyId: s.owner1.keyId, scheme: "ed25519", signature: `0x${"11".repeat(64)}` });
  const badZero = { ...s.statement(s.heads[3], null), head: { ...s.heads[3], position: 0 } };
  const r0 = w.head(id, fake(badZero));
  assert.equal(code(r0), "INVALID_STATEMENT");
  assert.match(r0.error.message, /position 0/);
  const badPrev = { ...s.statement(s.heads[3], s.heads[0]), previous: { hash: s.heads[1].hash, position: 0 } };
  assert.equal(code(w.head(id, fake(badPrev))), "INVALID_STATEMENT");
  // previous ahead of head.
  const ahead = { ...s.statement(s.heads[3], s.heads[0]), previous: { hash: s.heads[5].hash, position: 5 } };
  assert.equal(code(w.head(id, fake(ahead))), "INVALID_STATEMENT");

  // A flipped signature.
  const tampered = wire(s.statements.s0);
  tampered.signature = `${tampered.signature.slice(0, -2)}${tampered.signature.endsWith("00") ? "01" : "00"}`;
  const bad = w.head(id, tampered);
  assert.equal(bad.status, 400);
  assert.equal(code(bad), "SIGNATURE_INVALID");
  assert.equal(bad.error.hint, undefined);
  // A signature by a key the witness has never seen: ROTATION_REQUIRED hint.
  const stranger = signerOf(keyPair("owner:stranger", 0x9999));
  const unknown = w.head(id, await t.signHeadStatement(stranger, s.statement(s.heads[0], null)));
  assert.equal(code(unknown), "SIGNATURE_INVALID");
  assert.equal(unknown.error.hint, "ROTATION_REQUIRED");
  // The new key before the witness saw the rotation: also unknown to it.
  const early = w.head(id, await t.signHeadStatement(s.owner2, s.statement(s.heads[0], null)));
  assert.equal(early.error.hint, "ROTATION_REQUIRED");
  assert.equal(w.state.histories.get(id).latest, undefined, "nothing was appended");
});

test("KEY EVENT: head unknown, accept, idempotent, invalid variants; keys by position afterwards", async () => {
  const s = await buildScenario();
  const id = s.historyId;
  const w = pureWitness();
  const body = { event: s.rotation, previousHead: { hash: s.heads[6].hash, position: 6 }, eventHead: { hash: s.heads[7].hash, position: 7 } };
  assert.equal(code(w.keyEvent(id, body)), "NOT_REGISTERED");
  w.register({ genesis: s.events[0] });
  w.head(id, s.statements.s0);
  w.head(id, s.statements.s3);
  w.head(id, s.statements.s6);

  // (d) the rotation head must be witnessed first.
  const unknownHead = w.keyEvent(id, body);
  assert.equal(unknownHead.status, 409);
  assert.equal(code(unknownHead), "KEY_EVENT_HEAD_UNKNOWN");
  const s7 = await t.signHeadStatement(s.owner1, s.statement(s.heads[7], s.heads[6]));
  assert.equal(w.head(id, s7).result, "APPENDED");

  // Shape and rule failures.
  assert.equal(code(w.keyEvent(id, { event: s.rotation })), "INVALID_REQUEST");
  assert.equal(code(w.keyEvent(id, { ...body, previousHead: { hash: "0x12", position: 6 } })), "INVALID_REQUEST");
  assert.equal(code(w.keyEvent(id, { ...body, event: "x" })), "KEY_EVENT_INVALID");
  assert.equal(code(w.keyEvent(id, { ...body, eventHead: { hash: s.heads[8].hash, position: 8 } })), "KEY_EVENT_INVALID");
  const wrongPrev = w.keyEvent(id, { ...body, previousHead: { hash: s.heads[5].hash, position: 6 } });
  assert.equal(code(wrongPrev), "KEY_EVENT_INVALID");
  assert.match(wrongPrev.error.message, /signature/);
  const byStranger = await core.signControlEvent(signerOf(keyPair("owner:stranger", 0x9999)),
    { id: "rotation:x", type: "OWNER_KEYS_ROTATED", timestamp: 7, data: { ownerKeys: s.ownerKeys2 } }, s.statement(s.heads[0], null).domain, s.heads[6], "sha256");
  assert.equal(code(w.keyEvent(id, { ...body, event: byStranger })), "KEY_EVENT_INVALID");
  assert.equal(code(w.keyEvent(id, { ...body, event: s.events[6] })), "KEY_EVENT_INVALID", "not a rotation event");

  // Accept.
  const accepted = w.keyEvent(id, body);
  assert.equal(accepted.status, 201);
  assert.equal(accepted.epochs, true);
  assert.equal(w.entries[accepted.index].kind, "ROTATED");
  assert.deepEqual(w.entries[accepted.index].rotationHead, { hash: s.heads[7].hash, position: 7 });
  assert.deepEqual(w.entries[accepted.index].previousHead, { hash: s.heads[6].hash, position: 6 }, "§9.2: the leaf carries the head the rotation signs");
  assert.equal(t.validateEntry(w.entries[accepted.index]), null);
  assert.deepEqual(wire(w.state.histories.get(id).epochs), wire(s.ownerKeyEpochs));
  // Idempotent on the same event; a different event under the same id is refused.
  const again = w.keyEvent(id, body);
  assert.equal(again.status, 200);
  assert.equal(again.receipt, accepted.index);
  const altered = { ...wire(s.rotation), data: { ...wire(s.rotation).data, reason: "changed" } };
  assert.equal(code(w.keyEvent(id, { ...body, event: altered })), "KEY_EVENT_INVALID");
  assert.equal(code(w.keyEvent(id, { ...body, previousHead: { hash: s.heads[5].hash, position: 6 } })), "KEY_EVENT_INVALID", "same event, another previousHead: not idempotent");
  // A second rotation at or before the epoch start: out of order.
  const second = await core.signControlEvent(s.owner1, { id: "rotation:2", type: "OWNER_KEYS_ROTATED", timestamp: 7, data: { ownerKeys: s.ownerKeys1 } },
    s.statement(s.heads[0], null).domain, s.heads[5], "sha256");
  const outOfOrder = w.keyEvent(id, { event: second, previousHead: { hash: s.heads[5].hash, position: 5 }, eventHead: { hash: s.heads[6].hash, position: 6 } });
  assert.equal(code(outOfOrder), "KEY_EVENT_INVALID");

  // After the rotation: head 8 by the new key is accepted; by the retired key rejected (no hint: the witness knows that key).
  const oldKey8 = await t.signHeadStatement(s.owner1, s.statement(s.heads[8], s.heads[7]));
  const rejected = w.head(id, oldKey8);
  assert.equal(code(rejected), "SIGNATURE_INVALID");
  assert.equal(rejected.error.hint, undefined);
  const newKey8 = await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7]));
  assert.equal(w.head(id, newKey8).result, "APPENDED");
  // Heads up to and including the rotation head stay under the old key: resubmissions are still accepted.
  for (const statement of [s.statements.s0, s.statements.s3, s.statements.s6, s7]) assert.equal(w.head(id, statement).result, "ALREADY_WITNESSED");
  // The new key cannot state old heads.
  const newKeyOld = await t.signHeadStatement(s.owner2, s.statement(s.heads[6], s.heads[3]));
  assert.equal(code(w.head(id, newKeyOld)), "SIGNATURE_INVALID");
});

test("rotation order: new-key heads need the rotation first; heads the witness held before it keep verifying", async () => {
  const h = await buildHistory({ name: "late", agents: 6, rotateAt: 4 });
  const w = pureWitness();
  w.register({ genesis: h.genesis });
  w.head(h.historyId, await h.statement(0, null));
  w.head(h.historyId, await h.statement(4, 0));
  const early = w.head(h.historyId, await h.statement(5, 4));
  assert.equal(early.error.hint, "ROTATION_REQUIRED", "head 5 needs the rotation first");
  // Before the witness hears of the rotation, the old key is in force everywhere: an old-key statement of head 5 is accepted.
  const oldKey5 = await h.statement(5, 4, h.signer1);
  assert.equal(w.head(h.historyId, oldKey5).result, "APPENDED");
  const rotated = w.keyEvent(h.historyId, { event: h.rotation, previousHead: h.at(h.heads[3]), eventHead: h.at(h.heads[4]) });
  assert.equal(rotated.status, 201, rotated.error?.message);
  // Kept: it was valid when signed. The identical statement is still answered; the new key's statement of the same head too.
  assert.equal(w.head(h.historyId, oldKey5).result, "ALREADY_WITNESSED");
  assert.equal(w.head(h.historyId, await h.statement(5, 4)).result, "ALREADY_WITNESSED");
  assert.equal(w.head(h.historyId, await h.statement(4, 0)).result, "ALREADY_WITNESSED");
  // New heads need the new key.
  assert.equal(code(w.head(h.historyId, await h.statement(6, 5, h.signer1))), "SIGNATURE_INVALID");
  assert.equal(w.head(h.historyId, await h.statement(6, 5)).result, "APPENDED");
});

test("replay: applyEntry rebuilds the same state, re-verifying signatures; forged entries are refused", async () => {
  const s = await buildScenario();
  const w = pureWitness();
  w.register({ genesis: s.events[0] });
  w.head(s.historyId, s.statements.s0);
  w.head(s.historyId, s.statements.s3);
  w.head(s.historyId, s.statements.s6);
  const s7 = await t.signHeadStatement(s.owner1, s.statement(s.heads[7], s.heads[6]));
  w.head(s.historyId, s7);
  const rot = w.keyEvent(s.historyId, { event: s.rotation, previousHead: s.heads[6], eventHead: s.heads[7] });
  // Fix the helper's call above: heads carry canonicalTime, which the body shape refuses.
  assert.equal(code(rot), "INVALID_REQUEST");
  const ok = w.keyEvent(s.historyId, { event: s.rotation, previousHead: { hash: s.heads[6].hash, position: 6 }, eventHead: { hash: s.heads[7].hash, position: 7 } });
  assert.equal(ok.status, 201);
  w.head(s.historyId, await t.signHeadStatement(s.owner2, s.statement(s.heads[8], s.heads[7])));
  // Equivocation evidence at 6 (twice the same: one entry), then more heads.
  w.head(s.historyId, s.statements.s6fork);
  w.head(s.historyId, s.statements.s6fork);
  const s8fork = await t.signHeadStatement(s.owner1, s.statement(s.fork.heads[6], s.heads[0]));
  assert.equal(w.head(s.historyId, s8fork).capped, true, "a second conflicting statement at 6: capped, not recorded");
  w.head(s.historyId, await t.signHeadStatement(s.owner1, s.statement({ hash: s.heads[5].hash, position: 3, canonicalTime: s.heads[3].canonicalTime }, s.heads[0])));

  const replayed = emptyState();
  const lookup = (index) => w.entries[index];
  w.entries.forEach((entry, index) => {
    assert.equal(applyEntry(replayed, wire(entry), index, { lookup, verify: true }), null);
  });
  const summary = (state) => wire({
    size: state.size, kinds: state.kinds, equivocatingHistories: state.equivocatingHistories,
    histories: [...state.histories.values()].map((h) => ({ ...h, heads: [...h.heads.entries()], keyEvents: [...h.keyEvents.entries()], equivocationsByPosition: [...h.equivocationsByPosition.entries()] })),
  });
  assert.deepEqual(summary(replayed), summary(w.state));
  assert.equal(replayed.size, w.entries.length);
  assert.equal(replayed.histories.get(s.historyId).equivocations, 2);

  const replayUntil = (n) => {
    const state = emptyState();
    for (let index = 0; index < n; index += 1) assert.equal(applyEntry(state, w.entries[index], index, { lookup, verify: true }), null);
    return state;
  };
  // A forged signature on a HEAD line.
  const forged = wire(w.entries[2]);
  forged.signedStatement.signature = `0x${"22".repeat(64)}`;
  assert.match(applyEntry(replayUntil(2), forged, 2, { lookup, verify: true }), /signature/);
  assert.equal(applyEntry(replayUntil(2), forged, 2, { lookup, verify: false }), null, "without verify only the structure is checked");
  // A HEAD that does not chain.
  assert.match(applyEntry(replayUntil(3), wire(w.entries[1]), 3, { lookup }), /chain/);
  // Index out of order, double registration.
  assert.match(applyEntry(replayUntil(2), wire(w.entries[1]), 5, { lookup }), /out of order/);
  assert.match(applyEntry(replayUntil(2), wire(w.entries[0]), 2, { lookup }), /registered twice/);
  // §9.2: a rotation is verified from its leaf alone; a leaf whose previousHead was altered fails its owner signature.
  const rotIndex = w.entries.findIndex((entry) => entry.kind === "ROTATED");
  const moved = { ...wire(w.entries[rotIndex]), previousHead: { hash: s.heads[5].hash, position: 6 } };
  assert.match(applyEntry(replayUntil(rotIndex), moved, rotIndex, { lookup, verify: true }), /signature/);
  const unlinked = { ...wire(w.entries[rotIndex]), previousHead: { hash: s.heads[5].hash, position: 5 } };
  assert.match(applyEntry(replayUntil(rotIndex), unlinked, rotIndex, { lookup, verify: true }), /previousHead\.position \+ 1/);
  const { previousHead: _dropped, ...withoutPrevious } = wire(w.entries[rotIndex]);
  assert.match(applyEntry(replayUntil(rotIndex), withoutPrevious, rotIndex, { lookup, verify: true }), /ROTATED entry fields/);
  // ROTATED is the only key-event leaf: a COMMITTED-shaped leaf (event, previousHead, eventHead) is an unknown kind.
  const { rotation, rotationHead, ...rest } = wire(w.entries[rotIndex]);
  const committedShaped = { ...rest, kind: "COMMITTED", event: rotation, eventHead: rotationHead };
  assert.match(applyEntry(replayUntil(rotIndex), committedShaped, rotIndex, { lookup, verify: false }), /kind must be one of REGISTERED, HEAD, ROTATED, EQUIVOCATION, SUPERSEDED/);
  // A second equivocation at one position cannot come from the rules (they cap it at one per position).
  const eqIndex = w.entries.findIndex((entry) => entry.kind === "EQUIVOCATION");
  const beforeSecond = w.entries.findIndex((entry, index) => index > eqIndex && entry.kind === "EQUIVOCATION");
  assert.match(applyEntry(replayUntil(beforeSecond), { ...wire(w.entries[eqIndex]), receivedAt: 5 }, beforeSecond, { lookup, verify: true }), /second equivocation recorded at position 6/);
  // An entry for an unknown history.
  const orphan = { ...wire(w.entries[1]), historyId: `0x${"ab".repeat(32)}` };
  assert.notEqual(applyEntry(replayUntil(1), orphan, 1, { lookup }), null);
});

test("the transparency scenario's pre-rotation log is exactly what the rules produce, and it replays: a genesis commitment known from REGISTERED lets a pre-rotated rotation supersede a thief's head", async () => {
  const s = await buildScenario();
  const P = s.preRotation;
  const offset = s.entries.length; // the scenario log holds the main history's leaves first
  const w = pureWitness({ now: () => 0 });
  const ref = (head) => ({ hash: head.hash, position: head.position });
  assert.equal(w.register({ genesis: P.events[0] }).status, 201);
  assert.deepEqual(wire(w.state.histories.get(P.historyId).epochs), wire([P.ownerKeyEpochs[0]]), "epoch 0 carries the genesis commitment");
  for (const statement of [P.statements.s0, P.statements.s2, P.statements.thief]) assert.equal(w.head(P.historyId, statement).result, "APPENDED");
  // Without the pre-rotated rotation (a plain one signed by the leaked key alone), nothing is superseded.
  const plain = await core.signControlEvent(s.owner1, { id: "rotation:thief", type: "OWNER_KEYS_ROTATED", timestamp: 4, data: { ownerKeys: s.ownerKeys2 } }, P.statement(P.heads[0], null).domain, P.heads[3], "sha256");
  assert.equal(code(w.keyEvent(P.historyId, { event: plain, previousHead: ref(P.heads[3]), eventHead: ref(P.heads[4]), chain: P.statements.chain })), "KEY_EVENT_INVALID");
  const superseded = w.keyEvent(P.historyId, { event: P.rotation, previousHead: ref(P.heads[3]), eventHead: ref(P.heads[4]), chain: P.statements.chain });
  assert.equal(superseded.status, 201, superseded.error?.message);
  assert.equal(superseded.superseded, "first");
  assert.equal(w.head(P.historyId, P.statements.s5).result, "APPENDED");
  const rebased = (entry) => {
    const copy = { ...wire(entry), receivedAt: 0 };
    if (copy.kind !== "SUPERSEDED") return copy;
    return { ...copy, supersededFromIndex: copy.supersededFromIndex - offset, supersededToIndex: copy.supersededToIndex - offset, supersededLatest: { ...copy.supersededLatest, index: copy.supersededLatest.index - offset } };
  };
  assert.deepEqual(w.entries.map((entry) => ({ ...wire(entry), receivedAt: 0 })), P.entries.map(rebased));
  // The replay re-verifies every signature and rebuilds the same state.
  const replayed = emptyState();
  for (const [index, entry] of w.entries.entries()) assert.equal(applyEntry(replayed, wire(entry), index, { lookup: (i) => w.entries[i], verify: true }), null, `leaf ${index}`);
  const history = replayed.histories.get(P.historyId);
  assert.deepEqual([history.supersedes, history.latest.position, history.latest.hash], [1, 5, P.heads[5].hash]);
  assert.deepEqual(wire(history.epochs), wire(P.ownerKeyEpochs));
  assert.deepEqual(replayed.kinds, { REGISTERED: 1, HEAD: 5, ROTATED: 1, EQUIVOCATION: 0, SUPERSEDED: 1 });
});

test("L1 (review): a stolen owner key cannot grow the log without bound — one EQUIVOCATION entry per position, 64 per history; beyond the cap the answer is the most recent recorded entry and nothing is appended; the replay refuses a log beyond the cap", async () => {
  const h = await buildHistory({ name: "cap", agents: 80 });
  const w = pureWitness();
  w.register({ genesis: h.genesis });
  // The witness holds heads 0..70 (a chain of statements).
  let previous = null;
  for (let p = 0; p <= 70; p += 1) {
    assert.equal(w.head(h.historyId, await h.statement(p, previous)).result, "APPENDED");
    previous = p;
  }
  const history = w.state.histories.get(h.historyId);
  const conflicting = async (position, variant) => t.signHeadStatement(h.signerAt(position), {
    version: t.HEAD_STATEMENT_VERSION, historyId: h.historyId, domain: h.domain,
    head: { hash: `0x${(variant + 1).toString(16).padStart(2, "0").repeat(32)}`, position, canonicalTime: h.heads[position].canonicalTime + variant }, previous: null,
  });
  // Many distinct conflicting statements at one position (the review's PoC varies canonicalTime): one entry.
  const size = w.entries.length;
  const first = w.head(h.historyId, await conflicting(10, 0));
  assert.equal(code(first), "EQUIVOCATION");
  for (let variant = 1; variant <= 20; variant += 1) {
    const again = w.head(h.historyId, await conflicting(10, variant));
    assert.equal(code(again), "EQUIVOCATION");
    assert.equal(again.receipt, first.index, "the recorded entry of that position");
    assert.equal(again.capped, true);
    assert.equal(again.append, undefined);
  }
  assert.equal(w.entries.length, size + 1);
  // One entry per position, up to 64 per history.
  const positions = Array.from({ length: 70 }, (_, i) => i + 1).filter((p) => p !== 10).slice(0, 63);
  for (const position of positions) assert.equal(w.head(h.historyId, await conflicting(position, 0)).receipt, "appended", `position ${position}`);
  assert.equal(history.equivocations, witnessLib.MAX_EQUIVOCATIONS_PER_HISTORY);
  assert.equal(witnessLib.MAX_EQUIVOCATIONS_PER_HISTORY, 64);
  const last = history.lastEquivocationIndex;
  const full = w.entries.length;
  // Past the cap: a conflict at a position without evidence is answered with the most recent entry, nothing is appended.
  const beyond = w.head(h.historyId, await conflicting(69, 0));
  assert.equal(code(beyond), "EQUIVOCATION");
  assert.equal(beyond.status, 409);
  assert.equal(beyond.receipt, last);
  assert.equal(beyond.capped, true);
  assert.equal(w.entries.length, full);
  // The history stays open.
  assert.equal(w.head(h.historyId, await h.statement(71, 70)).result, "APPENDED");
  // A 65th EQUIVOCATION line cannot be replayed.
  const replayed = emptyState();
  w.entries.forEach((entry, index) => assert.equal(applyEntry(replayed, wire(entry), index, { lookup: (i) => w.entries[i] }), null));
  const extra = { ...wire(w.entries[last]), first: wire(w.entries[w.state.histories.get(h.historyId).heads.get(69).index].signedStatement), second: wire(await conflicting(69, 0)) };
  assert.match(applyEntry(replayed, extra, w.entries.length, { lookup: (i) => w.entries[i] }), /more than 64 equivocations/);
});

test("format 2 (SPEC §7.4, A-5): a format-2 genesis registers under recordHash(0); its heads chain; its owner key rotation is checked against the /2 control challenge; the log replays", async () => {
  const { dir, cleanup } = tempDir("irontrellis-witness-f2-");
  try {
    const historyFile = join(dir, "history.jsonl");
    const owner = await core.createLocalOwner({ historyFile, domain: core.createLocalDomain(), owner: "o", controller: "o", now: () => Date.now(), nextKey: false, witness: false });
    await owner.createAgent({ id: "a:1" });
    const signer = core.loadOwnerKeyFile(`${historyFile}.owner-key.json`);
    await owner.rotateOwnerKey({ reason: "format 2" });
    await owner.createAgent({ id: "a:2" });
    const state = core.openHistoryStore(historyFile, { inspect: true, witness: false }).state();
    assert.equal(state.format, "irontrellis-event/2");
    const genesis = state.events[0], historyId = state.eventHistoryHashes[0];
    assert.equal(core.historyIdOfGenesis(genesis), historyId);
    const w = pureWitness();
    const registered = w.register({ genesis });
    assert.equal(registered.status, 201);
    assert.equal(registered.historyId, historyId, "historyId = recordHash(0)");
    assert.equal(w.state.histories.get(historyId).format, "irontrellis-event/2");
    const head = (p) => ({ hash: state.eventHistoryHashes[p], position: p, canonicalTime: state.events[p].timestamp });
    const statement = (p, previous) => ({ version: "irontrellis-head-statement/1", historyId, domain: state.genesis.domain, head: head(p), previous: previous === null ? null : { hash: head(previous).hash, position: previous } });
    const rotation = state.events.findIndex((e) => e.type === "OWNER_KEYS_ROTATED");
    assert.equal(w.head(historyId, await t.signHeadStatement(signer, statement(rotation - 1, null))).status, 201);
    // The rotation, checked as a format-2 event against the /2 challenge, delivered with the statement for its own head.
    const keyEvent = w.keyEvent(historyId, {
      event: state.events[rotation], previousHead: { hash: head(rotation - 1).hash, position: rotation - 1 }, eventHead: { hash: head(rotation).hash, position: rotation },
      statement: await t.signHeadStatement(signer, statement(rotation, rotation - 1)),
    });
    assert.equal(keyEvent.status, 201, JSON.stringify(keyEvent.error));
    // A head after the rotation is signed by the new key.
    const next = core.loadOwnerKeyFile(`${historyFile}.owner-key.json`);
    assert.equal(w.head(historyId, await t.signHeadStatement(next, statement(state.head.position, rotation))).status, 201);
    assert.equal(code(w.head(historyId, await t.signHeadStatement(signer, statement(state.head.position, rotation)))), "SIGNATURE_INVALID", "the retired key no longer signs");
    // A tampered rotation is refused.
    const forged = { ...state.events[rotation], data: { ...state.events[rotation].data, reason: "forged" } };
    assert.equal(code(pureWitnessWith(genesis).keyEvent(historyId, { event: forged, previousHead: { hash: head(rotation - 1).hash, position: rotation - 1 }, eventHead: { hash: head(rotation).hash, position: rotation } })), "KEY_EVENT_INVALID");
    // The log replays with every signature re-verified.
    const replayed = emptyState();
    w.entries.forEach((entry, index) => assert.equal(applyEntry(replayed, wire(entry), index, { verify: true, lookup: (i) => w.entries[i] }), null));
    assert.equal(replayed.histories.get(historyId).epochs.length, 2);
    owner.close();
  } finally { cleanup(); }
});

/** A fresh pure witness holding only `genesis` (for refusals that must not touch `w`). */
function pureWitnessWith(genesis) {
  const fresh = pureWitness();
  fresh.register({ genesis });
  return fresh;
}

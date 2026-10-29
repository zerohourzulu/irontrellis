// A-202.1 (r5.2 §13.1–§13.2, Appendix A rows 29–31): for ATTEMPT_DUTY_POLICY_ACTIVATED, ATTEMPT_DUTY_DISPOSITION_RECORDED and
// ATTEMPT_DUTY_CONTEST_RECORDED the outer session fence is the first of the type's checks, after the envelope (C4 closed
// shape, T1, T3) and ahead of the §13 literal fields (version, rulesHash and, for 29, criteriaProfile, the two limits and
// the digest algorithm; the finding challenge's version, rulesHash and reportDigest algorithm). Found by Astra in the ZK guest (4dt, 2026-10-26);
// the TypeScript engine at 3866a75 had the same order (the literals were schema checks, before the fence).
//
// Each event is the engine's own (the T6 duty fixture). The fence is a real owner-signed CONTROL_EPOCH_ADVANCED for the
// worker (1 → 2), written by the same owner key on a copy of the history cut just before the event.
// The coordinator's scope ruling (2026-10-26, architect list item 17): a check against one fixed literal follows the fence; a
// shape-selecting or self-consistency check (the finding's purpose and transitionEventType) stays at C4.
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, copyFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename } from "node:path";

const core = await import("../src/index.ts");
const { dispositionFixture } = await import("./helpers/duty-fixture.mjs");
const TYPES = ["ATTEMPT_DUTY_POLICY_ACTIVATED", "ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"];
const ZERO = `0x${"00".repeat(32)}`;

/** The full T6 history and, per type, the history cut before that event with the worker fenced by its owner. */
async function setup(t) {
  const x = await dispositionFixture(t);
  await x.duties.dispose(x.input);
  await x.duties.contest(x.contest("challenge"));
  const all = x.events;
  assert.equal(core.replay(all).status, "ACCEPTED");
  const lines = readFileSync(x.config.historyFile, "utf8").split("\n").filter((l) => l.length > 0);
  assert.equal(lines.length, all.length);
  const fenced = {};
  for (const type of TYPES) {
    const i = all.findIndex((e) => e.type === type);
    const fork = mkdtempSync(join(tmpdir(), "irontrellis-a202-")); t.after(() => rmSync(fork, { recursive: true, force: true }));
    writeFileSync(join(fork, basename(x.config.historyFile)), lines.slice(0, i).join("\n") + "\n");
    // The owner's key file(s), not the lock or the rollback pin: the cut copy is re-pinned as it is (acceptRollback).
    for (const n of readdirSync(x.dir)) if (n !== basename(x.config.historyFile) && !n.endsWith(".lock") && !n.endsWith(".head") && !n.startsWith(".")) copyFileSync(join(x.dir, n), join(fork, n));
    const owner = await core.openLocalOwner({ ...x.config, historyFile: join(fork, basename(x.config.historyFile)), acceptRollback: true });
    await owner.advanceEpoch({ agent: "worker", from: 1, to: 2 });
    const prefix = owner.exportHistory();
    assert.equal(prefix.length, i + 1); assert.equal(prefix.at(-1).type, "CONTROL_EPOCH_ADVANCED");
    fenced[type] = { prefix, event: all[i], unfenced: all.slice(0, i) };
  }
  return fenced;
}
const variant = (type, event, fault) => {
  const e = structuredClone(event), target = type === "ATTEMPT_DUTY_POLICY_ACTIVATED" ? e.data.descriptor : e.data;
  if (fault === "closed-shape") e.data.unexpected = true;
  else if (fault === "rulesHash") target.rulesHash = ZERO;
  else if (fault === "version") target.version = "synthetic-wrong-version/1";
  else if (fault === "criteriaProfile") target.criteriaProfile = "synthetic-profile/1";
  else if (fault === "dispositionLimit") target.dispositionLimit = 5;
  else if (fault === "contestLimit") target.contestLimit = 3;
  else if (fault === "digestAlgorithm") target.incidentSourceDigest.algorithm = "sha512";
  else if (fault === "findingVersion") e.data.finding.challenge.version = "synthetic-finding/1";
  else if (fault === "findingRulesHash") e.data.finding.challenge.rulesHash = ZERO;
  else if (fault === "reportDigestAlgorithm") e.data.finding.challenge.operation.reportDigest.algorithm = "sha512";
  else if (fault === "purpose" || fault === "transitionEventType") e.data.finding.challenge[fault] = "synthetic-wrong";
  else if (fault === "versionNotText") target.version = 7;
  else if (fault === "rulesHashNotHash") target.rulesHash = "0x1234";
  else if (fault !== "none") throw Error(fault);
  return e;
};
const codeOf = (events) => { const r = core.replay(events); return r.status === "ACCEPTED" ? "ACCEPTED" : r.code; };

test("A-202.1: with the outer session fenced, a wrong version or rulesHash on types 29–31 is SESSION_FENCED (the 6 cases); the event itself and an extra field are the controls", async (t) => {
  const f = await setup(t);
  for (const type of TYPES) {
    const { prefix, event } = f[type];
    assert.equal(codeOf([...prefix, variant(type, event, "none")]), "SESSION_FENCED", `${type}: the fenced control`);
    assert.equal(codeOf([...prefix, variant(type, event, "closed-shape")]), "EVENT_DATA_INVALID", `${type}: C4 still precedes the fence`);
    assert.equal(codeOf([...prefix, variant(type, event, "rulesHash")]), "SESSION_FENCED", `${type}: rulesHash`);
    assert.equal(codeOf([...prefix, variant(type, event, "version")]), "SESSION_FENCED", `${type}: version`);
  }
});

test("A-202.1: every other §13 literal field also follows the fence (29: criteriaProfile, the limits, the digest algorithm; 30–31: the finding challenge's literals)", async (t) => {
  const f = await setup(t);
  const faults = { ATTEMPT_DUTY_POLICY_ACTIVATED: ["criteriaProfile", "dispositionLimit", "contestLimit", "digestAlgorithm"],
    ATTEMPT_DUTY_DISPOSITION_RECORDED: ["findingVersion", "findingRulesHash", "reportDigestAlgorithm"], ATTEMPT_DUTY_CONTEST_RECORDED: ["findingVersion", "findingRulesHash", "reportDigestAlgorithm"] };
  for (const type of TYPES) for (const fault of faults[type]) assert.equal(codeOf([...f[type].prefix, variant(type, f[type].event, fault)]), "SESSION_FENCED", `${type}: ${fault}`);
});

test("A-202.1 scope ruling: the finding's purpose and transitionEventType select its shape and stay at C4, ahead of the fence (fenced or not)", async (t) => {
  const f = await setup(t);
  for (const type of TYPES.slice(1)) for (const fault of ["purpose", "transitionEventType"]) {
    assert.equal(codeOf([...f[type].prefix, variant(type, f[type].event, fault)]), "EVENT_DATA_INVALID", `${type}: ${fault}, fenced`);
    assert.equal(codeOf([...f[type].unfenced, variant(type, f[type].event, fault)]), "EVENT_DATA_INVALID", `${type}: ${fault}, unfenced`);
  }
});

test("A-202.1: a mistyped literal field is still the closed schema (C4), ahead of the fence", async (t) => {
  const f = await setup(t);
  for (const type of TYPES) for (const fault of ["versionNotText", "rulesHashNotHash"]) assert.equal(codeOf([...f[type].prefix, variant(type, f[type].event, fault)]), "EVENT_DATA_INVALID", `${type}: ${fault}`);
});

test("A-202.1: unfenced, every wrong literal is still EVENT_DATA_INVALID with the reason the schema gave before; the unchanged events are accepted", async (t) => {
  const f = await setup(t);
  const cases = { ATTEMPT_DUTY_POLICY_ACTIVATED: [["rulesHash", /descriptor literals must be those of continuity-attempt-disposition\/1/], ["version", /descriptor literals/], ["criteriaProfile", /descriptor literals/],
      ["dispositionLimit", /descriptor literals/], ["contestLimit", /descriptor literals/], ["digestAlgorithm", /incidentSourceDigest\.algorithm: must be sha256/]],
    ATTEMPT_DUTY_DISPOSITION_RECORDED: [["rulesHash", /disposition literals must be/], ["version", /disposition literals must be/], ["findingVersion", /finding literals must be those of continuity-duty-finding\/1/], ["findingRulesHash", /finding literals/], ["reportDigestAlgorithm", /reportDigest\.algorithm: must be sha256/]],
    ATTEMPT_DUTY_CONTEST_RECORDED: [["rulesHash", /disposition literals must be/], ["version", /disposition literals/], ["findingVersion", /finding literals/], ["findingRulesHash", /finding literals/], ["reportDigestAlgorithm", /reportDigest\.algorithm: must be sha256/]] };
  for (const type of TYPES) {
    const { unfenced, event } = f[type];
    assert.equal(codeOf([...unfenced, event]), "ACCEPTED", type);
    for (const [fault, reason] of cases[type]) {
      const r = core.replay([...unfenced, variant(type, event, fault)]);
      assert.equal(r.code, "EVENT_DATA_INVALID", `${type}: ${fault}`); assert.match(r.reason, reason, `${type}: ${fault}`);
    }
  }
});

test("A-202.1: the 67 ordering controls of Astra's clean guest (edition03), each history exactly as the guest's test built it, give the ruled first code", () => {
  const vectors = JSON.parse(readFileSync(new URL("./fixtures/a202-order-vectors.json", import.meta.url), "utf8"));
  assert.equal(vectors.cases.length, 67);
  for (const c of vectors.cases) {
    const r = core.replay([...vectors.prefixes[c.prefix], c.event]);
    assert.equal(r.status === "ACCEPTED" ? "ACCEPTED" : r.code, c.expectedCode, `${c.id} (${c.test}): ${r.reason}`);
    if (c.expectedDetail !== undefined) assert.equal(r.reason, c.expectedDetail, c.id);
  }
});

test("A-202.1 C4 boundary (the coordinator's ruling): the Identifier grammar of the fixed-literal string slots stays at C4, only the equality follows the fence; the hash slots likewise", () => {
  const vectors = JSON.parse(readFileSync(new URL("./fixtures/a202-boundary-vectors.json", import.meta.url), "utf8"));
  assert.equal(vectors.cases.length, 61);
  const counts = {};
  for (const c of vectors.cases) {
    const r = core.replay([...vectors.prefixes[c.prefix], c.event]);
    const code = r.status === "ACCEPTED" ? "ACCEPTED" : r.code;
    assert.equal(code, c.expectedCode, `${c.id}: ${r.reason}`);
    counts[`${c.group}:${c.variant}:${code}`] = (counts[`${c.group}:${c.variant}:${code}`] ?? 0) + 1;
  }
  // Nine slots: 29's descriptor version, criteriaProfile and digest algorithm; 30–31's version, finding version and reportDigest algorithm.
  // Per slot: a well-formed wrong value → SESSION_FENCED; empty, a C0 control, DEL → EVENT_DATA_INVALID; 257 UTF-8 bytes ("long") → INVALID_INPUT.
  for (const [variant, code] of [["valid-wrong", "SESSION_FENCED"], ["empty", "EVENT_DATA_INVALID"], ["control", "EVENT_DATA_INVALID"], ["del", "EVENT_DATA_INVALID"], ["long", "INVALID_INPUT"]]) {
    assert.equal(counts[`identifier-boundary:${variant}:${code}`], 9, `${variant} → ${code} on all nine slots`);
  }
});

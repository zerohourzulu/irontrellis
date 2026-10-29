// E5 (BUILD §6) performance paths that must not change a single byte or verdict:
//  - the export view reads its ends (records, root, projection head) from the state's undo lists instead of replaying
//    the prefix: every view equals the one computed from a private replay of the prefix;
//  - a large format-2 file replays with its Ed25519 verifications on the verification pool (crypto/parallel-verify.ts),
//    kept only when every one verified: the same state as sequentially, the same first error when a signature is bad.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const core = await import("../src/index.ts");
const { openHistoryStore, SPECULATIVE_REPLAY_MIN_RECORDS } = await import("../src/store.ts");
const { recordHash: chainRecordHash } = await import("../src/hash.ts");
const pv = await import("../src/crypto/parallel-verify.ts");
const { tempDir, richHistory } = await import("./helpers/format2-histories.mjs");
const { buildFormat2History } = await import("../bench/format2-history.mjs");

const plain = (value) => JSON.parse(JSON.stringify(value));

test("export view: ends read from the undo lists equal the ends of a replayed prefix, for every (from, to) pair tried", async () => {
  const dir = tempDir();
  try {
    const { events } = await richHistory(dir);
    const full = core.replay(events).state;
    const head = events.length - 1;
    const pairs = [[0, head], [0, 0], [1, 5], [7, 7], [10, head - 3], [Math.floor(head / 2), head], [head - 1, head], [head, head], [3, head - 1]];
    for (const [from, to] of pairs) {
      const include = { fromRecords: true, toRecords: true, inclusion: [{ kind: "event", key: core.positionKey(to) }], keyEvents: true };
      const view = core.exportViewState(full, { fromPosition: from, toPosition: to, include });
      // The reference: the same view from a state that ends at `to` (its own head), with `from` read from a replayed prefix.
      const atTo = core.replay(events.slice(0, to + 1)).state, atFrom = core.replay(events.slice(0, from + 1)).state;
      assert.equal(view.from.stateRoot, atFrom.stateRoots[from], `from ${from}`);
      assert.equal(view.from.recordCount, atFrom.stateRecords.size);
      assert.equal(view.from.projectionHead, atFrom.projectionHeads[from]);
      assert.equal(view.to.stateRoot, atTo.stateRoots[to], `to ${to}`);
      assert.equal(view.to.recordCount, atTo.stateRecords.size);
      assert.deepEqual(plain(view.fromRecords), plain(core.stateRecordsOf(atFrom).map((e) => ({ kind: e.kind, key: e.key, record: e.record }))));
      assert.deepEqual(plain(view.toRecords), plain(core.stateRecordsOf(atTo).map((e) => ({ kind: e.kind, key: e.key, record: e.record }))));
      assert.deepEqual(plain(view), plain(core.exportViewState(atTo, { fromPosition: from, toPosition: to, include })), `view ${from}..${to}`);
      const verified = core.verifyExportView(view, { genesisEventHash: view.genesisEventHash });
      assert.equal(verified.to.stateRoot, view.to.stateRoot);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** Opens `path` for inspection with `threads` verification workers; the outcome as comparable data. */
const openWith = async (path, threads) => {
  await pv.setVerifyThreadsForTests(threads);
  try {
    const store = openHistoryStore(path, { inspect: true });
    const state = store.state();
    const outcome = { ok: true, head: store.head(), root: core.stateRootOf(state), projection: state.projectionHeads.at(-1), records: core.stateRecordsOf(state).map((e) => core.canonicalEncode(e.record)).join("\n") };
    store.close();
    return { outcome, stats: pv.speculationStats() };
  } catch (error) {
    return { outcome: { ok: false, code: error.code, message: error.message, detail: error.detail }, stats: pv.speculationStats() };
  }
};
test.after(() => pv.setVerifyThreadsForTests(undefined));

test("speculative replay, format 2: the pool gives the sequential state, and the sequential first error for a bad signature", async () => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-f2-pv-"));
  try {
    const { historyFile } = await buildFormat2History(dir, SPECULATIVE_REPLAY_MIN_RECORDS + 60);
    const sequential = await openWith(historyFile, 0);
    const pooled = await openWith(historyFile, 2);
    assert.equal(sequential.outcome.ok, true);
    assert.deepEqual(pooled.outcome, sequential.outcome);
    assert.equal(sequential.stats.runs, 0, "no pool: no speculation");
    assert.equal(pooled.stats.runs, 1);
    assert.equal(pooled.stats.discarded, 0, "every queued verification succeeded");
    assert.ok(pooled.stats.queued >= SPECULATIVE_REPLAY_MIN_RECORDS / 2, `${pooled.stats.queued} verifications on the pool`);
    // One control signature flipped (the line chain re-hashed so the signature is the defect the replay meets first).
    const lines = readFileSync(historyFile, "utf8").trim().split("\n").map((line) => JSON.parse(line));
    const k = lines.findIndex((line, i) => i > SPECULATIVE_REPLAY_MIN_RECORDS - 10 && line.event.type === "BUDGET_UPDATED");
    const signature = lines[k].event.data.controlAuthorization.signature;
    lines[k].event.data.controlAuthorization.signature = `${signature.slice(0, -2)}${signature.endsWith("00") ? "01" : "00"}`;
    let previousHash = null;
    const tampered = join(dir, "tampered.jsonl");
    writeFileSync(tampered, `${lines.map((line, position) => {
      const recordHash = chainRecordHash(previousHash, line.event, position);
      const text = JSON.stringify({ version: line.version, previousHash, event: line.event, recordHash });
      previousHash = recordHash;
      return text;
    }).join("\n")}\n`);
    const bad = await openWith(tampered, 0);
    const badPooled = await openWith(tampered, 2);
    assert.equal(bad.outcome.ok, false);
    assert.equal(bad.outcome.detail.position, k);
    assert.equal(bad.outcome.detail.code, "CONTROL_AUTHORIZATION_INVALID");
    assert.deepEqual(badPooled.outcome, bad.outcome);
    assert.equal(badPooled.stats.discarded, 1, "the speculative result was thrown away");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resumed store: lines read lazily by their hash (writer's form) equal the full replay's events; other forms and defects take the full path", async () => {
  const dir = tempDir();
  try {
    const { config, events } = await richHistory(dir);
    const path = config.historyFile;
    const resumed = openHistoryStore(path, { inspect: true, trust: "CHECKPOINT_RESUME" });
    assert.equal(resumed.loadedBy(), "CHECKPOINT_RESUME");
    const lazy = [...resumed.readAll()];
    resumed.close();
    assert.deepEqual(lazy.map((e) => core.canonicalEncode(e)), events.map((e) => core.canonicalEncode(e)));
    const lines = readFileSync(path, "utf8").trim().split("\n");
    const q = 5;
    // The same record with its keys in another order: not the writer's form, still the same record (the full path accepts it).
    const record = JSON.parse(lines[q]);
    const reordered = [...lines];
    reordered[q] = JSON.stringify({ recordHash: record.recordHash, event: record.event, previousHash: record.previousHash, version: record.version });
    writeFileSync(path, `${reordered.join("\n")}\n`);
    const again = openHistoryStore(path, { inspect: true, trust: "CHECKPOINT_RESUME" });
    assert.equal(again.loadedBy(), "CHECKPOINT_RESUME");
    assert.equal(core.canonicalEncode(again.readAll()[q]), core.canonicalEncode(events[q]));
    again.close();
    // A changed event in the writer's form: its hash is not the record's, and the full path refuses it with its own error.
    const tampered = [...lines];
    tampered[q] = lines[q].replace(`"timestamp":${events[q].timestamp}`, `"timestamp":${events[q].timestamp + 1}`);
    assert.notEqual(tampered[q], lines[q]);
    writeFileSync(path, `${tampered.join("\n")}\n`);
    const bad = openHistoryStore(path, { inspect: true, trust: "CHECKPOINT_RESUME" });
    assert.equal(bad.loadedBy(), "CHECKPOINT_RESUME");
    assert.throws(() => bad.readAll()[q], (error) => error.code === "INVALID_HISTORY" && error.detail.position === q && /record integrity check failed/.test(error.message));
    bad.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("strict JSON (A-34): the faster string and number scans give the 0923d57 validator's verdict and message on every input", async () => {
  const fast = await import("../src/strict-json.ts");
  const reference = await import("./helpers/strict-json-r23.ts");
  let seed = 0x2545f491;
  const random = () => { seed ^= seed << 13; seed >>>= 0; seed ^= seed >>> 17; seed ^= seed << 5; seed >>>= 0; return seed / 0x1_0000_0000; };
  const pick = (list) => list[Math.floor(random() * list.length)];
  const PIECES = ["a", "é", " ", "😀", "\\n", "\\\"", "\\\\", "\\/", "\\u0041", "\\ud83d\\ude00", "\\ud800", "\\udc00x", "\ud800", "\udc00", "\\x", "\\u12G4", "\u0001", "\t", "key", "0x"];
  const string = () => `"${Array.from({ length: Math.floor(random() * 4) }, () => pick(PIECES)).join("")}"`;
  const number = () => pick([
    () => String(Math.floor(random() * 1000)), () => `-${Math.floor(random() * 1000)}`, () => "0", () => "-0", () => "00", () => "012", () => "1.5", () => "1e3", () => "1E3", () => "-",
    () => "9007199254740991", () => "-9007199254740991", () => "9007199254740992", () => "12345678901234567", () => "1".repeat(Math.floor(random() * 45) + 1), () => `-${"9".repeat(Math.floor(random() * 30) + 1)}`,
  ])();
  const value = (depth) => {
    const r = random();
    if (depth > 4 || r < 0.35) return pick([string, number, () => pick(["true", "false", "null", "tru", "nul", "falsey", "nulll"])])();
    if (r < 0.7) {
      const keys = Array.from({ length: Math.floor(random() * 4) }, () => (random() < 0.15 ? "\"k\"" : string()));
      return `{${keys.map((k) => `${pick(["", " ", "\n"])}${k}${pick([":", " : ", ":"])}${value(depth + 1)}`).join(pick([",", " ,", ","]))}}`;
    }
    return `[${Array.from({ length: Math.floor(random() * 4) }, () => value(depth + 1)).join(",")}]`;
  };
  const mutate = (text) => {
    if (text.length === 0 || random() < 0.5) return text;
    const at = Math.floor(random() * text.length);
    const r = random();
    if (r < 0.33) return text.slice(0, at) + text.slice(at + 1);
    if (r < 0.66) return text.slice(0, at) + pick(["\"", "\\", ",", ":", "{", "}", "[", "]", "-", "0", "9", "e", ".", " ", "\ud800"]) + text.slice(at);
    return text.slice(0, at);
  };
  const outcome = (module, text) => { const problem = module.strictJsonProblem(text); return problem === undefined ? "ok" : `${problem.code}: ${problem.message}`; };
  let valid = 0;
  for (let i = 0; i < 25_000; i += 1) {
    const text = mutate(value(0));
    const expected = outcome(reference, text);
    assert.equal(outcome(fast, text), expected, JSON.stringify(text));
    if (expected === "ok") { valid += 1; assert.deepEqual(fast.parseStrictJson(text), reference.parseStrictJson(text)); }
  }
  assert.ok(valid > 2_000 && valid < 23_000, `${valid} valid texts`);
  // And the real inputs: every line and the snapshot of a format-2 history.
  const dir = tempDir();
  try {
    const { config } = await richHistory(dir);
    for (const text of [...readFileSync(config.historyFile, "utf8").trim().split("\n"), readFileSync(`${config.historyFile}.state`, "utf8")]) assert.equal(outcome(fast, text), outcome(reference, text));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

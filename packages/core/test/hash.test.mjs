import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

import { HistoryHasher, bytesToHex, hashBytes, hashCanonical, hashEventHistory, hashEventHistoryPrefixes, historyHashAlgorithm, sha256Hex } from "../src/hash.ts";
import { CanonicalError, canonicalEncode } from "../src/canonical.ts";

import { referenceCore02, fixturesRoot as FIXTURES, vectorsPath } from "./reference.mjs";
const reference = await referenceCore02("core/canonical.ts");
const VECTORS = JSON.parse(readFileSync(vectorsPath, "utf8"));
const reviveBigints = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string" ? BigInt(value["$continuity.bigint"]) : value;
const loadFixture = (name, revive = true) => JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8"), revive ? reviveBigints : undefined);

const LEGACY = "continuity-event/0.2";
const FORMAT1 = "irontrellis-event/1";
const HEX64 = /^0x[0-9a-f]{64}$/;

test("hashCanonical reproduces the spec vectors and the reference", () => {
  assert.equal(hashCanonical({ a: 1 }, "keccak256"), "0x25e7c2a96531eb50246780c1f25742e489bf55210e26981dc02992bb585feb97");
  assert.equal(hashCanonical("", "keccak256"), "0x2392a80f8a87b8cfde0aa5c84e199f163aae4c2a4c512d37598362ace687ad0c");
  const events = loadFixture("handover-history.json");
  assert.equal(hashCanonical(events[1], "keccak256"), "0xf3455a16a2af7a75bfae76f1311c15b879009fe8c94ae0ad48ddf9fa0db1dbb0");
  assert.equal(
    hashCanonical({ version: "continuity-portable-file-store/0.2", previousHash: null, event: events[0] }, "keccak256"),
    "0x4d81d24f7dff9f4aee041d08c5d7fdb3d07f03e30a0c0607a172f14a13b454ce",
  );
  for (const name of ["handover-history.json", "handover-denied-history.json", "mandate-history.json"]) {
    for (const event of loadFixture(name)) assert.equal(hashCanonical(event, "keccak256"), reference.hashCanonical(event));
  }
  for (const vector of VECTORS) assert.equal(hashCanonical(vector, "keccak256"), reference.hashCanonical(vector));
  // sha256 is the same construction with a different digest.
  const text = canonicalEncode({ b: 2n, a: [1, "x"] });
  assert.equal(hashCanonical({ b: 2n, a: [1, "x"] }, "sha256"), `0x${createHash("sha256").update(text).digest("hex")}`);
  assert.throws(() => hashCanonical(-0, "sha256"), CanonicalError);
  assert.throws(() => hashCanonical(undefined, "keccak256"), CanonicalError);
});

test("hashBytes / sha256Hex / bytesToHex", () => {
  const empty = new Uint8Array(0);
  assert.equal(sha256Hex(empty), "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(hashBytes(empty, "sha256"), sha256Hex(empty));
  assert.equal(hashBytes(empty, "keccak256"), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(bytesToHex(new Uint8Array([0, 1, 15, 16, 255])), "00010f10ff");
  assert.equal(historyHashAlgorithm(LEGACY), "keccak256");
  assert.equal(historyHashAlgorithm(FORMAT1), "sha256");
  assert.throws(() => new HistoryHasher("bogus/9"), CanonicalError);
});

test("legacy history hashes match the reference on the handover fixture (every prefix)", () => {
  const events = loadFixture("handover-history.json");
  assert.equal(events.length, 26);
  const expectedPrefixes = reference.hashEventHistoryPrefixes(events);
  const prefixes = hashEventHistoryPrefixes(events, LEGACY);
  assert.deepEqual([...prefixes], [...expectedPrefixes]);
  assert.ok(Object.isFrozen(prefixes));
  assert.equal(prefixes[0], "0xe035299cb5520cc603d60273ae4c51ea1eaddad3cc9a47102edab60447d38397");
  assert.equal(prefixes[1], "0xa6f8cae49ad736cfcb45734fcf37da48d9fd364d5a93c7cc875560f4112f70b9");
  assert.equal(prefixes[25], "0x4958d40342fc047d3fff0d3ab0f36e572ea28d9a1bb6dcbfbc1961c52231b779");
  assert.ok(prefixes[14].startsWith("0xf156c2c9"), "head including the admission event");
  const hasher = new HistoryHasher(LEGACY);
  for (let position = 0; position < events.length; position += 1) {
    const head = hasher.push(events[position]);
    assert.equal(head, expectedPrefixes[position], `prefix ${position}`);
    assert.equal(head, reference.hashEventHistory(events.slice(0, position + 1)), `one-shot ${position}`);
    assert.equal(hashEventHistory(events.slice(0, position + 1), LEGACY), head);
    assert.equal(hasher.count, position + 1);
  }
  assert.equal(hashEventHistory(events, LEGACY), reference.hashEventHistory(events));
  assert.equal(hashEventHistory([], LEGACY), "0x65dc4448f700facf3bfb5d5a80a22e827e673b409b8293994847b56b5629b3b0");
  assert.deepEqual([...hashEventHistoryPrefixes([], LEGACY)], []);
});

test("legacy history hashes match the reference on every conformance vector and fixture", () => {
  const histories = [
    ...VECTORS.filter((vector) => Array.isArray(vector.events)).map((vector) => [vector.id, vector.events]),
    ["handover-denied", loadFixture("handover-denied-history.json")],
    ["mandate", loadFixture("mandate-history.json")],
    ["mandate-raw-markers", loadFixture("mandate-history.json", false)],
  ];
  let compared = 0;
  for (const [label, events] of histories) {
    const expected = reference.hashEventHistoryPrefixes(events);
    const prefixes = hashEventHistoryPrefixes(events, LEGACY);
    assert.deepEqual([...prefixes], [...expected], label);
    assert.equal(hashEventHistory(events, LEGACY), reference.hashEventHistory(events), label);
    const hasher = new HistoryHasher(LEGACY);
    for (let position = 0; position < events.length; position += 1) assert.equal(hasher.push(events[position]), expected[position], `${label}@${position}`);
    compared += events.length;
  }
  assert.ok(compared > 150, `compared ${compared} prefixes`);
});

test("format 1: sha256 over the irontrellis wrapper, incremental equals one-shot", () => {
  const events = loadFixture("handover-history.json");
  const empty = hashEventHistory([], FORMAT1);
  assert.equal(empty, `0x${createHash("sha256").update('["irontrellis-event-history/1",[]]').digest("hex")}`);
  assert.equal(empty, hashCanonical(["irontrellis-event-history/1", []], "sha256"));
  const hasher = new HistoryHasher(FORMAT1);
  assert.equal(hasher.format, FORMAT1);
  assert.equal(hasher.algorithm, "sha256");
  for (let position = 0; position < events.length; position += 1) {
    const head = hasher.push(events[position]);
    const prefix = events.slice(0, position + 1);
    assert.match(head, HEX64);
    assert.equal(head, hashEventHistory(prefix, FORMAT1), `one-shot ${position}`);
    // Independent construction: sha256 of the canonical text of the whole wrapper.
    const text = canonicalEncode(["irontrellis-event-history/1", prefix]);
    assert.equal(head, `0x${createHash("sha256").update(text).digest("hex")}`, `wrapper text ${position}`);
    assert.notEqual(head, hashEventHistory(prefix, LEGACY), "formats never collide");
  }
  assert.deepEqual([...hashEventHistoryPrefixes(events, FORMAT1)], events.map((_, index) => hashEventHistory(events.slice(0, index + 1), FORMAT1)));
});

test("legacy incremental equals one-shot on synthetic histories with bigints and unicode", () => {
  const events = [];
  for (let index = 0; index < 40; index += 1) {
    events.push({
      id: `e${index}`,
      type: index % 2 === 0 ? "AUTHORITY_GRANTED" : "OBLIGATION_CREATED",
      timestamp: index,
      data: { amount: (1n << BigInt(index * 6)) - 1n, text: `é€😀\u0000"\\${index}`, nested: { list: [index, null, true, { "$continuity.bigint": `${-index}` }] } },
    });
  }
  for (const format of [LEGACY, FORMAT1]) {
    const hasher = new HistoryHasher(format);
    for (let position = 0; position < events.length; position += 1) {
      assert.equal(hasher.push(events[position]), hashEventHistory(events.slice(0, position + 1), format), `${format} ${position}`);
    }
  }
  assert.deepEqual([...hashEventHistoryPrefixes(events, LEGACY)], [...reference.hashEventHistoryPrefixes(events)]);
});

test("clone forks the incremental state without sharing it", () => {
  const events = loadFixture("mandate-history.json");
  const hasher = new HistoryHasher(LEGACY);
  hasher.push(events[0]);
  hasher.push(events[1]);
  const fork = hasher.clone();
  assert.equal(fork.count, 2);
  const forkHead = fork.push(events[2]);
  assert.equal(forkHead, hashEventHistory(events.slice(0, 3), LEGACY));
  assert.equal(hasher.count, 2);
  assert.equal(hasher.push(events[2]), forkHead, "original continues independently");
  assert.equal(fork.push(events[3]), hashEventHistory(events.slice(0, 4), LEGACY));
  const sha = new HistoryHasher(FORMAT1);
  sha.push(events[0]);
  const shaFork = sha.clone();
  assert.equal(shaFork.push(events[1]), sha.push(events[1]));
  assert.equal(sha.push(events[2]), shaFork.push(events[2]));
});

test("history input validation mirrors the reference wrapper capture", () => {
  const event = { id: "e", type: "T", timestamp: 0, data: {} };
  assert.throws(() => hashEventHistory({ length: 1, 0: event }, LEGACY), CanonicalError, "array-likes are not histories");
  assert.throws(() => reference.hashEventHistory({ length: 1, 0: event }));
  const sparse = [event, , event];
  assert.throws(() => hashEventHistory(sparse, LEGACY), CanonicalError);
  assert.throws(() => reference.hashEventHistory(sparse));
  const expando = [event];
  expando.extra = 1;
  assert.throws(() => hashEventHistory(expando, LEGACY), CanonicalError);
  assert.throws(() => reference.hashEventHistory(expando));
  assert.throws(() => hashEventHistory([undefined], FORMAT1), CanonicalError);
  assert.throws(() => hashEventHistoryPrefixes([event, -0], LEGACY), CanonicalError);
  // Events are encoded two containers deep: 28 levels fit under data, 29 do not (spec 01 A.8).
  const nest = (levels) => { let value = 1; for (let index = 0; index < levels; index += 1) value = { a: value }; return value; };
  const deep = (levels) => ({ id: "e", type: "T", timestamp: 0, data: { a: nest(levels) } });
  assert.equal(hashEventHistory([deep(28)], LEGACY), reference.hashEventHistory([deep(28)]));
  assert.throws(() => reference.hashEventHistory([deep(29)]));
  assert.throws(() => hashEventHistory([deep(29)], LEGACY), CanonicalError);
  assert.throws(() => new HistoryHasher(LEGACY).push(deep(29)), CanonicalError);
  assert.throws(() => new HistoryHasher(FORMAT1).push(deep(29)), CanonicalError);
  // The legacy whole-history member bound (4096) applies; format 1 has none.
  const small = Array.from({ length: 4097 }, (_, index) => ({ id: `e${index}`, type: "T", timestamp: index, data: {} }));
  assert.throws(() => reference.hashEventHistory(small));
  const legacyError = (() => { try { hashEventHistory(small, LEGACY); } catch (error) { return error; } return undefined; })();
  assert.ok(legacyError instanceof CanonicalError && legacyError.limit === true);
  const legacyHasher = new HistoryHasher(LEGACY);
  for (let index = 0; index < 4096; index += 1) legacyHasher.push(small[index]);
  assert.throws(() => legacyHasher.push(small[4096]), CanonicalError);
  assert.equal(hashEventHistory(small.slice(0, 4096), LEGACY), reference.hashEventHistory(small.slice(0, 4096)));
  assert.match(hashEventHistory(small, FORMAT1), HEX64);
  const trellisHasher = new HistoryHasher(FORMAT1);
  let head;
  for (const item of small) head = trellisHasher.push(item);
  assert.equal(head, hashEventHistory(small, FORMAT1));
});

test("legacy whole-history byte budget (16 MiB) is enforced incrementally", () => {
  const chunk = "x".repeat(4096);
  const fat = { id: "e", type: "T", timestamp: 0, data: { list: Array.from({ length: 200 }, () => chunk) } };
  const eventBytes = new TextEncoder().encode(canonicalEncode(fat)).length;
  // Wrapper bytes: `["continuity-event-history/0.2",[` (33) + events + separators + `]]` (2).
  const expectedFit = Math.floor((16_777_216 - 35 + 1) / (eventBytes + 1));
  const hasher = new HistoryHasher(LEGACY);
  let count = 0;
  let error;
  try {
    for (;;) { hasher.push(fat); count += 1; }
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof CanonicalError && error.limit === true);
  assert.equal(count, expectedFit);
  assert.equal(35 + expectedFit * eventBytes + (expectedFit - 1) <= 16_777_216, true);
  assert.equal(35 + (expectedFit + 1) * eventBytes + expectedFit > 16_777_216, true);
  assert.throws(() => hashEventHistory(Array.from({ length: expectedFit + 1 }, () => fat), LEGACY), CanonicalError);
  // The reference applies the same 16 MiB bound to the whole wrapper (slow, so only the reject side is checked).
  assert.throws(() => reference.hashEventHistory(Array.from({ length: expectedFit + 1 }, () => fat)));
  const trellis = new HistoryHasher(FORMAT1);
  for (let index = 0; index <= expectedFit; index += 1) trellis.push(fat);
  assert.equal(trellis.count, expectedFit + 1, "format 1 has no whole-history budget");
});

test("performance: incremental push of a typical event", () => {
  const events = loadFixture("handover-history.json");
  const typical = events.find((event) => event.type === "AUTHORITY_GRANTED");
  const measure = (format) => {
    const hasher = new HistoryHasher(format);
    for (let index = 0; index < 2000; index += 1) hasher.push(typical);
    const start = process.hrtime.bigint();
    for (let index = 0; index < 2000; index += 1) hasher.push(typical);
    return Number(process.hrtime.bigint() - start) / 2000 / 1000;
  };
  const legacyMicros = measure(LEGACY);
  const trellisMicros = measure(FORMAT1);
  console.log(`HistoryHasher.push: legacy/keccak ${legacyMicros.toFixed(2)} µs, format-1/sha256 ${trellisMicros.toFixed(2)} µs`);
  assert.ok(legacyMicros < 2000 && trellisMicros < 2000);
});

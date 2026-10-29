import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  CanonicalError,
  LIMITS,
  canonicalEncode,
  captureValue,
  compareProtocolStrings,
  isAmount,
  isChainId,
  isContentHash,
  isEthereumAddress,
  isIdentifier,
  isProtocolString,
  isU53,
  jsonParseWithBigints,
  jsonStringifyWithBigints,
  sortedIdentifiers,
} from "../src/canonical.ts";

import { referenceCore02, fixturesRoot as FIXTURES, vectorsPath } from "./reference.mjs";
import { bestOf, loadFactor } from "./helpers/timing.mjs";
const reference = await referenceCore02("core/canonical.ts");
const VECTORS = JSON.parse(readFileSync(vectorsPath, "utf8"));

const reviveBigints = (_key, value) =>
  value !== null && typeof value === "object" && typeof value["$continuity.bigint"] === "string"
    ? BigInt(value["$continuity.bigint"])
    : value;
const loadFixture = (name, revive = true) => JSON.parse(readFileSync(`${FIXTURES}${name}`, "utf8"), revive ? reviveBigints : undefined);

/** Both implementations must agree: same text, or both reject. */
function assertParity(value, label = "") {
  let expected;
  let expectedError;
  try {
    expected = reference.canonicalEncode(value);
  } catch (error) {
    expectedError = error;
  }
  if (expectedError === undefined) {
    assert.equal(canonicalEncode(value), expected, `text mismatch ${label}`);
    // captureValue accepts exactly what canonicalEncode accepts, and its copy re-encodes identically.
    assert.equal(canonicalEncode(captureValue(value)), expected, `capture mismatch ${label}`);
  } else {
    assert.throws(() => canonicalEncode(value), CanonicalError, `expected rejection ${label}: ${expectedError.message}`);
    assert.throws(() => captureValue(value), CanonicalError, `expected capture rejection ${label}`);
  }
}

// ---------------------------------------------------------------- worked examples (spec 01 A.0)

test("spec worked examples encode byte-identically", () => {
  const cases = [
    [{ b: 1, a: "x", c: [true, false, null] }, '{"a":"x","b":1,"c":[true,false,null]}'],
    [{}, "{}"],
    [[], "[]"],
    [0, "0"],
    [-1, "-1"],
    [Number.MAX_SAFE_INTEGER, "9007199254740991"],
    [-Number.MAX_SAFE_INTEGER, "-9007199254740991"],
    [5n, '{"$continuity.bigint":"5"}'],
    [-5n, '{"$continuity.bigint":"-5"}'],
    [0n, '{"$continuity.bigint":"0"}'],
    [{ amount: 5n }, '{"amount":{"$continuity.bigint":"5"}}'],
    [{ "$continuity.bigint": "5" }, '{"$continuity.bigint":"5"}'],
    ['a"b\\c\n\t\u0001\u001f\u007f\u0080é€😀/', '"a\\"b\\\\c\\u000a\\u0009\\u0001\\u001f\u007f\u0080é€😀/"'],
    [{ a: undefined, b: 1 }, '{"b":1}'],
    [JSON.parse('{"a":1,"__proto__":{"evil":true}}'), '{"__proto__":{"evil":true},"a":1}'],
    [Object.assign(Object.create(null), { own: "mine" }), '{"own":"mine"}'],
    [{ b: 1, B: 2, a: 3, A: 4, "": 5, aa: 6, "a-": 7, 10: 8, 2: 9, é: 10, z: 11 }, '{"":5,"10":8,"2":9,"A":4,"B":2,"a":3,"a-":7,"aa":6,"b":1,"z":11,"é":10}'],
    ["", '""'],
    [{ "\u{10000}": 1, "￿": 2 }, '{"￿":2,"\u{10000}":1}'],
    ["  ", '"  "'],
    [(1n << 256n) - 1n, `{"$continuity.bigint":"${(1n << 256n) - 1n}"}`],
    [-((1n << 256n) - 1n), `{"$continuity.bigint":"-${(1n << 256n) - 1n}"}`],
  ];
  for (const [value, text] of cases) {
    assert.equal(canonicalEncode(value), text);
    assert.equal(reference.canonicalEncode(value), text, "reference disagrees with the spec table");
  }
  const shared = { x: 1 };
  assert.equal(canonicalEncode([shared, shared]), '[{"x":1},{"x":1}]');
});

test("bigint marker objects and native bigints encode identically", () => {
  assert.equal(canonicalEncode({ a: { "$continuity.bigint": "7" } }), canonicalEncode({ a: 7n }));
  assert.equal(canonicalEncode([{ "$continuity.bigint": "-12" }]), canonicalEncode([-12n]));
  assert.equal(canonicalEncode({ "$continuity.bigint": "0" }), '{"$continuity.bigint":"0"}');
});

// ---------------------------------------------------------------- rejections (spec 01 A.10 + G)

test("rejects exactly what the reference rejects", () => {
  const big = (1n << 256n) - 1n;
  class Thing { constructor() { this.a = 1; } }
  const cyclic = { a: {} };
  cyclic.a.self = cyclic;
  const selfArray = [];
  selfArray.push(selfArray);
  const sparse = [1, , 3];
  const expando = [1, 2];
  expando.extra = 1;
  const symbolKeyed = { [Symbol("s")]: 1, a: 1 };
  const symbolArray = [1];
  symbolArray[Symbol("s")] = 1;
  const manyKeys = Object.fromEntries(Array.from({ length: 256 }, (_, index) => [`k${index}`, index]));
  const tooManyKeys = { ...manyKeys, extra: undefined };
  const longString = "a".repeat(4096);
  const tooLongString = "a".repeat(4097);
  const wideString = "€".repeat(1365) + "ab"; // 4097 bytes
  const bigArray = Array.from({ length: 4096 }, () => 0);
  const tooBigArray = Array.from({ length: 4097 }, () => 0);
  const nest = (depth, make) => { let value = 1; for (let index = 0; index < depth; index += 1) value = make(value); return value; };
  const rejected = [
    undefined, [undefined], { a: [undefined] }, () => 1, Symbol("s"), { a: () => 1 }, { a: Symbol("s") },
    NaN, Infinity, -Infinity, 1.5, -0, [-0], { a: -0 }, 1e21, Number.MAX_SAFE_INTEGER + 1, -(Number.MAX_SAFE_INTEGER + 1),
    big + 1n, -(big + 1n), { a: big + 1n },
    new Date(0), new Map(), new Set(), /x/, new Number(1), new String("x"), new Boolean(true), new Thing(),
    Object.assign(Object.create(Array.prototype), { own: 1 }), Object.create({ inherited: 1 }),
    symbolKeyed, symbolArray, sparse, expando, cyclic, selfArray, tooManyKeys, tooLongString, wideString, { [tooLongString]: 1 }, tooBigArray,
    "\ud800", "\udc00", "a\ud800b", "\udc00\ud800", { "\ud800": 1 }, { a: "\udfff" }, { "\ud800": undefined },
    { "$continuity.bigint": "5", x: 1 }, { "$continuity.bigint": "5", x: undefined }, { "$continuity.other": 1 }, { "$continuity.": 1 },
    { "$continuity.bigint": 5 }, { "$continuity.bigint": 5n }, { "$continuity.bigint": "05" }, { "$continuity.bigint": "-0" },
    { "$continuity.bigint": "+5" }, { "$continuity.bigint": "5n" }, { "$continuity.bigint": " 5" }, { "$continuity.bigint": "" },
    { "$continuity.bigint": "1".repeat(80) }, { "$continuity.bigint": `${big + 1n}` }, { "$continuity.bigint": `-${big + 1n}` },
    { "$continuity.bigint": undefined }, { "$continuity.bigint": null }, { "$continuity.bigint": ["5"] },
    nest(33, (v) => [v]), nest(33, (v) => ({ a: v })), nest(32, (v) => ({ a: v, e: {} })), nest(32, (v) => [v, []]),
  ];
  for (const value of rejected) {
    assert.throws(() => reference.canonicalEncode(value), undefined, "reference should reject");
    assert.throws(() => canonicalEncode(value), CanonicalError);
    assert.throws(() => captureValue(value), CanonicalError);
  }
  const accepted = [
    manyKeys, longString, { [longString]: 1 }, bigArray, nest(32, (v) => [v]), nest(32, (v) => ({ a: v })),
    nest(32, (v) => ({ a: 5n })), nest(32, (v) => [{ "$continuity.bigint": "9" }]), // markers add no depth
    { "$continuity.bigint": "1".repeat(77) }, { "$continuity.bigint": `${big}` }, { "$continuity.bigint": `-${big}` },
    { a: undefined }, { "": "" }, { " ": " " }, "\u007f", "\u0080", { "\u{1F600}": "\u{1F600}" },
    { get a() { return 1; }, b: 2 }, { set a(v) {}, b: 1 }, Object.defineProperty({}, "hidden", { value: 1, enumerable: false }),
    Object.freeze([1, { a: 2n }]), Object.defineProperty([1], "0", { get() { return 5; } }), Object.assign(Object.create(null), { 0: "a", length: 1 }),
    { $: 1, $continuit: 2, $continuity: 3 }, "-0", "😀".repeat(1024),
  ];
  for (const value of accepted) assertParity(value);
});

test("limit flag marks size, depth and count overruns", () => {
  const limitCases = [
    "a".repeat(4097),
    Object.fromEntries(Array.from({ length: 257 }, (_, index) => [`k${index}`, index])),
    Array.from({ length: 4097 }, () => 0),
    Array.from({ length: 33 }).reduce((inner) => [inner], 1),
    { a: 1n << 256n },
    { "$continuity.bigint": `${1n << 256n}` },
  ];
  const caught = (fn) => { try { fn(); } catch (error) { return error; } assert.fail("expected a throw"); };
  for (const value of limitCases) {
    const error = caught(() => canonicalEncode(value));
    assert.ok(error instanceof CanonicalError);
    assert.equal(error.limit, true, error.message);
  }
  for (const value of [-0, 1.5, NaN, undefined, new Date(0), "\ud800", { "$continuity.bigint": "05" }]) {
    const error = caught(() => canonicalEncode(value));
    assert.ok(error instanceof CanonicalError);
    assert.equal(error.limit, false, error.message);
    assert.equal(error.reason, error.message);
  }
  const overBudget = caught(() => canonicalEncode({ a: "x".repeat(100) }, { maxTotalBytes: 50 }));
  assert.equal(overBudget.limit, true);
  assert.equal(canonicalEncode({ a: "x" }, { maxTotalBytes: 9 }), '{"a":"x"}');
  assert.throws(() => canonicalEncode({ a: "x" }, { maxTotalBytes: 8 }), CanonicalError);
});

test("depth: ancestorDepth option and captureValue maxDepth", () => {
  const nest = (depth) => { let value = 1; for (let index = 0; index < depth; index += 1) value = { a: value }; return value; };
  assert.equal(typeof canonicalEncode(nest(30), { ancestorDepth: 2 }), "string");
  assert.throws(() => canonicalEncode(nest(31), { ancestorDepth: 2 }), CanonicalError);
  // An event inside the history wrapper: data sits at depth 4, so 28 more levels fit.
  const event = (levels) => ({ id: "e", type: "T", timestamp: 0, data: { a: nest(levels) } });
  assert.equal(typeof reference.canonicalEncode(["continuity-event-history/0.2", [event(28)]]), "string");
  assert.throws(() => reference.canonicalEncode(["continuity-event-history/0.2", [event(29)]]));
  assert.equal(typeof canonicalEncode(event(28), { ancestorDepth: 2 }), "string");
  assert.throws(() => canonicalEncode(event(29), { ancestorDepth: 2 }), CanonicalError);
  assert.equal(typeof canonicalEncode(event(30)), "string", "a bare event allows 30 levels under data");
  assert.throws(() => canonicalEncode(event(31)), CanonicalError);
  assert.deepEqual(captureValue(nest(3), { maxDepth: 3 }), nest(3));
  assert.throws(() => captureValue(nest(4), { maxDepth: 3 }), CanonicalError);
  assert.throws(() => captureValue(nest(33), { maxDepth: 99 }), CanonicalError, "maxDepth is clamped to 32");
  assert.throws(() => captureValue({}, { maxDepth: -1 }), CanonicalError);
  assert.throws(() => captureValue({}, { maxTotalBytes: 1.5 }), CanonicalError);
});

// ---------------------------------------------------------------- differential fuzz

function makeRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

const ALPHABET = ["a", "b", "Z", "", "10", "2", "é", "€", "😀", "\u0000", "\u001f", "\u007f", "\u0080", '"', "\\", "/", " ", "\n", "$", "$continuity.", "__proto__", "constructor", "￿", "\u{10000}", "length", "0", "1"];

function randomString(random) {
  const parts = Math.floor(random() * 4);
  let text = "";
  for (let index = 0; index < parts; index += 1) text += ALPHABET[Math.floor(random() * ALPHABET.length)];
  return text;
}

function randomValue(random, depth) {
  const roll = random();
  if (depth > 4 || roll < 0.45) {
    const scalar = random();
    if (scalar < 0.25) return randomString(random);
    if (scalar < 0.45) return Math.floor(random() * 2000) - 1000;
    if (scalar < 0.55) return BigInt(Math.floor(random() * 1e9)) * (random() < 0.5 ? -1n : 1n) ** 1n * (1n << BigInt(Math.floor(random() * 200)));
    if (scalar < 0.65) return { "$continuity.bigint": `${Math.floor(random() * 1e6) * (random() < 0.3 ? -1 : 1)}` };
    if (scalar < 0.75) return random() < 0.5;
    if (scalar < 0.85) return null;
    if (scalar < 0.9) return undefined;
    if (scalar < 0.93) return -0;
    if (scalar < 0.96) return random();
    return Number.MAX_SAFE_INTEGER;
  }
  if (roll < 0.7) {
    const length = Math.floor(random() * 5);
    const list = [];
    for (let index = 0; index < length; index += 1) list.push(randomValue(random, depth + 1));
    return list;
  }
  const count = Math.floor(random() * 6);
  const record = random() < 0.2 ? Object.create(null) : {};
  for (let index = 0; index < count; index += 1) {
    const key = randomString(random);
    Object.defineProperty(record, key, { value: randomValue(random, depth + 1), enumerable: true, writable: true, configurable: true });
  }
  return record;
}

test("differential fuzz: 3000 random values agree with the reference", () => {
  const random = makeRandom(20260923);
  let accepted = 0;
  for (let round = 0; round < 3000; round += 1) {
    const value = randomValue(random, 0);
    assertParity(value, `round ${round}`);
    try { reference.canonicalEncode(value); accepted += 1; } catch { /* counted as a rejection */ }
  }
  assert.ok(accepted > 500, `fuzz should exercise the accept path (${accepted} accepted)`);
});

test("fixtures and conformance vectors encode identically (raw JSON markers and revived bigints)", () => {
  for (const name of ["handover-history.json", "handover-denied-history.json", "mandate-history.json", "handover-case.json", "mandate-case.json"]) {
    for (const revive of [true, false]) {
      const value = loadFixture(name, revive);
      assert.equal(canonicalEncode(value), reference.canonicalEncode(value), `${name} revive=${revive}`);
      const events = Array.isArray(value) ? value : [];
      for (const event of events) assert.equal(canonicalEncode(event), reference.canonicalEncode(event));
    }
  }
  for (const vector of VECTORS) {
    assert.equal(canonicalEncode(vector), reference.canonicalEncode(vector), vector.id);
    assert.equal(canonicalEncode(captureValue(vector)), reference.canonicalEncode(vector), vector.id);
  }
});

// ---------------------------------------------------------------- compareProtocolStrings

test("compareProtocolStrings is UTF-8 byte order and validates its inputs", () => {
  assert.equal(compareProtocolStrings("B", "a"), -1);
  assert.equal(compareProtocolStrings("", "a"), -1);
  assert.equal(compareProtocolStrings("10", "2"), -1);
  assert.equal(compareProtocolStrings("a", "a"), 0);
  assert.equal(compareProtocolStrings("ab", "a"), 1);
  assert.equal(compareProtocolStrings("\u{10000}", "￿"), 1);
  assert.equal(compareProtocolStrings("￿", "\u{10000}"), -1);
  assert.equal(compareProtocolStrings("", "\u{10ffff}"), -1);
  assert.equal(compareProtocolStrings("\u{10ffff}", "\u{10000}"), 1);
  assert.throws(() => compareProtocolStrings("\ud800", "a"), CanonicalError);
  assert.throws(() => compareProtocolStrings("a", "\udc00"), CanonicalError);
  assert.throws(() => compareProtocolStrings("a".repeat(4097), "a"), CanonicalError);
  const random = makeRandom(7);
  const pool = [];
  for (let index = 0; index < 400; index += 1) pool.push(randomString(random));
  pool.push("\u{10000}", "￿", "", "퟿", "\u{10ffff}", "\u{1F600}a", "￿a", "a\u{10000}", "a￿");
  const encoder = new TextEncoder();
  for (let index = 0; index < pool.length; index += 1) {
    for (let other = 0; other < pool.length; other += 3) {
      const left = pool[index];
      const right = pool[other];
      let expected;
      try { expected = reference.compareProtocolStrings(left, right); } catch { assert.throws(() => compareProtocolStrings(left, right), CanonicalError); continue; }
      assert.equal(compareProtocolStrings(left, right), expected, `${JSON.stringify(left)} vs ${JSON.stringify(right)}`);
      // Independent oracle: byte-wise comparison of UTF-8 encodings.
      const a = encoder.encode(left);
      const b = encoder.encode(right);
      let oracle = 0;
      for (let position = 0; position < Math.min(a.length, b.length) && oracle === 0; position += 1) oracle = a[position] < b[position] ? -1 : a[position] > b[position] ? 1 : 0;
      if (oracle === 0) oracle = a.length < b.length ? -1 : a.length > b.length ? 1 : 0;
      assert.equal(expected, oracle);
    }
  }
});

test("sortedIdentifiers returns a frozen UTF-8-ordered copy", () => {
  const input = ["b", "B", "a", "A", "", "aa", "a-", "10", "2", "é", "z", "\u{10000}", "￿"];
  const sorted = sortedIdentifiers(input);
  assert.deepEqual([...sorted], [...input].sort(reference.compareProtocolStrings));
  assert.ok(Object.isFrozen(sorted));
  assert.deepEqual(input[0], "b", "input untouched");
  assert.throws(() => sortedIdentifiers(["a", "\ud800"]), CanonicalError);
});

// ---------------------------------------------------------------- captureValue

test("captureValue returns a frozen sorted deep copy with markers decoded", () => {
  const source = { z: [1, { "$continuity.bigint": "42" }], a: { y: undefined, x: "s" }, m: 7n };
  Object.defineProperty(source, "__proto__", { value: { evil: true }, enumerable: true, writable: true, configurable: true });
  const captured = captureValue(source);
  assert.notEqual(captured, source);
  assert.ok(Object.isFrozen(captured) && Object.isFrozen(captured.z) && Object.isFrozen(captured.a) && Object.isFrozen(captured.z[1] === 42n ? captured.a : captured.z));
  assert.deepEqual(Object.keys(captured), ["__proto__", "a", "m", "z"]);
  assert.equal(Object.getPrototypeOf(captured), Object.prototype);
  assert.deepEqual(Object.getOwnPropertyDescriptor(captured, "__proto__").value, { evil: true });
  assert.equal(captured.z[1], 42n);
  assert.equal(typeof captured.z[1], "bigint");
  assert.equal(captured.m, 7n);
  assert.equal(Object.hasOwn(captured.a, "y"), false, "undefined fields are dropped");
  assert.deepEqual(Object.keys(captured.a), ["x"]);
  assert.equal(canonicalEncode(captured), canonicalEncode(source));
  assert.equal(captureValue({ "$continuity.bigint": "-9" }), -9n);
  assert.equal(captureValue(3), 3);
  assert.equal(captureValue("x"), "x");
  assert.equal(captureValue(null), null);
  // Parity with the reference immutable snapshot on fixture data.
  const events = loadFixture("mandate-history.json", false);
  const mine = captureValue(events);
  const theirs = reference.immutableProtocolValue(events);
  assert.equal(JSON.stringify(mine, (_k, v) => (typeof v === "bigint" ? `${v}n` : v)), JSON.stringify(theirs, (_k, v) => (typeof v === "bigint" ? `${v}n` : v)));
  assert.equal(canonicalEncode(mine), reference.canonicalEncode(theirs));
});

test("captureValue mirrors canonicalEncode rejections and byte limits", () => {
  assert.throws(() => captureValue({ a: NaN }), CanonicalError);
  assert.throws(() => captureValue({ a: { "$continuity.bigint": "5", b: 1 } }), CanonicalError);
  assert.throws(() => captureValue([1, , 2]), CanonicalError);
  assert.throws(() => captureValue(new Date(0)), CanonicalError);
  assert.throws(() => captureValue("\udc00"), CanonicalError);
  assert.throws(() => captureValue({ [Symbol("x")]: 1 }), CanonicalError);
  assert.throws(() => captureValue({ a: "x".repeat(100) }, { maxTotalBytes: 50 }), CanonicalError);
  // The byte accounting of capture equals the canonical text length.
  const random = makeRandom(99);
  for (let round = 0; round < 300; round += 1) {
    const value = randomValue(random, 0);
    let text;
    try { text = canonicalEncode(value); } catch { continue; }
    const bytes = new TextEncoder().encode(text).length;
    assert.equal(canonicalEncode(captureValue(value, { maxTotalBytes: bytes })), text);
    if (bytes > 0) assert.throws(() => captureValue(value, { maxTotalBytes: bytes - 1 }), CanonicalError, `budget ${bytes - 1} for ${text}`);
  }
});

// ---------------------------------------------------------------- predicates

test("scalar predicates follow the spec definitions", () => {
  assert.ok(isIdentifier("a") && isIdentifier(" ") && isIdentifier("\u0080") && isIdentifier("é".repeat(128)) && isIdentifier("a".repeat(256)));
  assert.ok(!isIdentifier("") && !isIdentifier("a\u0000") && !isIdentifier("\u001f") && !isIdentifier("\u007f") && !isIdentifier("a".repeat(257)) && !isIdentifier("é".repeat(129)) && !isIdentifier("\ud800") && !isIdentifier(1));
  assert.ok(isProtocolString("") && isProtocolString("a".repeat(4096)) && !isProtocolString("a".repeat(4097)) && !isProtocolString("\udc00") && !isProtocolString(null));
  assert.ok(isU53(0) && isU53(Number.MAX_SAFE_INTEGER) && !isU53(-0) && !isU53(-1) && !isU53(1.5) && !isU53(Number.MAX_SAFE_INTEGER + 1) && !isU53(1n) && !isU53(NaN));
  assert.ok(isAmount(0n) && isAmount((1n << 256n) - 1n) && !isAmount(-1n) && !isAmount(1n << 256n) && !isAmount(1));
  assert.ok(isContentHash(`0x${"a1".repeat(32)}`) && !isContentHash(`0x${"A1".repeat(32)}`) && !isContentHash(`0x${"a1".repeat(31)}`) && !isContentHash(5));
  assert.ok(isEthereumAddress(`0x${"aB".repeat(20)}`) && !isEthereumAddress(`0x${"ab".repeat(19)}`) && !isEthereumAddress("ab".repeat(21)));
  assert.ok(isChainId("1") && isChainId("31337") && isChainId(`${(1n << 256n) - 1n}`) && !isChainId("0") && !isChainId("01") && !isChainId(`${1n << 256n}`) && !isChainId("") && !isChainId(1) && !isChainId("1".repeat(79)));
});

// ---------------------------------------------------------------- JSON helpers

test("jsonStringifyWithBigints / jsonParseWithBigints round-trip with strict markers", () => {
  const value = { amount: 2500n, nested: [{ "$continuity.bigint": "1" }, -7n], text: "x", n: 1 };
  const text = jsonStringifyWithBigints(value);
  assert.equal(text, '{"amount":{"$continuity.bigint":"2500"},"nested":[{"$continuity.bigint":"1"},{"$continuity.bigint":"-7"}],"text":"x","n":1}');
  const parsed = jsonParseWithBigints(text);
  assert.equal(parsed.amount, 2500n);
  assert.equal(parsed.nested[0], 1n);
  assert.equal(parsed.nested[1], -7n);
  assert.equal(canonicalEncode(parsed), canonicalEncode(value));
  const proto = jsonParseWithBigints('{"__proto__":{"evil":true},"a":1}');
  assert.equal(Object.getPrototypeOf(proto), Object.prototype);
  assert.deepEqual(Object.getOwnPropertyDescriptor(proto, "__proto__").value, { evil: true });
  assert.equal(canonicalEncode(proto), '{"__proto__":{"evil":true},"a":1}');
  for (const bad of ['{"$continuity.bigint":"05"}', '{"$continuity.bigint":"-0"}', '{"$continuity.bigint":5}', '{"$continuity.bigint":"5","x":1}', `{"$continuity.bigint":"${1n << 256n}"}`, `{"$continuity.bigint":"${"1".repeat(80)}"}`]) {
    assert.throws(() => jsonParseWithBigints(bad), CanonicalError, bad);
  }
  assert.throws(() => jsonParseWithBigints("{"), SyntaxError);
  // Fixture files parse to the same values the reference test helper produces.
  const raw = readFileSync(`${FIXTURES}mandate-history.json`, "utf8");
  assert.equal(canonicalEncode(jsonParseWithBigints(raw)), reference.canonicalEncode(JSON.parse(raw, reviveBigints)));
  assert.equal(jsonStringifyWithBigints(undefined), undefined);
});

// ---------------------------------------------------------------- LIMITS + performance

test("LIMITS carries the spec constants", () => {
  assert.deepEqual({ ...LIMITS }, { maxStringBytes: 4096, maxIdentifierBytes: 256, maxRecordKeys: 256, maxListMembers: 4096, maxDepth: 32, maxTotalBytes: 16777216 });
  assert.ok(Object.isFrozen(LIMITS));
});

test("performance: canonicalEncode of a typical event", async (t) => {
  const events = loadFixture("handover-history.json");
  // The admission event is the largest; pick a ~500-byte control event and report both.
  const typical = events.find((event) => event.type === "AUTHORITY_GRANTED");
  const typicalBytes = new TextEncoder().encode(canonicalEncode(typical)).length;
  const measure = (value, rounds) => {
    for (let index = 0; index < 2000; index += 1) canonicalEncode(value);
    const start = process.hrtime.bigint();
    for (let index = 0; index < rounds; index += 1) canonicalEncode(value);
    return Number(process.hrtime.bigint() - start) / rounds / 1000;
  };
  // Best of three rounds, bound scaled by the machine's current speed (helpers/timing.mjs): a busy host must not fail it.
  const micros = await bestOf(3, () => measure(typical, 20000));
  const captureMicros = (() => {
    for (let index = 0; index < 2000; index += 1) captureValue(typical);
    const start = process.hrtime.bigint();
    for (let index = 0; index < 20000; index += 1) captureValue(typical);
    return Number(process.hrtime.bigint() - start) / 20000 / 1000;
  })();
  const referenceMicros = (() => {
    for (let index = 0; index < 500; index += 1) reference.canonicalEncode(typical);
    const start = process.hrtime.bigint();
    for (let index = 0; index < 2000; index += 1) reference.canonicalEncode(typical);
    return Number(process.hrtime.bigint() - start) / 2000 / 1000;
  })();
  console.log(`canonicalEncode ${typical.type} (${typicalBytes} bytes): ${micros.toFixed(2)} µs; captureValue ${captureMicros.toFixed(2)} µs; reference ${referenceMicros.toFixed(2)} µs`);
  const factor = loadFactor();
  t.diagnostic(`load factor ${factor.toFixed(2)}`);
  assert.ok(micros < 200 * factor, `canonicalEncode took ${micros} µs (target 20 µs, hard bound 200 µs × load factor ${factor.toFixed(2)})`);
});

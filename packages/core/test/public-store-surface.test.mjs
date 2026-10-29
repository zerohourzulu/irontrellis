// Step 5c (the coordinator's step 5b review): the public store surface. Driven from package.json's `exports` map, so a new
// subpath cannot escape it: every public subpath that hands out openHistoryStore or createHistoryStore refuses a legacy and a
// format-1 genesis and leaves nothing behind (§0: ./adapter re-exported the permissive store until 5c); no public subpath
// carries a test-only or internal name except the two recorded rc.1 hooks; the public create reads one plain-data snapshot of
// its genesis (P1-b); the test-tooling mark is read only from a same-realm plain record (§3). The built dist is tested, as a
// package consumer loads it.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
const HERE = dirname(fileURLToPath(import.meta.url)), PKG = join(HERE, "..");
const { FORMAT1_TEST_TOOLING } = await import("../src/internal-format1.ts");
const core = await import("../src/index.ts");
const { LEGACY_FORMAT, TRELLIS_FORMAT } = await import("../src/events.ts");
const { hasFormat1TestTooling } = await import("../src/format1-tooling.ts");
const exportsMap = JSON.parse(readFileSync(join(PKG, "package.json"), "utf8")).exports;
const subpaths = Object.entries(exportsMap).filter(([name]) => name !== "./package.json");
const loaded = Object.fromEntries(await Promise.all(subpaths.map(async ([name, target]) => [name, await import(join(PKG, target.default))])));
const code = (value) => (e) => e.code === value;
/**
 * Test hooks that existed at import-7ab8f95 (the rc.1 API) and can neither write an older format nor relax a write guard,
 * fence, mark or signer; kept public by the coordinator's decision (step 5b review), recorded in DEVIATIONS r2.2.
 *   resetStoreCountersForTests: zeroes the store's diagnostic counters (fullReplays, resumes, snapshotRebuilds, rootRecomputations).
 *   setStoreCutHookForTests: a callback at the store's crash-cut points, all after the write's validation and format fence
 *     (the first is "before-append"); it can abort a write the way a crash does, never change what is written.
 */
const KEPT_HOOKS = new Set(["resetStoreCountersForTests", "setStoreCutHookForTests"]);

async function genesisOf(dir, format) {
  const historyFile = join(dir, `source-${(format ?? "format-2").replaceAll("/", "-")}-${Math.random().toString(36).slice(2)}.jsonl`);
  const owner = await core.createLocalOwner({ historyFile, domain: core.createLocalDomain(format === undefined ? {} : { format }), owner: "o", controller: "c", now: () => 1,
    ...(format === undefined ? {} : { format, [FORMAT1_TEST_TOOLING]: true }) });
  await owner.createAgent({ id: "a" });
  return owner.exportHistory();
}
const leftovers = (dir, base) => readdirSync(dir).filter((name) => name.startsWith(base));

test("step 5c §0: every public subpath that exports the store writers refuses a legacy and a format-1 genesis and leaves no file", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-surface-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const older = { legacy: await genesisOf(dir, LEGACY_FORMAT), format1: await genesisOf(dir, TRELLIS_FORMAT) }, current = await genesisOf(dir, undefined);
  const writers = subpaths.filter(([name]) => name !== "./internal-format1" && ("openHistoryStore" in loaded[name] || "createHistoryStore" in loaded[name]));
  assert.deepEqual(writers.map(([name]) => name).sort(), [".", "./adapter", "./store"], "the subpaths that hand out the store writers");
  for (const [name] of writers) {
    const m = loaded[name], tag = name === "." ? "root" : name.slice(2);
    for (const [kind, events] of Object.entries(older)) {
      const created = `c-${tag}-${kind}.jsonl`, opened = `o-${tag}-${kind}.jsonl`;
      assert.throws(() => m.createHistoryStore(join(dir, created), events), code("INVALID_INPUT"), `${name} createHistoryStore, ${kind}`);
      assert.deepEqual(leftovers(dir, created), [], `${name} createHistoryStore, ${kind}: nothing left behind`);
      assert.throws(() => m.openHistoryStore(join(dir, opened)).appendAll(events), code("INVALID_INPUT"), `${name} openHistoryStore().appendAll, ${kind}`);
      assert.deepEqual(leftovers(dir, opened), [], `${name} openHistoryStore().appendAll, ${kind}: nothing left behind`);
    }
    m.createHistoryStore(join(dir, `ok-${tag}.jsonl`), current, { witness: false }).close(); // the same entry takes a format-2 genesis
  }
});

test("step 5c §0: no public subpath exports an internal or test-only name, except internal-format1 and the two recorded rc.1 hooks", () => {
  const found = {};
  for (const [name] of subpaths) {
    if (name === "./internal-format1") continue;
    const hits = Object.keys(loaded[name]).filter((key) => /Internal|ForTests|restrictToFormat2|FORMAT1_TEST_TOOLING/.test(key) && !KEPT_HOOKS.has(key));
    if (hits.length > 0) found[name] = hits;
  }
  assert.deepEqual(found, {});
  assert.equal("restrictToFormat2" in loaded["./store"], false);
});

test("step 5c P1-b: the public create reads one plain-data snapshot; a getter that flips the format, a Proxy, an accessor or an exotic record is refused before any write", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-surface-flip-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const current = await genesisOf(dir, undefined), format1 = await genesisOf(dir, TRELLIS_FORMAT);
  const v2 = current[0].data.versions.eventSchemaVersion, v1 = format1[0].data.versions.eventSchemaVersion;
  assert.notEqual(v1, v2);
  for (const [name] of [["."], ["./store"], ["./adapter"]]) {
    const m = loaded[name], tag = name === "." ? "root" : name.slice(2);
    let reads = 0;
    const versions = { ...current[0].data.versions };
    Object.defineProperty(versions, "eventSchemaVersion", { enumerable: true, configurable: true, get: () => (reads++ === 0 ? v2 : v1) });
    const flipping = [{ ...current[0], data: { ...current[0].data, versions } }, ...current.slice(1)];
    const cases = {
      getter: flipping,
      proxy: new Proxy(current, {}),
      "proxy event": [new Proxy(current[0], {}), ...current.slice(1)],
      "exotic record": [Object.assign(Object.create({ inherited: true }), current[0]), ...current.slice(1)],
      "undetected format": [{ id: "x", type: "DEPLOYMENT_INITIALIZED", timestamp: 1, data: {} }],
      "not an array": { 0: current[0], length: 1 },
    };
    for (const [kind, genesis] of Object.entries(cases)) {
      const file = `flip-${tag}-${kind.replaceAll(" ", "-")}.jsonl`;
      assert.throws(() => m.createHistoryStore(join(dir, file), genesis), code("INVALID_INPUT"), `${name}, ${kind}`);
      assert.deepEqual(leftovers(dir, file), [], `${name}, ${kind}: nothing left behind (no history, .writer-lock or .head)`);
    }
  }
});

test("step 5c P2 (JOB75-01): a refused fresh public store leaves neither the history nor its .writer-lock or .head", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-surface-fresh-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const fresh = join(dir, "fresh.jsonl"), genesis = (await genesisOf(dir, TRELLIS_FORMAT))[0];
  assert.throws(() => core.openHistoryStore(fresh).append(genesis), code("INVALID_INPUT"));
  for (const suffix of ["", ".writer-lock", ".head"]) assert.equal(existsSync(fresh + suffix), false, `fresh.jsonl${suffix}`);
});

test("step 5c §3 (defence in depth): a vm context's global is not read for the test-tooling mark; its Proxy sandbox's traps never see the symbol", () => {
  const seen = [];
  const sandbox = new Proxy({}, {
    getOwnPropertyDescriptor: (_target, key) => { seen.push(key); return { value: true, writable: true, enumerable: true, configurable: true }; },
    get: (_target, key) => { seen.push(key); return true; },
    has: (_target, key) => { seen.push(key); return true; },
  });
  const global = vm.runInContext("globalThis", vm.createContext(sandbox));
  assert.equal(hasFormat1TestTooling(global), false);
  assert.equal(seen.includes(FORMAT1_TEST_TOOLING), false, "no trap saw the mark");
  assert.equal(hasFormat1TestTooling({ [FORMAT1_TEST_TOOLING]: true }), true);
  assert.equal(hasFormat1TestTooling(Object.assign(Object.create(null), { [FORMAT1_TEST_TOOLING]: true })), true);
  assert.equal(hasFormat1TestTooling(Object.assign(Object.create({}), { [FORMAT1_TEST_TOOLING]: true })), false, "another prototype is not read");
});

// ---------------------------------------------------------------- step 5d (the reviews of 0bcdc69)
const dist = async (file) => import(join(PKG, "dist", file));
const PUBLIC_WRITERS = [".", "./store", "./adapter"];

test("step 5d P0-1: the public store reads its options once; a getter or a Proxy cannot open an existing format-1 file writable, and the file is unchanged", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-surface-ro-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const historyFile = join(dir, "format1.jsonl");
  const writer = await core.createLocalOwner({ historyFile, domain: core.createLocalDomain({ format: TRELLIS_FORMAT }), owner: "o", controller: "c", now: () => 1, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  await writer.createAgent({ id: "a" });
  const before = readFileSync(historyFile), event = { id: "x", type: "PRINCIPAL_CREATED", timestamp: 2, data: {} };
  for (const name of PUBLIC_WRITERS) {
    const m = loaded[name];
    let reads = 0;
    const flipping = { get readOnlyFormats() { return reads++ === 0 ? undefined : false; } };
    assert.throws(() => m.openHistoryStore(historyFile, flipping), code("INVALID_INPUT"), `${name}: a getter`);
    assert.throws(() => m.openHistoryStore(historyFile, new Proxy({}, { get: (_t, k) => (k === "readOnlyFormats" ? (reads++ === 0 ? undefined : false) : undefined) })), code("INVALID_INPUT"), `${name}: a Proxy`);
    assert.throws(() => m.openHistoryStore(historyFile, { readOnlyFormats: false }), code("INVALID_INPUT"), `${name}: readOnlyFormats false`);
    assert.throws(() => m.openHistoryStore(historyFile, { [Symbol("x")]: true }), code("INVALID_INPUT"), `${name}: a symbol key`);
    assert.throws(() => m.openHistoryStore(historyFile, { hooks: core.defaultReplayHooks }), code("INVALID_INPUT"), `${name}: replay hooks on a store that can write`);
    m.openHistoryStore(historyFile, { inspect: true, hooks: core.defaultReplayHooks }).close(); // read only: accepted
    const plain = m.openHistoryStore(historyFile, { readOnlyFormats: undefined });
    assert.throws(() => plain.append(event), code("FORMAT_READ_ONLY"), `${name}: a plain open is read only`);
    plain.close();
    assert.deepEqual(readFileSync(historyFile), before, `${name}: the format-1 file is byte-unchanged`);
  }
});

test("step 5d P0-1 (b): a format-2-only store refuses an older format whatever readOnlyFormats says", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-surface-fence-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const historyFile = join(dir, "format1.jsonl");
  const writer = await core.createLocalOwner({ historyFile, domain: core.createLocalDomain({ format: TRELLIS_FORMAT }), owner: "o", controller: "c", now: () => 1, format: TRELLIS_FORMAT, [FORMAT1_TEST_TOOLING]: true });
  await writer.createAgent({ id: "a" });
  const { openHistoryStore } = await import("../src/store.ts"), { restrictToFormat2 } = await import("../src/store-fence.ts");
  const before = readFileSync(historyFile);
  const store = restrictToFormat2(openHistoryStore(historyFile, { readOnlyFormats: false, [FORMAT1_TEST_TOOLING]: true }));
  assert.throws(() => store.append({ id: "x", type: "PRINCIPAL_CREATED", timestamp: 2, data: {} }), code("FORMAT_READ_ONLY"));
  store.close();
  assert.deepEqual(readFileSync(historyFile), before);
});

test("step 5d P1-1: no public subpath exports a value identical to an internal one (the internal-format1 tooling, the format mark and its reader, the fence, the raw store writers, the removed hooks); no test-named export but the two kept hooks", async () => {
  const internal = new Map();
  const collect = (label, m, names) => { for (const name of names ?? Object.keys(m)) { assert.ok(name in m, `${label}.${name}`); internal.set(m[name], `${label}.${name}`); } };
  collect("internal-format1", await dist("internal-format1.js"));
  collect("format1-tooling", await dist("format1-tooling.js"));
  collect("store-fence", await dist("store-fence.js"));
  collect("store", await dist("store.js"), ["openHistoryStore", "createHistoryStore", "witnessSessionOf"]);
  collect("capacity", await dist("capacity.js"), ["setCapacityLimitsForTests"]);
  collect("ssh-agent", await dist("custody/ssh-agent.js"), ["setAgentConnectorForTests"]);
  collect("session-writes", await dist("session-writes.js"), ["resetRefusalRateLimitsForTests"]);
  collect("runtime-writes", await dist("runtime-writes.js"), ["signedTransition", "sessionOf"]);
  const found = {};
  for (const [name] of subpaths) {
    if (name === "./internal-format1") continue;
    const bad = Object.entries(loaded[name]).filter(([key, value]) => internal.has(value) || (/Internal|ForTests|Test[A-Z]|restrictToFormat2|FORMAT1_TEST_TOOLING/.test(key) && !KEPT_HOOKS.has(key)))
      .map(([key, value]) => `${key}${internal.has(value) ? ` (= ${internal.get(value)})` : ""}`);
    if (bad.length > 0) found[name] = bad;
  }
  assert.deepEqual(found, {});
});

test("step 5d P1-2: the exported type sets that enforcement reads are read-only views; a mutation attempt throws and changes nothing", async () => {
  const sets = ["CONTROL_EVENT_TYPES", "RESERVE_CLASS", "MAX_UNWITNESSED_EXEMPT_TYPES", "POWER_REDUCING_TYPES", "SESSION_SIGNED_EVENT_TYPES", "TRELLIS_ONLY_EVENT_TYPES", "FORMAT2_ONLY_EVENT_TYPES", "ALWAYS_ADMITTED_EVENT_TYPES", "ALWAYS_ADMITTED_NON_CONTROL"];
  const root = loaded["."];
  for (const name of sets) {
    const view = root[name];
    assert.ok(view !== undefined, name);
    const size = view.size, first = [...view][0];
    assert.equal(Object.isFrozen(view), true, `${name} is frozen`);
    for (const method of ["add", "delete", "clear"]) assert.equal(view[method], undefined, `${name}.${method}`);
    assert.throws(() => Set.prototype.add.call(view, "INJECTED"), TypeError, `${name}: Set.prototype.add on the view`);
    assert.throws(() => Set.prototype.delete.call(view, first), TypeError, `${name}: Set.prototype.delete on the view`);
    assert.throws(() => { view.has = () => true; }, TypeError, `${name}.has cannot be replaced`);
    assert.equal(view.size, size); assert.equal(view.has(first), true); assert.equal(view.has("INJECTED"), false);
  }
  // KNOWN-ISSUES r2.2 59: the type list itself is frozen at runtime.
  assert.equal(Object.isFrozen(root.EVENT_TYPES), true);
  const types = root.EVENT_TYPES.length;
  assert.throws(() => { root.EVENT_TYPES.push("INJECTED"); }, TypeError);
  assert.throws(() => { root.EVENT_TYPES[0] = "INJECTED"; }, TypeError);
  assert.equal(root.EVENT_TYPES.length, types); assert.equal(root.EVENT_TYPES[0], "DEPLOYMENT_INITIALIZED");
  assert.equal(Object.isFrozen(root.EVENT_TYPE_CODES), true);
  assert.equal(root.EVENT_TYPE_CODES.set, undefined);
  assert.throws(() => Map.prototype.set.call(root.EVENT_TYPE_CODES, "AGENT_CREATED", 99), TypeError);
  // Enforcement reads the same private collections: a control event is still exempt from T3, and T3 still applies to a ◇ event.
  assert.equal(root.CONTROL_EVENT_TYPES.has("AGENT_CREATED"), true);
  assert.equal(root.RESERVE_CLASS.has("AGENT_CREATED"), false);
});

test("step 5d P2-5: the genesis snapshot refuses a symbol key, a cycle, a non-enumerable property and a function, and copies a __proto__ key as data, never as a prototype", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "irontrellis-surface-snap-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const current = await genesisOf(dir, undefined);
  const withData = (data) => [{ ...current[0], data }, ...current.slice(1)];
  const cyclic = { ...current[0].data }; cyclic.self = cyclic;
  const hidden = { ...current[0].data }; Object.defineProperty(hidden, "hidden", { value: 1, enumerable: false });
  const cases = {
    "symbol key": withData({ ...current[0].data, [Symbol("x")]: 1 }),
    cycle: withData(cyclic),
    "non-enumerable": withData(hidden),
    function: withData({ ...current[0].data, extra: () => 1 }),
  };
  for (const name of PUBLIC_WRITERS) {
    const tag = name === "." ? "root" : name.slice(2);
    for (const [kind, genesis] of Object.entries(cases)) {
      const file = `snap-${tag}-${kind.replaceAll(" ", "-")}.jsonl`;
      assert.throws(() => loaded[name].createHistoryStore(join(dir, file), genesis), code("INVALID_INPUT"), `${name}, ${kind}`);
      assert.deepEqual(leftovers(dir, file), [], `${name}, ${kind}: nothing left behind`);
    }
    // A `__proto__` own key stays data: the event then fails validation as an unknown field, but no prototype is set.
    const proto = JSON.parse(`{"__proto__": {"polluted": true}}`);
    const file = `snap-${tag}-proto.jsonl`;
    assert.throws(() => loaded[name].createHistoryStore(join(dir, file), withData({ ...current[0].data, ...proto })));
    assert.equal({}.polluted, undefined, "Object.prototype untouched");
    assert.deepEqual(leftovers(dir, file), []);
  }
});

test("step 5d P2-6: the §3 check on the built copies (the package's own mark and reader)", async () => {
  const { FORMAT1_TEST_TOOLING: mark } = await dist("internal-format1.js"), { hasFormat1TestTooling: has } = await dist("format1-tooling.js");
  assert.notEqual(mark, FORMAT1_TEST_TOOLING, "the dist copy holds its own mark");
  const seen = [];
  const global = vm.runInContext("globalThis", vm.createContext(new Proxy({}, { getOwnPropertyDescriptor: (_t, k) => { seen.push(k); return { value: true, writable: true, enumerable: true, configurable: true }; } })));
  assert.equal(has(global), false);
  assert.equal(seen.includes(mark), false);
  assert.equal(has({ [mark]: true }), true);
  assert.equal(has({ [FORMAT1_TEST_TOOLING]: true }), false, "the source copy's mark does not unlock the dist copy");
});

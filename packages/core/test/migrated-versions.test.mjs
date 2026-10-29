// RC2-FIXES-D (the coordinator's ruling, 2026-10-26; architect list item 18): a migrated genesis's `migratedFrom.versions`
// MUST equal `migratedFrom.genesis.versions`, the same keys and each value byte for byte (r5.2 §16.2 step 4: "the source
// `versions` block as written"). Otherwise EVENT_DATA_INVALID at position 0, at migratedFrom.versions.<first differing key>.
// Found by the format-2 differential fuzzer (FUZZ-FORMAT2-02): this engine read only the source genesis's own block and
// accepted a different copy, which the independent checker g25 used for its shadow challenges and so refused.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const core = await import("../src/index.ts");
const load = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), "utf8"));
const MIGRATED = ["migrated-legacy-v2", "migrated-format1-v2", "migrated-horizon-legacy-v2", "migrated-horizon-format1-v2", "migrated-no-expiry-v2"];
const PATH = "$.data.migratedFrom.versions.";

test("the four fuzz cases (re-signed): EVENT_DATA_INVALID at position 0, at the first differing key", () => {
  const vectors = load("./fixtures/migrated-versions-vectors.json");
  assert.equal(vectors.cases.length, 4);
  for (const c of vectors.cases) {
    const r = core.replay(c.events);
    assert.equal(r.status, "REJECTED", c.id); assert.equal(r.code, c.expectedCode, c.id); assert.equal(r.position, c.expectedPosition, c.id);
    assert.equal(r.reason, `${c.expectedPath}: must equal migratedFrom.genesis.versions (§16.2 step 4)`, c.id);
  }
});

test("every migrated history of the regenerated suite still replays to its pinned result; its two versions blocks are equal", () => {
  for (const name of MIGRATED) {
    const events = load(`../../../conformance/v2-regenerated/histories/${name}.json`), m = events[0].data.migratedFrom;
    assert.deepEqual(m.versions, m.genesis.versions, name);
    assert.equal(core.replay(events).status, "ACCEPTED", name);
  }
});

test("any one version value changed, or the two blocks' differing values swapped, is refused at that key; the first in canonical key order is named", () => {
  for (const name of ["migrated-legacy-v2", "migrated-format1-v2"]) {
    const events = load(`../../../conformance/v2-regenerated/histories/${name}.json`), keys = Object.keys(events[0].data.migratedFrom.versions).sort();
    for (const key of keys) {
      for (const value of [" " + events[0].data.migratedFrom.versions[key], events[0].data.migratedFrom.versions[key] + "x", "other-version/1"]) {
        const e = structuredClone(events); e[0].data.migratedFrom.versions[key] = value;
        const r = core.replay(e);
        assert.equal(r.code, "EVENT_DATA_INVALID", `${name} ${key}`); assert.equal(r.position, 0); assert.equal(r.reason, `${PATH}${key}: must equal migratedFrom.genesis.versions (§16.2 step 4)`);
      }
    }
    // Two values swapped: the first of the two keys in canonical order is named.
    const e = structuredClone(events), v = e[0].data.migratedFrom.versions, [a, b] = [keys[0], keys[1]];
    [v[a], v[b]] = [v[b], v[a]];
    assert.equal(core.replay(e).reason, `${PATH}${a}: must equal migratedFrom.genesis.versions (§16.2 step 4)`, name);
  }
});

test("a mistyped or missing versions entry is still the closed schema's refusal, ahead of the equality", () => {
  const events = load("../../../conformance/v2-regenerated/histories/migrated-format1-v2.json");
  const missing = structuredClone(events); delete missing[0].data.migratedFrom.versions.signatureScheme;
  assert.equal(core.replay(missing).code, "EVENT_DATA_INVALID");
  assert.doesNotMatch(core.replay(missing).reason, /must equal migratedFrom\.genesis\.versions/);
  const mistyped = structuredClone(events); mistyped[0].data.migratedFrom.versions.signatureScheme = 7;
  assert.match(core.replay(mistyped).reason, /signatureScheme: must be an Identifier/);
});

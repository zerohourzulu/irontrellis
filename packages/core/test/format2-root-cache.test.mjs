// E5 (BUILD §6, addendum A-67): the state root computed where it is consumed. The aligned-subtree cache (`RecordTree`)
// must equal the from-scratch RFC 6962 MTH (`transparency/merkle.ts rootOf`, an independent implementation) after any
// sequence of insertions, updates and deletions; the per-position roots computed lazily (undo lists) must equal the
// root of the record set derived from scratch at that position; forks read the base and never touch it.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { rmSync } from "node:fs";
import { test } from "node:test";

const core = await import("../src/index.ts");
const { RecordTree } = await import("../src/state-roots.ts");
const nodes = await import("../src/crypto/sha256-nodes.ts");
const { rootOf } = await import("../src/transparency/merkle.ts");
const { tempDir, richHistory, e2History } = await import("./helpers/format2-histories.mjs");

const hex = (bytes) => `0x${Buffer.from(bytes).toString("hex")}`;
const leafOfNumber = (n) => createHash("sha256").update(`leaf ${n}`).digest();
/** A small deterministic PRNG (xorshift32) so a failure is reproducible from its seed. */
const prng = (seed) => { let x = seed >>> 0 || 1; return () => { x ^= x << 13; x >>>= 0; x ^= x >>> 17; x ^= x << 5; x >>>= 0; return x / 0x1_0000_0000; }; };
const scratch = (leaves) => hex(rootOf(leaves));

test("RecordTree: the cached root equals the from-scratch MTH after thousands of random insert/update/delete steps", () => {
  let checks = 0;
  for (const [seed, steps, target] of [[1, 4000, 40], [2, 4000, 300], [3, 3000, 1500], [4, 6000, 7], [5, 2000, 4100]]) {
    const random = prng(seed);
    const model = [];
    let fresh = 0;
    const tree = new RecordTree([]);
    for (let step = 0; step < steps; step += 1) {
      const r = random();
      // Drift towards `target` leaves: inserts while below it, deletes while above, updates throughout.
      const insertBias = model.length < target ? 0.55 : 0.25;
      if (model.length === 0 || r < insertBias) {
        const index = Math.floor(random() * (model.length + 1)), leaf = leafOfNumber(`${seed}:${(fresh += 1)}`);
        model.splice(index, 0, leaf);
        tree.insert(index, leaf);
      } else if (r < insertBias + 0.3) {
        const index = Math.floor(random() * model.length), leaf = leafOfNumber(`${seed}:${(fresh += 1)}`);
        model[index] = leaf;
        tree.update(index, leaf);
      } else {
        const index = Math.floor(random() * model.length);
        model.splice(index, 1);
        tree.remove(index);
      }
      // Several changes may accumulate between two roots (as between two checkpoints); check often, and always at the end.
      if (random() < 0.35 || step === steps - 1) {
        assert.equal(tree.root(), scratch(model), `seed ${seed}, step ${step}, ${model.length} leaves`);
        checks += 1;
      }
    }
  }
  assert.ok(checks > 5000);
});

test("RecordTree: an in-place change rehashes one path; an append rehashes the right edge; an insertion at i rehashes only right of i", () => {
  const n = 12_000;
  const leaves = Array.from({ length: n }, (_v, i) => leafOfNumber(i));
  const tree = new RecordTree(leaves.slice());
  tree.root();
  const cost = (change) => { const before = tree.hashes; change(); const root = tree.root(); return { hashes: tree.hashes - before, root }; };
  const depth = Math.ceil(Math.log2(n)), spine = n.toString(2).split("").filter((b) => b === "1").length;
  // In place: one node per level plus the fold of the decomposition.
  for (const index of [0, 1, 4095, 6000, n - 1]) {
    leaves[index] = leafOfNumber(`u${index}`);
    const { hashes, root } = cost(() => tree.update(index, leaves[index]));
    assert.ok(hashes <= depth + spine, `update at ${index}: ${hashes} hashes`);
    assert.equal(root, scratch(leaves));
  }
  // An insertion at i: every perfect subtree left of i is reused (about n − i nodes are rehashed, never ~n when i is late).
  for (const index of [11_990, 9_000, 6_000]) {
    leaves.splice(index, 0, leafOfNumber(`i${index}`));
    const { hashes, root } = cost(() => tree.insert(index, leaves[index]));
    assert.ok(hashes <= (leaves.length - index) + 2 * depth + spine, `insert at ${index}: ${hashes} hashes`);
    assert.equal(root, scratch(leaves));
  }
  // Unchanged: no hash at all.
  assert.equal(cost(() => {}).hashes, 0);
});

test("interior-node hashing (4-lane WebAssembly SIMD, node:crypto fallback) equals sha256(0x01 ‖ left ‖ right) for every count and lane", () => {
  for (const force of [false, true]) {
    nodes.useNodeCryptoForTests(force);
    try {
      assert.equal(nodes.nodeHasherKind(), force ? "node-crypto" : "wasm-simd", "SIMD is available on Node ≥ 22 (the self-test passed)");
      for (const count of [0, 1, 2, 3, 4, 5, 7, 1023, 1024, 1025, 3001]) {
        const children = randomBytes(64 * count), got = Buffer.alloc(32 * count);
        nodes.hashNodes(count, (i, memory, offset) => children.copy(memory, offset, 64 * i, 64 * i + 64), (i, memory, offset) => memory.copy(got, 32 * i, offset, offset + 32));
        for (let i = 0; i < count; i += 1) {
          const expected = createHash("sha256").update(Buffer.from([1])).update(children.subarray(64 * i, 64 * i + 64)).digest();
          assert.ok(got.subarray(32 * i, 32 * i + 32).equals(expected), `${nodes.nodeHasherKind()}: node ${i} of ${count}`);
        }
      }
      // And the tree on top of either engine.
      const leaves = Array.from({ length: 777 }, (_v, i) => leafOfNumber(`e${i}`));
      assert.equal(new RecordTree(leaves.slice()).root(), scratch(leaves));
    } finally {
      nodes.useNodeCryptoForTests(false);
    }
  }
});

/** The root of a state's record set derived from scratch (every record re-derived, leaves re-hashed, the independent MTH). */
const independentRoot = (state) => {
  const entries = core.deriveAllRecords(state).map((e) => ({ k: core.recordKey(e.kind, e.key), leaf: core.leafOf(e.kind, e.key, e.record) }));
  entries.sort((a, b) => core.compareProtocolStrings(a.k, b.k));
  return { root: scratch(entries.map((e) => e.leaf)), count: entries.length };
};

test("rootAt(p) computed lazily (head cache, undo lists) equals the from-scratch root of the prefix at every position, in any order", async () => {
  for (const build of [richHistory, e2History]) {
    const dir = tempDir();
    try {
      const { events } = await build(dir);
      const full = core.replay(events);
      assert.equal(full.status, "ACCEPTED");
      // The rich history carries every kind, A-71's `observation` and `reconciliation-cursor` included (inserted and updated in place).
      if (build === richHistory) for (const kind of core.STATE_RECORD_KINDS) if (kind !== "shadow") assert.ok([...full.state.stateRecords.values()].some((e) => e.kind === kind), kind);
      const expected = [];
      for (let p = 0; p < events.length; p += 1) {
        const prefix = core.replay(events.slice(0, p + 1));
        assert.equal(prefix.status, "ACCEPTED");
        const independent = independentRoot(prefix.state);
        assert.equal(prefix.stateRoot, independent.root, `${build.name}: head root of the prefix through ${p}`);
        assert.equal(prefix.state.stateRecords.size, independent.count);
        expected.push(independent.root);
      }
      // A fresh replay read in a shuffled order (each read reconstructs from the head or reuses earlier reads).
      const order = [...expected.keys()];
      const random = prng(7);
      for (let i = order.length - 1; i > 0; i -= 1) { const j = Math.floor(random() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
      const shuffled = core.replay(events).state;
      for (const p of order) assert.equal(core.rootAt(shuffled, p), expected[p], `${build.name}: rootAt(${p}) (shuffled)`);
      // The array view: length, at(), indexing and iteration.
      assert.equal(full.state.stateRoots.length, events.length);
      assert.equal(full.state.stateRoots.at(-1), expected.at(-1));
      assert.deepEqual([...full.state.stateRoots], expected);
      assert.equal(core.rootAt(full.state, events.length), undefined);
      assert.equal(core.rootAt(full.state, -1), undefined);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("forks: a prospective event's state reads earlier roots through the base and never changes the base's roots or cache", async () => {
  const dir = tempDir();
  try {
    const { events } = await richHistory(dir);
    const head = events.length - 1;
    const base = core.replay(events.slice(0, head)).state;
    const rootBefore = core.rootAt(base, head - 1), early = core.rootAt(base, 5);
    const prospective = core.withProspectiveEvent(base, events[head]);
    assert.ok(prospective.ok);
    assert.equal(core.rootAt(prospective.state, head - 1), rootBefore);
    assert.equal(core.rootAt(prospective.state, 5), early);
    assert.equal(core.rootAt(prospective.state, head), core.replay(events).stateRoot);
    assert.equal(core.rootAt(base, head), undefined);
    assert.equal(core.rootAt(base, head - 1), rootBefore);
    // The base keeps extending correctly after the fork was used.
    assert.ok(core.applyEvent(base, events[head]).ok);
    assert.equal(core.rootAt(base, head), core.replay(events).stateRoot);
    assert.equal(core.stateRootOf(base).root, independentRoot(base).root);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

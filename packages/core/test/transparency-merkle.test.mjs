// RFC 6962 / RFC 9162 Merkle tree (WITNESS-DESIGN §2.4): the published
// transparency-dev reference vectors, an independent naive implementation
// written from the RFC 9162 text, exhaustive proof properties for sizes 1..64,
// tamper rejection and malformed-input handling.
//
// PUBLISHED constants below (leaves, roots, node hashes, inclusion and
// consistency proofs) are copied verbatim from github.com/transparency-dev/merkle:
//   testonly/constants.go (branch main): LeafInputs, NodeHashes, RootHashes, EmptyRootHash
//   proof/verify_test.go (tag v0.0.2): inclusionProofs, consistencyProofs, sha256SomeHash,
//     and the TestVerifyInclusion / TestVerifyConsistency edge-case tables
// (fetched 2026-09-25 from raw.githubusercontent.com; Copyright 2017 and 2019 Google LLC, Apache License 2.0,
// see THIRD-PARTY-NOTICES.md; the same vectors are
// used by certificate-transparency-go). Everything else in this file is
// computed at run time by the naive reference and compared with the tree.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const merkle = await import("../src/transparency/merkle.ts");
const { leafHash, nodeHash, rootOf, MerkleTree, verifyInclusion, verifyConsistency, emptyRoot } = merkle;

const hx = (text) => new Uint8Array(Buffer.from(text, "hex"));
const toHex = (bytes) => Buffer.from(bytes).toString("hex");

// ---------------------------------------------------------------- published vectors (transparency-dev/merkle)

const LEAF_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"].map(hx);
const EMPTY_ROOT = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const NODE_HASHES = [
  ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
    "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7", "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
    "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
    "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1"],
  ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
    "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"],
  ["d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"],
  ["5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"],
];
/** RootHashes()[size], size 0..8. */
const ROOTS = [
  EMPTY_ROOT,
  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
  "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
  "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
  "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];
/** verify_test.go inclusionProofs; `leaf` is 1-based there, converted to a 0-based index here. The {0, 0, nil} "invalid path" row is covered by the edge cases. */
const INCLUSION = [
  { index: 0, size: 1, proof: [] },
  { index: 0, size: 8, proof: ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
  { index: 5, size: 8, proof: ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
  { index: 2, size: 3, proof: ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"] },
  { index: 1, size: 5, proof: ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
];
/** verify_test.go consistencyProofs. */
const CONSISTENCY = [
  { from: 1, to: 1, proof: [] },
  { from: 1, to: 8, proof: ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"] },
  { from: 6, to: 8, proof: ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
  { from: 2, to: 5, proof: ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"] },
  { from: 6, to: 7, proof: ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"] },
];
const SOME_HASH = hx("abacaba000000000000000000000000000000000000000000060061e00123456");

// ---------------------------------------------------------------- naive reference, straight from RFC 9162 §2.1

const sha = (...parts) => {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return new Uint8Array(h.digest());
};
const largestPow2Below = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
/** MTH(D[n]) over raw leaf data. */
const naiveMth = (data) => {
  if (data.length === 0) return sha();
  if (data.length === 1) return sha(Uint8Array.of(0), data[0]);
  const k = largestPow2Below(data.length);
  return sha(Uint8Array.of(1), naiveMth(data.slice(0, k)), naiveMth(data.slice(k)));
};
/** PATH(m, D[n]) (§2.1.3.1). */
const naivePath = (m, data) => {
  if (data.length <= 1) return [];
  const k = largestPow2Below(data.length);
  return m < k ? [...naivePath(m, data.slice(0, k)), naiveMth(data.slice(k))] : [...naivePath(m - k, data.slice(k)), naiveMth(data.slice(0, k))];
};
/** SUBPROOF(m, D[n], b) and PROOF(m, D[n]) (§2.1.4.1). */
const naiveSubproof = (m, data, b) => {
  if (m === data.length) return b ? [] : [naiveMth(data)];
  const k = largestPow2Below(data.length);
  return m <= k
    ? [...naiveSubproof(m, data.slice(0, k), b), naiveMth(data.slice(k))]
    : [...naiveSubproof(m - k, data.slice(k), false), naiveMth(data.slice(0, k))];
};
const naiveProof = (m, data) => (m === 0 || m === data.length ? [] : naiveSubproof(m, data, true));
/** The root an audit path implies for leaf m of n, recomputed by the PATH recursion (null when the length does not fit). */
const naiveRootFromPath = (leaf, m, n, proof) => {
  if (n === 1) return proof.length === 0 ? leaf : null;
  if (proof.length === 0) return null;
  const k = largestPow2Below(n);
  const last = proof[proof.length - 1];
  const rest = proof.slice(0, -1);
  if (m < k) { const left = naiveRootFromPath(leaf, m, k, rest); return left === null ? null : sha(Uint8Array.of(1), left, last); }
  const right = naiveRootFromPath(leaf, m - k, n - k, rest);
  return right === null ? null : sha(Uint8Array.of(1), last, right);
};
/** Whether a proof "should" verify per the RFC recursion (an oracle independent of the iterative verifier). */
const naiveVerifies = (leaf, m, n, proof, root) => {
  const computed = m < n ? naiveRootFromPath(leaf, m, n, proof) : null;
  return computed !== null && toHex(computed) === toHex(root);
};

/** Deterministic leaf data for sizes beyond the 8 published leaves. */
const leafData = (count) => Array.from({ length: count }, (_, i) => (i < LEAF_INPUTS.length ? LEAF_INPUTS[i] : sha(Buffer.from(`leaf-${i}`))));
const treeOf = (data) => {
  const tree = new MerkleTree();
  for (const d of data) tree.append(leafHash(d));
  return tree;
};

// ---------------------------------------------------------------- published vectors

test("leaf and node hashing reproduce the published node hashes", () => {
  assert.equal(toHex(emptyRoot()), EMPTY_ROOT);
  assert.deepEqual(LEAF_INPUTS.map((d) => toHex(leafHash(d))), NODE_HASHES[0]);
  for (let level = 1; level < NODE_HASHES.length; level += 1) {
    NODE_HASHES[level].forEach((expected, i) => {
      assert.equal(toHex(nodeHash(hx(NODE_HASHES[level - 1][2 * i]), hx(NODE_HASHES[level - 1][2 * i + 1]))), expected, `level ${level} node ${i}`);
    });
  }
});

test("roots for sizes 0..8 match the published RootHashes (tree, historical sizes and rootOf)", () => {
  const tree = treeOf(LEAF_INPUTS);
  for (let size = 0; size <= 8; size += 1) {
    assert.equal(toHex(tree.root(size)), ROOTS[size], `tree.root(${size})`);
    assert.equal(toHex(rootOf(LEAF_INPUTS.slice(0, size).map(leafHash))), ROOTS[size], `rootOf(${size})`);
    assert.equal(toHex(naiveMth(LEAF_INPUTS.slice(0, size))), ROOTS[size], `naive MTH(${size})`);
    assert.equal(toHex(treeOf(LEAF_INPUTS.slice(0, size)).root()), ROOTS[size], `fresh tree of ${size}`);
  }
  assert.equal(tree.size, 8);
  assert.equal(toHex(tree.leaf(3)), NODE_HASHES[0][3]);
});

test("inclusion proofs match the published proofs and verify", () => {
  const tree = treeOf(LEAF_INPUTS);
  for (const { index, size, proof } of INCLUSION) {
    assert.deepEqual(tree.inclusionProof(index, size).map(toHex), proof, `PATH(${index}, ${size})`);
    assert.equal(verifyInclusion(leafHash(LEAF_INPUTS[index]), index, size, proof.map(hx), hx(ROOTS[size])), true, `verify ${index}/${size}`);
  }
});

test("consistency proofs match the published proofs and verify", () => {
  const tree = treeOf(LEAF_INPUTS);
  for (const { from, to, proof } of CONSISTENCY) {
    assert.deepEqual(tree.consistencyProof(from, to).map(toHex), proof, `PROOF(${from}, ${to})`);
    assert.equal(verifyConsistency(from, to, hx(ROOTS[from]), hx(ROOTS[to]), proof.map(hx)), true, `verify ${from}->${to}`);
  }
});

test("published inclusion edge cases (TestVerifyInclusion probes) are rejected", () => {
  for (const [index, size] of [[0, 0], [0, 1], [1, 0], [2, 1]]) {
    assert.equal(verifyInclusion(SOME_HASH, index, size, [], new Uint8Array(0)), false);
    assert.equal(verifyInclusion(new Uint8Array(0), index, size, [], hx(EMPTY_ROOT)), false);
    assert.equal(verifyInclusion(SOME_HASH, index, size, [], hx(EMPTY_ROOT)), false);
  }
});

test("published consistency edge cases (TestVerifyConsistency table)", () => {
  // Upstream uses the 12-byte strings "don't care 1/2" as roots; this API rejects hashes that are not 32 bytes,
  // so two distinct 32-byte stand-ins play their part. Expected outcomes are the upstream ones.
  const root1 = sha(Buffer.from("don't care 1"));
  const root2 = sha(Buffer.from("don't care 2"));
  const empty = hx(EMPTY_ROOT);
  const rows = [
    [0, 0, root1, root2, [], false], [1, 1, root1, root2, [], false],
    [0, 0, root1, root1, [], true], [0, 1, root1, root2, [], true], [1, 1, root2, root2, [], true],
    [1, 0, root1, root2, [], false], [2, 1, root1, root2, [], false],
    [1, 2, root1, root2, [], false],
    [0, 0, empty, root2, [], false], [1, 1, empty, root2, [], false],
    [0, 0, empty, empty, [empty], false], [0, 1, empty, empty, [empty], false], [1, 1, empty, empty, [empty], false],
  ];
  for (const [from, to, a, b, proof, ok] of rows) assert.equal(verifyConsistency(from, to, a, b, proof), ok, `${from}->${to}`);
  // And the upstream "don't care" byte strings themselves are malformed hashes here.
  assert.equal(verifyConsistency(0, 0, Buffer.from("don't care 1"), Buffer.from("don't care 1"), []), false);
});

// ---------------------------------------------------------------- properties, sizes 1..64

const MAX = 64;
const DATA = leafData(MAX);
const TREE = treeOf(DATA);
const ROOT_AT = Array.from({ length: MAX + 1 }, (_, size) => TREE.root(size));

const flipped = (bytes, at = 0) => { const copy = Uint8Array.from(bytes); copy[at] ^= 0x01; return copy; };

test("tree agrees with the naive RFC 9162 reference for every size, index and pair up to 64", () => {
  for (let n = 0; n <= MAX; n += 1) {
    const data = DATA.slice(0, n);
    assert.equal(toHex(ROOT_AT[n]), toHex(naiveMth(data)), `root ${n}`);
    for (let m = 0; m < n; m += 1) assert.deepEqual(TREE.inclusionProof(m, n).map(toHex), naivePath(m, data).map(toHex), `PATH(${m}, ${n})`);
    for (let m = 0; m <= n; m += 1) assert.deepEqual(TREE.consistencyProof(m, n).map(toHex), naiveProof(m, data).map(toHex), `PROOF(${m}, ${n})`);
  }
});

test("every inclusion proof verifies for sizes 1..64; every tampering fails", () => {
  let equivalentSizes = 0;
  let rejectedSizes = 0;
  for (let n = 1; n <= MAX; n += 1) {
    const root = ROOT_AT[n];
    for (let m = 0; m < n; m += 1) {
      const leaf = TREE.leaf(m);
      const proof = TREE.inclusionProof(m, n);
      assert.equal(verifyInclusion(leaf, m, n, proof, root), true, `inclusion ${m}/${n}`);
      assert.equal(verifyInclusion(flipped(leaf, m % 32), m, n, proof, root), false, "tampered leaf");
      assert.equal(verifyInclusion(leaf, m, n, proof, flipped(root, 31)), false, "tampered root");
      for (let i = 0; i < proof.length; i += 1) {
        for (const at of [0, 17, 31]) {
          const bad = proof.slice(); bad[i] = flipped(proof[i], at);
          assert.equal(verifyInclusion(leaf, m, n, bad, root), false, `tampered element ${i} byte ${at}`);
        }
      }
      // A wrong index or size fails unless it gives the audit path the same shape (then the claim is
      // equivalent: e.g. leaf 0 of 3 and of 4 hash identically); the naive PATH recursion is the oracle.
      for (let other = 0; other < n; other += 1) if (other !== m) assert.equal(verifyInclusion(leaf, other, n, proof, root), false, `wrong index ${other} for ${m}/${n}`);
      for (let size = m + 1; size <= n + 16; size += 1) {
        if (size === n) continue;
        const expected = naiveVerifies(leaf, m, size, proof, root);
        assert.equal(verifyInclusion(leaf, m, size, proof, root), expected, `size ${size} for ${m}/${n}`);
        if (expected) equivalentSizes += 1; else rejectedSizes += 1;
      }
      if (proof.length > 0) {
        assert.equal(verifyInclusion(leaf, m, n, proof.slice(0, -1), root), false, "truncated");
        assert.equal(verifyInclusion(leaf, m, n, proof.slice(1), root), false, "first element dropped");
      }
      assert.equal(verifyInclusion(leaf, m, n, [...proof, proof[0] ?? leaf], root), false, "extended");
      assert.equal(verifyInclusion(leaf, m, n, [...proof].reverse(), root), proof.length < 2 || proof.every((p) => toHex(p) === toHex(proof[0])), "reversed");
    }
  }
  assert.ok(rejectedSizes > equivalentSizes && equivalentSizes > 0, `wrong sizes: ${rejectedSizes} rejected, ${equivalentSizes} shape-equivalent`);
});

test("every consistency proof verifies for 0 <= m <= n <= 64; every tampering fails", () => {
  for (let n = 1; n <= MAX; n += 1) {
    for (let m = 0; m <= n; m += 1) {
      const proof = TREE.consistencyProof(m, n);
      const [a, b] = [ROOT_AT[m], ROOT_AT[n]];
      assert.equal(verifyConsistency(m, n, a, b, proof), true, `consistency ${m}->${n}`);
      if (m === 0) continue; // any roots are consistent with the empty tree
      assert.equal(verifyConsistency(m, n, flipped(a, 5), b, proof), false, "tampered first root");
      assert.equal(verifyConsistency(m, n, a, flipped(b, 5), proof), false, "tampered second root");
      if (m === n) {
        assert.equal(verifyConsistency(m, n, a, b, [a]), false, "non-empty proof at equal sizes");
        continue;
      }
      assert.equal(verifyConsistency(m, n, b, a, proof), false, "swapped roots");
      assert.equal(verifyConsistency(n, m, a, b, proof), false, "swapped sizes");
      for (let i = 0; i < proof.length; i += 1) {
        const bad = proof.slice(); bad[i] = flipped(proof[i], i % 32);
        assert.equal(verifyConsistency(m, n, a, b, bad), false, `tampered element ${i} of ${m}->${n}`);
      }
      assert.equal(verifyConsistency(m, n, a, b, proof.slice(0, -1)), false, "truncated");
      assert.equal(verifyConsistency(m, n, a, b, [...proof, proof[0]]), false, "extended");
      for (const size of [m - 1, m + 1]) if (size > 0 && size < n) assert.equal(verifyConsistency(size, n, ROOT_AT[size], b, proof), false, `wrong from size ${size}`);
      for (const size of [n - 1, n + 1]) if (size > m && size <= MAX) assert.equal(verifyConsistency(m, size, a, ROOT_AT[size], proof), false, `wrong to size ${size}`);
    }
  }
});

test("random historical pairs in a 1500-leaf tree", () => {
  const data = Array.from({ length: 1500 }, (_, i) => sha(Buffer.from(`big-${i}`)));
  const tree = treeOf(data);
  let seed = 7;
  const next = (bound) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % bound; };
  for (let i = 0; i < 200; i += 1) {
    const n = 1 + next(1500);
    const m = next(n + 1);
    const index = next(n);
    const rootN = tree.root(n);
    assert.equal(verifyConsistency(m, n, tree.root(m), rootN, tree.consistencyProof(m, n)), true, `${m}->${n}`);
    assert.equal(verifyInclusion(tree.leaf(index), index, n, tree.inclusionProof(index, n), rootN), true, `${index}/${n}`);
  }
  assert.equal(toHex(tree.root()), toHex(rootOf(data.map(() => null).map((_, i) => tree.leaf(i)))));
  assert.equal(toHex(tree.root(1000)), toHex(naiveMth(data.slice(0, 1000))));
});

// ---------------------------------------------------------------- API contract

test("verify functions return false (never throw) for malformed input", () => {
  const leaf = TREE.leaf(0);
  const root = ROOT_AT[2];
  const proof = TREE.inclusionProof(0, 2);
  const junk = [undefined, null, "x", 1.5, -1, NaN, Infinity, 2 ** 53, {}, [1], new Uint8Array(31), new Uint8Array(33)];
  for (const value of junk) {
    assert.equal(verifyInclusion(value, 0, 2, proof, root), false);
    assert.equal(verifyInclusion(leaf, value, 2, proof, root), false);
    assert.equal(verifyInclusion(leaf, 0, value, proof, root), false);
    assert.equal(verifyInclusion(leaf, 0, 2, value, root), false);
    assert.equal(verifyInclusion(leaf, 0, 2, [value], root), false);
    assert.equal(verifyInclusion(leaf, 0, 2, proof, value), false);
    assert.equal(verifyConsistency(value, 2, ROOT_AT[1], root, TREE.consistencyProof(1, 2)), false);
    assert.equal(verifyConsistency(1, value, ROOT_AT[1], root, TREE.consistencyProof(1, 2)), false);
    assert.equal(verifyConsistency(1, 2, value, root, TREE.consistencyProof(1, 2)), false);
    assert.equal(verifyConsistency(1, 2, ROOT_AT[1], value, TREE.consistencyProof(1, 2)), false);
    assert.equal(verifyConsistency(1, 2, ROOT_AT[1], root, value), false);
    assert.equal(verifyConsistency(3, 5, ROOT_AT[3], ROOT_AT[5], [...TREE.consistencyProof(3, 5).slice(0, 1), value]), false);
  }
  assert.equal(verifyInclusion(leaf, 2, 2, proof, root), false, "index == size");
  assert.equal(verifyConsistency(3, 2, ROOT_AT[3], root, []), false, "from > to");
});

test("MerkleTree rejects bad arguments and returns detached copies", () => {
  const tree = treeOf(LEAF_INPUTS.slice(0, 3));
  assert.throws(() => tree.append(new Uint8Array(31)), TypeError);
  assert.throws(() => tree.append("00"), TypeError);
  assert.throws(() => tree.root(4), RangeError);
  assert.throws(() => tree.root(-1), RangeError);
  assert.throws(() => tree.inclusionProof(3, 3), RangeError);
  assert.throws(() => tree.inclusionProof(0, 0), RangeError);
  assert.throws(() => tree.inclusionProof(0, 4), RangeError);
  assert.throws(() => tree.consistencyProof(3, 2), RangeError);
  assert.throws(() => tree.consistencyProof(0, 4), RangeError);
  assert.throws(() => tree.leaf(3), RangeError);
  assert.deepEqual(tree.consistencyProof(0, 3), []);
  assert.deepEqual(tree.consistencyProof(3), []);
  const leaf = tree.leaf(0);
  leaf[0] ^= 0xff;
  assert.equal(toHex(tree.leaf(0)), NODE_HASHES[0][0]);
  const root = tree.root();
  root[0] ^= 0xff;
  assert.equal(toHex(tree.root()), ROOTS[3]);
  const input = hx(NODE_HASHES[0][3]);
  assert.equal(tree.append(input), 3);
  input[0] ^= 0xff;
  assert.equal(toHex(tree.root()), ROOTS[4]);
});

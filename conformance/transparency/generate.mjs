#!/usr/bin/env node
/**
 * Writes conformance/transparency/vectors.json: the witness wire-format vectors
 * (docs/WITNESS.md §9) — RFC 6962 Merkle proofs, C2SP signed notes, verifier and
 * signer keys, checkpoints, owner-signed head statements, witness log entries,
 * receipts and witness-signed latest notes. Deterministic (fixed seeds, fixed clock); `--check` compares
 * with the committed file instead of writing it and exits 1 on a difference.
 *
 * Published vectors are copied verbatim and marked with their `source`; every
 * other vector is generated here by the TypeScript core (packages/core/dist,
 * so run `pnpm build` first) and marked `source: "generated"`.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildScenario, keysAt } from "./scenario.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = dirname(dirname(HERE));
const core = await import(join(ROOT, "packages/core/dist/index.js"));
const t = await import(join(ROOT, "packages/core/dist/transparency/index.js"));

const lib = {
  ...t, keyPairFromPrivateKey: core.keyPairFromPrivateKey, signHashWith: core.signHashWith, signControlEvent: core.signControlEvent,
  HistoryHasher: core.HistoryHasher, TRELLIS_VERSIONS: core.TRELLIS_VERSIONS, ADAPTER_POLICY_HASHES: core.ADAPTER_POLICY_HASHES, ownerKeyDigest: core.ownerKeyDigest,
  controlAuthorizationHash: core.controlAuthorizationHash, controlEffectHash: core.controlEffectHash,
};

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const hx = (text) => new Uint8Array(Buffer.from(text, "hex"));
const clone = (value) => JSON.parse(JSON.stringify(value));

const SOURCES = {
  "transparency-dev/merkle": "github.com/transparency-dev/merkle: testonly/constants.go (main) and proof/verify_test.go (tag v0.0.2); the RFC 6962 vectors also used by certificate-transparency-go",
  "golang.org/x/mod/sumdb/note": "github.com/golang/mod sumdb/note/note_test.go (master): TestNewVerifier, TestNewSigner, TestSign, TestOpen",
  "c2sp.org/signed-note": "github.com/C2SP/C2SP signed-note.md (main): verifier key example and example notes",
  "c2sp.org/tlog-checkpoint": "github.com/C2SP/C2SP tlog-checkpoint.md (main): example checkpoint",
  generated: "conformance/transparency/generate.mjs with the TypeScript core (deterministic)",
};

// ---------------------------------------------------------------- merkle

const PUBLISHED_LEAVES = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"];
const PUBLISHED_ROOTS = [
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
  "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125", "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
  "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7", "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
  "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
  "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
];
const PUBLISHED_INCLUSION = [
  [0, 1, []],
  [0, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]],
  [5, 8, ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]],
  [2, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]],
  [1, 5, ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]],
];
const PUBLISHED_CONSISTENCY = [
  [1, 1, []],
  [1, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]],
  [6, 8, ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]],
  [2, 5, ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]],
  [6, 7, ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]],
];

const flip = (hash, at = 0) => { const b = hx(hash); b[at] ^= 1; return hex(b); };

function merkleVectors() {
  const published = new t.MerkleTree();
  const publishedLeafHashes = PUBLISHED_LEAVES.map((leaf) => hex(t.leafHash(hx(leaf))));
  publishedLeafHashes.forEach((leaf) => published.append(hx(leaf)));
  for (let size = 0; size <= 8; size += 1) if (hex(published.root(size)) !== PUBLISHED_ROOTS[size]) throw new Error(`published root ${size} mismatch`);
  const inclusion = [];
  const consistency = [];
  for (const [index, size, proof] of PUBLISHED_INCLUSION) {
    inclusion.push({ source: "transparency-dev/merkle", leafHash: publishedLeafHashes[index], index, size, proof, root: PUBLISHED_ROOTS[size], valid: true });
  }
  for (const [from, to, proof] of PUBLISHED_CONSISTENCY) {
    consistency.push({ source: "transparency-dev/merkle", from, to, fromRoot: PUBLISHED_ROOTS[from], toRoot: PUBLISHED_ROOTS[to], proof, valid: true });
  }
  // Published edge probes (TestVerifyInclusion): empty proofs at impossible index/size pairs.
  const someHash = "abacaba000000000000000000000000000000000000000000060061e00123456";
  for (const [index, size] of [[0, 0], [0, 1], [1, 0], [2, 1]]) {
    inclusion.push({ source: "transparency-dev/merkle", desc: "edge probe", leafHash: someHash, index, size, proof: [], root: PUBLISHED_ROOTS[0], valid: false });
  }
  // Generated: a 13-leaf tree; every inclusion proof at sizes 7 and 13, every consistency proof into 13, and mutations.
  const tree = new t.MerkleTree();
  const leaves = Array.from({ length: 13 }, (_, i) => createHash("sha256").update(`irontrellis-transparency-vector-leaf-${i}`).digest("hex"));
  const leafHashes = leaves.map((leaf) => hex(t.leafHash(hx(leaf))));
  leafHashes.forEach((leaf) => tree.append(hx(leaf)));
  const roots = Array.from({ length: 14 }, (_, size) => hex(tree.root(size)));
  for (const size of [7, 13]) {
    for (let index = 0; index < size; index += 1) {
      inclusion.push({ source: "generated", leafHash: leafHashes[index], index, size, proof: tree.inclusionProof(index, size).map(hex), root: roots[size], valid: true });
    }
  }
  for (let from = 0; from <= 13; from += 1) {
    consistency.push({ source: "generated", from, to: 13, fromRoot: roots[from], toRoot: roots[13], proof: tree.consistencyProof(from, 13).map(hex), valid: true });
  }
  const base = { source: "generated", leafHash: leafHashes[5], index: 5, size: 13, proof: tree.inclusionProof(5, 13).map(hex), root: roots[13] };
  inclusion.push(
    { ...base, desc: "wrong index", index: 4, valid: false },
    { ...base, desc: "index equals size", index: 13, size: 13, valid: false },
    { ...base, desc: "wrong size", size: 8, valid: false },
    { ...base, desc: "tampered leaf", leafHash: flip(base.leafHash), valid: false },
    { ...base, desc: "tampered root", root: flip(base.root, 31), valid: false },
    { ...base, desc: "tampered proof element", proof: base.proof.map((p, i) => (i === 1 ? flip(p, 9) : p)), valid: false },
    { ...base, desc: "truncated proof", proof: base.proof.slice(0, -1), valid: false },
    { ...base, desc: "extended proof", proof: [...base.proof, base.proof[0]], valid: false },
    { ...base, desc: "31-byte proof element", proof: base.proof.map((p, i) => (i === 0 ? p.slice(2) : p)), valid: false },
  );
  const cbase = { source: "generated", from: 5, to: 13, fromRoot: roots[5], toRoot: roots[13], proof: tree.consistencyProof(5, 13).map(hex) };
  consistency.push(
    { ...cbase, desc: "from greater than to", from: 13, to: 5, fromRoot: roots[13], toRoot: roots[5], valid: false },
    { ...cbase, desc: "swapped roots", fromRoot: roots[13], toRoot: roots[5], valid: false },
    { ...cbase, desc: "wrong first root", fromRoot: roots[6], valid: false },
    { ...cbase, desc: "wrong second root", toRoot: roots[12], valid: false },
    { ...cbase, desc: "tampered proof element", proof: cbase.proof.map((p, i) => (i === 0 ? flip(p) : p)), valid: false },
    { ...cbase, desc: "truncated proof", proof: cbase.proof.slice(0, -1), valid: false },
    { ...cbase, desc: "extended proof", proof: [...cbase.proof, cbase.proof[0]], valid: false },
    { ...cbase, desc: "empty proof", proof: [], valid: false },
    { source: "generated", desc: "equal sizes, different roots", from: 13, to: 13, fromRoot: roots[13], toRoot: roots[12], proof: [], valid: false },
    { source: "generated", desc: "equal sizes, non-empty proof", from: 13, to: 13, fromRoot: roots[13], toRoot: roots[13], proof: [roots[13]], valid: false },
    { source: "generated", desc: "power-of-two first size (8 -> 13)", from: 8, to: 13, fromRoot: roots[8], toRoot: roots[13], proof: tree.consistencyProof(8, 13).map(hex), valid: true },
  );
  for (const v of inclusion) if (t.verifyInclusion(hx(v.leafHash), v.index, v.size, v.proof.map(hx), hx(v.root)) !== v.valid) throw new Error(`inclusion vector disagrees: ${JSON.stringify(v)}`);
  for (const v of consistency) if (t.verifyConsistency(v.from, v.to, hx(v.fromRoot), hx(v.toRoot), v.proof.map(hx)) !== v.valid) throw new Error(`consistency vector disagrees: ${JSON.stringify(v)}`);
  return {
    published: { source: "transparency-dev/merkle", leaves: PUBLISHED_LEAVES, leafHashes: publishedLeafHashes, roots: PUBLISHED_ROOTS },
    generated: { source: "generated", leaves, leafHashes, roots },
    inclusion, consistency,
  };
}

// ---------------------------------------------------------------- notes, keys, checkpoints

const PETER_SKEY = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
const PETER_VKEY = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
const ENOCH_VKEY = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop";
const TEXT = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n";
const PETER_SIG = "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
const ENOCH_SIG = "— EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";
const FOO_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
const FOO_NOTE = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";
const spliceBytes = (text, at, insert) => { const b = Buffer.from(text, "utf8"); return Buffer.concat([b.subarray(0, at), Buffer.from(insert), b.subarray(at)]).toString("utf8"); };

function openExpectation(note, verifierKeys) {
  try {
    return { ok: true, ...t.openNote(note, verifierKeys) };
  } catch (error) {
    if (!(error instanceof t.NoteError)) throw error;
    return { ok: false, error: error.code };
  }
}

function noteVectors(S) {
  const cases = [
    ["golang.org/x/mod/sumdb/note", "TestSign/TestOpen: one known signer", `${TEXT}\n${PETER_SIG}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: one verified, one unknown ignored", `${TEXT}\n${PETER_SIG}${ENOCH_SIG}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: both verified (note order)", `${TEXT}\n${PETER_SIG}${ENOCH_SIG}`, [ENOCH_VKEY, PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: no known key", `${TEXT}\n${PETER_SIG}${ENOCH_SIG}`, []],
    ["golang.org/x/mod/sumdb/note", "TestOpen: 101 signatures", `${TEXT}\n${PETER_SIG.repeat(101)}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: bad signature by a known key", `${TEXT}\n${spliceBytes(PETER_SIG, 60, "ABCD")}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: duplicated verified and unverified signatures", `${TEXT}\n${PETER_SIG}${PETER_SIG}${ENOCH_SIG}${ENOCH_SIG}${spliceBytes(ENOCH_SIG, 60, "ABCD")}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: text only", TEXT, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: no signature lines", `${TEXT}\n`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: missing final newline", `${TEXT}\n${PETER_SIG.slice(0, -1)}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: control character", `\x01${TEXT}\n${PETER_SIG}`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: space in key name", `${TEXT}\n— Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=`, [PETER_VKEY]],
    ["golang.org/x/mod/sumdb/note", "TestOpen: unexpected line after signatures", `${TEXT}\n${PETER_SIG}Unexpected line.\n`, [PETER_VKEY]],
    ["c2sp.org/signed-note", "verifier key example", FOO_NOTE, [FOO_VKEY]],
    ["generated", "checkpoint note of the scenario witness (size 7)", S.checkpoint7, [S.witnessVkey]],
    ["generated", "same-name key with another hash is unknown", S.checkpointAt(7, S.other), [S.witnessVkey]],
    ["generated", "checkpoint body altered", S.checkpoint7.replace("\n7\n", "\n8\n"), [S.witnessVkey]],
    ["generated", "unpadded base64 signature", `${S.checkpoint7.slice(0, S.checkpoint7.lastIndexOf("=\n"))}\n`, [S.witnessVkey]],
  ];
  return cases.map(([source, desc, note, verifierKeys]) => ({ source, desc, note, verifierKeys, expect: openExpectation(note, verifierKeys) }));
}

function keyVectors(S) {
  const verifier = (source, vkey) => {
    try {
      const parsed = t.parseVerifierKey(vkey);
      return { source, vkey, valid: true, name: parsed.name, keyHash: hex(parsed.keyHash), publicKey: hex(parsed.publicKey) };
    } catch {
      return { source, vkey, valid: false };
    }
  };
  const signer = (source, skey) => {
    try {
      const parsed = t.parseSignerKey(skey);
      return { source, skey, valid: true, verifierKey: t.verifierKey(parsed.name, parsed.publicKey) };
    } catch {
      return { source, skey, valid: false };
    }
  };
  const seed = t.formatSignerKey(S.witness.name, new Uint8Array(32).fill(0x77));
  return {
    verifierKeys: [
      verifier("golang.org/x/mod/sumdb/note", PETER_VKEY), verifier("golang.org/x/mod/sumdb/note", ENOCH_VKEY), verifier("c2sp.org/signed-note", FOO_VKEY),
      verifier("golang.org/x/mod/sumdb/note", "PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY=="),
      verifier("golang.org/x/mod/sumdb/note", "PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"),
      verifier("golang.org/x/mod/sumdb/note", PETER_VKEY.replace("c74f20a3", "c74f20a4")),
      verifier("golang.org/x/mod/sumdb/note", PETER_VKEY.slice(0, -1)),
      verifier("generated", S.witnessVkey),
      verifier("generated", S.witnessVkey.replace(/^[^+]+/, "irontrellis witness")),
    ],
    signerKeys: [
      signer("golang.org/x/mod/sumdb/note", PETER_SKEY), signer("golang.org/x/mod/sumdb/note", PETER_SKEY.replace("PRIVATE", "PRIVATF")),
      signer("golang.org/x/mod/sumdb/note", PETER_SKEY.replace("c74f20a3", "c74f20a4")), signer("generated", seed),
    ],
    signing: [
      { source: "golang.org/x/mod/sumdb/note", signerKey: PETER_SKEY, body: TEXT, note: t.signNote(TEXT, t.parseSignerKey(PETER_SKEY)) },
      { source: "generated", signerKey: seed, body: t.openNote(S.checkpoint7, [S.witnessVkey]).body, note: S.checkpoint7 },
    ],
  };
}

function checkpointVectors(S) {
  const root = b64(S.tree.root(7));
  const bodies = [
    ["c2sp.org/tlog-checkpoint", "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"],
    ["generated", `irontrellis-witness/vectors\n7\n${root}\n`],
    ["generated", `irontrellis-witness/vectors\n0\n${b64(t.emptyRoot())}\n`],
    ["generated", `irontrellis-witness/vectors\n7\n${root}\nextension line one\nx\n`],
    ["generated", `irontrellis-witness/vectors\n9007199254740991\n${root}\n`],
    ["generated", `irontrellis-witness/vectors\n07\n${root}\n`],
    ["generated", `irontrellis-witness/vectors\n-7\n${root}\n`],
    ["generated", `irontrellis-witness/vectors\n9007199254740992\n${root}\n`],
    ["generated", `irontrellis-witness/vectors\n7\n${root.replace("=", "")}\n`],
    ["generated", `irontrellis-witness/vectors\n7\n${b64(new Uint8Array(31))}\n`],
    ["generated", `irontrellis-witness/vectors\n7\n${root}`],
    ["generated", `irontrellis-witness/vectors\n7\n`],
    ["generated", `\n7\n${root}\n`],
    ["generated", `irontrellis-witness/vectors\n7\n${root}\n\n`],
  ];
  return bodies.map(([source, body]) => {
    try {
      const c = t.parseCheckpoint(body);
      return { source, body, valid: true, origin: c.origin, size: c.size, root: b64(c.root), extensions: c.extensions };
    } catch {
      return { source, body, valid: false };
    }
  });
}

// ---------------------------------------------------------------- statements, entries, receipts

function statementVectors(S) {
  const { s0, s3, s6, s8, s6fork } = S.statements;
  const e1 = [{ fromPosition: 0, keys: S.ownerKeys1 }];
  const epochs = S.ownerKeyEpochs;
  const mutate = (signed, fn) => { const copy = clone(signed); fn(copy); return copy; };
  const cases = [
    ["first statement (previous null)", s0, e1], ["chained 3 <- 0", s3, e1], ["chained 6 <- 3", s6, e1], ["fork at 6 <- 3 (valid on its own)", s6fork, e1],
    ["after rotation, new key, epochs", s8, epochs], ["after rotation, only the old key known", s8, e1],
    ["old key statement checked against the new epoch only", s6, [{ fromPosition: 0, keys: S.ownerKeys2 }]],
    ["canonicalTime altered", mutate(s6, (c) => { c.statement.head.canonicalTime += 1; }), e1],
    ["previous altered", mutate(s6, (c) => { c.statement.previous = { hash: S.heads[5].hash, position: 5 }; }), e1],
    ["signature zeroed", mutate(s6, (c) => { c.signature = `0x${"00".repeat(64)}`; }), e1],
    ["previous beyond head", mutate(s6, (c) => { c.statement.previous.position = 7; }), e1],
    ["same position, different hash", mutate(s6, (c) => { c.statement.previous = { hash: S.heads[5].hash, position: 6 }; }), e1],
    ["extra field", mutate(s6, (c) => { c.statement.note = "x"; }), e1],
    ["short signature", mutate(s6, (c) => { c.signature = c.signature.slice(0, -2); }), e1],
    ["pre-rotation history: the chain statement 4 <- 2, under the genesis-committed epoch", S.preRotation.statements.chain, S.preRotation.ownerKeyEpochs],
    ["pre-rotation history: the thief's head (valid on its own; the supersede overrides it)", S.preRotation.statements.thief, S.preRotation.ownerKeyEpochs],
    ["pre-rotation history: the revealed key after the rotation", S.preRotation.statements.s5, S.preRotation.ownerKeyEpochs],
    ["pre-rotation history: the old key after the rotation", mutate(S.preRotation.statements.s5, (c) => { c.keyId = "owner:1"; }), S.preRotation.ownerKeyEpochs],
  ];
  return cases.map(([desc, signed, ownerKeyEpochs]) => {
    const result = t.verifySignedHeadStatement(signed, (position) => keysAt(ownerKeyEpochs, position));
    const valid = t.validateHeadStatement(signed.statement) === null;
    return { source: "generated", desc, signed, ownerKeyEpochs, statementHash: valid ? t.headStatementHash(signed.statement) : null, expect: result.ok ? "OK" : result.reason };
  });
}

function entryVectors(S) {
  const accepted = (desc, entry) => ({ source: "generated", desc, entry, valid: true, canonical: Buffer.from(t.encodeEntry(entry)).toString("utf8"), leafHash: hex(t.entryLeafHash(entry)) });
  const valid = [
    ...S.entries.map((entry, index) => accepted(`scenario entry ${index} (${entry.kind})`, entry)),
    ...S.preRotation.entries.map((entry, n) => accepted(`pre-rotation entry ${S.entries.length + n} (${entry.kind}${entry.kind === "REGISTERED" ? ", genesis with a next-key commitment" : ""})`, entry)),
  ];
  const [registered, head, , , rotated, , equivocation] = S.entries;
  const invalid = [
    ["unknown kind", { ...head, kind: "OTHER" }], ["wrong version", { ...head, version: "irontrellis-witness-entry/2" }], ["extra field", { ...head, extra: 1 }],
    ["genesis does not hash to historyId", { ...registered, genesis: { ...registered.genesis, timestamp: 1 } }],
    ["statement for another history", { ...head, historyId: S.heads[1].hash }],
    ["rotation of the wrong type", { ...rotated, rotation: { ...rotated.rotation, type: "AGENT_CREATED" } }],
    ["rotation without previousHead", Object.fromEntries(Object.entries(rotated).filter(([key]) => key !== "previousHead"))],
    ["rotation whose previousHead does not precede rotationHead", { ...rotated, previousHead: { ...rotated.previousHead, position: rotated.rotationHead.position } }],
    ["rotation previousHead hash not a content hash", { ...rotated, previousHead: { ...rotated.previousHead, hash: "0x12" } }],
    ["equivocation of one head with itself", { ...equivocation, second: equivocation.first }],
    ["receivedAt negative", { ...head, receivedAt: -1 }],
  ].map(([desc, entry]) => ({ source: "generated", desc, entry, valid: false }));
  // SUPERSEDED variants of the pre-rotation log's entry (a pre-rotated rotation overrides the heads after the last good head).
  const P = S.preRotation;
  const [preRegistered, , , , superseded] = P.entries;
  const from = superseded.supersededFromIndex, to = superseded.supersededToIndex;
  const keyEvents = [
    ["SUPERSEDED of a flood (a range of 100,000 leaves; the entry does not grow with it)", { ...superseded, supersededToIndex: from + 100_001, supersededLatest: { ...superseded.supersededLatest, position: 100_000, index: from + 100_000 }, supersededCount: 100_000 }, true],
    ["SUPERSEDED whose chain states another head", { ...superseded, chain: P.statements.s2 }, false],
    ["SUPERSEDED whose chain has no previous", { ...superseded, chain: { ...superseded.chain, statement: { ...superseded.chain.statement, previous: null } } }, false],
    ["SUPERSEDED with supersededCount 0", { ...superseded, supersededCount: 0 }, false],
    ["SUPERSEDED counting more heads than leaves in the range", { ...superseded, supersededCount: 2 }, false],
    ["SUPERSEDED latest not after the last good head", { ...superseded, supersededLatest: { position: 2, hash: P.heads[2].hash, index: from + 1 } }, false],
    ["SUPERSEDED latest leaf at supersededFromIndex", { ...superseded, supersededLatest: { ...superseded.supersededLatest, index: from } }, false],
    ["SUPERSEDED latest leaf at supersededToIndex", { ...superseded, supersededLatest: { ...superseded.supersededLatest, index: to } }, false],
    ["SUPERSEDED range ending before it starts", { ...superseded, supersededToIndex: from - 1 }, false],
    ["SUPERSEDED listing heads instead of a range", { ...Object.fromEntries(Object.entries(superseded).filter(([key]) => !["supersededToIndex", "supersededLatest", "supersededCount"].includes(key))), supersededHeads: [{ ...superseded.supersededLatest }] }, false],
    ["SUPERSEDED of an event that is not a rotation", { ...superseded, rotation: P.events[1] }, false],
    ["SUPERSEDED whose rotationHead does not follow previousHead", { ...superseded, rotationHead: { ...superseded.rotationHead, position: superseded.previousHead.position + 2 } }, false],
    ["REGISTERED genesis with a next-key commitment, under another history id", { ...preRegistered, historyId: S.historyId }, false],
  ].map(([desc, entry, ok]) => (ok ? accepted(desc, entry) : { source: "generated", desc, entry, valid: false }));
  for (const v of [...valid, ...invalid, ...keyEvents]) if ((t.validateEntry(v.entry) === null) !== v.valid) throw new Error(`entry vector disagrees: ${v.desc}: ${t.validateEntry(v.entry)}`);
  return [...valid, ...invalid, ...keyEvents];
}

function receiptVectors(S) {
  const trusted = [S.witnessVkey];
  const good = S.receipts[2];
  const cases = [
    ...S.receipts.map((receipt, index) => [`entry ${index} (${receipt.entry.kind}) at size 7`, receipt, trusted]),
    ["entry 2 at size 4", S.receiptAt4, trusted],
    ["untrusted witness key", good, [S.otherVkey]],
    ["checkpoint signed by a same-name impostor key", { ...good, checkpoint: S.checkpointAt(7, S.other) }, trusted],
    ["checkpoint size altered", { ...good, checkpoint: good.checkpoint.replace("\n7\n", "\n8\n") }, trusted],
    ["signed note that is not a checkpoint", { ...good, checkpoint: t.signNote("not a checkpoint\n", S.witness) }, trusted],
    ["receipt names another origin", { ...good, witness: { ...good.witness, origin: "irontrellis-witness/other" } }, trusted],
    ["entry kind unknown", { ...good, entry: { ...good.entry, kind: "NOPE" } }, trusted],
    ["index equals checkpoint size", { ...good, index: 7 }, trusted],
    ["index 5 against the size-4 checkpoint", { ...S.receipts[5], checkpoint: S.checkpoint4 }, trusted],
    ["wrong index", { ...good, index: 3 }, trusted],
    ["entry receivedAt altered", { ...good, entry: { ...good.entry, receivedAt: good.entry.receivedAt + 1 } }, trusted],
    ["truncated inclusion proof", { ...good, inclusionProof: good.inclusionProof.slice(0, -1) }, trusted],
    ["size-7 proof against the size-4 checkpoint", { ...good, checkpoint: S.checkpoint4 }, trusted],
    ["wrong receipt version", { ...good, version: "irontrellis-witness-receipt/2" }, trusted],
    ...S.preRotation.receipts.map((receipt) => [`pre-rotation entry ${receipt.index} (${receipt.entry.kind}) at size ${S.log.length}`, receipt, trusted]),
    ["the SUPERSEDED receipt against the size-7 checkpoint", { ...S.preRotation.receipts[4], checkpoint: S.checkpoint7 }, trusted],
  ];
  return cases.map(([desc, receipt, trustedVerifierKeys]) => {
    const result = t.verifyWitnessReceipt(receipt, trustedVerifierKeys);
    const expect = result.ok ? { ok: true, index: result.index, checkpoint: { origin: result.checkpoint.origin, size: result.checkpoint.size, root: b64(result.checkpoint.root) } } : { ok: false, reason: result.reason };
    return { source: "generated", desc, receipt, trustedVerifierKeys, expect };
  });
}

// ---------------------------------------------------------------- latest notes (docs/WITNESS.md §9.8)

const nonceOf = (byte, length) => Buffer.alloc(length, byte).toString("base64url");

function latestNoteVectors(S) {
  const origin = "irontrellis-witness/vectors";
  const historyId = S.historyId;
  const nonce = nonceOf(0x11, 32), nonce16 = nonceOf(0x22, 16), nonce64 = nonceOf(0x33, 64);
  const head6 = { position: 6, hash: S.heads[6].hash, index: 5 };
  const fields = (extra) => ({ origin, historyId, nonce, latest: head6, treeSize: 7, equivocations: 1, supersedes: 1, ...extra });
  // format: fields → body text, or MALFORMED_LATEST_NOTE.
  const format = [
    ["a latest head", fields({})], ["no head yet (registration only)", fields({ latest: null, treeSize: 1, equivocations: 0, supersedes: 0 })],
    ["16-byte nonce", fields({ nonce: nonce16 })], ["64-byte nonce", fields({ nonce: nonce64 })],
    ["leaf index equals the tree size", fields({ treeSize: 5 })], ["15-byte nonce", fields({ nonce: nonceOf(0x44, 15) })],
    ["65-byte nonce", fields({ nonce: nonceOf(0x44, 65) })], ["padded base64url nonce", fields({ nonce: `${nonce16}==` })],
    ["standard base64 alphabet in the nonce", fields({ nonce: Buffer.alloc(32, 0xfb).toString("base64").replace(/=+$/, "") })],
    ["origin is the latest-note version line", fields({ origin: "irontrellis-witness-latest/1" })], ["origin with a newline", fields({ origin: "a\nb" })],
    ["uppercase history id", fields({ historyId: historyId.toUpperCase().replace("0X", "0x") })], ["negative equivocation count", fields({ equivocations: -1 })],
    ["tree size above 2^53 - 1", fields({ treeSize: 2 ** 53 })], ["negative supersede count", fields({ supersedes: -1 })],
    ["no supersede count", Object.fromEntries(Object.entries(fields({})).filter(([key]) => key !== "supersedes"))],
  ].map(([desc, value]) => {
    try {
      return { source: "generated", desc, fields: value, valid: true, body: t.formatLatestNote(value) };
    } catch (error) {
      if (!(error instanceof t.NoteError)) throw error;
      return { source: "generated", desc, fields: value, valid: false, error: error.code };
    }
  });
  const body = t.formatLatestNote(fields({}));
  const lines = body.slice(0, -1).split("\n");
  const withLine = (at, text) => `${lines.map((line, i) => (i === at ? text : line)).join("\n")}\n`;
  // parse: body → fields, or MALFORMED_LATEST_NOTE.
  const parse = [
    ["well-formed", body], ["no head", t.formatLatestNote(fields({ latest: null, treeSize: 1, equivocations: 0, supersedes: 0 }))],
    ["nine lines (missing supersede count)", `${lines.slice(0, 9).join("\n")}\n`],
    ["leading zero in the supersede count", withLine(9, "01")],
    ["a checkpoint body is not a latest note", `${origin}\n7\n${b64(S.tree.root(7))}\n`],
    ["unknown version line", withLine(0, "irontrellis-witness-latest/2")], ["missing final newline", body.slice(0, -1)],
    ["an extra line", `${body}extension\n`], ["position none but hash present", withLine(4, "none")],
    ["leading zero in the position", withLine(4, "06")], ["leaf index not below the tree size", withLine(6, "7")],
    ["nonce not canonical base64url", withLine(3, `${nonce.slice(0, -1)}B`)], ["origin equal to the version line", withLine(1, "irontrellis-witness-latest/1")],
    ["empty origin", withLine(1, "")], ["history id without 0x", withLine(2, historyId.slice(2))],
  ].map(([desc, text]) => {
    try {
      return { source: "generated", desc, body: text, valid: true, fields: clone(t.parseLatestNote(text)) };
    } catch (error) {
      if (!(error instanceof t.NoteError)) throw error;
      return { source: "generated", desc, body: text, valid: false, error: error.code };
    }
  });
  // verify: signed note + trusted keys + what the client asked → {ok, latest} or {ok:false, reason}.
  const signed = t.signNote(body, S.witness);
  const expectOf = { origin, historyId, nonce };
  const verify = [
    ["the answer to this request", signed, [S.witnessVkey], expectOf],
    ["no expectation: fails closed (a verification without the request's nonce would accept a replayed answer)", signed, [S.witnessVkey], {}],
    ["null expectation", signed, [S.witnessVkey], null],
    ["an array as the expectation", signed, [S.witnessVkey], [origin, historyId, nonce]],
    ["no nonce in the expectation", signed, [S.witnessVkey], { origin, historyId }],
    ["no history id in the expectation", signed, [S.witnessVkey], { origin, nonce }],
    ["a null nonce in the expectation", signed, [S.witnessVkey], { origin, historyId, nonce: null }],
    ["a nonce that is not canonical base64url", signed, [S.witnessVkey], { origin, historyId, nonce: `${nonce}=` }],
    ["a numeric history id", signed, [S.witnessVkey], { origin, historyId: 7, nonce }],
    ["a null origin in the expectation", signed, [S.witnessVkey], { origin: null, historyId, nonce }],
    ["a misspelt field in the expectation", signed, [S.witnessVkey], { origin, historyId, nonces: nonce }],
    ["history id and nonce only (the origin is optional)", signed, [S.witnessVkey], { historyId, nonce }],
    ["no head, fresh", t.signNote(t.formatLatestNote(fields({ latest: null, treeSize: 1, equivocations: 0, supersedes: 0 })), S.witness), [S.witnessVkey], expectOf],
    ["a replayed answer to another nonce", t.signNote(t.formatLatestNote(fields({ nonce: nonce16 })), S.witness), [S.witnessVkey], expectOf],
    ["about another history", t.signNote(t.formatLatestNote(fields({ historyId: S.heads[1].hash })), S.witness), [S.witnessVkey], expectOf],
    ["from another origin", t.signNote(t.formatLatestNote(fields({ origin: "irontrellis-witness/other" })), S.witness), [S.witnessVkey], expectOf],
    ["signed by an untrusted key", t.signNote(body, S.other), [S.witnessVkey], expectOf],
    ["body altered after signing", signed.replace("\n6\n", "\n5\n"), [S.witnessVkey], expectOf],
    ["a signed checkpoint is not a latest note", S.checkpoint7, [S.witnessVkey], expectOf],
    ["not a string", 7, [S.witnessVkey], expectOf],
  ].map(([desc, note, trustedVerifierKeys, expect]) => {
    const result = t.verifyLatestNote(note, trustedVerifierKeys, expect);
    return { source: "generated", desc, note, trustedVerifierKeys, expect, result: result.ok ? { ok: true, latest: clone(result.latest) } : { ok: false, reason: result.reason } };
  });
  return { format, parse, verify };
}

// ---------------------------------------------------------------- assemble

const S = await buildScenario(lib);
const vectors = {
  schemaVersion: "irontrellis-transparency-vectors/1",
  conventions: {
    hashes: "Merkle leaf data, leaf hashes, node hashes and roots are lowercase hex without 0x. Checkpoint roots, receipt proofs and note signatures are standard padded base64 (RFC 4648 §4), decoded strictly (canonical spelling only).",
    merkle: "RFC 6962 / RFC 9162 §2.1: leafHash = SHA-256(0x00 || data), nodeHash = SHA-256(0x01 || left || right). Inclusion: verifyInclusion(leafHash, index, size, proof, root). Consistency: verifyConsistency(from, to, fromRoot, toRoot, proof); from = 0 is consistent with anything given an empty proof; equal sizes need equal roots and an empty proof.",
    notes: "C2SP signed-note (golang.org/x/mod/sumdb/note): open(note, verifierKeys) → {ok:true, body, verifiedBy} or {ok:false, error}; error codes MALFORMED_NOTE, UNVERIFIED_NOTE, INVALID_SIGNATURE, AMBIGUOUS_KEY, INVALID_KEY. Unknown signers are ignored; a known key with a bad signature rejects the note.",
    statements: "Signed head statements verify against the owner keys of the epoch in effect at statement.head.position: keys of the last ownerKeyEpochs entry with fromPosition <= position. statementHash = sha256 of the canonical encoding of the statement (0x-hex). expect is OK, MALFORMED, UNKNOWN_KEY or SIGNATURE_INVALID.",
    entries: "canonical is the exact canonical text (continuity-canonical/0.2) whose UTF-8 bytes are the Merkle leaf data; leafHash = SHA-256(0x00 || canonical).",
    receipts: "verifyWitnessReceipt(receipt, trustedVerifierKeys) → {ok:true, index, checkpoint:{origin,size,root(base64)}} or {ok:false, reason}; reasons RECEIPT_MALFORMED, NOTE_UNVERIFIED, CHECKPOINT_MALFORMED, ORIGIN_MISMATCH, ENTRY_MALFORMED, INDEX_OUT_OF_RANGE, INCLUSION_INVALID, checked in that order.",
    latestNotes: "Witness-signed latest notes (docs/WITNESS.md §9.8): the body is ten lines, `irontrellis-witness-latest/1`, origin, historyId, nonce (canonical unpadded base64url of 16..64 bytes), latest position, latest head hash, leaf index of that HEAD entry (the three are all `none` when the witness holds no head), tree size, equivocation count, supersede count, each ending in a newline. The origin is never the version line. format(fields) → body or MALFORMED_LATEST_NOTE; parse(body) → fields or MALFORMED_LATEST_NOTE; verify(note, trustedVerifierKeys, expect {historyId, nonce, origin?}) → {ok:true, latest:fields} or {ok:false, reason}; reasons EXPECTATION_INVALID (expect is not a plain object whose fields are exactly historyId (a content hash), nonce (a valid nonce) and optionally origin (a note line that is not a version line)), NOTE_UNVERIFIED, LATEST_MALFORMED, ORIGIN_MISMATCH, HISTORY_MISMATCH, NONCE_MISMATCH, checked in that order.",
    scenario: "Statements, entries and receipts come from conformance/transparency/scenario.mjs: one witness log with two histories. Main history: owner:1 = Ed25519 seed 0x…3001, owner:2 = seed 0x…3002 (after the OWNER_KEYS_ROTATED at position 7, out of an uncommitted epoch). Pre-rotation history (log leaves 7..14): its genesis commits to owner:2's key digest; a head a thief of owner:1 stated after the last good head is superseded by the pre-rotated rotation at position 4 (revealing owner:2, committing to owner:3 = seed 0x…3003). Witness note key irontrellis-witness/vectors = seed 0x77 × 32. Test keys only.",
  },
  sources: SOURCES,
  merkle: merkleVectors(),
  notes: noteVectors(S),
  keys: keyVectors(S),
  checkpoints: checkpointVectors(S),
  statements: statementVectors(S),
  entries: entryVectors(S),
  receipts: receiptVectors(S),
  latestNotes: latestNoteVectors(S),
};

const text = `${JSON.stringify(vectors, null, 2)}\n`;
const target = join(HERE, "vectors.json");
if (process.argv.includes("--check")) {
  let current = "";
  try { current = readFileSync(target, "utf8"); } catch { /* missing */ }
  if (current !== text) {
    console.error("conformance/transparency/vectors.json differs from a fresh generation");
    process.exit(1);
  }
  console.log("conformance/transparency/vectors.json is up to date");
} else {
  writeFileSync(target, text);
  console.log(`wrote ${target} (${text.length} bytes)`);
}

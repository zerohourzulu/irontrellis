/**
 * Crypto tests: every vector in specs/04-crypto-vectors.json for the parts this
 * package owns (keccak, incremental keccak, EIP-191 digest/recovery/rejections,
 * the hash+recover halves of the challenge/receipt/administrative vectors), plus
 * key generation, signing round trips and a differential check against the
 * legacy reference engine when it is available on this machine.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { cryptoVectorsPath, referenceCore02, fixturePath as referenceFixturePath } from "./reference.mjs";

import {
  keccak256,
  createKeccakState,
  updateKeccakState,
  cloneKeccakState,
  finalizeKeccakState,
} from "../src/crypto/keccak.ts";
import {
  recoverAddress,
  recoverPublicKey,
  signDigest,
  encodeCompactSignature,
  publicKeyFromPrivateKey,
  addressFromPublicKey,
  hexToBytes,
  bytesToHex,
  SECP256K1_N,
  SECP256K1_HALF_N,
} from "../src/crypto/secp256k1.ts";
import {
  suiteFor,
  eip191Digest,
  recoverContentHashSigner,
  generateKeyPair,
  keyPairFromPrivateKey,
  signHashWith,
  isContentHash,
} from "../src/crypto/suites.ts";

const vectorPath = cryptoVectorsPath;
assert.ok(vectorPath, "04-crypto-vectors.json not found");
const V = JSON.parse(readFileSync(vectorPath, "utf8"));

const reference = {
  intrinsics: await referenceCore02("core/host-intrinsics.ts"),
  engine: await referenceCore02("core/portable-authority-engine.ts"),
  canonical: await referenceCore02("core/canonical.ts"),
};

const utf8 = (s) => new TextEncoder().encode(s);
const hex = (bytes) => `0x${bytesToHex(bytes)}`;
const keccakHex = (bytes) => hex(keccak256(bytes));
const eip191 = suiteFor("eip191-personal-sign-keccak256");
const ed25519 = suiteFor("ed25519");

/** Reproduce a vector's signature with our own RFC 6979 signer and check it verifies. */
async function assertReproducesSignature(contentHash, privateKeyHex, expectedSignature, expectedAddress) {
  const pair = keyPairFromPrivateKey("eip191-personal-sign-keccak256", "k", privateKeyHex);
  assert.equal(pair.credential, expectedAddress);
  const signature = await signHashWith(pair)(contentHash);
  assert.equal(signature, expectedSignature);
  assert.ok(eip191.isSignature(signature));
  assert.ok(eip191.verify(contentHash, signature, pair.credential));
  assert.equal(recoverContentHashSigner(contentHash, signature), expectedAddress);
}

// ---------------------------------------------------------------- keccak

test("keccak256: one-shot vectors", () => {
  for (const t of V.keccak256) {
    assert.equal(keccakHex(hexToBytes(t.inputHex)), t.keccak256, `input of ${t.inputBytes} bytes`);
    if (typeof t.input === "string") assert.equal(keccakHex(utf8(t.input)), t.keccak256);
  }
});

test("keccak256: chunked absorption equals one-shot at every split", () => {
  const input = hexToBytes(V.keccak256.at(-1).inputHex); // 1024 bytes
  const expected = V.keccak256.at(-1).keccak256;
  for (const split of [0, 1, 3, 4, 7, 135, 136, 137, 271, 272, 273, 500, 1023, 1024]) {
    const state = createKeccakState();
    updateKeccakState(state, input.subarray(0, split));
    updateKeccakState(state, input.subarray(split));
    assert.equal(hex(finalizeKeccakState(state)), expected, `split at ${split}`);
  }
  // Many tiny updates crossing block boundaries.
  const state = createKeccakState();
  for (let i = 0; i < input.length; i += 5) updateKeccakState(state, input.subarray(i, i + 5));
  assert.equal(hex(finalizeKeccakState(state)), expected);
});

test("keccak256: incremental state trace (clone, non-destructive finalize)", () => {
  const states = new Map();
  for (const step of V.keccakIncremental.steps) {
    switch (step.op) {
      case "create":
        states.set(step.state, createKeccakState());
        break;
      case "update":
        updateKeccakState(states.get(step.state), utf8(step.inputUtf8));
        break;
      case "clone":
        states.set(step.to, cloneKeccakState(states.get(step.from)));
        break;
      case "finalize":
        assert.equal(hex(finalizeKeccakState(states.get(step.state))), step.digest, step.note);
        break;
      default:
        assert.fail(`unknown op ${step.op}`);
    }
  }
});

test("keccak256: event-history prefix hashing from canonical texts", () => {
  const { eventCanonicalText, prefixHashes } = V.eventHistoryPrefixHashes;
  const state = createKeccakState();
  updateKeccakState(state, utf8('["continuity-event-history/0.2",['));
  eventCanonicalText.forEach((text, k) => {
    if (k > 0) updateKeccakState(state, utf8(","));
    updateKeccakState(state, utf8(text));
    const tail = cloneKeccakState(state);
    updateKeccakState(tail, utf8("]]"));
    assert.equal(hex(finalizeKeccakState(tail)), prefixHashes[k], `prefix ${k}`);
  });
});

test("keccak256: differential against the reference implementation", { skip: reference === undefined }, () => {
  const { keccak256Bytes } = reference.intrinsics;
  for (let i = 0; i < 200; i += 1) {
    const length = i < 140 ? i : Math.floor(Math.random() * 2000);
    const input = new Uint8Array(randomBytes(length));
    assert.equal(keccakHex(input), keccak256Bytes(input), `length ${length}`);
  }
});

test("keccak256: head of the 26-event fixture via the reference canonical encoder", { skip: reference === undefined }, () => {
  const fixturePath = referenceFixturePath("handover-history.json");
  const revive = (_k, v) => (v !== null && typeof v === "object" && typeof v["$continuity.bigint"] === "string" ? BigInt(v["$continuity.bigint"]) : v);
  const events = JSON.parse(readFileSync(fixturePath, "utf8"), revive);
  const { canonicalEncode, hashEventHistory } = reference.canonical;
  const text = `["continuity-event-history/0.2",[${events.map((e) => canonicalEncode(e)).join(",")}]]`;
  const expected = V.eventHistoryPrefixHashes.headOfFixtureAfter26Events.hash;
  assert.equal(keccakHex(utf8(text)), expected);
  assert.equal(hashEventHistory(events), expected);
});

// ---------------------------------------------------------------- EIP-191 / secp256k1

test("eip191: digest, recovery, and deterministic re-signing for every known-key vector", async () => {
  for (const t of V.eip191) {
    assert.equal(eip191Digest(t.contentHash), t.eip191Digest);
    if (t.eip191PreimageHex) assert.equal(keccakHex(hexToBytes(t.eip191PreimageHex)), t.eip191Digest);
    const digest = hexToBytes(t.eip191Digest);
    const signature = hexToBytes(t.signature);
    assert.equal(recoverAddress(digest, signature), t.recoveredAddress);
    assert.equal(hex(recoverPublicKey(digest, BigInt(t.r), BigInt(t.s), t.vDecimal - 27)).length, 130);
    assert.equal(recoverContentHashSigner(t.contentHash, t.signature), t.recoveredAddress);
    assert.ok(eip191.verify(t.contentHash, t.signature, t.recoveredAddress));
    assert.ok(eip191.verify(t.contentHash, t.signature, V.keys[t.key].addressChecksummed), "checksummed credential accepted");
    assert.ok(!eip191.verify(t.contentHash, t.signature, V.keys[t.key === "k1" ? "k1001" : "k1"].addressLowercase));
    await assertReproducesSignature(t.contentHash, V.keys[t.key].privateKey, t.signature, t.recoveredAddress);
  }
});

test("eip191: rejection vectors", () => {
  for (const t of V.eip191Rejections) {
    const expected = t.recovered === null ? undefined : t.recovered;
    assert.equal(recoverContentHashSigner(t.contentHash, t.signature), expected, t.why);
    if (expected === undefined) {
      assert.ok(!eip191.verify(t.contentHash, t.signature, V.keys.k1.addressLowercase), t.why);
    } else {
      // Flipped v recovers a different address: valid syntax, wrong signer.
      assert.ok(eip191.isSignature(t.signature));
      assert.ok(eip191.verify(t.contentHash, t.signature, expected));
      assert.ok(!eip191.verify(t.contentHash, t.signature, V.keys.k1.addressLowercase));
    }
  }
});

test("eip191: isSignature accepts exactly what the legacy isSignature65 accepts", () => {
  const r = "37ac0657cf003eeb682b39c1b6b4a7b9fbd6bb5e4fc05d3ff0f2db3958d8c3e2";
  const s = "1257f365e84a3a5218eecce74f2c933ee1bd4d68e99f8b959a4c622c01d4e7a4";
  const pad = (n) => n.toString(16).padStart(64, "0");
  const sig = (rr, ss, v) => `0x${rr}${ss}${v}`;
  assert.ok(eip191.isSignature(sig(r, s, "1b")));
  assert.ok(eip191.isSignature(sig(r, s, "1c")));
  assert.ok(eip191.isSignature(sig(pad(1n), pad(1n), "1b")));
  assert.ok(eip191.isSignature(sig(pad(SECP256K1_N - 1n), pad(SECP256K1_HALF_N), "1c")), "boundary values accepted");
  assert.ok(!eip191.isSignature(sig(pad(SECP256K1_N), pad(1n), "1b")), "r = n");
  assert.ok(!eip191.isSignature(sig(pad(0n), pad(1n), "1b")), "r = 0");
  assert.ok(!eip191.isSignature(sig(pad(1n), pad(0n), "1b")), "s = 0");
  assert.ok(!eip191.isSignature(sig(pad(1n), pad(SECP256K1_HALF_N + 1n), "1b")), "high s");
  for (const v of ["00", "01", "1a", "1d", "25", "26"]) assert.ok(!eip191.isSignature(sig(r, s, v)), `v ${v}`);
  assert.ok(!eip191.isSignature(sig(r, s, "1B")), "uppercase v");
  assert.ok(!eip191.isSignature(sig(r.toUpperCase(), s, "1b")), "uppercase hex");
  assert.ok(!eip191.isSignature(`0x${r}${s}`), "64 bytes");
  assert.ok(!eip191.isSignature(`0x${r}${s}1b00`), "66 bytes");
  assert.ok(!eip191.isSignature(`${r}${s}1b`), "missing 0x");
  assert.ok(!eip191.isSignature(42));
  assert.ok(!eip191.isSignature(undefined));
});

test("eip191: credential syntax and normalisation", () => {
  assert.ok(eip191.isCredential(V.keys.k1.addressChecksummed));
  assert.ok(eip191.isCredential(V.keys.k1.addressLowercase));
  assert.ok(eip191.isCredential(V.keys.k1.addressLowercase.toUpperCase().replace("0X", "0x")));
  assert.ok(!eip191.isCredential("0x1234"));
  assert.ok(!eip191.isCredential(V.keys.k1.addressLowercase.slice(2)));
  assert.equal(eip191.normalizeCredential(V.keys.k1.addressChecksummed), V.keys.k1.addressLowercase);
  assert.throws(() => eip191Digest(V.eip191Rejections.at(-1).contentHash), /lowercase/);
  assert.ok(!eip191.verify(V.eip191Rejections.at(-1).contentHash, V.eip191[0].signature, V.keys.k1.addressLowercase), "uppercase hash");
  assert.ok(!eip191.verify("0x1234", V.eip191[0].signature, V.keys.k1.addressLowercase));
  assert.ok(!eip191.verify(V.eip191[0].contentHash, V.eip191[0].signature, "not-an-address"));
});

test("eip191: dev keys 1001 / 1003 reproduce the fixture addresses", () => {
  for (const key of Object.values(V.keys)) {
    const scalar = BigInt(key.privateKey);
    assert.equal(addressFromPublicKey(publicKeyFromPrivateKey(scalar)), key.addressLowercase);
    const pair = keyPairFromPrivateKey("eip191-personal-sign-keccak256", "dev", key.privateKey);
    assert.equal(pair.credential, key.addressLowercase);
    assert.equal(pair.privateKey, key.privateKey);
  }
  assert.throws(() => keyPairFromPrivateKey("eip191-personal-sign-keccak256", "x", `0x${"0".repeat(64)}`));
  assert.throws(() => keyPairFromPrivateKey("eip191-personal-sign-keccak256", "x", `0x${SECP256K1_N.toString(16)}`));
  assert.throws(() => keyPairFromPrivateKey("eip191-personal-sign-keccak256", "x", "0x01"));
});

test("runtime authorization challenge vectors: hash, digest, recover, re-sign", async () => {
  for (const t of V.runtimeAuthorizationChallenge) {
    assert.equal(utf8(t.canonicalText).length, t.canonicalBytes);
    assert.equal(keccakHex(utf8(t.canonicalText)), t.challengeHash, t.label);
    if (t.storedRuntimeAuthorizationHash) assert.equal(t.challengeHash, t.storedRuntimeAuthorizationHash);
    if (t.storedRuntimeSignature) assert.equal(t.signature, t.storedRuntimeSignature);
    assert.equal(eip191Digest(t.challengeHash), t.eip191Digest);
    assert.equal(recoverContentHashSigner(t.challengeHash, t.signature), t.recoveredAddress);
    await assertReproducesSignature(t.challengeHash, t.signerKey, t.signature, t.recoveredAddress);
  }
});

test("receipt vectors: content hash, commitment preimage hash, recover, re-sign", async () => {
  for (const t of V.receipt) {
    assert.equal(utf8(t.payloadCanonicalText).length, t.payloadCanonicalBytes);
    assert.equal(keccakHex(utf8(t.payloadCanonicalText)), t.contentHash, t.label);
    assert.equal(keccakHex(utf8(t.receiptArtifactCommitmentPreimageCanonicalText)), t.receiptArtifactCommitment);
    assert.equal(
      t.receiptArtifactCommitmentPreimageCanonicalText,
      `["continuity-receipt-artifact-commitment/0.2","${t.contentHash}","${t.signature}"]`,
    );
    assert.equal(eip191Digest(t.contentHash), t.eip191Digest);
    assert.equal(recoverContentHashSigner(t.contentHash, t.signature), t.recoveredAddress);
    await assertReproducesSignature(t.contentHash, V.keys.k1001.privateKey, t.signature, t.recoveredAddress);
  }
});

test("administrative authorization vectors: effect/proof/challenge hashes, recover, re-sign", async () => {
  for (const t of V.administrativeAuthorization) {
    assert.equal(keccakHex(utf8(t.transitionEffectCanonicalText)), t.transitionEffectHash, t.label);
    assert.equal(keccakHex(utf8(t.authorityProofCanonicalText)), t.authorityProofHash);
    assert.equal(utf8(t.challengeCanonicalText).length, t.challengeCanonicalBytes);
    assert.equal(keccakHex(utf8(t.challengeCanonicalText)), t.signingHash);
    assert.equal(eip191Digest(t.signingHash), t.eip191Digest);
    assert.equal(recoverContentHashSigner(t.signingHash, t.signature), t.recoveredAddress);
    assert.equal(t.signedEvent.data.administrativeAuthorization.runtimeSignature, t.signature);
    await assertReproducesSignature(t.signingHash, t.signerKey, t.signature, t.recoveredAddress);
  }
});

test("secp256k1: differential recovery against the reference engine", { skip: reference === undefined }, async () => {
  const { recoverPortableContentHashSigner } = reference.engine;
  const cases = [...V.eip191Rejections.map((t) => [t.contentHash, t.signature])];
  for (let i = 0; i < 6; i += 1) {
    const pair = generateKeyPair("eip191-personal-sign-keccak256", `k${i}`);
    const hash = keccakHex(randomBytes(40));
    const signature = await signHashWith(pair)(hash);
    cases.push([hash, signature]);
    // Corrupt one nibble of r, s or v.
    const at = 2 + Math.floor(Math.random() * 130);
    const flipped = signature.slice(0, at) + ((Number.parseInt(signature[at], 16) + 1) % 16).toString(16) + signature.slice(at + 1);
    cases.push([hash, flipped]);
    cases.push([keccakHex(randomBytes(8)), signature]);
  }
  for (const [hash, signature] of cases) {
    assert.equal(recoverContentHashSigner(hash, signature), recoverPortableContentHashSigner(hash, signature), `${hash} ${signature}`);
  }
});

test("secp256k1: recoverAddress rejects malformed inputs", () => {
  const t = V.eip191[0];
  const digest = hexToBytes(t.eip191Digest);
  const sig = hexToBytes(t.signature);
  assert.equal(recoverAddress(digest, sig.subarray(0, 64)), undefined);
  assert.equal(recoverAddress(digest.subarray(0, 31), sig), undefined);
  const badV = Uint8Array.from(sig);
  badV[64] = 0;
  assert.equal(recoverAddress(digest, badV), undefined);
  // r not an x-coordinate on the curve (x = 5 is a non-residue case) → undefined.
  assert.equal(recoverPublicKey(digest, 5n, 1n, 0), undefined);
  assert.equal(recoverPublicKey(digest, 1n, SECP256K1_N, 0), undefined);
  assert.equal(recoverPublicKey(digest, 1n, 1n, 2), undefined);
  assert.throws(() => signDigest(digest, 0n));
  assert.throws(() => signDigest(digest.subarray(1), 1n));
});

// ---------------------------------------------------------------- key pairs and signing

test("generateKeyPair(eip191): signs, verifies through the suite, recovers to the credential", async () => {
  for (let i = 0; i < 3; i += 1) {
    const pair = generateKeyPair("eip191-personal-sign-keccak256", `gen:${i}`);
    assert.equal(pair.scheme, "eip191-personal-sign-keccak256");
    assert.equal(pair.keyId, `gen:${i}`);
    assert.match(pair.privateKey, /^0x[0-9a-f]{64}$/);
    assert.match(pair.credential, /^0x[0-9a-f]{40}$/);
    assert.ok(eip191.isCredential(pair.credential));
    assert.equal(keyPairFromPrivateKey(pair.scheme, pair.keyId, pair.privateKey).credential, pair.credential);
    const signHash = signHashWith(pair);
    const hash = keccakHex(utf8(`message ${i}`));
    const signature = await signHash(hash);
    assert.ok(eip191.isSignature(signature), "low-s, v in {1b,1c}, lowercase");
    assert.ok(eip191.verify(hash, signature, pair.credential));
    assert.equal(recoverContentHashSigner(hash, signature), pair.credential);
    assert.equal(await signHash(hash), signature, "deterministic");
    assert.ok(!eip191.verify(keccakHex(utf8("other")), signature, pair.credential));
    const other = generateKeyPair("eip191-personal-sign-keccak256", "other");
    assert.ok(!eip191.verify(hash, signature, other.credential));
    await assert.rejects(signHash("0xABCD"), /lowercase/);
  }
});

test("ed25519: sign/verify round-trips, rejects a flipped bit, wrong key, wrong hash", async () => {
  const pair = generateKeyPair("ed25519", "owner");
  assert.equal(pair.scheme, "ed25519");
  assert.match(pair.privateKey, /^0x[0-9a-f]{64}$/);
  assert.match(pair.credential, /^0x[0-9a-f]{64}$/);
  assert.ok(ed25519.isCredential(pair.credential));
  assert.equal(ed25519.normalizeCredential(pair.credential.toUpperCase().replace("0X", "0x")), pair.credential);
  assert.deepEqual(keyPairFromPrivateKey("ed25519", "owner", pair.privateKey), pair, "public key derives from the seed");

  const hash = keccakHex(utf8("control event"));
  const signature = await signHashWith(pair)(hash);
  assert.match(signature, /^0x[0-9a-f]{128}$/);
  assert.ok(ed25519.isSignature(signature));
  assert.ok(!ed25519.isSignature(signature.toUpperCase().replace("0X", "0x")));
  assert.ok(!ed25519.isSignature(`${signature}00`));
  assert.ok(ed25519.verify(hash, signature, pair.credential));
  assert.ok(ed25519.verify(hash, signature, pair.credential.toUpperCase().replace("0X", "0x")), "credential case-insensitive");
  assert.equal(await signHashWith(pair)(hash), signature, "Ed25519 is deterministic");

  const bytes = hexToBytes(signature);
  bytes[7] ^= 0x01;
  assert.ok(!ed25519.verify(hash, hex(bytes), pair.credential), "flipped bit");
  assert.ok(!ed25519.verify(keccakHex(utf8("something else")), signature, pair.credential), "other hash");
  assert.ok(!ed25519.verify(hash, signature, generateKeyPair("ed25519", "x").credential), "other key");
  assert.ok(!ed25519.verify(hash, signature, `0x${"ff".repeat(32)}`), "credential that is not a valid point");
  assert.ok(!ed25519.verify(hash.toUpperCase().replace("0X", "0x"), signature, pair.credential), "uppercase hash");
  assert.ok(!ed25519.verify(hash, V.eip191[0].signature, pair.credential), "65-byte signature");
  assert.ok(!ed25519.isCredential(V.keys.k1.addressLowercase));
});

test("ed25519: the public-key cache is transparent (hits, eviction past 4,096 keys, invalid credentials)", async () => {
  const hash = keccakHex(utf8("cached"));
  const pairs = [];
  for (let i = 0; i < 4200; i += 1) pairs.push(generateKeyPair("ed25519", `c:${i}`));
  const signatures = await Promise.all(pairs.map((p) => signHashWith(p)(hash)));
  const invalid = `0x${"ff".repeat(32)}`;
  assert.ok(!ed25519.verify(hash, signatures[0], invalid));
  assert.ok(!ed25519.verify(hash, signatures[0], invalid), "cached invalid credential stays false");
  for (let i = 0; i < pairs.length; i += 1) {
    assert.ok(ed25519.verify(hash, signatures[i], pairs[i].credential), `key ${i}`);
    assert.ok(ed25519.verify(hash, signatures[i], pairs[i].credential), "second verify hits the cache");
  }
  // The first keys were evicted by now; verifying them again re-imports and still works.
  for (let i = 0; i < 20; i += 1) {
    assert.ok(ed25519.verify(hash, signatures[i], pairs[i].credential));
    assert.ok(!ed25519.verify(hash, signatures[i + 1], pairs[i].credential), "cached key still rejects a foreign signature");
  }
});

test("suiteFor / key helpers reject unknown schemes and bad keys", () => {
  assert.throws(() => suiteFor("rsa"), { code: "UNSUPPORTED_VERSION" });
  assert.throws(() => generateKeyPair("rsa", "k"), { code: "UNSUPPORTED_VERSION" });
  assert.throws(() => keyPairFromPrivateKey("ed25519", "k", "0x00"), { code: "INVALID_INPUT" });
  assert.throws(() => signHashWith({ keyId: "k", scheme: "rsa", credential: "", privateKey: `0x${"11".repeat(32)}` }), { code: "UNSUPPORTED_VERSION" });
  assert.ok(isContentHash(V.eip191[0].contentHash));
  assert.ok(!isContentHash(V.eip191[0].contentHash.toUpperCase()));
});

test("timings (diagnostic): keccak256 of 1 KiB and one recovery", (t) => {
  const kib = new Uint8Array(1024);
  for (let i = 0; i < kib.length; i += 1) kib[i] = i & 0xff;
  for (let i = 0; i < 500; i += 1) keccak256(kib);
  let start = process.hrtime.bigint();
  for (let i = 0; i < 2000; i += 1) keccak256(kib);
  const keccakMicros = Number(process.hrtime.bigint() - start) / 2000 / 1000;

  const v = V.eip191[0];
  const digest = hexToBytes(v.eip191Digest);
  const signature = hexToBytes(v.signature);
  for (let i = 0; i < 20; i += 1) recoverAddress(digest, signature);
  start = process.hrtime.bigint();
  for (let i = 0; i < 100; i += 1) recoverAddress(digest, signature);
  const recoverMicros = Number(process.hrtime.bigint() - start) / 100 / 1000;

  const scalar = BigInt(V.keys.k1001.privateKey);
  start = process.hrtime.bigint();
  for (let i = 0; i < 50; i += 1) encodeCompactSignature(signDigest(digest, scalar));
  const signMicros = Number(process.hrtime.bigint() - start) / 50 / 1000;

  t.diagnostic(`keccak256(1 KiB): ${keccakMicros.toFixed(1)} µs; secp256k1 recover: ${recoverMicros.toFixed(0)} µs; sign: ${signMicros.toFixed(0)} µs`);
  assert.ok(keccakMicros < 2000 && recoverMicros < 50_000);
});

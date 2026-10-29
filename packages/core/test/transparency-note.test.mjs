// C2SP signed notes and checkpoints (WITNESS-DESIGN §2.5).
//
// PUBLISHED vectors:
//   * golang.org/x/mod/sumdb/note note_test.go (github.com/golang/mod, branch master, fetched 2026-09-25):
//     the PeterNeumann signer/verifier keys, TestSign's expected note, TestOpen's Peter and Enoch
//     signatures, the EnochRoot verifier key, and the TestNewVerifier / TestNewSigner / TestOpen
//     rejection cases.
//   * c2sp.org/signed-note (C2SP/C2SP signed-note.md, main): the example.com/foo verifier key and
//     signed note, and the quasimodo.example note (its key is not published: used as an unknown-key note).
//   * c2sp.org/tlog-checkpoint (C2SP/C2SP tlog-checkpoint.md, main): the example.com/behind-the-sofa checkpoint.
// Copyright and licences: golang/mod, Copyright 2019 The Go Authors, BSD-style licence; C2SP specifications, CC BY 4.0
// (see THIRD-PARTY-NOTICES.md). Everything else is generated at run time.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

const note = await import("../src/transparency/note.ts");
const { NoteError, noteKeyHash, verifierKey, parseVerifierKey, noteSignerFromSeed, noteSignerFromKeyObject, parseSignerKey, formatSignerKey, generateNoteKey,
  signNote, openNote, formatCheckpoint, parseCheckpoint, isValidNoteKeyName } = note;

const PETER_SKEY = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz";
const PETER_VKEY = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW";
const ENOCH_VKEY = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop";
const TEXT = "If you think cryptography is the answer to your problem,\nthen you don't know what your problem is.\n";
const PETER_SIG = "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n";
const ENOCH_SIG = "— EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n";

const codeOf = (fn) => {
  try {
    fn();
  } catch (error) {
    assert.ok(error instanceof NoteError, `expected NoteError, got ${error}`);
    return error.code;
  }
  return "NO_ERROR";
};
/** Go indexes strings by byte; splice at a UTF-8 byte offset. */
const spliceBytes = (text, at, insert) => { const b = Buffer.from(text, "utf8"); return Buffer.concat([b.subarray(0, at), Buffer.from(insert), b.subarray(at)]).toString("utf8"); };
/** Go's `b[i]++` on a byte string, then back to a JS string (may produce invalid UTF-8 → U+FFFD, which Go also rejects). */
const bumpByte = (text, i) => { const b = Buffer.from(text, "utf8"); b[i] = (b[i] + 1) & 0xff; return b.toString("utf8"); };

// ---------------------------------------------------------------- golang.org/x/mod/sumdb/note vectors

test("TestSign: the PeterNeumann key signs the published note byte for byte", () => {
  const signer = parseSignerKey(PETER_SKEY);
  assert.equal(signer.name, "PeterNeumann");
  assert.equal(Buffer.from(signer.keyHash).toString("hex"), "c74f20a3");
  assert.equal(verifierKey(signer.name, signer.publicKey), PETER_VKEY);
  assert.equal(signNote(TEXT, signer), `${TEXT}\n${PETER_SIG}`);
  assert.equal(codeOf(() => signNote("abc", signer)), "MALFORMED_NOTE");
  assert.equal(codeOf(() => signNote(TEXT, { ...signer, name: "bad name" })), "INVALID_SIGNER");
  assert.equal(codeOf(() => signNote(TEXT, { ...signer, sign: () => new Uint8Array(63) })), "INVALID_SIGNER");
});

test("TestNewVerifier: the verifier key parses; every substring and every single-byte bump is rejected", () => {
  const parsed = parseVerifierKey(PETER_VKEY);
  assert.equal(parsed.name, "PeterNeumann");
  assert.equal(Buffer.from(parsed.keyHash).toString("hex"), "c74f20a3");
  assert.deepEqual(parsed.publicKey, parseSignerKey(PETER_SKEY).publicKey);
  const b = Buffer.from(PETER_VKEY);
  for (let i = 0; i <= b.length; i += 1) {
    for (let j = i + 1; j <= b.length; j += 1) {
      if (i === 0 && j === b.length) continue;
      assert.equal(codeOf(() => parseVerifierKey(b.subarray(i, j).toString())), "INVALID_KEY", `substring ${i}..${j}`);
    }
  }
  for (let i = 0; i < b.length; i += 1) assert.equal(codeOf(() => parseVerifierKey(bumpByte(PETER_VKEY, i))), "INVALID_KEY", `bump ${i}`);
  // Wrong-length key and unknown algorithm, each with an adjusted (correct) key hash.
  assert.equal(codeOf(() => parseVerifierKey("PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==")), "INVALID_KEY");
  assert.equal(codeOf(() => parseVerifierKey("PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW")), "INVALID_KEY");
});

test("TestNewSigner: the signer key parses; every substring and every single-byte bump is rejected", () => {
  const b = Buffer.from(PETER_SKEY);
  for (let i = 0; i <= b.length; i += 1) {
    for (let j = i + 1; j <= b.length; j += 1) {
      if (i === 0 && j === b.length) continue;
      assert.equal(codeOf(() => parseSignerKey(b.subarray(i, j).toString())), "INVALID_SIGNER", `substring ${i}..${j}`);
    }
  }
  for (let i = 0; i < b.length; i += 1) assert.equal(codeOf(() => parseSignerKey(bumpByte(PETER_SKEY, i))), "INVALID_SIGNER", `bump ${i}`);
});

test("TestOpen: verified, ignored-unknown, unverified, invalid and malformed notes", () => {
  const both = `${TEXT}\n${PETER_SIG}${ENOCH_SIG}`;
  // One verified, one (unknown key) ignored.
  assert.deepEqual(openNote(both, [PETER_VKEY]), { body: TEXT, verifiedBy: [PETER_VKEY] });
  // Both verified, in note order.
  assert.deepEqual(openNote(both, [ENOCH_VKEY, PETER_VKEY]).verifiedBy, [PETER_VKEY, ENOCH_VKEY]);
  // None known.
  assert.equal(codeOf(() => openNote(both, [])), "UNVERIFIED_NOTE");
  // A verifier listed twice is one verifier (upstream's VerifierList(enoch, peter, enoch) reports
  // "ambiguous key" for the same *object* twice; identical key strings here are deduplicated).
  assert.deepEqual(openNote(`${TEXT}\n${ENOCH_SIG}`, [ENOCH_VKEY, PETER_VKEY, ENOCH_VKEY]).verifiedBy, [ENOCH_VKEY]);
  assert.deepEqual(openNote(`${TEXT}\n${ENOCH_SIG}`, [ENOCH_VKEY, ENOCH_VKEY.replace("af0cfe78", "AF0CFE78")]).verifiedBy, [ENOCH_VKEY]);
  // Too many signatures (101), known or not.
  assert.equal(codeOf(() => openNote(`${TEXT}\n${PETER_SIG.repeat(101)}`, [PETER_VKEY])), "MALFORMED_NOTE");
  assert.equal(codeOf(() => openNote(`${TEXT}\n${PETER_SIG.repeat(101)}`, [])), "MALFORMED_NOTE");
  assert.deepEqual(openNote(`${TEXT}\n${PETER_SIG.repeat(100)}`, [PETER_VKEY]).verifiedBy, [PETER_VKEY]);
  // A known key with a bad signature rejects the whole note ("ABCD" spliced into the base64 at byte 60).
  const badPeter = spliceBytes(PETER_SIG, 60, "ABCD");
  assert.equal(codeOf(() => openNote(`${TEXT}\n${badPeter}`, [PETER_VKEY])), "INVALID_SIGNATURE");
  // Duplicated verified and unverified signatures.
  const badEnoch = spliceBytes(ENOCH_SIG, 60, "ABCD");
  assert.deepEqual(openNote(`${TEXT}\n${PETER_SIG}${PETER_SIG}${ENOCH_SIG}${ENOCH_SIG}${badEnoch}`, [PETER_VKEY]).verifiedBy, [PETER_VKEY]);
  // Invalid encoded message syntax.
  const badMessages = [
    TEXT,
    `${TEXT}\n`,
    `${TEXT}\n${PETER_SIG.slice(0, -1)}`,
    `\x01${TEXT}\n${PETER_SIG}`,
    Buffer.concat([Buffer.from([0xff]), Buffer.from(`${TEXT}\n${PETER_SIG}`)]).toString("utf8"), // invalid UTF-8 decodes to U+FFFD: the signature no longer verifies
    `${TEXT}\n— Bad Name x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=`,
    `${TEXT}\n${PETER_SIG}Unexpected line.\n`,
  ];
  for (const [i, message] of badMessages.entries()) {
    const code = codeOf(() => openNote(message, [PETER_VKEY]));
    assert.ok(i === 4 ? code === "INVALID_SIGNATURE" : code === "MALFORMED_NOTE", `bad message ${i}: ${code}`);
  }
  // Lone surrogates are not UTF-8 at all.
  assert.equal(codeOf(() => openNote(`\ud800${TEXT}\n${PETER_SIG}`, [PETER_VKEY])), "MALFORMED_NOTE");
  // Signature line naming Peter with another key's hash is simply unknown.
  assert.equal(codeOf(() => openNote(`${TEXT}\n${PETER_SIG.replace("x08g", "xxxx")}`, [PETER_VKEY])), "UNVERIFIED_NOTE");
  assert.equal(codeOf(() => openNote(`${TEXT}\n${PETER_SIG.replaceAll("PeterNeumann", "CarmenSandiego")}`, [PETER_VKEY])), "UNVERIFIED_NOTE");
  // Malformed trusted keys are a configuration error.
  assert.equal(codeOf(() => openNote(`${TEXT}\n${PETER_SIG}`, ["not a key"])), "INVALID_KEY");
});

// ---------------------------------------------------------------- C2SP examples

test("c2sp.org/signed-note example verifies; the quasimodo note parses as unverified", () => {
  const vkey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
  const signed = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";
  assert.deepEqual(openNote(signed, [vkey]), { body: "This is an example message.\n", verifiedBy: [vkey] });
  const parsed = parseVerifierKey(vkey);
  assert.equal(verifierKey(parsed.name, parsed.publicKey), vkey);
  const quasimodo = "Ognuno sta solo sul cuor della terra\ntrafitto da un raggio di sole:\n\ned è subito sera.\n\n— quasimodo.example/salvatore NnugSzTjtVAewIS+Z/iJhUPeFDkO/5QQ2i5ddnGITLlC+EhfLW9oJKONrMouFSQU0xMcXxj99ihAQwaqP3ZekRwNtIc=\n";
  assert.equal(codeOf(() => openNote(quasimodo, [vkey, PETER_VKEY])), "UNVERIFIED_NOTE");
  // The body keeps its own blank line: the split is at the last blank line.
  const own = noteSignerFromSeed("quasimodo.example/test", new Uint8Array(32).fill(3));
  const body = "Ognuno sta solo sul cuor della terra\ntrafitto da un raggio di sole:\n\ned è subito sera.\n";
  assert.equal(openNote(signNote(body, own), [verifierKey(own.name, own.publicKey)]).body, body);
});

test("c2sp.org/tlog-checkpoint example parses strictly", () => {
  const body = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";
  const checkpoint = parseCheckpoint(body);
  assert.equal(checkpoint.origin, "example.com/behind-the-sofa");
  assert.equal(checkpoint.size, 20852163);
  assert.equal(Buffer.from(checkpoint.root).toString("base64"), "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=");
  assert.deepEqual(checkpoint.extensions, []);
  assert.equal(formatCheckpoint(checkpoint.origin, checkpoint.size, checkpoint.root), body);
});

// ---------------------------------------------------------------- keys and names

test("key names follow Go isValidName (Unicode spaces per unicode.IsSpace, no plus)", () => {
  for (const good of ["a", "example.com/log", "irontrellis-witness/w1", "\u00e9", "a\ufeffb", "a\u200bb"]) assert.equal(isValidNoteKeyName(good), true, JSON.stringify(good));
  for (const bad of ["", "a b", "a+b", "a\tb", "a\nb", "a\u0085b", "a\u00a0b", "a\u1680b", "a\u2000b", "a\u200ab", "a\u2028b", "a\u2029b", "a\u202fb", "a\u205fb", "a\u3000b", "\ud800", 5, null]) {
    assert.equal(isValidNoteKeyName(bad), false, JSON.stringify(bad));
  }
  const key = new Uint8Array(32).fill(9);
  assert.equal(codeOf(() => verifierKey("a b", key)), "INVALID_KEY");
  assert.equal(codeOf(() => verifierKey("ok", new Uint8Array(31))), "INVALID_KEY");
  assert.equal(codeOf(() => noteKeyHash("a+b", key)), "INVALID_KEY");
  assert.equal(codeOf(() => noteSignerFromSeed("a b", key)), "INVALID_SIGNER");
  assert.equal(codeOf(() => noteSignerFromSeed("ok", new Uint8Array(31))), "INVALID_SIGNER");
});

test("seed, KeyObject, signer-key and generated signers agree", () => {
  const seed = new Uint8Array(32).map((_, i) => i * 7);
  const fromSeed = noteSignerFromSeed("irontrellis-witness/test", seed);
  const skey = formatSignerKey("irontrellis-witness/test", seed);
  assert.match(skey, /^PRIVATE\+KEY\+irontrellis-witness\/test\+[0-9a-f]{8}\+A/);
  const parsed = parseSignerKey(skey);
  assert.deepEqual(parsed.publicKey, fromSeed.publicKey);
  assert.deepEqual(parsed.keyHash, noteKeyHash(fromSeed.name, fromSeed.publicKey));
  assert.equal(signNote("x\n", parsed), signNote("x\n", fromSeed), "Ed25519 is deterministic");
  const { privateKey } = generateKeyPairSync("ed25519");
  const fromObject = noteSignerFromKeyObject("obj", privateKey);
  assert.deepEqual(openNote(signNote("y\n", fromObject), [verifierKey("obj", fromObject.publicKey)]).body, "y\n");
  assert.equal(codeOf(() => noteSignerFromKeyObject("obj", generateKeyPairSync("ed448").privateKey)), "INVALID_SIGNER");
  const generated = generateNoteKey("fresh");
  const signer = parseSignerKey(generated.signerKey);
  assert.equal(verifierKey("fresh", signer.publicKey), generated.verifierKey);
  assert.deepEqual(openNote(signNote("z\n", signer), [generated.verifierKey]).verifiedBy, [generated.verifierKey]);
  assert.equal(codeOf(() => openNote(signNote("z\n", signer), [PETER_VKEY])), "UNVERIFIED_NOTE");
});

// ---------------------------------------------------------------- notes and checkpoints

test("signNote/openNote round trip and tamper rejection", () => {
  const signer = noteSignerFromSeed("w", new Uint8Array(32).fill(1));
  const vkey = verifierKey("w", signer.publicKey);
  const body = formatCheckpoint("irontrellis-witness/w", 5, new Uint8Array(32).fill(0xab), ["ext one"]);
  const signed = signNote(body, signer);
  assert.ok(signed.endsWith("\n"));
  assert.deepEqual(openNote(signed, [vkey]), { body, verifiedBy: [vkey] });
  assert.equal(codeOf(() => openNote(signed.replace("\n5\n", "\n6\n"), [vkey])), "INVALID_SIGNATURE");
  assert.equal(codeOf(() => openNote(signed.replace("— w ", "— w  "), [vkey])), "MALFORMED_NOTE");
  assert.equal(codeOf(() => openNote(signed.replace("— w ", "- w "), [vkey])), "MALFORMED_NOTE");
  const lastPad = signed.lastIndexOf("=\n");
  assert.equal(codeOf(() => openNote(`${signed.slice(0, lastPad)}\n`, [vkey])), "MALFORMED_NOTE", "unpadded base64");
  assert.equal(codeOf(() => openNote(signed.slice(0, -1), [vkey])), "MALFORMED_NOTE");
  assert.equal(codeOf(() => openNote(`${signed}\n`, [vkey])), "MALFORMED_NOTE");
  assert.equal(codeOf(() => openNote(signed.replace("ext one", "ext\tone"), [vkey])), "MALFORMED_NOTE");
  assert.equal(codeOf(() => openNote(42, [vkey])), "MALFORMED_NOTE");
  assert.equal(codeOf(() => signNote("no newline", signer)), "MALFORMED_NOTE");
  assert.equal(codeOf(() => signNote("tab\there\n", signer)), "MALFORMED_NOTE");
  assert.equal(codeOf(() => signNote("\ud800\n", signer)), "MALFORMED_NOTE");
  // A signature line whose payload is shorter than 5 bytes is malformed, whoever signed.
  assert.equal(codeOf(() => openNote(`${body}\n— w AAAAAA==\n`, [vkey])), "MALFORMED_NOTE");
  // A known key hash with a truncated signature is an invalid signature.
  const truncated = `${body}\n— w ${Buffer.concat([Buffer.from(noteKeyHash("w", signer.publicKey)), Buffer.alloc(10)]).toString("base64")}\n`;
  assert.equal(codeOf(() => openNote(truncated, [vkey])), "INVALID_SIGNATURE");
});

test("checkpoint format and strict parse", () => {
  const root = new Uint8Array(32).fill(7);
  const body = formatCheckpoint("o", 0, root);
  assert.equal(body, `o\n0\n${Buffer.from(root).toString("base64")}\n`);
  assert.deepEqual(parseCheckpoint(body), { origin: "o", size: 0, root, extensions: [] });
  const withExt = formatCheckpoint("o", 12, root, ["a", "b c"]);
  assert.deepEqual(parseCheckpoint(withExt).extensions, ["a", "b c"]);
  assert.equal(parseCheckpoint(formatCheckpoint("o", Number.MAX_SAFE_INTEGER, root)).size, Number.MAX_SAFE_INTEGER);
  const b64 = Buffer.from(root).toString("base64");
  const bad = [
    `o\n01\n${b64}\n`, `o\n-1\n${b64}\n`, `o\n+1\n${b64}\n`, `o\n 1\n${b64}\n`, `o\n1.0\n${b64}\n`, `o\n\n${b64}\n`, `o\n9007199254740992\n${b64}\n`,
    `o\n1\n${Buffer.alloc(31).toString("base64")}\n`, `o\n1\n${b64.replace("=", "")}\n`, `o\n1\n${b64.slice(0, -2)}d=\n`, `o\n1\n${b64}`, `o\n1\n`, `\n1\n${b64}\n`,
    `o\n1\n${b64}\n\n`, `o\n1\n${b64}\next\n\n`, `o\x01\n1\n${b64}\n`,
  ];
  for (const text of bad) assert.equal(codeOf(() => parseCheckpoint(text)), "MALFORMED_CHECKPOINT", JSON.stringify(text));
  assert.equal(codeOf(() => formatCheckpoint("", 1, root)), "MALFORMED_CHECKPOINT");
  assert.equal(codeOf(() => formatCheckpoint("a\nb", 1, root)), "MALFORMED_CHECKPOINT");
  assert.equal(codeOf(() => formatCheckpoint("o", -1, root)), "MALFORMED_CHECKPOINT");
  assert.equal(codeOf(() => formatCheckpoint("o", 1.5, root)), "MALFORMED_CHECKPOINT");
  assert.equal(codeOf(() => formatCheckpoint("o", 1, new Uint8Array(31))), "MALFORMED_CHECKPOINT");
  assert.equal(codeOf(() => formatCheckpoint("o", 1, root, [""])), "MALFORMED_CHECKPOINT");
});

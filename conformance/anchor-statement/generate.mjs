#!/usr/bin/env node
/**
 * conformance/anchor-statement — the builder's A-144 `irontrellis-anchor-statement/1` vector (G6.6, R8-01).
 *
 * One statement over a real pinned format-2 history (conformance/v2-regenerated `rotation-v2`, head position 6),
 * bound to the suite's positive `/2` head attestation of that head. Every binding is re-derived here from the engine
 * (packages/core/dist): genesis domain as written, historyId = recordHash(0), genesisEventHash = eventHash(e0),
 * head / stateRoot / projectionHead from replay, attestationDigest = hashCanonical(attestation as written).
 *
 * Canonical rule (A-144.1): canonical text per SPEC §3.1, digest = hashCanonical(statement) per §3.2
 * ("0x" + hex(sha256(utf8(canonical(v))))), every optional field written as explicit null.
 *
 * Two derivations must agree or the generator exits 1:
 *   (1) the engine: canonicalEncode + hashCanonical(statement, "sha256");
 *   (2) independent: a 20-line sorted-key serializer below, and plain node:crypto sha256 over the literal bytes
 *       (hex in vector.json decoded back to bytes).
 *
 *   node conformance/anchor-statement/generate.mjs           # write vector.json
 *   node conformance/anchor-statement/generate.mjs --check   # exit 1 when a fresh generation differs from vector.json
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const core = await import(join(ROOT, "packages/core/dist/index.js"));
const CHECK = process.argv.includes("--check");
const fail = (message) => { console.error(`anchor-statement: ${message}`); process.exit(1); };
const assert = (cond, message) => { if (!cond) fail(message); };

// ------------------------------------------------------------------ source history and attestation (engine-derived)
const HISTORY_REF = "conformance/v2-regenerated/histories/rotation-v2.json";
const ATTESTATION_VECTOR = "attestation/v2r/post-rotation-head-by-new-key-verifies";
const events = JSON.parse(readFileSync(join(ROOT, HISTORY_REF), "utf8"));
const result = core.replay(events);
assert(result.status === "ACCEPTED", `source history rejected: ${result.code}`);
const vectors = JSON.parse(readFileSync(join(ROOT, "conformance/v2-regenerated/vectors.json"), "utf8"));
const attVector = vectors.find((v) => v.id === ATTESTATION_VECTOR);
assert(attVector && attVector.expect.valid === true, `${ATTESTATION_VECTOR} missing or not a positive vector`);
const attestation = attVector.input.attestation;
const facts = core.verifyHeadAttestationFacts(attestation, result.state);
assert(facts.valid && facts.signatureValid && facts.prefix && facts.stateRootValid && facts.projectionValid,
  `attestation does not verify at the head: ${JSON.stringify(facts)}`);
const head = { hash: result.head.hash, position: result.head.position, canonicalTime: result.head.canonicalTime };
for (const k of ["hash", "position", "canonicalTime"]) assert(attestation.head[k] === head[k], `attestation head.${k} is not the replayed head`);

// Cross-check against the G2.5 independently re-derived pins when the build tree carries them (outside the repo).
// Finding (c): without that file the same pin is read from the tracked suite manifest (conformance/v2-regenerated/MANIFEST.json
// records each history's head, stateRoot and projectionHead, which scripts/pin-roots.mjs pins as v2-regenerated.<name>@<head>),
// so `--check` reproduces the committed bytes, note included, on any host.
const PINS = join(ROOT, "..", "RESULTS", "PINNED-ROOTS.json");
const V2R_MANIFEST = join(ROOT, "conformance", "v2-regenerated", "MANIFEST.json");
let pinNote = "RESULTS/PINNED-ROOTS.json not present; pin cross-check skipped";
const pin = existsSync(PINS)
  ? JSON.parse(readFileSync(PINS, "utf8")).pins.find((p) => p.history === "v2-regenerated.rotation-v2" && p.position === head.position)
  : (() => { const h = JSON.parse(readFileSync(V2R_MANIFEST, "utf8")).histories?.["rotation-v2"]; return h?.head?.position === head.position ? h : undefined; })();
if (existsSync(PINS) || existsSync(V2R_MANIFEST)) {
  assert(pin, "no G2.5 pin for v2-regenerated.rotation-v2 at the head position");
  assert(pin.head.hash === head.hash && pin.head.canonicalTime === head.canonicalTime, "replayed head differs from the G2.5 pin");
  assert(pin.stateRoot === result.stateRoot && pin.projectionHead === result.projectionHead, "replayed roots differ from the G2.5 pin");
  pinNote = "head, stateRoot and projectionHead equal RESULTS/PINNED-ROOTS.json pin v2-regenerated.rotation-v2@6";
}

// ------------------------------------------------------------------ fixed external (non-Core) values, illustrative
// The profile-manifest schema, the destination contract and the availability vocabulary are NOT frozen (A-144.4);
// these values are realistic placeholders so the vector exercises every field. Chain id: Etherlink mainnet (A-150.0).
const PROFILE_MANIFEST = {
  version: "irontrellis-anchor-profile-manifest/0-illustrative",
  connector: "etherlink",
  chainId: "eip155:42793",
  finality: { barrier: "L1_FINAL", mode: "CONSENSUS_VERIFIED" },
  testnet: false,
};
const statement = {
  version: "irontrellis-anchor-statement/1",
  domain: events[0].data.domain,
  historyId: core.historyIdOfGenesis(events[0]),
  genesisEventHash: core.eventHash(events[0]),
  profile: { id: "etherlink-mainnet-consensus-verified", manifestHash: core.hashCanonical(PROFILE_MANIFEST, "sha256") },
  head,
  stateRoot: result.stateRoot,
  projectionHead: result.projectionHead,
  attestationDigest: core.hashCanonical(attestation, "sha256"),
  sequence: 0,
  predecessor: null,
  previousHead: null,
  chain: { id: "eip155:42793", destination: "0x00000000000000000000000000000000000a0144" },
  evidence: { manifestDigest: null, certificateDigest: null, checkpointEventId: null },
  availability: "ANCHOR_ONLY",
};

// ------------------------------------------------------------------ closed-schema check (A-144.2, scalars per §3.3)
const HASH = /^0x[0-9a-f]{64}$/;
const isHash = (v) => typeof v === "string" && HASH.test(v);
const isU53 = (v) => Number.isSafeInteger(v) && v >= 0;
const utf8len = (s) => Buffer.byteLength(s, "utf8");
const isIdentifier = (v) => typeof v === "string" && utf8len(v) >= 1 && utf8len(v) <= 256 && !/[\u0000-\u001f\u007f]/.test(v) && v.isWellFormed();
const isProtocolString = (v) => typeof v === "string" && utf8len(v) <= 4096 && v.isWellFormed();
const keys = (o, list) => o !== null && typeof o === "object" && !Array.isArray(o) && JSON.stringify(Object.keys(o).sort()) === JSON.stringify([...list].sort());
const s = statement;
assert(keys(s, ["version", "domain", "historyId", "genesisEventHash", "profile", "head", "stateRoot", "projectionHead", "attestationDigest", "sequence", "predecessor", "previousHead", "chain", "evidence", "availability"]), "statement keys");
assert(s.version === "irontrellis-anchor-statement/1", "version");
assert(keys(s.domain, ["protocol", "version", "deploymentId"]) && s.domain.protocol === "irontrellis" && s.domain.version === "2" && isIdentifier(s.domain.deploymentId), "domain");
assert(isHash(s.historyId) && isHash(s.genesisEventHash) && isHash(s.stateRoot) && isHash(s.attestationDigest), "hashes");
assert(keys(s.profile, ["id", "manifestHash"]) && isIdentifier(s.profile.id) && isHash(s.profile.manifestHash), "profile");
assert(keys(s.head, ["hash", "position", "canonicalTime"]) && isHash(s.head.hash) && isU53(s.head.position) && isU53(s.head.canonicalTime), "head");
assert(s.projectionHead === null || isHash(s.projectionHead), "projectionHead");
assert(isU53(s.sequence), "sequence");
assert((s.sequence === 0) === (s.predecessor === null) && (s.sequence === 0) === (s.previousHead === null), "predecessor/previousHead null iff sequence = 0");
assert(keys(s.chain, ["id", "destination"]) && isProtocolString(s.chain.id) && isProtocolString(s.chain.destination), "chain");
assert(keys(s.evidence, ["manifestDigest", "certificateDigest", "checkpointEventId"]), "evidence keys (explicit nulls)");
assert(isIdentifier(s.availability), "availability");

// ------------------------------------------------------------------ derivation 1: the engine
const engineText = core.canonicalEncode(statement);
const engineDigest = core.hashCanonical(statement, "sha256");

// ------------------------------------------------------------------ derivation 2: independent
// Records with keys sorted by UTF-8 byte order, JSON.stringify string escaping, safe integers, true/false/null (§3.1).
const utf8Compare = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
function independentCanonical(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("non-integer"); return String(v); }
  if (Array.isArray(v)) return `[${v.map(independentCanonical).join(",")}]`;
  if (typeof v === "object") return `{${Object.keys(v).sort(utf8Compare).map((k) => `${JSON.stringify(k)}:${independentCanonical(v[k])}`).join(",")}}`;
  throw new Error(`unencodable ${typeof v}`);
}
const independentText = independentCanonical(statement);
assert(independentText === engineText, "independent canonical text differs from the engine's canonicalEncode");
const bytes = Buffer.from(engineText, "utf8");
const hex = bytes.toString("hex");
const literalDigest = `0x${createHash("sha256").update(Buffer.from(hex, "hex")).digest("hex")}`;
assert(literalDigest === engineDigest, `digest disagreement: engine ${engineDigest}, node:crypto ${literalDigest}`);

const vector = {
  version: "irontrellis-anchor-statement-vector/1",
  id: "anchor-statement/v1/etherlink-mainnet-sequence-0",
  rule: "A-144.1: canonical text per SPEC §3.1; digest = hashCanonical(statement) = \"0x\" + hex(sha256(utf8(canonical)))(§3.2); every optional field explicit null",
  source: {
    history: HISTORY_REF,
    headPosition: head.position,
    attestationVector: `conformance/v2-regenerated/vectors.json#${ATTESTATION_VECTOR}`,
    attestation,
    pinCrossCheck: pinNote,
    illustrative: {
      note: "Not frozen by A-144 (A-144.4): profile-manifest schema, destination contract, availability vocabulary. The values below are placeholders; the statement bytes and digest rule are what this vector fixes.",
      profileManifest: PROFILE_MANIFEST,
      profileManifestHash: "hashCanonical(profileManifest)",
      chain: "Etherlink mainnet, EIP-155 chain id 42793 (A-150.0); the destination is a placeholder address, no contract bytes are frozen",
    },
  },
  statement,
  canonical: { utf8: engineText, hex, byteLength: bytes.length },
  digest: { algorithm: "sha256", value: engineDigest },
  derivations: {
    engine: "packages/core canonicalEncode + hashCanonical(statement, \"sha256\")",
    independent: "generate.mjs independentCanonical (sorted-key serializer) + node:crypto sha256 over the hex-decoded literal bytes",
    agree: true,
  },
};
const out = `${JSON.stringify(vector, null, 1)}\n`;
const target = join(HERE, "vector.json");

if (CHECK) {
  assert(existsSync(target), "vector.json missing");
  const onDisk = readFileSync(target, "utf8");
  // The committed file is checked by its own bytes too: its literal hex must hash to its digest with node:crypto alone.
  const parsed = JSON.parse(onDisk);
  const diskDigest = `0x${createHash("sha256").update(Buffer.from(parsed.canonical.hex, "hex")).digest("hex")}`;
  assert(diskDigest === parsed.digest.value, "vector.json: literal bytes do not hash to the recorded digest");
  assert(Buffer.from(parsed.canonical.hex, "hex").toString("utf8") === parsed.canonical.utf8, "vector.json: hex and utf8 disagree");
  assert(core.canonicalEncode(parsed.statement) === parsed.canonical.utf8, "vector.json: statement does not re-encode to the recorded bytes");
  assert(onDisk === out, "vector.json differs from a fresh generation");
  console.log(`anchor-statement: OK ${engineDigest} (${bytes.length} bytes; engine and independent derivations agree)`);
} else {
  writeFileSync(target, out);
  console.log(`anchor-statement: wrote vector.json ${engineDigest} (${bytes.length} bytes)`);
}

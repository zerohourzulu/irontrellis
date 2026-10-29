// The history side of a run: canonical bodies and their §4.3 chain, replayed heads and roots, and `/2` head attestations
// signed with the published test seeds of conformance/v2-regenerated (MANIFEST.json `keys`; conformance/v2/TEST-KEYS.md).
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";

const ROOT = new URL("../../../", import.meta.url);
export const core = await import(new URL("packages/core/dist/index.js", ROOT).href);
export const gateway = await import(new URL("packages/mcp-gateway/dist/index.js", ROOT).href);
const signerModule = await import(new URL("packages/core/dist/signer.js", ROOT).href); // signerFromKeyPair, as conformance/v2-regenerated/generate.mjs

export const sha256 = bytes => "0x" + createHash("sha256").update(bytes).digest("hex");
export const canonical = value => Buffer.from(core.canonicalEncode(value));
export const CHUNK_BYTES = 16384;

/** Core §4.3: sha256("irontrellis-record/2" ‖ 0x00 ‖ prev ‖ eventHash ‖ be64(position)), prev = 32 zero bytes at position 0. */
export function recordHashOf(previous, eventHash, position) {
  const be = Buffer.alloc(8); be.writeBigUInt64BE(BigInt(position));
  return sha256(Buffer.concat([Buffer.from("irontrellis-record/2"), Buffer.from([0]), Buffer.from((previous ?? "0x" + "00".repeat(32)).slice(2), "hex"),
    Buffer.from(eventHash.slice(2), "hex"), be]));
}

export function chunksOf(bytes, size = CHUNK_BYTES) {
  const out = [];
  for (let i = 0; i < bytes.length; i += size) out.push(bytes.subarray(i, i + size));
  return out;
}

/**
 * A history, with its canonical bodies and record chain checked against Core's own replay. `name` is a regenerated-suite
 * history name (signed with the suite's published test seeds), or the absolute path of a folder made by
 * tools/make-scenario.mjs (history.json plus the owner's own attestations.json; no seed is known or needed here).
 */
export function loadHistory(name) {
  const folder = name.startsWith("/");
  const events = JSON.parse(readFileSync(folder ? `${name}/history.json` : new URL(`conformance/v2-regenerated/histories/${name}.json`, ROOT), "utf8"));
  const manifest = folder ? { keys: {} } : JSON.parse(readFileSync(new URL("conformance/v2-regenerated/MANIFEST.json", ROOT), "utf8"));
  const attestations = folder ? JSON.parse(readFileSync(`${name}/attestations.json`, "utf8")) : null;
  const bodies = [];
  let previous = null;
  for (const [position, event] of events.entries()) {
    const bytes = canonical(event), eventHash = sha256(bytes), recordHash = recordHashOf(previous, eventHash, position);
    bodies.push({ position, bytes, eventHash, previousHash: previous, recordHash, chunks: chunksOf(bytes) });
    previous = recordHash;
  }
  const full = core.replay(events);
  if (full.head.hash !== previous || full.head.position !== events.length - 1) throw Error("HISTORY_CHAIN_DISAGREES_WITH_REPLAY");
  return Object.freeze({ name, events, bodies, keys: manifest.keys, attestations, domain: events[0].data.domain,
    historyId: bodies[0].recordHash, genesisEventHash: bodies[0].eventHash, receipts: folder ? loadReceipts(name, events) : null });
}

/**
 * The §12.3 (b) receipt artifacts of a story folder (`receipts/<commitment>.json`, canonical bytes, from make-story.mjs), one
 * per RECEIPT_RECORDED in history order: `[{ position, commitment, bytes }]`. Null when the folder has no `receipts/` (then
 * the run claims BODIES only). Every file must be canonical, named by its own commitment, and named by an event.
 */
function loadReceipts(folder, events) {
  if (!existsSync(`${folder}/receipts`)) return null;
  const files = new Map(readdirSync(`${folder}/receipts`).map(f => [f.replace(/\.json$/, ""), readFileSync(`${folder}/receipts/${f}`)]));
  const receipts = [];
  for (const [position, e] of events.entries()) {
    if (e.type !== "RECEIPT_RECORDED") continue;
    const commitment = e.data.receiptArtifactCommitment, bytes = files.get(commitment);
    if (bytes === undefined) throw Error(`RECEIPT_ARTIFACT_MISSING ${commitment} (position ${position})`);
    const artifact = JSON.parse(bytes.toString("utf8"));
    if (!canonical(artifact).equals(bytes) || core.receiptArtifactCommitment(artifact) !== commitment || artifact.contentHash !== e.data.receiptContentHash) {
      throw Error(`RECEIPT_ARTIFACT_INVALID ${commitment}`);
    }
    receipts.push({ position, commitment, bytes });
    files.delete(commitment);
  }
  if (files.size) throw Error("RECEIPT_ARTIFACT_UNNAMED " + [...files.keys()].join(","));
  return Object.freeze(receipts);
}

/** Head, roots and replay state of the prefix through `position`. */
export function prefixAt(history, position) {
  const r = core.replay(history.events.slice(0, position + 1));
  if (r.head.position !== position || r.head.hash !== history.bodies[position].recordHash) throw Error("PREFIX_HEAD_MISMATCH");
  return { head: { hash: r.head.hash, position: r.head.position, canonicalTime: r.head.canonicalTime }, stateRoot: r.stateRoot,
    projectionHead: r.projectionHead, state: r.state };
}

/** A `/2` head attestation by whichever published owner test key verifies at this prefix (the current owner key). */
export async function attestPrefix(history, prefix) {
  if (history.attestations !== null) {
    // A scenario's attestations were made by its owner in the owner's own process; they are only checked here.
    const attestation = history.attestations[prefix.head.position];
    if (!attestation) throw Error("NO_OWNER_ATTESTATION_AT_" + prefix.head.position + " (choose heads from acts.json)");
    const facts = core.verifyHeadAttestationFacts(attestation, prefix.state);
    if (!(facts.valid && facts.signatureValid && facts.prefix && facts.stateRootValid && facts.projectionValid)) throw Error("OWNER_ATTESTATION_INVALID_AT_" + prefix.head.position);
    return { attestation, keyLabel: attestation.keyId, facts };
  }
  for (const [label, k] of Object.entries(history.keys)) {
    if (k.scheme !== "ed25519" || typeof k.seed !== "string" || typeof k.keyId !== "string" || !k.keyId.startsWith("owner:")) continue;
    const signer = signerModule.signerFromKeyPair(core.keyPairFromPrivateKey("ed25519", k.keyId, k.seed));
    const attestation = await core.attestHead(signer, history.domain, prefix.head, "sha256", { stateRoot: prefix.stateRoot, projectionHead: prefix.projectionHead });
    const facts = core.verifyHeadAttestationFacts(attestation, prefix.state);
    if (facts.valid && facts.signatureValid && facts.prefix && facts.stateRootValid && facts.projectionValid) return { attestation, keyLabel: label, facts };
  }
  throw Error("NO_PUBLISHED_OWNER_KEY_VERIFIES_AT_" + prefix.head.position);
}

/** The §6.2 statement for `prefix`, bound to the trust root; `previous` is the retained statement before it (or null). */
export function statementFor({ history, trustRoot, prefix, attestation, sequence, previous, availability = "BODIES" }) {
  return { version: "irontrellis-anchor-statement/1", domain: history.domain, historyId: history.historyId, genesisEventHash: history.genesisEventHash,
    profile: { id: trustRoot.manifest.id, manifestHash: trustRoot.manifestHash }, head: prefix.head, stateRoot: prefix.stateRoot,
    projectionHead: prefix.projectionHead, attestationDigest: core.hashCanonical(attestation, "sha256"), sequence,
    predecessor: previous ? sha256(canonical(previous)) : null, previousHead: previous ? { hash: previous.head.hash, position: previous.head.position } : null,
    chain: { id: trustRoot.manifest.chain.id, destination: trustRoot.destination },
    evidence: { manifestDigest: null, certificateDigest: null, checkpointEventId: null }, availability };
}

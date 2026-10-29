// Reader 1: rebuilds an anchored history from the trust root and the chain alone, at one pinned block, and checks it
// (SPEC-IRONTRELLIS-ANCHORING-PROFILES-r2 §11.3, §12.2–§12.5, §19.3–§19.5; Core §4.1–§4.3). It holds no local state from
// the writer: every byte it judges comes from the chain at that block. Replay is Core's own; nothing here judges events.
import { core, gateway, canonical, sha256, recordHashOf } from "./history.mjs";

export const SNAPSHOT_VERSION = "irontrellis-shadownet-reconstruction/0";

/** Profile §6.3: the attestation names exactly the statement's domain, head (hash, position, canonicalTime), stateRoot and projectionHead. */
export function attestationMatchesStatement(attestation, statement) {
  const a = attestation, st = statement;
  if (a === null || typeof a !== "object" || a.head === null || typeof a.head !== "object") return false;
  return canonical(a.domain ?? null).equals(canonical(st.domain)) && a.head.hash === st.head.hash && a.head.position === st.head.position &&
    a.head.canonicalTime === st.head.canonicalTime && a.stateRoot === st.stateRoot && a.projectionHead === st.projectionHead;
}

export async function reconstruct({ rpc, viem, abi, trustRootBytes, block, pinBy = "hash" }) {
  const failures = [], fail = (check, detail) => { failures.push({ check, detail }); };
  const pinned = await rpc.call("eth_getBlockByNumber", [block, false]);
  // Every read below is at this one block: by hash (EIP-1898) where the node accepts it, else by its number.
  const ref = pinBy === "hash" ? { blockHash: pinned.hash } : pinned.number;
  const get = async (functionName, args = []) => viem.decodeFunctionResult({ abi, functionName,
    data: await rpc.call("eth_call", [{ to: trustRoot.destination, data: viem.encodeFunctionData({ abi, functionName, args }) }, ref]) });

  // T1–T4 from the trust root alone; T5 from the immutables at the pinned block.
  const trustRoot = JSON.parse(Buffer.from(trustRootBytes).toString("utf8"));
  gateway.encodeTrustRoot(trustRootBytes); // throws on T1–T4
  if (!canonical(trustRoot).equals(Buffer.from(trustRootBytes))) fail("TRUST_ROOT_CANONICAL");
  const code = await rpc.call("eth_getCode", [trustRoot.destination, ref]);
  const immutables = { namespaceId: await get("namespaceId"), publisher: (await get("publisher")).toLowerCase(), chainId: "eip155:" + (await get("chainId")),
    historyId: await get("historyId") };
  if (immutables.namespaceId !== trustRoot.namespaceId) fail("T5_NAMESPACE");
  if (immutables.publisher !== trustRoot.manifest.publisher) fail("T5_PUBLISHER");
  if (immutables.chainId !== trustRoot.manifest.chain.id) fail("T5_CHAIN");
  if (immutables.historyId !== trustRoot.manifest.historyId) fail("HISTORY_ID_IMMUTABLE");

  // Bodies: chunks → bytes → eventHash; the §4.3 chain recomputed here; strict canonical event text.
  const bodyCount = Number(await get("bodyCount")), bodies = [], events = [];
  let previous = null;
  for (let p = 0; p < bodyCount; p++) {
    const [eventHash, recordHash, byteLength, chunkCount] = await get("bodyAt", [BigInt(p)]);
    const chunks = [];
    for (let i = 0; i < Number(chunkCount); i++) chunks.push(Buffer.from((await get("bodyChunk", [BigInt(p), BigInt(i)])).slice(2), "hex"));
    const bytes = Buffer.concat(chunks);
    if (bytes.length !== Number(byteLength)) fail("BODY_LENGTH", p);
    if (sha256(bytes) !== eventHash) fail("BODY_DIGEST", p);
    const expected = recordHashOf(previous, eventHash, p);
    if (expected !== recordHash) fail("RECORD_CHAIN", p);
    if (p === 0 && recordHash !== trustRoot.manifest.historyId) fail("GENESIS", p);
    let event = null;
    try { event = JSON.parse(bytes.toString("utf8")); if (!canonical(event).equals(bytes)) fail("BODY_NOT_CANONICAL", p); } catch { fail("BODY_NOT_JSON", p); }
    events.push(event);
    bodies.push({ version: "irontrellis-body-descriptor/1", namespaceId: trustRoot.namespaceId, position: p, previousHash: previous, eventHash, recordHash,
      byteLength: Number(byteLength), chunks: chunks.map(c => ({ digest: sha256(c), length: c.length })) });
    previous = recordHash;
  }
  if (bodyCount > 0 && sha256(canonical(events[0])) !== trustRoot.manifest.genesisEventHash) fail("GENESIS_EVENT_HASH");

  // Artifacts: the manifest payload and head attestations, each by sha256 of its canonical bytes; receipt artefacts (kind 2)
  // by their commitment, which is not a digest of the bytes and is checked with each RECEIPT_RECORDED below.
  const artifactCount = Number(await get("artifactCount")), artifacts = new Map();
  for (let i = 0; i < artifactCount; i++) {
    const [kind, boundBy, byteLength, chunkCount] = await get("artifactAt", [BigInt(i)]);
    const parts = [];
    for (let j = 0; j < Number(chunkCount); j++) parts.push(Buffer.from((await get("artifactChunk", [BigInt(i), BigInt(j)])).slice(2), "hex"));
    const bytes = Buffer.concat(parts);
    if (bytes.length !== Number(byteLength) || (Number(kind) !== 2 && sha256(bytes) !== boundBy)) fail("ARTIFACT_DIGEST", i);
    artifacts.set(`${kind}:${boundBy}`, bytes);
  }
  const manifestBytes = artifacts.get(`3:${trustRoot.manifestHash}`) ?? null;
  if (manifestBytes !== null && !manifestBytes.equals(canonical(trustRoot.manifest))) fail("MANIFEST_ARTIFACT");

  // Receipt artefacts (kind 2), each verified once: canonical bytes, the commitment and content hash its event carries, and
  // Core's receipt verification (content integrity, signature, issuer and historical authorization: `valid`). The issuance
  // history is the prefix through the RECEIPT_RECORDED itself, the one Core's verifier relates to the receipt.
  const receiptVerdicts = new Map();
  const receiptOk = (position, st) => {
    const event = events[position], commitment = event.data.receiptArtifactCommitment;
    if (!receiptVerdicts.has(commitment)) {
      const bytes = artifacts.get(`2:${commitment}`) ?? null;
      let ok = false;
      if (bytes !== null) {
        try {
          const artifact = JSON.parse(bytes.toString("utf8"));
          ok = canonical(artifact).equals(bytes) && core.receiptArtifactCommitment(artifact) === commitment && artifact.contentHash === event.data.receiptContentHash
            && core.verifyReceiptState(core.replay(events.slice(0, position + 1)).state, { operationVersion: core.RECEIPT_VERIFICATION_VERSION, artifact, expectedDomain: st.domain, verifierTime: st.head.canonicalTime }).valid === true;
        } catch { ok = false; }
      }
      receiptVerdicts.set(commitment, ok);
    }
    return receiptVerdicts.get(commitment);
  };

  // Statements: exact bytes, digest, canonical form, §19.4 binding, the predecessor chain, and replay at each head.
  const statementCount = Number(await get("statementCount")), statements = [];
  let prior = null, bodiesHead = -1;
  for (let s = 0; s < statementCount; s++) {
    const [raw, digest] = await get("statementAt", [BigInt(s)]);
    const bytes = Buffer.from(raw.slice(2), "hex"), st = JSON.parse(bytes.toString("utf8"));
    const checks = { digest: sha256(bytes) === digest, canonical: canonical(st).equals(bytes), sequence: st.sequence === s };
    checks.binding = gateway.checkStatementBinding(trustRootBytes, bytes, trustRoot.manifest.publisher).bindingsMatch;
    checks.chain = prior === null ? st.predecessor === null && st.previousHead === null
      : st.predecessor === prior.digest && st.previousHead?.hash === prior.head.hash && st.previousHead?.position === prior.head.position;
    const position = st.head.position;
    checks.headInBodies = position < bodyCount && bodies[position].recordHash === st.head.hash;
    let replay = null;
    if (checks.headInBodies) {
      const r = core.replay(events.slice(0, position + 1));
      replay = { head: r.head, stateRoot: r.stateRoot, projectionHead: r.projectionHead };
      checks.replayHead = r.head.hash === st.head.hash && r.head.position === position && r.head.canonicalTime === st.head.canonicalTime;
      checks.replayRoots = r.stateRoot === st.stateRoot && r.projectionHead === st.projectionHead;
      const att = artifacts.get(`1:${st.attestationDigest}`) ?? null;
      if (att === null) checks.attestation = checks.attestationMatchesStatement = null;
      else {
        const a = JSON.parse(att.toString("utf8")), f = core.verifyHeadAttestationFacts(a, r.state);
        checks.attestation = !!(f.valid && f.signatureValid && f.prefix && f.stateRootValid && f.projectionValid);
        // Valid at its own prefix is not enough: the attestation must attest this statement's head (profile §6.3). Without
        // this, a valid attestation of an earlier prefix passed for a later statement (Astra's Reader 1 review).
        checks.attestationMatchesStatement = attestationMatchesStatement(a, st);
      }
      // §12.3 (b), only where the statement claims it: every accepted RECEIPT_RECORDED through the head has its receipt
      // artefact on chain, canonical, opening the event's commitment and content hash, and verifying (Core verifyReceiptState).
      if (st.availability === "BODIES_AND_ARTIFACTS") checks.receiptClosure = events.slice(0, position + 1).every((e, at) => e.type !== "RECEIPT_RECORDED" || receiptOk(at, st));
      if (st.availability !== "ANCHOR_ONLY") bodiesHead = Math.max(bodiesHead, position);
    }
    for (const [k, v] of Object.entries(checks)) if (v === false) fail("STATEMENT_" + k.toUpperCase(), s);
    // An anchor verifies only with every check true, the head attestation included (§6.3): a missing artefact (null) is not
    // a structural failure, but it is not an anchor either (Astra's Shadownet review, reader note 2).
    const anchorVerified = Object.values(checks).every(v => v === true) && "attestation" in checks;
    statements.push({ sequence: s, digest, head: st.head, availability: st.availability, checks, anchorVerified, replay });
    prior = { digest, head: st.head };
  }
  // The pinned block's hash, read again by its number after every record read (Astra's review of 573b353; the coordinator
  // 20261028T114214Z): the hash reported must still be the block at that number, or nothing verifies. Without it a
  // number-pinned read had no end check (a reorganization or an inconsistent endpoint between the reads), and a hash-pinned
  // read could be of a block no longer at that number. A change that reverses between the two reads is not excluded.
  const after = await rpc.call("eth_getBlockByNumber", [pinned.number, false]);
  const hashAfterRead = after?.hash ?? null;
  if (hashAfterRead !== pinned.hash) fail("BLOCK_HASH_CHANGED_DURING_READ", { number: pinned.number, before: pinned.hash, after: hashAfterRead });
  const availabilityVerified = statementCount > 0 && bodiesHead >= 0 && failures.length === 0;
  const anchorsVerified = availabilityVerified && statements.every(st => st.anchorVerified);
  // The full consumer closure: anchors verified, and every statement claims BODIES_AND_ARTIFACTS and its receipts check.
  // §12.3 (c), §12.5: the profile-manifest payload is in the consumer closure, so its artefact must be on chain, canonical and
  // equal to the trust root's manifest (keyed by its sha256, which must be profile.manifestHash). The trust root the caller
  // supplies does not stand in for it (Astra's review of 51cdd55).
  const manifestOnChain = manifestBytes !== null && manifestBytes.equals(canonical(trustRoot.manifest)) && sha256(manifestBytes) === trustRoot.manifestHash;
  const closureVerified = anchorsVerified && manifestOnChain && statements.every(st => st.availability === "BODIES_AND_ARTIFACTS" && st.checks.receiptClosure === true);
  const storeLines = bodies.map((b, p) => `{"version":"irontrellis-portable-file-store/2","previousHash":${b.previousHash === null ? "null" : `"${b.previousHash}"`},"event":${canonical(events[p]).toString()},"recordHash":"${b.recordHash}"}\n`).join("");
  const snapshot = { version: SNAPSHOT_VERSION, status: "EXPERIMENTAL", block: { number: Number(BigInt(pinned.number)), hash: pinned.hash, hashAfterRead, pinnedBy: pinBy },
    trustRootDigest: sha256(trustRootBytes), destination: trustRoot.destination, codeSha256: sha256(Buffer.from(code.slice(2), "hex")), immutables,
    bodies, artifacts: [...artifacts.keys()], statements, storeLinesSha256: sha256(Buffer.from(storeLines)),
    availabilityVerified, anchorsVerified, closureVerified, manifestOnChain, failures, finality: { label: "L2_INCLUDED", mode: "UNVERIFIED", note: "read over RPC; no L1 evidence in this snapshot" } };
  return { snapshot, storeLines, rpcCalls: rpc.log.length };
}

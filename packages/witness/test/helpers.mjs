// Shared test helpers: real owner keys, real format-1 histories (built with the
// core engine), the deterministic transparency scenario, temp data dirs and an
// in-process witness server on an ephemeral port.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as core from "@ramex-labs/irontrellis";
import * as t from "@ramex-labs/irontrellis/transparency";

export { core, t };
export const here = fileURLToPath(new URL(".", import.meta.url));
export const packageRoot = resolve(here, "..");
export const BIN = join(packageRoot, "bin", "irontrellis-witness.mjs");
export const witnessLib = await import(pathToFileURL(join(packageRoot, "dist", "index.js")).href);

const scenarioModule = await import(pathToFileURL(resolve(packageRoot, "../../conformance/transparency/scenario.mjs")).href);
const lib = {
  ...t, keyPairFromPrivateKey: core.keyPairFromPrivateKey, signHashWith: core.signHashWith, signControlEvent: core.signControlEvent,
  HistoryHasher: core.HistoryHasher, TRELLIS_VERSIONS: core.TRELLIS_VERSIONS, ADAPTER_POLICY_HASHES: core.ADAPTER_POLICY_HASHES, ownerKeyDigest: core.ownerKeyDigest,
  controlAuthorizationHash: core.controlAuthorizationHash, controlEffectHash: core.controlEffectHash,
};
/** The shared deterministic witness scenario (conformance/transparency/scenario.mjs): heads 0..8, rotation at 7, a fork at 6. */
export const buildScenario = () => scenarioModule.buildScenario(lib);

const hexSeed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
export const ownerKeyOf = (pair) => Object.freeze({ keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential });
export const signerOf = (pair) => Object.freeze({ keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, signHash: core.signHashWith(pair) });
export const keyPair = (keyId, n) => core.keyPairFromPrivateKey("ed25519", keyId, hexSeed(n));

/**
 * A real format-1 history: genesis (owner key 1), PRINCIPAL_CREATED, then
 * `agents` AGENT_CREATED events, all owner-signed; with `rotateAt`, the event
 * at that position is an OWNER_KEYS_ROTATED to key 2 (signed by key 1) and
 * later control events are signed by key 2.
 */
export async function buildHistory({ name = "h", agents = 5, rotateAt, seed = 0x4001 } = {}) {
  const pair1 = keyPair(`owner:${name}:1`, seed);
  const pair2 = keyPair(`owner:${name}:2`, seed + 1);
  const signer1 = signerOf(pair1);
  const signer2 = signerOf(pair2);
  const domain = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: `deployment:${name}` });
  const genesis = {
    id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
    data: {
      domain, versions: { ...core.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [ownerKeyOf(pair1)],
      adapterPolicyHash: core.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: `lineage:${name}`, policyVersion: `policy:${name}/1`,
      rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: `policy-source:${name}`, timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    },
  };
  const hasher = new core.HistoryHasher("irontrellis-event/1");
  const events = [];
  const heads = [];
  const push = (event) => {
    const hash = hasher.push(event);
    events.push(event);
    heads.push(Object.freeze({ hash, position: events.length - 1, canonicalTime: event.timestamp }));
  };
  push(genesis);
  let current = signer1;
  let rotation;
  push(await core.signControlEvent(current, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, domain, heads.at(-1), "sha256"));
  for (let n = 0; n < agents; n += 1) {
    if (rotateAt !== undefined && events.length === rotateAt) {
      rotation = await core.signControlEvent(current, { id: "rotation:1", type: "OWNER_KEYS_ROTATED", timestamp: events.length, data: { ownerKeys: [ownerKeyOf(pair2)], reason: "test rotation" } }, domain, heads.at(-1), "sha256");
      push(rotation);
      current = signer2;
    }
    const event = { id: `agent:${n}`, type: "AGENT_CREATED", timestamp: events.length, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } };
    push(await core.signControlEvent(current, event, domain, heads.at(-1), "sha256"));
  }
  const historyId = heads[0].hash;
  const at = (head) => ({ hash: head.hash, position: head.position });
  const signerAt = (position) => (rotateAt !== undefined && position > rotateAt ? signer2 : signer1);
  /** A signed statement for heads[headPos] extending heads[prevPos] (null for none). */
  const statement = (headPos, prevPos, signer = signerAt(headPos)) => t.signHeadStatement(signer, {
    version: t.HEAD_STATEMENT_VERSION, historyId, domain, head: heads[headPos], previous: prevPos === null ? null : at(heads[prevPos]),
  });
  return { genesis, events, heads, historyId, domain, pair1, pair2, signer1, signer2, rotation, rotateAt, at, signerAt, statement };
}

/**
 * A real format-1 history with owner key events: genesis (key 1, no commitment), PRINCIPAL_CREATED, AGENT, a
 * commitment-only `OWNER_KEYS_ROTATED` (key 1 kept, committing to key 2's digest) at `commitAt` (default 3), agents, a
 * PRE-ROTATED `OWNER_KEYS_ROTATED` to key 2 (revealing it, its `nextKeyAuthorizations`, committing to key 3) at
 * `rotateAt` (default 6), then agents signed by key 2. `forge(position, previousPosition)` is a statement a thief of key 1 could sign: an arbitrary head at `position`
 * extending the real head at `previousPosition`. `plainRotation` is a rotation to a thief's key signed by key 1 alone.
 */
export async function buildKeyEventHistory({ name = "ke", agents = 3, commitAt = 3, rotateAt = 6, seed = 0x5001 } = {}) {
  const pair1 = keyPair(`owner:${name}:1`, seed), pair2 = keyPair(`owner:${name}:2`, seed + 1), pair3 = keyPair(`owner:${name}:3`, seed + 2), thief = keyPair(`owner:${name}:thief`, seed + 9);
  const signer1 = signerOf(pair1), signer2 = signerOf(pair2), thiefSigner = signerOf(thief);
  const domain = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: `deployment:${name}` });
  const genesis = {
    id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
    data: {
      domain, versions: { ...core.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: [ownerKeyOf(pair1)],
      adapterPolicyHash: core.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: `lineage:${name}`, policyVersion: `policy:${name}/1`,
      rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: `policy-source:${name}`, timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    },
  };
  const hasher = new core.HistoryHasher("irontrellis-event/1");
  const events = [], heads = [];
  const push = (event) => {
    const hash = hasher.push(event);
    events.push(event);
    heads.push(Object.freeze({ hash, position: events.length - 1, canonicalTime: event.timestamp }));
  };
  const agent = (n) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp: events.length, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
  push(genesis);
  let current = signer1, n = 0, commitment, rotation, plainRotation;
  push(await core.signControlEvent(current, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, domain, heads.at(-1), "sha256"));
  const challengeOf = (event, previous) => core.controlAuthorizationHash({
    domain, eventId: event.id, eventType: event.type, timestamp: event.timestamp, previousHead: { hash: previous.hash, position: previous.position }, effectHash: core.controlEffectHash(event, "sha256"),
  }, "sha256");
  while (events.length < rotateAt + 1 + agents) {
    if (events.length === commitAt) {
      commitment = await core.signControlEvent(current, {
        id: "commit:1", type: "OWNER_KEYS_ROTATED", timestamp: events.length, data: { ownerKeys: [ownerKeyOf(pair1)], reason: "next-key commitment", nextKeyDigests: [core.ownerKeyDigest(ownerKeyOf(pair2))] },
      }, domain, heads.at(-1), "sha256");
      push(commitment);
    } else if (events.length === rotateAt) {
      const previous = heads.at(-1);
      plainRotation = await core.signControlEvent(signer1, { id: "rotation:thief", type: "OWNER_KEYS_ROTATED", timestamp: events.length, data: { ownerKeys: [ownerKeyOf(thief)], nextKeyDigests: [core.ownerKeyDigest(ownerKeyOf(pair3))] } }, domain, previous, "sha256");
      const signed = await core.signControlEvent(signer1, { id: "rotation:1", type: "OWNER_KEYS_ROTATED", timestamp: events.length, data: { ownerKeys: [ownerKeyOf(pair2)], nextKeyDigests: [core.ownerKeyDigest(ownerKeyOf(pair3))] } }, domain, previous, "sha256");
      const proof = await signer2.signHash(challengeOf(signed, previous));
      rotation = { ...signed, data: { ...signed.data, nextKeyAuthorizations: [{ keyId: pair2.keyId, scheme: pair2.scheme, signature: proof }] } };
      push(rotation);
      current = signer2;
    } else {
      push(await core.signControlEvent(current, agent(n), domain, heads.at(-1), "sha256"));
      n += 1;
    }
  }
  const historyId = heads[0].hash;
  const at = (head) => ({ hash: head.hash, position: head.position });
  const signerAt = (position) => (position > rotateAt ? signer2 : signer1);
  const statement = (headPos, prevPos, signer = signerAt(headPos)) => t.signHeadStatement(signer, {
    version: t.HEAD_STATEMENT_VERSION, historyId, domain, head: heads[headPos], previous: prevPos === null ? null : at(heads[prevPos]),
  });
  const forge = (position, previousPosition, tag = 0) => t.signHeadStatement(signer1, {
    version: t.HEAD_STATEMENT_VERSION, historyId, domain, head: { hash: `0x${(0xa0 + tag).toString(16).repeat(32)}`, position, canonicalTime: position },
    previous: previousPosition === null ? null : at(heads[previousPosition]),
  });
  const keyEvent = (event, position, extra = {}) => ({ event, previousHead: at(heads[position - 1]), eventHead: at(heads[position]), ...extra });
  return {
    genesis, events, heads, historyId, domain, pair1, pair2, pair3, signer1, signer2, thiefSigner, commitment, rotation, plainRotation, commitAt, rotateAt, at, signerAt, statement, forge, keyEvent,
  };
}

/** JSON round trip (what goes over the wire). */
export const wire = (value) => JSON.parse(JSON.stringify(value));

export function tempDir(prefix = "irontrellis-witness-") {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true, maxRetries: 10 }) };
}

export const silentLogger = Object.freeze({ info: () => {}, warn: () => {}, error: () => {} });
export function collectingLogger() {
  const lines = [];
  const at = (level) => (msg, fields = {}) => lines.push({ level, msg, ...fields });
  return { lines, logger: { info: at("info"), warn: at("warn"), error: at("error") } };
}

export const ADMIN_TOKEN = "itw_test-admin-token-0123456789";

/** init + serve in-process on 127.0.0.1:0. */
export async function startWitness({ dir, name = "test.witness", override = {}, logger = silentLogger, now, init = true } = {}) {
  if (init) witnessLib.initDataDir(dir, name);
  const handle = await witnessLib.serve({
    dataDir: dir, listen: "127.0.0.1:0", logger, ...(now === undefined ? {} : { now }),
    configOverride: { adminTokenHashes: [witnessLib.hashToken(ADMIN_TOKEN)], rateLimit: { perIpPerMinute: 0, perHistoryPerMinute: 0 }, ...override },
  });
  return handle;
}

/** A small HTTP client for the §8.3 API that verifies every receipt and checks every checkpoint is consistent with the last one it saw. */
export class TestClient {
  constructor(url, verifierKey) {
    this.url = url;
    this.verifierKey = verifierKey;
    this.checkpoints = [];
  }

  async request(method, path, body, headers = {}) {
    const init = { method, headers: { ...headers } };
    if (body !== undefined) {
      init.body = typeof body === "string" ? body : JSON.stringify(body);
      init.headers["content-type"] ??= "application/json";
    }
    const response = await fetch(`${this.url}${path}`, init);
    const text = await response.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    if (json !== undefined) await this.#audit(json);
    return { status: response.status, headers: response.headers, text, json };
  }

  get(path) {
    return this.request("GET", path);
  }

  post(path, body, headers) {
    return this.request("POST", path, body, headers);
  }

  register(genesis, token = ADMIN_TOKEN) {
    return this.post("/v1/histories", { genesis }, token === null ? {} : { authorization: `Bearer ${token}` });
  }

  /** Verifies every receipt in a reply body and remembers its checkpoint. */
  async #audit(body) {
    const receipts = [];
    const visit = (value) => {
      if (value === null || typeof value !== "object") return;
      if (value.version === t.WITNESS_RECEIPT_VERSION) receipts.push(value);
      else for (const child of Object.values(value)) visit(child);
    };
    visit(body);
    for (const receipt of receipts) {
      const verdict = t.verifyWitnessReceipt(receipt, [this.verifierKey]);
      assert.equal(verdict.ok, true, `receipt must verify: ${verdict.reason} ${verdict.message}`);
      if (typeof body.checkpoint === "string") assert.equal(receipt.checkpoint, body.checkpoint, "one checkpoint per reply");
      await this.observe(receipt.checkpoint);
    }
    if (typeof body.checkpoint === "string") await this.observe(body.checkpoint);
  }

  /** Records a checkpoint and checks it is consistent with the largest one seen so far (via the proofs endpoint). */
  async observe(note) {
    const opened = t.openNote(note, [this.verifierKey]);
    const checkpoint = t.parseCheckpoint(opened.body);
    const previous = this.checkpoints.reduce((best, c) => (best === undefined || c.size > best.size ? c : best), undefined);
    this.checkpoints.push({ size: checkpoint.size, root: checkpoint.root, note });
    if (previous === undefined) return;
    const [from, to] = previous.size <= checkpoint.size ? [previous, checkpoint] : [checkpoint, previous];
    if (from.size === to.size) {
      assert.equal(t.encodeBase64(from.root), t.encodeBase64(to.root), "two checkpoints of one size must have one root");
      return;
    }
    if (from.size === 0) return;
    const response = await fetch(`${this.url}/v1/proofs/consistency?from=${from.size}&to=${to.size}`);
    const proof = (await response.json()).proof.map((b64) => t.decodeBase64(b64));
    assert.equal(t.verifyConsistency(from.size, to.size, from.root, to.root, proof), true, `checkpoints ${from.size} and ${to.size} must be consistent`);
  }
}

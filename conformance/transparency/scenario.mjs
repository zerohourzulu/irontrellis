/**
 * A deterministic witness scenario shared by the transparency vector generator
 * (`generate.mjs`, against packages/core/dist) and the core and witness unit
 * tests (against the sources). Every module is passed in as `lib`, so this file
 * imports nothing from the engine itself. One witness log holds two histories.
 *
 * Main history (format 1, owner key `owner:1`, seed 0x…3001, no next-key commitment):
 *   0 DEPLOYMENT_INITIALIZED   1 PRINCIPAL_CREATED   2..6 AGENT_CREATED agent:0..4
 *   7 OWNER_KEYS_ROTATED → owner:2 (seed 0x…3002), signed by owner:1 (a rotation out of an uncommitted epoch)
 *   8 AGENT_CREATED agent:5, signed by owner:2
 *   6' a forked position 6 (AGENT_CREATED agent:fork), signed by owner:1
 *
 * Pre-rotation history (owner:1, its genesis commits to owner:2's key digest):
 *   0 DEPLOYMENT_INITIALIZED (nextKeyDigests)   1 PRINCIPAL_CREATED   2, 3 AGENT_CREATED agent:0, agent:1
 *   4 OWNER_KEYS_ROTATED → owner:2, pre-rotated (reveals owner:2, proves possession, commits to owner:3, seed 0x…3003)
 *   5 AGENT_CREATED agent:2, signed by owner:2
 *   4' a head a thief of owner:1 stated after the last good head (position 4 of another branch: 3' agent:thief, 4' agent:thief2)
 *
 * Witness log (origin `irontrellis-witness/vectors`, note key seed 0x…77):
 *   main:          0 REGISTERED   1 HEAD 0←null   2 HEAD 3←0   3 HEAD 6←3   4 ROTATED (previousHead = head 6, rotationHead = head 7)
 *                  5 HEAD 8←6 (owner:2)   6 EQUIVOCATION (first = HEAD 6←3, second = HEAD 6'←3)
 *   pre-rotation:  7 REGISTERED (the witness learns the commitment from the genesis)   8 HEAD 0←null   9 HEAD 2←0 (the last good head)
 *                  10 HEAD 4'←2 (the thief)   11 SUPERSEDED (the pre-rotated rotation at 4 with a chain 4←2 overrides leaf 10)
 *                  12 HEAD 4←2 (the chain)   13 ROTATED (previousHead = head 3, rotationHead = head 4)   14 HEAD 5←4 (owner:2)
 * Checkpoints at sizes 4, 7 and 15; receipts for every main entry against size 7, for entry 2 against size 4, and for
 * every pre-rotation entry against size 15. The main history's leaves are a compact structural example (its ROTATED
 * leaf names a head at 7 that the log does not state; a witness would hold that head first). The pre-rotation leaves are
 * exactly what a witness produces for them (packages/witness/test/state.test.mjs checks it, leaf indexes rebased).
 */
export const DOMAIN = Object.freeze({ protocol: "irontrellis", version: "1", deploymentId: "deployment:witness-vectors" });
export const ORIGIN = "irontrellis-witness/vectors";
export const WITNESS_KEY_NAME = "irontrellis-witness/vectors";
export const RECEIVED_AT = 1_767_225_600_000; // 2026-01-01T00:00:00Z
const hexSeed = (n) => `0x${n.toString(16).padStart(64, "0")}`;
export const OWNER1_SEED = hexSeed(0x3001);
export const OWNER2_SEED = hexSeed(0x3002);
export const OWNER3_SEED = hexSeed(0x3003);
export const WITNESS_SEED = new Uint8Array(32).fill(0x77);
export const OTHER_WITNESS_SEED = new Uint8Array(32).fill(0x78);

const localSigner = (lib, pair) => Object.freeze({ keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential, signHash: lib.signHashWith(pair) });
const ownerKeyOf = (pair) => Object.freeze({ keyId: pair.keyId, scheme: pair.scheme, credential: pair.credential });

/**
 * lib: { keyPairFromPrivateKey, signHashWith, signControlEvent, HistoryHasher, TRELLIS_VERSIONS, ADAPTER_POLICY_HASHES,
 *        ownerKeyDigest, controlAuthorizationHash, controlEffectHash, signHeadStatement, noteSignerFromSeed, verifierKey,
 *        formatCheckpoint, signNote, MerkleTree, entryLeafHash, buildReceipt, WITNESS_ENTRY_VERSION, HEAD_STATEMENT_VERSION }
 */
export async function buildScenario(lib) {
  const owner1Pair = lib.keyPairFromPrivateKey("ed25519", "owner:1", OWNER1_SEED);
  const owner2Pair = lib.keyPairFromPrivateKey("ed25519", "owner:2", OWNER2_SEED);
  const owner1 = localSigner(lib, owner1Pair);
  const owner2 = localSigner(lib, owner2Pair);
  const ownerKeys1 = [ownerKeyOf(owner1Pair)];
  const ownerKeys2 = [ownerKeyOf(owner2Pair)];

  const genesisOf = (lineage, extra = {}) => ({
    id: "genesis", type: "DEPLOYMENT_INITIALIZED", timestamp: 0,
    data: {
      domain: DOMAIN, versions: { ...lib.TRELLIS_VERSIONS, signatureScheme: "ed25519" }, ownerKeys: ownerKeys1, ...extra,
      adapterPolicyHash: lib.ADAPTER_POLICY_HASHES.E6, canonicalLineageId: lineage, policyVersion: "policy:witness-vectors/1",
      rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:witness-vectors", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    },
  });
  const genesis = genesisOf("lineage:witness-vectors");
  const hasher = new lib.HistoryHasher("irontrellis-event/1");
  const events = [];
  const heads = [];
  const push = (event, into = { events, heads, hasher }) => {
    const hash = into.hasher.push(event);
    into.events.push(event);
    into.heads.push(Object.freeze({ hash, position: into.events.length - 1, canonicalTime: event.timestamp }));
  };
  const agent = (n, timestamp) => ({ id: `agent:${n}`, type: "AGENT_CREATED", timestamp, data: { agentId: `agent:${n}`, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 } });
  push(genesis);
  push(await lib.signControlEvent(owner1, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, DOMAIN, heads.at(-1), "sha256"));
  for (let n = 0; n < 4; n += 1) push(await lib.signControlEvent(owner1, agent(n, n + 2), DOMAIN, heads.at(-1), "sha256"));
  // Fork: a different event at position 6 on the same first six events.
  const fork = { events: events.slice(), heads: heads.slice(), hasher: hasher.clone() };
  push(await lib.signControlEvent(owner1, agent(4, 6), DOMAIN, heads.at(-1), "sha256"));
  const rotation = await lib.signControlEvent(owner1, { id: "rotation:1", type: "OWNER_KEYS_ROTATED", timestamp: 7, data: { ownerKeys: ownerKeys2, reason: "scheduled rotation (vector)" } }, DOMAIN, heads.at(-1), "sha256");
  push(rotation);
  push(await lib.signControlEvent(owner2, agent(5, 8), DOMAIN, heads.at(-1), "sha256"));
  push(await lib.signControlEvent(owner1, agent("fork", 6), DOMAIN, heads[5], "sha256"), fork);

  const historyId = heads[0].hash;
  const at = (head) => ({ hash: head.hash, position: head.position });
  const statement = (head, previous) => ({ version: lib.HEAD_STATEMENT_VERSION, historyId, domain: DOMAIN, head, previous: previous === null ? null : at(previous) });
  const s0 = await lib.signHeadStatement(owner1, statement(heads[0], null));
  const s3 = await lib.signHeadStatement(owner1, statement(heads[3], heads[0]));
  const s6 = await lib.signHeadStatement(owner1, statement(heads[6], heads[3]));
  const s8 = await lib.signHeadStatement(owner2, statement(heads[8], heads[6]));
  const s6fork = await lib.signHeadStatement(owner1, statement(fork.heads[6], heads[3]));

  const base = (i) => ({ version: lib.WITNESS_ENTRY_VERSION, historyId, receivedAt: RECEIVED_AT + i * 1000 });
  const entries = [
    { ...base(0), kind: "REGISTERED", genesis },
    { ...base(1), kind: "HEAD", signedStatement: s0 },
    { ...base(2), kind: "HEAD", signedStatement: s3 },
    { ...base(3), kind: "HEAD", signedStatement: s6 },
    { ...base(4), kind: "ROTATED", rotation, previousHead: at(heads[6]), rotationHead: at(heads[7]) },
    { ...base(5), kind: "HEAD", signedStatement: s8 },
    { ...base(6), kind: "EQUIVOCATION", first: s6, second: s6fork },
  ];

  const preRotation = await buildPreRotation(lib, { genesisOf, owner1, owner2, owner2Pair, ownerKeys1, agent, push, base, firstIndex: entries.length });
  const log = [...entries, ...preRotation.entries];

  const witness = lib.noteSignerFromSeed(WITNESS_KEY_NAME, WITNESS_SEED);
  const witnessVkey = lib.verifierKey(witness.name, witness.publicKey);
  const other = lib.noteSignerFromSeed(WITNESS_KEY_NAME, OTHER_WITNESS_SEED);
  const otherVkey = lib.verifierKey(other.name, other.publicKey);
  const tree = new lib.MerkleTree();
  for (const entry of log) tree.append(lib.entryLeafHash(entry));
  const checkpointAt = (size, signer = witness) => lib.signNote(lib.formatCheckpoint(ORIGIN, size, tree.root(size)), signer);
  const checkpoint4 = checkpointAt(4);
  const checkpoint7 = checkpointAt(7);
  const checkpoint15 = checkpointAt(log.length);
  const receiptFor = (index, size, checkpoint) =>
    lib.buildReceipt({ origin: ORIGIN, verifierKey: witnessVkey, entry: log[index], index, checkpoint, inclusionProof: tree.inclusionProof(index, size) });
  const receipts = entries.map((_, index) => receiptFor(index, 7, checkpoint7));
  const receiptAt4 = receiptFor(2, 4, checkpoint4);
  preRotation.receipts = preRotation.entries.map((_, n) => receiptFor(entries.length + n, log.length, checkpoint15));

  return {
    events, heads, fork, rotation, historyId, owner1, owner2, owner1Pair, owner2Pair, ownerKeys1, ownerKeys2,
    ownerKeyEpochs: [{ fromPosition: 0, keys: ownerKeys1 }, { fromPosition: 8, keys: ownerKeys2 }],
    statements: { s0, s3, s6, s8, s6fork }, statement, entries, log, preRotation, tree, witness, witnessVkey, other, otherVkey,
    checkpoint4, checkpoint7, checkpoint15, checkpointAt, receipts, receiptAt4, receiptFor,
  };
}

/**
 * The pre-rotation history and its leaves (log indexes from `firstIndex`): the witness registers a genesis that commits
 * to owner:2, holds heads 0 and 2, then a head a thief of owner:1 stated after head 2; the owner's pre-rotated rotation
 * at 4, delivered with a chain statement 4←2, supersedes the thief's head (SUPERSEDED, then the chain HEAD, then ROTATED).
 */
async function buildPreRotation(lib, { genesisOf, owner1, owner2, owner2Pair, ownerKeys1, agent, push, base, firstIndex }) {
  const owner3Pair = lib.keyPairFromPrivateKey("ed25519", "owner:3", OWNER3_SEED);
  const genesis = genesisOf("lineage:witness-vectors-pre-rotation", { nextKeyDigests: [lib.ownerKeyDigest(ownerKeyOf(owner2Pair))] });
  const branch = { events: [], heads: [], hasher: new lib.HistoryHasher("irontrellis-event/1") };
  push(genesis, branch);
  push(await lib.signControlEvent(owner1, { id: "principal", type: "PRINCIPAL_CREATED", timestamp: 1, data: { principalId: "owner" } }, DOMAIN, branch.heads.at(-1), "sha256"), branch);
  for (let n = 0; n < 2; n += 1) push(await lib.signControlEvent(owner1, agent(n, n + 2), DOMAIN, branch.heads.at(-1), "sha256"), branch);
  const { events, heads } = branch;
  // The thief's branch after head 2: two events signed with the leaked owner:1 key.
  const thief = { events: events.slice(0, 3), heads: heads.slice(0, 3), hasher: new lib.HistoryHasher("irontrellis-event/1") };
  for (const event of thief.events) thief.hasher.push(event);
  push(await lib.signControlEvent(owner1, agent("thief", 3), DOMAIN, thief.heads.at(-1), "sha256"), thief);
  push(await lib.signControlEvent(owner1, agent("thief2", 4), DOMAIN, thief.heads.at(-1), "sha256"), thief);
  // The owner's pre-rotated rotation at 4: reveals owner:2, proves possession of it over the event's own challenge, commits to owner:3.
  const previous = heads.at(-1);
  const unsigned = { id: "rotation:1", type: "OWNER_KEYS_ROTATED", timestamp: 4, data: { ownerKeys: [ownerKeyOf(owner2Pair)], nextKeyDigests: [lib.ownerKeyDigest(ownerKeyOf(owner3Pair))], reason: "pre-rotated rotation (vector)" } };
  const signed = await lib.signControlEvent(owner1, unsigned, DOMAIN, previous, "sha256");
  const challenge = lib.controlAuthorizationHash({
    domain: DOMAIN, eventId: signed.id, eventType: signed.type, timestamp: signed.timestamp, previousHead: { hash: previous.hash, position: previous.position },
    effectHash: lib.controlEffectHash(signed, "sha256"),
  }, "sha256");
  const rotation = { ...signed, data: { ...signed.data, nextKeyAuthorizations: [{ keyId: owner2.keyId, scheme: owner2.scheme, signature: await owner2.signHash(challenge) }] } };
  push(rotation, branch);
  push(await lib.signControlEvent(owner2, agent(2, 5), DOMAIN, heads.at(-1), "sha256"), branch);

  const historyId = heads[0].hash;
  const at = (head) => ({ hash: head.hash, position: head.position });
  const statement = (head, previousHead) => ({ version: lib.HEAD_STATEMENT_VERSION, historyId, domain: DOMAIN, head, previous: previousHead === null ? null : at(previousHead) });
  const statements = {
    s0: await lib.signHeadStatement(owner1, statement(heads[0], null)),
    s2: await lib.signHeadStatement(owner1, statement(heads[2], heads[0])),
    thief: await lib.signHeadStatement(owner1, statement(thief.heads[4], heads[2])),
    chain: await lib.signHeadStatement(owner1, statement(heads[4], heads[2])),
    s5: await lib.signHeadStatement(owner2, statement(heads[5], heads[4])),
  };
  const i = (n) => firstIndex + n;
  const leaf = (n) => ({ ...base(i(n)), historyId });
  const entries = [
    { ...leaf(0), kind: "REGISTERED", genesis },
    { ...leaf(1), kind: "HEAD", signedStatement: statements.s0 },
    { ...leaf(2), kind: "HEAD", signedStatement: statements.s2 },
    { ...leaf(3), kind: "HEAD", signedStatement: statements.thief },
    {
      ...leaf(4), kind: "SUPERSEDED", rotation, previousHead: at(heads[3]), rotationHead: at(heads[4]), chain: statements.chain,
      supersededFromIndex: i(2), supersededToIndex: i(4), supersededLatest: { position: 4, hash: thief.heads[4].hash, index: i(3) }, supersededCount: 1,
    },
    { ...leaf(5), kind: "HEAD", signedStatement: statements.chain },
    { ...leaf(6), kind: "ROTATED", rotation, previousHead: at(heads[3]), rotationHead: at(heads[4]) },
    { ...leaf(7), kind: "HEAD", signedStatement: statements.s5 },
  ];
  return {
    events, heads, thief, rotation, historyId, statements, statement, entries, owner3Pair,
    ownerKeyEpochs: [
      { fromPosition: 0, keys: ownerKeys1, nextKeyDigests: genesis.data.nextKeyDigests },
      { fromPosition: 5, keys: [ownerKeyOf(owner2Pair)], nextKeyDigests: rotation.data.nextKeyDigests },
    ],
  };
}

/** Owner keys in effect at `position` for an epoch list `[{fromPosition, keys}]` (the last epoch starting at or before it). */
export const keysAt = (epochs, position) => {
  let keys = [];
  for (const epoch of epochs) if (epoch.fromPosition <= position) keys = epoch.keys;
  return keys;
};

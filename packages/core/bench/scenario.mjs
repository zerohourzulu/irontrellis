// Shared scenario generator for the benchmarks: the same deterministic mix of
// principals, agents, roles, sessions, grants, delegations, prohibitions,
// revocations, intents and (format 1) runtime-signed admissions that
// bench/replay.mjs builds. Kept in one place so authorize.mjs and append.mjs
// measure the same history.
const { applyEvent, createReplayState } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const authority = await import("../src/authority.ts");
const { hashCanonical } = await import("../src/hash.ts");
const suites = await import("../src/crypto/suites.ts");

export const owner = suites.generateKeyPair("ed25519", "owner:bench");
const signOwner = suites.signHashWith(owner);

export const domainFor = (format) =>
  format === "irontrellis-event/1"
    ? { protocol: "irontrellis", version: "1", deploymentId: "deployment:bench" }
    : { protocol: "continuity", version: "0.2", deploymentId: "deployment:bench", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000001" };

export const genesisFor = (format) => {
  const trellis = format === "irontrellis-event/1";
  return {
    domain: domainFor(format), adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E1, canonicalLineageId: "lineage:bench", policyVersion: "policy:bench/1",
    versions: trellis ? { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" } : events.LEGACY_VERSIONS,
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:bench", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    ...(trellis ? { ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }], capacity: { maxEvents: null } } : {}),
  };
};

/** Builds `target` events and returns them with the state they replay to. */
export const scenario = async (format, target) => {
  const trellis = format === "irontrellis-event/1";
  const domain = domainFor(format);
  const genesis = genesisFor(format);
  const state = createReplayState(format);
  const history = [];
  let clock = 0;
  const full = () => history.length >= target;
  const add = async (type, data) => {
    if (full()) return undefined;
    const id = `e:${history.length}`;
    const timestamp = clock++;
    let payload = data;
    if (trellis && history.length > 0 && events.isControlEvent(type)) {
      const hash = events.controlAuthorizationHash({ domain, eventId: id, eventType: type, timestamp,
        previousHead: { hash: state.head.hash, position: state.head.position }, effectHash: hashCanonical(data, "sha256") }, "sha256");
      payload = { ...data, controlAuthorization: { keyId: owner.keyId, signature: await signOwner(hash) } };
    }
    const event = { id, type, timestamp, data: payload };
    const result = applyEvent(state, event);
    if (!result.ok) throw new Error(`${type} at ${history.length}: ${result.code} ${result.reason}`);
    history.push(event);
    return event;
  };
  await add("DEPLOYMENT_INITIALIZED", genesis);
  await add("PRINCIPAL_CREATED", { principalId: "owner" });
  const agents = [], runtimes = new Map();
  const constraints = (extra = {}) => ({ actions: ["read", "write"], resources: ["doc:*"], quantitative: false, maxDelegationDepth: 3, requiredIntersectionIds: [], ...extra });
  let grants = 0, intents = 0, admissions = 0, revocations = 0;
  while (history.length < target) {
    const n = agents.length;
    const agent = `agent:${n}`;
    agents.push(agent);
    await add("AGENT_CREATED", { agentId: agent, principalId: "owner", controllerId: "controller", initialControlEpoch: 1 });
    await add("ROLE_CREATED", { roleId: `role:${n}`, principalId: "owner", exclusive: true });
    await add("AGENT_APPOINTED", { agentId: agent, roleId: `role:${n}`, roleTenureId: `tenure:${n}`, tenureNumber: 1, principalId: "owner" });
    if (trellis) {
      const runtime = suites.generateKeyPair("ed25519", `runtime:${n}`);
      runtimes.set(agent, runtime);
      await add("RUNTIME_SESSION_ADMITTED", { sessionId: `session:${n}`, agentId: agent, controllerId: "controller", controlEpoch: 1, credentialKeyId: `key:${n}`, credentialScheme: "ed25519", credentialPublicKey: runtime.credential });
    } else {
      await add("RUNTIME_SESSION_ADMITTED", { sessionId: `session:${n}`, agentId: agent, controllerId: "controller", controlEpoch: 1, credentialKeyId: `key:${n}`, credentialAddress: `0x${String(n).padStart(40, "0")}` });
    }
    await add("AUTHORITY_GRANTED", { grant: { kind: "PERMISSION", authorityId: `root:${n}`, grantorId: "owner", granteeId: agent, rootAuthorityId: `root:${n}`, independent: true, constraints: constraints() } });
    grants += 1;
    if (n > 0) {
      await add("AUTHORITY_GRANTED", { grant: { kind: "PERMISSION", authorityId: `delegated:${n}`, grantorId: `agent:${n - 1}`, granteeId: agent, rootAuthorityId: `root:${n - 1}`, parentAuthorityId: `root:${n - 1}`, independent: true,
        constraints: constraints({ actions: ["read"], maxDelegationDepth: 1 }) } });
      await add("AUTHORITY_GRANTED", { grant: { kind: "PROHIBITION", scope: "ROOT", authorityId: `prohibit:${n}`, grantorId: "owner", rootAuthorityId: `root:${n}`, subjectActorId: agent,
        constraints: constraints({ actions: ["write"], resources: ["doc:*"], maxDelegationDepth: 0 }) } });
      grants += 2;
      if (n % 4 === 0) { await add("AUTHORITY_REVOKED", { authorityId: `delegated:${n - 1}`, revokerId: "owner" }); revocations += 1; }
    }
    for (let k = 0; k < 3 && !full(); k += 1) {
      const intentId = `intent:${n}:${k}`;
      await add("TRANSACTION_INTENT_DECLARED", { intentId, nonce: `nonce:${n}:${k}`, actorId: agent, action: "read", resource: "doc:*", roleId: `role:${n}`, roleTenureId: `tenure:${n}`, adapterProfile: editions.knownAdapterProfile("adapter:simulated") });
      intents += 1;
      if (trellis && k === 0) {
        const request = { actorId: agent, action: "read", resource: "doc:*", claimedAt: clock };
        const binding = { runtimeSessionId: `session:${n}`, credentialKeyId: `key:${n}`, controlEpoch: 1, roleId: `role:${n}`, roleTenureId: `tenure:${n}`, intentId, nonce: `nonce:${n}:${k}` };
        const challenge = authority.createRuntimeAuthorizationChallenge({ domain, request, evaluationTime: clock, policyVersion: genesis.policyVersion, historyHead: state.head, binding });
        const hash = authority.hashRuntimeAuthorizationChallenge(challenge, "sha256");
        const runtimeSignature = await suites.signHashWith(runtimes.get(agent))(hash);
        const result = authority.authorizeState(state, { expectedHistoryHead: state.head, domain, policyVersion: genesis.policyVersion, rootRecognitionPolicy: "declared-principal-root/0.2",
          request, evaluationTime: clock, consequential: true, binding: { ...binding, runtimeSignature } });
        if (result.decision !== "ALLOW") throw new Error(`authorize: ${result.decision} ${result.code}`);
        await add("TRANSACTION_INTENT_ADMITTED", { intentId, evaluationTime: clock, expectedHistoryHead: state.head, authorizationProof: result.proof, runtimeAuthorizationHash: hash, runtimeSignature });
        admissions += 1;
      }
    }
    if (n % 5 === 4) await add("CONTROL_EPOCH_ADVANCED", { agentId: agent, controllerId: "controller", fromEpoch: 1, toEpoch: 2 });
    if (trellis && n % 50 === 49) await add("ANCHOR_RECORDED", { anchoredHead: state.head, anchor: "local-head-file", receipt: { note: "bench" }, anchoredAt: clock });
  }
  return { history, state, genesis, domain, stats: { agents: agents.length, grants, intents, admissions, revocations }, clock };
};

export const median = (values) => [...values].sort((a, b) => a - b)[Math.floor(values.length / 2)];
export const fmt = (ms) => (ms < 1 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(2)} ms`);

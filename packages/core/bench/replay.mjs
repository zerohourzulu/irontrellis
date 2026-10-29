// Replay benchmark: builds synthetic histories (format 1 with ed25519-signed
// control events and runtime-signed admissions; legacy at the 4096-event
// canonical cap) and reports replay throughput and incremental append latency.
//   node --experimental-strip-types bench/replay.mjs [eventCount]
const { replay, applyEvent, createReplayState } = await import("../src/replay.ts");
const events = await import("../src/events.ts");
const editions = await import("../src/adapter-editions.ts");
const authority = await import("../src/authority.ts");
const { hashCanonical } = await import("../src/hash.ts");
const suites = await import("../src/crypto/suites.ts");

const TARGET = Number(process.argv[2] ?? 10_000);
const owner = suites.generateKeyPair("ed25519", "owner:bench");
const signOwner = suites.signHashWith(owner);

/** A deterministic scenario generator: principals, agents, roles, sessions, grants, delegations, revocations, intents and admissions. */
const scenario = async (format, target) => {
  const trellis = format === "irontrellis-event/1";
  const domain = trellis
    ? { protocol: "irontrellis", version: "1", deploymentId: "deployment:bench" }
    : { protocol: "continuity", version: "0.2", deploymentId: "deployment:bench", chainId: "31337", verifyingContract: "0x0000000000000000000000000000000000000001" };
  const genesis = {
    domain, adapterPolicyHash: editions.ADAPTER_POLICY_HASHES.E1, canonicalLineageId: "lineage:bench", policyVersion: "policy:bench/1",
    versions: trellis ? { ...events.TRELLIS_VERSIONS, signatureScheme: "ed25519" } : events.LEGACY_VERSIONS,
    rootRecognitionPolicy: "declared-principal-root/0.2", globalPolicySourceId: "policy-source:bench", timeSource: "EVENT_TIMESTAMP", finality: "LOCAL_ONLY",
    ...(trellis ? { ownerKeys: [{ keyId: owner.keyId, scheme: "ed25519", credential: owner.credential }], capacity: { maxEvents: null } } : {}),
  };
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
      // Delegate from the previous agent, then grant a prohibition and revoke an older delegation.
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
  return { history, state, stats: { agents: agents.length, grants, intents, admissions, revocations } };
};

const measure = (label, fn, runs = 3) => {
  const times = [];
  let result;
  for (let i = 0; i < runs; i += 1) { const t = performance.now(); result = fn(); times.push(performance.now() - t); }
  console.log(`${label}: best ${Math.min(...times).toFixed(1)} ms, median ${times.sort((a, b) => a - b)[Math.floor(runs / 2)].toFixed(1)} ms`);
  return result;
};

for (const [format, target] of [["irontrellis-event/1", TARGET], ["continuity-event/0.2", Math.min(TARGET, 4096)]]) {
  const t0 = performance.now();
  const { history, state, stats } = await scenario(format, target);
  console.log(`\n${format}: built ${history.length} events in ${(performance.now() - t0).toFixed(0)} ms (${JSON.stringify(stats)})`);
  const result = measure(`replay ${history.length} events`, () => replay(history));
  if (result.status !== "ACCEPTED") throw new Error(`replay rejected: ${result.code} ${result.reason} at ${result.position}`);
  if (result.head.hash !== state.head.hash) throw new Error("head mismatch between incremental build and replay");
  const byType = new Map();
  const profiled = createReplayState(format);
  for (const event of history) {
    const t = performance.now();
    applyEvent(profiled, event);
    const entry = byType.get(event.type) ?? { count: 0, ms: 0 };
    entry.count += 1; entry.ms += performance.now() - t;
    byType.set(event.type, entry);
  }
  for (const [type, { count, ms }] of [...byType].sort((a, b) => b[1].ms - a[1].ms)) console.log(`  ${type.padEnd(30)} ${String(count).padStart(5)} × ${(ms / count * 1000).toFixed(0).padStart(5)} µs = ${ms.toFixed(0).padStart(5)} ms`);
  // Incremental append latency: the cost of one more event on top of the full state.
  const last = history[history.length - 1];
  const prefixState = createReplayState(format);
  for (const event of history.slice(0, -1)) applyEvent(prefixState, event);
  const t1 = performance.now();
  const appended = applyEvent(prefixState, last);
  console.log(`applyEvent of event #${history.length - 1} (${last.type}): ${(performance.now() - t1).toFixed(3)} ms (${appended.ok ? "ok" : appended.code})`);
}

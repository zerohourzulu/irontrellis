/**
 * T5's twin builder and comparison projection (BUILD §4; SPEC §16.3 as a test technique).
 *
 * `transcribeLegacyToFormat2(legacyEvents, options)` turns a legacy (`continuity-event/0.2`) history built by frozen
 * reference-0.3 into a format-2 history with the same ids, types, timestamps and effects: the genesis carries the format-2
 * literals and an owner key; every control event is re-signed over the `/2` chain; declarations gain a session-signed
 * `declarationAuthorization`; admissions are re-derived and re-signed over the format-2 runtime challenge; administrative
 * events (duty creation, assignment, review, observation, policy activation) are re-produced over the format-2 heads with
 * the `/2` administrative challenge; observations re-create their acknowledgment for the format-2 adapter identity;
 * activations re-derive their descriptor (format-2 domain and genesis hash) and the grants naming the descriptor hash are
 * rewritten; findings are re-made through the two-phase producer (attester signature, then the outer signature).
 * Everything is produced by the IronTrellis engine's own producers, so the twin is what the engine would have written.
 *
 * `project(value, context)` is the BUILD §4 comparison projection with the hash normalization the two chains require:
 * Amount markers → strings, the `/0.2` and `/2` literals → one token, the format-2-only fields removed, every per-position
 * history hash and event content hash → a position token (`#H<p>` / `#E<p>`), every other 32-byte hash or signature →
 * an alpha-renamed token in first-occurrence order (the two engines' descriptor, finding, index and proof hashes differ by
 * construction: different domain, genesis hash and hash algorithm), the domain → its `deploymentId`, `scope.versions` dropped.
 * After the projection the answers must be byte-identical.
 */
const core = await import("../../src/index.ts");
const { canonicalEncode, hashCanonical, replay, createReplayState, applyEvent, wireAmounts, FORMAT2_VERSIONS, signControlEvent, intentDeclarationHash, createRuntimeAuthorizationChallenge, hashRuntimeAuthorizationChallenge, proposeIntentAdmissionState, INTENT_ADMISSION_VERSION, produceAdministrativeEventState, prepareDutyFinding, attachDutyFinding, deriveDutyPolicyDescriptor, createRemoteServiceReportAcknowledgment, CONTROL_EVENT_TYPES, eventHash } = core;
const { generateKeyPair, signHashWith } = await import("../../src/crypto/suites.ts");

const plain = (v) => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x)));
const ADMINISTRATIVE = new Set(["OBLIGATION_CREATED", "OBLIGATION_PERFORMANCE_ASSIGNED", "OBLIGATION_STATUS_RECORDED", "OUTCOME_OBSERVATION_RECORDED", "ATTEMPT_DUTY_CREATED", "ATTEMPT_DUTY_ASSIGNED", "ATTEMPT_DUTY_REVIEW_CLOSED", "ATTEMPT_DUTY_POLICY_ACTIVATED"]);
const FINDINGS = new Set(["ATTEMPT_DUTY_DISPOSITION_RECORDED", "ATTEMPT_DUTY_CONTEST_RECORDED"]);

/** An owner signer for the twin (EIP-191, the deployment's suite). */
export function twinOwner(keyId = "owner:1") {
  const pair = generateKeyPair("eip191-personal-sign-keccak256", keyId);
  const sign = signHashWith(pair);
  return Object.freeze({ keyId, scheme: pair.scheme, credential: pair.credential, signHash: (hash) => sign(hash), pair });
}

/**
 * Transcribes `legacy` (an accepted legacy history) to format 2. `options.sessions` maps a session id to its `signHash`
 * (default: `options.sign` for every session). Returns the format-2 events and the final IronTrellis state.
 */
export async function transcribeLegacyToFormat2(legacy, options) {
  const owner = options.owner ?? twinOwner();
  const signerOf = (sessionId) => options.sessions?.[sessionId] ?? options.sign;
  const state = createReplayState("irontrellis-event/2");
  const out = [];
  const accept = (event) => {
    const result = applyEvent(state, event);
    if (!result.ok) throw new Error(`twin refused at ${out.length} (${event.type} ${event.id}): ${result.code} ${result.reason}`);
    out.push(result.event);
    return result.event;
  };
  // Selections of every activation, by their legacy descriptor hash (grants naming it are rewritten once the format-2 descriptor is derivable).
  const activations = new Map();
  for (const s of options.selections ?? []) activations.set(s.legacyHash, { dutyId: s.dutyId, incidentSourceDigest: s.incidentSourceDigest, acceptedAttesterRoleId: s.acceptedAttesterRoleId });
  for (const e of legacy) if (e.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") activations.set(e.data.descriptorHash, { dutyId: e.data.descriptor.dutyId, incidentSourceDigest: e.data.descriptor.incidentSourceDigest, acceptedAttesterRoleId: e.data.descriptor.acceptedAttesterRoleId });
  const format2Hash = (legacyHash) => {
    const selection = activations.get(legacyHash);
    if (selection === undefined) return undefined;
    const descriptor = deriveDutyPolicyDescriptor(state, selection);
    return descriptor === undefined ? undefined : hashCanonical(descriptor, "sha256");
  };
  const rewriteResource = (resource) => {
    const m = /^(duty-policy|duty):(0x[0-9a-f]{64})$/.exec(resource);
    if (m === null) return resource;
    const hash = format2Hash(m[2]);
    return hash === undefined ? resource : `${m[1]}:${hash}`;
  };
  const sessionBinding = (sessionId) => {
    const session = state.runtimeSessions.get(sessionId);
    if (session === undefined) throw new Error(`twin: session ${sessionId} unknown at ${out.length}`);
    return { runtimeSessionId: sessionId, credentialKeyId: session.credentialKeyId, controlEpoch: session.controlEpoch };
  };
  const admissionSessionFor = (intentId, from) => {
    const admission = legacy.slice(from).find((e) => e.type === "TRANSACTION_INTENT_ADMITTED" && e.data.intentId === intentId);
    return admission?.data.authorizationProof.runtimeSessionId;
  };
  for (let p = 0; p < legacy.length; p += 1) {
    const e = legacy[p];
    const d = plain(e.data);
    if (p === 0) {
      const { domain, versions: _v, policyVersion: _p, ...rest } = d;
      accept({ id: e.id, type: e.type, timestamp: e.timestamp, data: {
        ...rest, domain: { protocol: "irontrellis", version: "2", deploymentId: domain.deploymentId }, policyVersion: "irontrellis-local-owner/2",
        versions: { ...FORMAT2_VERSIONS, signatureScheme: "eip191-personal-sign-keccak256" }, ownerKeys: [{ keyId: owner.keyId, scheme: owner.scheme, credential: owner.credential }],
      } });
      continue;
    }
    if (CONTROL_EVENT_TYPES.has(e.type)) {
      let data = d;
      if (e.type === "RUNTIME_SESSION_ADMITTED") data = { ...d, credentialScheme: "eip191-personal-sign-keccak256", credentialAddress: String(d.credentialAddress).toLowerCase() };
      if (e.type === "AUTHORITY_GRANTED" && d.grant.constraints?.resources !== undefined) data = { ...d, grant: { ...d.grant, constraints: { ...d.grant.constraints, resources: d.grant.constraints.resources.map(rewriteResource) } } };
      accept(await signControlEvent(owner, { id: e.id, type: e.type, timestamp: e.timestamp, data: wireAmounts(data) }, state.genesis.domain, state.head, "sha256"));
      continue;
    }
    if (e.type === "TRANSACTION_INTENT_DECLARED") {
      const sessionId = admissionSessionFor(d.intentId, p) ?? state.runtimeSessionIdsByAgent.get(d.actorId)?.[0];
      const binding = sessionBinding(sessionId);
      const fields = wireAmounts(d);
      const hash = intentDeclarationHash(state.genesis.domain, fields, { hash: state.head.hash, position: state.head.position }, binding, e);
      const signature = await signerOf(sessionId)(hash);
      accept({ id: e.id, type: e.type, timestamp: e.timestamp, data: { ...fields, declarationAuthorization: { ...binding, hash, signature } } });
      continue;
    }
    if (e.type === "TRANSACTION_INTENT_ADMITTED") {
      const proof = d.authorizationProof;
      const binding = { runtimeSessionId: proof.runtimeSessionId, credentialKeyId: proof.credentialKeyId, controlEpoch: proof.controlEpoch, roleId: proof.roleId, roleTenureId: proof.roleTenureId, intentId: proof.intentId, nonce: proof.nonce };
      const request = wireAmounts(proof.request);
      const challenge = createRuntimeAuthorizationChallenge({ domain: state.genesis.domain, request, evaluationTime: proof.evaluationTime, policyVersion: state.genesis.policyVersion, historyHead: state.head, binding });
      const runtimeSignature = await signerOf(proof.runtimeSessionId)(hashRuntimeAuthorizationChallenge(challenge, "sha256"));
      const proposal = proposeIntentAdmissionState(state, {
        operationVersion: INTENT_ADMISSION_VERSION, expectedHistoryHead: state.head, admissionEventId: e.id, domain: state.genesis.domain, policyVersion: state.genesis.policyVersion,
        request, evaluationTime: proof.evaluationTime, binding: { ...binding, runtimeSignature },
      });
      if (proposal.status !== "PROPOSED") throw new Error(`twin: admission ${e.id} not proposed: ${JSON.stringify(plain(proposal)).slice(0, 300)}`);
      if (proposal.admissionEvent.timestamp !== e.timestamp) throw new Error(`twin: admission timestamp ${proposal.admissionEvent.timestamp} ≠ ${e.timestamp}`);
      accept(proposal.admissionEvent);
      continue;
    }
    if (ADMINISTRATIVE.has(e.type)) {
      const { administrativeAuthorization, ...effect } = d;
      const sessionId = administrativeAuthorization.challenge.runtimeSessionId;
      let data = effect;
      if (e.type === "OUTCOME_OBSERVATION_RECORDED") {
        const identity = state.intentAdmissions.get(d.intentId)?.adapterIdentity;
        data = { ...effect, acknowledgment: createRemoteServiceReportAcknowledgment(identity, d.acknowledgment.result.reportDigest.value) };
      }
      if (e.type === "ATTEMPT_DUTY_POLICY_ACTIVATED") {
        const descriptor = deriveDutyPolicyDescriptor(state, { dutyId: d.descriptor.dutyId, incidentSourceDigest: d.descriptor.incidentSourceDigest, acceptedAttesterRoleId: d.descriptor.acceptedAttesterRoleId });
        if (descriptor === undefined) throw new Error(`twin: descriptor of ${e.id} does not derive`);
        data = { ...effect, descriptor, descriptorHash: hashCanonical(descriptor, "sha256") };
      }
      const produced = await produceAdministrativeEventState(state, { expectedDomain: state.genesis.domain, expectedHistoryHead: state.head, runtimeSessionId: sessionId, transition: { id: e.id, type: e.type, timestamp: e.timestamp, data } }, { signHash: (hash) => signerOf(sessionId)(hash) });
      accept(produced.event);
      continue;
    }
    if (FINDINGS.has(e.type)) {
      const c = d.finding.challenge, outerSession = d.administrativeAuthorization.challenge.runtimeSessionId;
      const request = { dutyId: d.dutyId, actorId: d.actorId, attesterId: c.attesterId, attesterRuntimeSessionId: c.runtimeSessionId, attestationAuthorityId: c.attestationAuthorityId, dispositionAuthorityId: d.dispositionAuthorityId, operation: c.operation };
      const input = { expectedDomain: state.genesis.domain, expectedHistoryHead: state.head, runtimeSessionId: outerSession, transition: { id: e.id, type: e.type, timestamp: e.timestamp, data: request } };
      const prepared = prepareDutyFinding(state, input);
      const attached = attachDutyFinding(state, input, await signerOf(c.runtimeSessionId)(prepared.signingHash));
      const produced = await produceAdministrativeEventState(state, attached, { signHash: (hash) => signerOf(outerSession)(hash) });
      accept(produced.event);
      continue;
    }
    throw new Error(`twin: no transcription for ${e.type} at ${p}`);
  }
  return { events: out, state, owner };
}

// ---------------------------------------------------------------- the comparison projection

const LITERALS = new Map([
  ["continuity-authorization-proof/0.2", "#proof"], ["irontrellis-authorization-proof/2", "#proof"],
  ["continuity-runtime-authorization/0.2", "#runtime"], ["irontrellis-runtime-authorization/2", "#runtime"],
  ["continuity-administrative-authorization/0.2", "#admin"], ["irontrellis-administrative-authorization/2", "#admin"],
  ["continuity-event/0.2", "#event"], ["irontrellis-event/2", "#event"],
  ["continuity-local-owner/0.3-preview.1", "#policy"], ["irontrellis-local-owner/2", "#policy"],
  ["continuity-receipt/0.2", "#receipt"], ["irontrellis-receipt/2", "#receipt"],
]);
const DROPPED_KEYS = new Set(["versions", "budgetId", "stateRoot", "projectionHead"]);
const HASH = /^0x[0-9a-f]{64}$/, SIGNATURE = /^0x[0-9a-f]{128,130}$/;

/** The per-position tokens of a replayed state (legacy: the reference state; format 2: the IronTrellis state). */
export function positionTokens(events, { legacy }) {
  const tokens = new Map();
  if (legacy) {
    const { hashEventHistory, hashCanonical: refHash } = legacy;
    for (let p = 0; p < events.length; p += 1) {
      tokens.set(hashEventHistory(events.slice(0, p + 1)), `#H${p}`);
      tokens.set(refHash(events[p]), `#E${p}`);
    }
  } else {
    const state = replay(events).state;
    for (let p = 0; p < events.length; p += 1) {
      tokens.set(state.eventHistoryHashes[p], `#H${p}`);
      tokens.set(eventHash(events[p]), `#E${p}`);
    }
  }
  return tokens;
}

/** The projection: a plain JSON value with every engine-specific byte replaced by a token (see the header). */
export function project(value, tokens) {
  const alpha = new Map();
  const token = (prefix, s) => {
    const known = tokens.get(s);
    if (known !== undefined) return known;
    let t = alpha.get(s);
    if (t === undefined) { t = `${prefix}${alpha.size}`; alpha.set(s, t); }
    return t;
  };
  const visit = (v) => {
    if (typeof v === "bigint") return v.toString();
    if (typeof v === "string") {
      const literal = LITERALS.get(v);
      if (literal !== undefined) return literal;
      if (HASH.test(v)) return token("#X", v);
      if (SIGNATURE.test(v)) return token("#SIG", v);
      const m = /^(duty-policy|duty):(0x[0-9a-f]{64})$/.exec(v);
      if (m !== null) return `${m[1]}:${token("#X", m[2])}`;
      return v;
    }
    if (Array.isArray(v)) return v.map(visit);
    if (v !== null && typeof v === "object") {
      if (typeof v.protocol === "string" && typeof v.version === "string" && typeof v.deploymentId === "string") return { deploymentId: v.deploymentId };
      const out = {};
      for (const key of Object.keys(v).sort()) {
        if (DROPPED_KEYS.has(key) || v[key] === undefined) continue;
        out[key] = visit(v[key]);
      }
      return out;
    }
    return v;
  };
  return visit(plain(value));
}
export const projected = (value, tokens) => canonicalEncode(project(value, tokens));

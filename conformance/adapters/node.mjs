#!/usr/bin/env node
/**
 * Conformance adapter for the IronTrellis engine (`@ramex-labs/irontrellis`).
 *
 * Implements conformance/legacy/ADAPTER.md: one JSON request per line on stdin,
 * one JSON response per line on stdout. Build the core first
 * (`cd packages/core && pnpm build`); the adapter imports the compiled `dist/`.
 *
 * Format-2 additions (SPEC-IRONTRELLIS-CORE-v2 §17, conformance/v2/README.md): `replay` also answers
 * `stateRoot` and `projectionHead`, `authorize` `budgetId`, `verify-attestation` `stateRootValid` and
 * `projectionValid` (all `null` / `true` for histories other than format 2), and the new ops `headroom`,
 * `export` and `duty-view` call the engine functions the SPEC names. Until the core exports one of
 * them, its op answers `{"ok":false,"error":"UNIMPLEMENTED: …"}`, so the runner lists the vector as an
 * ERROR and goes on to the next one.
 *
 * The regenerated suite (conformance/v2-regenerated/README.md) adds: a replay request may carry
 * `testCapacityLimits` (the test-only lowered hard limits of capacity.ts, applied for that request only); `verify-export`
 * answers the export-view verifier's report (A-53, A-65); `open-for-write` writes the given store files to a scratch
 * directory and reports what an owner write answers (FORMAT_READ_ONLY, SPEC §16.1).
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const core = await import('../../packages/core/dist/index.js');
// The TEST-ONLY capacity hook is not on a public subpath (step 5b review); this in-tree adapter loads its module file.
const { setCapacityLimitsForTests } = await import('../../packages/core/dist/capacity.js');
const store = await import('../../packages/core/dist/store.js');
const signerLib = await import('../../packages/core/dist/signer.js');

// Amounts arrive as {"$continuity.bigint":"…"} and must go back out the same way.
const revive = value => {
  if (value === null || typeof value !== 'object') return value;
  if (Object.hasOwn(value, '$continuity.bigint')) {
    if (Object.keys(value).length !== 1 || typeof value['$continuity.bigint'] !== 'string' ||
        !/^(0|-?[1-9][0-9]{0,77})$/.test(value['$continuity.bigint'])) {
      throw new Error('INVALID_QUANTITY_ENCODING');
    }
    const amount = BigInt(value['$continuity.bigint']);
    const max = (1n << 256n) - 1n;
    if (amount < -max || amount > max) throw new Error('INVALID_QUANTITY_ENCODING');
    return amount;
  }
  if (Array.isArray(value)) return value.map(revive);
  const out = Object.create(null);
  for (const [key, inner] of Object.entries(value)) out[key] = revive(inner);
  return out;
};
const encode = (_key, value) => (typeof value === 'bigint' ? { '$continuity.bigint': value.toString() } : value);
const plain = value => JSON.parse(JSON.stringify(value, encode));
// Format-2 results spell Amounts as decimal strings (SPEC §3.4), never as the legacy tag.
const plain2 = value => JSON.parse(JSON.stringify(value ?? null, (_key, inner) => (typeof inner === 'bigint' ? inner.toString() : inner)));
// Format-2 vectors carry decimal-string Amounts and never the marker: their events and requests go to the engine as they are, so a
// planted marker reaches the format-2 schema (SPEC §3.1, vector rejects-bigint-marker-amount) instead of being decoded here.
const isFormat2History = events => Array.isArray(events) && events[0]?.data?.versions?.eventSchemaVersion === 'irontrellis-event/2';
const reviveEvents = events => (isFormat2History(events) ? events : revive(events));

/** A format-2 engine function by its SPEC name, or an UNIMPLEMENTED adapter error while the core does not export it. */
const v2 = (name, op) => {
  if (typeof core[name] !== 'function') throw new Error(`UNIMPLEMENTED: op ${op} needs core.${name} (SPEC-IRONTRELLIS-CORE-v2 §17), which this core does not export`);
  return core[name];
};
const V2_OPS = { headroom: 'headroom', export: 'exportView', 'duty-view': 'inspectDutyPolicyState' };
/** The replayed state of a history a format-2 op reads; a rejected history is an adapter error, as for verify-attestation. */
const acceptedState = events => {
  const result = core.replay(reviveEvents(events));
  if (result.status !== 'ACCEPTED') throw new Error(`history rejected: ${result.code}`);
  return result;
};

const projectAuthorization = result => ({
  decision: result.decision,
  code: result.code ?? null,
  scopeAssurance: result.scopeAssurance ?? null,
  controllingAuthorityIds: plain(result.proof?.controllingAuthorityIds ?? null),
  failureCodes: (result.failures ?? []).map(failure => failure.code),
  budgetId: result.budgetId ?? null,
});

function handle(request) {
  const { op } = request;
  if (op === 'describe') {
    return {
      implementation: 'irontrellis-core',
      language: 'typescript',
      coreVersion: '1.0.0',
      levels: ['verifier', 'evaluator'],
      operations: ['replay', 'authorize', 'evaluate-authority', 'survives', 'verify-attestation', ...Object.entries(V2_OPS).filter(([, name]) => typeof core[name] === 'function').map(([op]) => op)],
      formats: [core.LEGACY_FORMAT, core.TRELLIS_FORMAT, ...(core.TRELLIS2_FORMAT === undefined ? [] : [core.TRELLIS2_FORMAT])],
    };
  }
  if (op === 'replay') {
    if (request.operationVersion !== core.REPLAY_VERSION) return { status: 'REJECTED', head: null };
    const result = withTestCapacityLimits(request.testCapacityLimits, () => core.replay(reviveEvents(request.events)));
    const accepted = result.status === 'ACCEPTED';
    // Format-1 facts a replay establishes (a vector declares them in `expect` when it tests them): the remote witnesses the
    // history binds, in binding order, the owner-signed witness policy minimum, and the next-key commitment of the owner keys in force.
    return {
      status: result.status, head: accepted ? plain(result.head) : null, code: accepted ? null : result.code,
      boundWitnesses: accepted ? result.state.boundWitnesses.map((w) => w.verifierKey) : null,
      boundPolicy: accepted ? plain(result.state.boundPolicy ?? null) : null,
      nextKeyDigests: accepted ? plain(result.state.ownerKeyEpochs.at(-1)?.nextKeyDigests ?? null) : null,
      // Format 2 (SPEC §17): rootAt(head.position) and the projection head; null unless the history is format 2 and accepted.
      stateRoot: accepted ? (result.stateRoot ?? null) : null,
      projectionHead: accepted ? (result.projectionHead ?? null) : null,
    };
  }
  if (op === 'verify-attestation') {
    // An owner head attestation against the history (SPEC §7.4): signed by an owner key in force at its position over this history's domain,
    // a prefix of the history, and (format 2) the state root and projection head at that position; both are true for other formats.
    const result = core.replay(reviveEvents(request.events));
    if (result.status !== 'ACCEPTED') throw new Error(`history rejected: ${result.code}`);
    const { signatureValid, prefix, stateRootValid, projectionValid, valid } = core.verifyHeadAttestationFacts(request.attestation, result.state);
    return { valid, signatureValid, prefix, stateRootValid, projectionValid };
  }
  if (op === 'authorize') {
    const format2 = isFormat2History(request.events);
    const input = {
      operationVersion: request.operationVersion,
      events: reviveEvents(request.events),
      expectedHistoryHead: request.expectedHistoryHead,
      domain: request.domain,
      policyVersion: request.policyVersion,
      rootRecognitionPolicy: request.rootRecognitionPolicy,
      request: format2 ? request.request : revive(request.request),
      evaluationTime: request.evaluationTime,
      authoritative: request.authoritative,
      consequential: request.consequential,
    };
    if (Object.hasOwn(request, 'binding')) input.binding = format2 ? request.binding : revive(request.binding);
    return projectAuthorization(core.authorizePortable(input, core.replay));
  }
  if (op === 'evaluate-authority') {
    // G6.5 A-136.4: the supplied-scope raw path (spec02 §7.1); the JSON input goes to the engine as it is (its capture
    // decodes the 0.2-transport `$continuity.bigint` markers and refuses a non-Amount, so nothing is revived here).
    return projectAuthorization(core.evaluateAuthorityPath(request.input));
  }
  if (op === 'headroom') {
    // SPEC §9.7: headroom(state, budgetId, at) → the record, or null for an unknown budget.
    const headroom = v2(V2_OPS.headroom, op);
    return plain2(headroom(acceptedState(request.events).state, request.budgetId, request.at));
  }
  if (op === 'export') {
    // SPEC §15 names exportView(store, options); the engine port decides how the adapter hands it the captured events.
    const exportView = v2(V2_OPS.export, op);
    const view = plain2(exportView(reviveEvents(request.events), { fromPosition: request.fromPosition, toPosition: request.toPosition, include: request.include }));
    for (const key of ['events', 'checkpoints', 'fromRecords', 'toRecords', 'inclusion']) delete view[key];
    return view;
  }
  if (op === 'duty-view') {
    // SPEC §13.3: inspectDutyPolicyState(state, dutyId) → the continuity-attempt-duty-view/1 record, or null (E4).
    const inspect = v2(V2_OPS['duty-view'], op);
    return plain2(inspect(acceptedState(request.events).state, request.dutyId));
  }
  if (op === 'verify-export') {
    // SPEC §15 / A-27 / A-53 / A-65: the verifier's report over a view as the vector carries it (JSON).
    const v = core.verifyExportView(request.view);
    const end = (e) => ({ position: e.position, stateRoot: e.stateRoot, verified: e.verified, authenticated: e.authenticated });
    return { ok: v.ok, code: v.code ?? null, missingPositions: v.missingPositions === undefined ? null : [...v.missingPositions], from: end(v.from), to: end(v.to), eventCount: v.eventCount };
  }
  if (op === 'open-for-write') return openForWrite(request);
  if (op === 'survives') {
    // This adapter answers a format-2 history through the state API (observeHistory) at the request's evaluation time,
    // and the other formats through the portable query envelope (continuity-query-envelope/0.2).
    const result = isFormat2History(request.events)
      ? core.observeHistory(request.events, { at: request.evaluationTime }).survives(request.targetAgentId)
      : core.survivesPortable({
        operationVersion: request.operationVersion,
        observedEvents: reviveEvents(request.events),
        targetAgentId: request.targetAgentId,
        evaluationTime: request.evaluationTime,
        disclosure: core.publicQueryDisclosure('SURVIVES'),
      }, core.replay);
    if (!Object.hasOwn(result, 'answer')) {
      return { established: false, code: result.code, epistemicStatus: result.epistemicStatus };
    }
    const answer = result.answer;
    return {
      established: true,
      exists: answer.exists,
      lifecycleStatus: answer.lifecycleStatus,
      obligationIds: answer.obligations.map(row => row.obligationId).sort(),
      currentAssignments: answer.currentPerformanceAssignments.map(row => ({
        obligationId: row.obligationId, assigneeId: row.assigneeId, successionRuleId: row.successionRuleId ?? null,
      })),
      currentRoleTenureCount: answer.currentRoleTenures.length,
      transferredRoleTenureCount: answer.transferredRoleTenures.length,
      invalidatedAuthorityIds: answer.invalidatedAuthorityDependencies.map(row => row.authorityId).sort(),
      unresolvedIntentIds: answer.unresolvedIntents.map(row => row.intentId).sort(),
    };
  }
  throw new Error(`unsupported op: ${op}`);
}

/** A replay under the test-only lowered hard limits of capacity.ts (regenerated-suite vectors only); the SPEC limits are restored after. */
function withTestCapacityLimits(limits, fn) {
  if (limits === undefined) return fn();
  const keys = ['maxStateRecords', 'reservedStateRecords'];
  if (limits === null || typeof limits !== 'object' || Object.keys(limits).some((k) => !keys.includes(k)) || !keys.every((k) => Number.isSafeInteger(limits[k]) && limits[k] >= 0)) throw new Error('INVALID_INPUT: testCapacityLimits');
  setCapacityLimitsForTests(limits);
  try { return fn(); } finally { setCapacityLimitsForTests(); }
}

/** SPEC §16.1 / A-41: what an owner write answers for a history given as store files (`lines`, optional `pin` and `marker`, optional `ownerKey`). */
async function openForWrite({ lines, pin, marker, ownerKey }) {
  const dir = mkdtempSync(join(tmpdir(), 'irontrellis-adapter-open-'));
  try {
    const historyFile = join(dir, 'history.jsonl');
    writeFileSync(historyFile, lines);
    if (pin !== undefined) writeFileSync(`${historyFile}.head`, pin);
    if (marker !== undefined) writeFileSync(store.migratedMarkerPathFor(historyFile), marker);
    const inspected = core.openHistoryStore(historyFile, { inspect: true, allowUnpinned: true }), state = inspected.state();
    inspected.close?.();
    const signer = ownerKey === undefined ? {} : { signer: signerLib.signerFromKeyPair(core.keyPairFromPrivateKey(ownerKey.scheme, ownerKey.keyId, ownerKey.seed)) };
    try {
      const owner = core.openLocalOwner({ historyFile, domain: state.genesis.domain, owner: state.events[1]?.data?.principalId ?? 'operations', controller: 'operator', now: () => state.head.canonicalTime + 1, ...signer });
      await owner.createAgent({ id: 'probe' });
      return { written: true, code: null, reason: null };
    } catch (error) {
      return { written: false, code: error.code ?? 'ERROR', reason: error.detail?.reason ?? null };
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

/**
 * One JSON request per line, and only `\n` ends a line (conformance/README.md). U+2028 and U+2029 are ordinary characters
 * inside JSON strings (JSON.stringify and the canonical text write them raw), and one trailing `\r` is dropped so CRLF
 * runners keep working; a raw `\r` cannot occur inside a JSON string. `readline` was used before and also ends lines at
 * U+2028, U+2029 and a lone `\r`, which cut a valid request in two (fuzz VAST-FUZZ-01 F2).
 */
async function* requestLines(input) {
  input.setEncoding('utf8');
  let pending = '';
  const strip = (line) => (line.endsWith('\r') ? line.slice(0, -1) : line);
  for await (const chunk of input) {
    pending += chunk;
    for (let end = pending.indexOf('\n'); end >= 0; end = pending.indexOf('\n')) {
      yield strip(pending.slice(0, end));
      pending = pending.slice(end + 1);
    }
  }
  if (pending !== '') yield strip(pending);
}

for await (const line of requestLines(process.stdin)) {
  if (line.trim() === '') continue;
  let response;
  try {
    const request = JSON.parse(line);
    // A-34: a format-2 request is parsed strictly (duplicate keys, non-integers, -0, lone surrogates → INVALID_INPUT).
    if (isFormat2History(request?.events)) { const problem = core.strictJsonProblem(line); if (problem !== undefined) throw new Error(`INVALID_INPUT: ${problem.message}`); }
    response = { ok: true, result: await handle(request) };
  }
  catch (error) { response = { ok: false, error: String(error?.message ?? error).slice(0, 500) }; }
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

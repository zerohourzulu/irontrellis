/**
 * A format-2 E5/E6 investigation case for the duty-policy tests (SPEC §13): the port of reference-0.3's
 * `tests/core-0.3/fixtures/{history,duty}-fixture.mjs` onto the IronTrellis API — owner `owner`, agents `worker` and
 * `replacement`, role `role` (tenure `tenure`, succession `succession`), session `session` (EIP-191 key 0x11…11, the
 * reference's known-public fixture key, so the same credential address appears in both engines), grants `work`
 * (inspect on incident, one transaction), `record` (the attempt actions) and `revoked`, a REMOTE_REPORT execution
 * `job` and the duty `duty` over it. `dutyFixture` adds the selection (`describe`), the activation input and the
 * `grant` helper of the reference's duty fixture; the clock is `setTime`, every signature is counted in `calls`.
 */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const core = await import("../../src/index.ts");
const { createLocalAttemptOwner, createLocalReviewOwner, createLocalDomain, openLocalExecution, commitTerms, openLocalAttemptRecorder, openLocalDutyPolicy } = core;
const { keyPairFromPrivateKey, signHashWith } = await import("../../src/crypto/suites.ts");

/** The reference's synthetic fixture credential (never a deployment credential). */
export const FIXTURE_KEY = keyPairFromPrivateKey("eip191-personal-sign-keccak256", "key", `0x${"11".repeat(32)}`);
export const signHash = signHashWith(FIXTURE_KEY);
/** A second runtime key: A-32.3 refuses one credential for two sessions. */
export const SECOND_KEY = keyPairFromPrivateKey("eip191-personal-sign-keccak256", "key:2", `0x${"22".repeat(32)}`);
export const signHashSecond = signHashWith(SECOND_KEY);
export const digest = Object.freeze({ algorithm: "sha256", value: `0x${"a".repeat(64)}` });
export const DIGEST = (n) => ({ algorithm: "sha256", value: `0x${n.repeat(64)}` });
export const KEYS = ["SOURCE_REVIEWED", "HISTORY_REVIEWED", "FINDING_RECORDED", "CONTROL_REVIEWED"];
export const checklist = () => Object.fromEntries(KEYS.map((k) => [k, { state: "SATISFIED", reason: "Reviewed; remaining outside uncertainty stated." }]));
export const unknownOutcome = (input) => { const identity = core.deriveAdapterIdentity(input); return { status: "OUTCOME_UNKNOWN", idempotencyKey: identity.idempotencyKey, submissionFingerprint: identity.submissionFingerprint }; };

export async function fixture(t, { policy = "E5", sign = signHash, workspace, maxEvents } = {}) {
  const dir = workspace ?? mkdtempSync(join(tmpdir(), "irontrellis-duty-"));
  if (t && workspace === undefined) t.after(() => rmSync(dir, { recursive: true, force: true }));
  let clock = 100, calls = 0;
  const signHashCounted = async (hash) => { calls += 1; return sign(hash); };
  // The deployment's signature scheme is EIP-191 (`versions.signatureScheme`): the admission binding shape follows it, so the
  // reference's EIP-191 session key works unchanged (the owner key is generated under the same suite).
  const config = { historyFile: join(dir, "history.jsonl"), domain: createLocalDomain(), owner: "owner", controller: "controller", now: () => clock, signatureScheme: "eip191-personal-sign-keccak256", ...(maxEvents === undefined ? {} : { maxEvents }) };
  const owner = await (policy === "E6" ? createLocalReviewOwner : createLocalAttemptOwner)(config);
  await owner.createAgent({ id: "worker" });
  await owner.createAgent({ id: "replacement" });
  await owner.createRole({ id: "role" });
  await owner.appoint({ agent: "worker", role: "role", tenure: "tenure", number: 1 });
  await owner.declareSuccession({ id: "succession", from: "worker", to: "replacement", role: "role" });
  await owner.admitRuntime({ agent: "worker", session: "session", epoch: 1, key: "key", address: FIXTURE_KEY.credential, scheme: "eip191-personal-sign-keccak256", expiresAt: 10000 });
  await owner.grant({ id: "work", to: "worker", actions: ["inspect"], resources: ["incident"], expiresAt: 10000, maxTransactions: 1 });
  await owner.grant({ id: "record", to: "worker", actions: ["OBLIGATE", "ASSIGN_PERFORMANCE", "record-collection-disposition", "OBSERVE_OUTCOME", "CREATE_ATTEMPT_DUTY", "ASSIGN_ATTEMPT_DUTY", "CLOSE_ATTEMPT_DUTY"], resources: ["incident", "job", "duty"], expiresAt: 10000 });
  await owner.grant({ id: "revoked", to: "worker", actions: ["export"], resources: ["incident"], expiresAt: 10000 });
  await owner.revoke("revoked");
  // The setup run and the duty creation sign with the plain fixture key (as the reference's `fixture`); the returned options
  // carry the caller's `sign` (counted), which only the duty-policy operations use.
  const setupOptions = { ...config, session: "session", signHash };
  const options = { ...config, session: "session", signHash: signHashCounted };
  const hash = policy === "E6" ? core.ADAPTER_POLICY_E6_HASH : core.ADAPTER_POLICY_E5_HASH;
  const adapter = { adapterProfile: core.approvedAdapterProfileForPolicy(hash, core.REMOTE_SERVICE_REPORT_ADAPTER_ID), submit: async (input) => unknownOutcome(input), reconcile: unknownOutcome };
  // A raw intent id (A-37.2): the fixtures name the job "job" (format 2 would otherwise derive it from the actor and the operation id).
  const op = { id: "job", intentId: "job", action: "inspect", resource: "incident", role: "role", tenure: "tenure", termsCommitment: commitTerms({ case: "synthetic" }) };
  const result = await openLocalExecution(setupOptions, adapter, "REMOTE_REPORT").run(op);
  await openLocalAttemptRecorder(setupOptions).createDuty({ id: "duty", intent: "job", description: "Investigate the unknown result", deadline: 10000 });
  calls = 0;
  return {
    dir, config, options, setupOptions, owner, op, result, adapter, policy,
    get events() { return owner.exportHistory(); },
    get calls() { return calls; },
    setTime: (at) => { clock = at; },
    now: () => clock,
    state: () => core.replay(owner.exportHistory()).state,
  };
}

/** The reference duty fixture: `describe` the duty for attester role `role`, the activation input and the exact activation grant. */
export async function dutyFixture(t, options = {}) {
  const f = await fixture(t, options);
  const duties = openLocalDutyPolicy(f.options);
  const selection = duties.describe({ duty: "duty", incidentSourceDigest: digest, attesterRole: "role" });
  const input = { id: "activate", descriptor: selection.descriptor, activationAuthority: "activation" };
  const grant = (changes = {}) => f.owner.grant({ id: "activation", to: "worker", actions: [selection.activationAction], resources: [selection.activationResource], expiresAt: 1000, ...changes });
  return { ...f, duties, selection, input, grant, get calls() { return f.calls; }, get events() { return f.events; } };
}

/** The reference disposition setup: an activated duty, the finding and disposition grants, the COMPLETED input and a contest builder. */
export async function dispositionFixture(t, { policy = "E5", findingGrant = true, dispositionGrant = true, sign = signHash } = {}) {
  const f = await dutyFixture(t, { policy, sign });
  await f.grant();
  await f.duties.activate(f.input);
  const resource = `duty:${f.selection.descriptorHash}`;
  if (findingGrant) await f.owner.grant({ id: "finding", to: "worker", actions: ["ATTEST_DUTY_FINDING"], resources: [resource], expiresAt: 1000 });
  if (dispositionGrant) await f.owner.grant({ id: "disposition", to: "worker", actions: ["RECORD_DUTY_DISPOSITION"], resources: [resource], expiresAt: 1000 });
  const input = { id: "complete", duty: "duty", disposition: "COMPLETED_UNDER_POLICY", checklist: checklist(), reportDigest: DIGEST("b"), nextStep: null, attestationAuthority: "finding", dispositionAuthority: "disposition" };
  const contest = (id) => ({ id, duty: "duty", targetDispositionId: "duty-disposition:complete", reason: "Incident material may have been incomplete.", reportDigest: DIGEST("c"), attestationAuthority: "finding", dispositionAuthority: "disposition" });
  const calls = [];
  const make = (finding, outer) => openLocalDutyPolicy({
    ...f.options, signHash: async (h) => { calls.push("outer"); return outer ? outer(h) : sign(h); },
    attester: { session: "session", signHash: async (h) => { calls.push("finding"); return finding ? finding(h) : sign(h); } },
  });
  return { ...f, f, resource, input, contest, calls, make, duties: make(), get events() { return f.events; } };
}

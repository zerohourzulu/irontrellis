# Runtime API contracts and worked inputs

Reference, selected from master `00ca4c0` `API.md`. See the [API guide](../API.md) for workflow and scope. Original section numbers in retained contracts refer to the baseline page; exact source ranges appear below. Current-format facts were checked against the engine when these pages were merged.

**Edition boundary:** Current writers target format 2. Legacy and format-1 files are read-only: writes refuse with `FORMAT_READ_ONLY`. Legacy/format-1 write clauses and the legacy→format-1 migration signature below are historical. The current creation and migration calls (`createLocalOwner`, `migrateHistory`, `migrationStatus`) are in [API](../API.md) §1 and §3. Read-only behavior and explicitly format-2 additions keep their stated scope.

**Historical worked example:** this requires the old format-1 `owner` and `base` setup from the exported API, which is not a current creation recipe. It is retained for input/output shapes, not to recommend format-1 writes; it was not rerun.

<!-- Source API.md:193-247; retained API contract -->

All runtime handles take `LocalOwnerOptions & { session: Id, signHash: SignHash }` where `SignHash = (hash: Hash) => Promise<HexSignature>` is the application's signing callback for the session's key (the private key never enters the history) and `session` is a `RUNTIME_SESSION_ADMITTED` session under this handle's controller (`RUNTIME_NOT_CURRENT` otherwise). The signature must have the session's suite's shape (128 hex for ed25519, 130 for eip191); a callback that throws or returns anything else is `SIGNER_FAILED`.

```js
import { openLocalSimulation, openLocalRuntime, commitTerms } from "@ramex-labs/irontrellis/local";
import { generateKeyPair, signHashWith } from "@ramex-labs/irontrellis";

await owner.createRole({ id: "role:responder" });
await owner.appoint({ agent: "bea", role: "role:responder", tenure: "tenure:bea:1", number: 1 });
await owner.createAgent({ id: "alex" });
await owner.declareSuccession({ id: "rule:bea-to-alex", from: "bea", to: "alex", role: "role:responder" });
// OBLIGATE is the administrative action a session needs to record a duty from its own operation.
// A new authority id: "collect" was revoked above, and an authority id is never reused.
await owner.grant({ id: "operate", to: "bea", actions: ["read", "collect", "OBLIGATE"], resources: ["incident:42"], expiresAt: Date.now() + 3_600_000 });

const key = generateKeyPair("ed25519", "key:bea:1");     // dev helper; production keys live with the application
await owner.admitRuntime({ session: "session:bea:1", agent: "bea", epoch: 1, key: key.keyId, credential: key.credential, expiresAt: Date.now() + 3_600_000 });

const session = { ...base, session: "session:bea:1", signHash: signHashWith(key) };
const simulation = openLocalSimulation(session);
const operation = { id: "operation:42", action: "collect", resource: "incident:42", role: "role:responder", tenure: "tenure:bea:1", termsCommitment: commitTerms({ ticket: 42 }) };
const run = await simulation.run(operation);
console.log(run.status, run.invocation.status);                      // SIMULATION_RESULT SUBMITTED
const receipt = await simulation.recordReceipt(operation);
console.log(receipt.status, receipt.recording.status);              // RECEIPT_RESULT ADMITTED

const duty = await openLocalRuntime(session).obligate({ id: "duty:42", operation: "operation:42", description: "close incident 42",
  deadline: Date.now() + 86_400_000, succession: "rule:bea-to-alex", reviewAuthority: "operate" });
console.log(owner.handover("bea").openDuties.map((d) => [d.kind, d.id, d.status]));   // [ [ 'OBLIGATION', 'duty:42', 'OPEN' ] ]
```

### `openLocalSimulation(options)` / `openLocalExecution(options, adapter, mode)`

For mode `REMOTE_REPORT`, `openLocalExecution` also takes optional dispatch hooks as a fourth argument; see [dispatch hooks and resumption](api-execution-dispatch.md).

`LocalExecutionOptions` adds `additionalPolicy?: AdditionalPolicy` (§9). `openLocalSimulation` is `openLocalExecution` with the deterministic simulated adapter and mode `"SIMULATION"`; `openLocalExecution` is the internal constructor behind the simulation and the evidence tool and takes a `TransactionAdapter` (`{ adapterProfile, submit(submission), reconcile(submission) }`) and a mode (`"SIMULATION" | "LOCAL_PACKET" | "REMOTE_REPORT"`); do not let an agent choose the adapter. The handle has `profile` (`EFFECT_FREE_SIMULATION` | `LOCAL_EVIDENCE_PACKET` | `REMOTE_REPORTED_OUTCOME`) and:

* `run(operation)` with `LocalOperation` = `{ id, action, resource, role, tenure, termsCommitment: Hash, amount?: bigint, counterparty? }`. Declares the intent (`TRANSACTION_INTENT_DECLARED`, id `operation:<hash>` bound to the first declaration; different arguments under the same id are `OPERATION_CONFLICT`), authorizes, signs the runtime challenge, re-checks the policy after the asynchronous boundary, admits through `DurableAdmissionCoordinator` (`TRANSACTION_INTENT_ADMITTED`) and invokes the adapter (`TRANSACTION_INTENT_CONSUMED` or `TRANSACTION_OUTCOME_RECORDED`). Result `status`: `SIMULATION_RESULT` / `EXECUTION_RESULT` (`{ operationId, externalEffect, admission, invocation }`), `RECONCILIATION_ONLY` (the operation was admitted earlier: the original attempt is reconciled, nothing is re-invoked), `NOT_AUTHORIZED` (`evidence`: the DENY/INDETERMINATE), `POLICY_REFUSED` (`policyIdentity`, `reason`), `NOT_ADMITTED` (`admission`). `invocation.status`: `SUBMITTED` | `FAILED` | `RETRY` (with `disposition`, `recorded: true`, `head`), `TERMINAL`, `OUTCOME_UNKNOWN`, `NOT_INVOKED`, `IDEMPOTENCY_FINGERPRINT_CONFLICT`. The whole path works on the store's cached replay state (`prepareState`, `recordState`, `createReceiptState`); it never takes an event snapshot or replays the history (§12).
* `recordReceipt(operation)`: creates a receipt artifact signed by the session over the actual consumption and records `RECEIPT_RECORDED`. Result `{ status: "RECEIPT_RESULT", artifact, recording }` or `{ status: "ALREADY_RECORDED", contentHash, eventId, artifactAvailable: false }`; `RECEIPT_UNAVAILABLE` when the intent was not admitted by this session or not consumed.

`commitTerms(terms)` hashes bounded data with keccak-256 (as Core 0.3 did) for `termsCommitment`; keep the terms themselves in application storage. `createSimulatedAdapter({ failIntentIds? })` builds the reference simulator (`attempts` exposes what it retained).

### `openLocalRuntime(options)`

* `obligate({ id, operation, description, deadline, succession, reviewAuthority })` records `OBLIGATION_CREATED` (`obligation:<id>:create`) from the session's own admitted, consumed and receipted operation whose intent carries a `termsCommitment` (`RECEIPT_UNAVAILABLE` otherwise). The session's agent must hold a permission for action `OBLIGATE` on the operation's resource in the operation's role tenure; `reviewAuthority` is the authority id that may later record a status change (`record-collection-disposition`) and `succession` the rule the duty follows.
* `assign({ id, obligation })` records `OBLIGATION_PERFORMANCE_ASSIGNED` (`assignment:<id>`) from the obligation's original assignee to the session's agent; needs a permission for action `ASSIGN_PERFORMANCE` on the obligation id.

A repeated call with the same id and the same effect observes the earlier event and writes nothing; a different effect under the same id is `OPERATION_CONFLICT`.

* `recordObservation({ source, call, decision?, observationId?, reconcilerAgentId? })` (format 2) records a `RECONCILIATION_OBSERVED` signed by this session ([HISTORY-FORMAT.md §14](../HISTORY-FORMAT.md)). The session's agent is the reconciler; a different `reconcilerAgentId` is `TRANSITION_REJECTED`. `source` is `{ streamId, eventRef, eventDigest }`, where `eventDigest` is your SHA-256 of the provider event in a serialization you keep stable per stream. `call` is `{ actorId, action?, resource?, observedAt?, amount? }`; whatever you leave out is recorded as not supplied. `decision` is `{ intentId }` or `{ refusalId }`: when the history holds that admission or refusal, the observation is `MATCHED` to it, otherwise `UNMATCHED`. Without `observationId`, the id is derived from the reconciler, the stream, the reference and the digest, so a repeat after a crash gets the same id. The result is `{ eventId, head, observationId, match, equivocates }`. If an observation with the same `(streamId, eventRef, eventDigest)` is already in the history, the call throws `OBSERVATION_DUPLICATE` before anything is signed; `detail.position` names the recorded one. Treat that code as "recorded": advance your own checkpoint only after a successful call or this code.

### `openLocalEvidenceTool(options)`

`EvidenceToolOptions` = `LocalExecutionOptions & { inputDirectory, outputDirectory, selection: EvidenceSelection, resource, role, tenure }`. A fixed file-copy operation over a pre-selected input set (`selectEvidence(inputDirectory)`, persist the selection) into `<outputDirectory>/<sha256(operationId)>/`. `collect({ operationId, resource })` runs it (`{ result, packet }`), `recordReceipt` and `inspect` as above. No caller paths, no adapter injection.

### `openLocalAttemptRecorder(options)` (`/attempts`)

For E5/E6 histories (`createLocalAttemptOwner` / `createLocalReviewOwner`; `PROFILE_MISMATCH` otherwise) and intents declared against the remote-service-report adapter: `observe({ id, intent, acknowledgment })` → `OUTCOME_OBSERVATION_RECORDED`; `createDuty({ id, intent, description, deadline })` → `ATTEMPT_DUTY_CREATED`; `assignDuty({ id, duty })` → `ATTEMPT_DUTY_ASSIGNED`; `reviewDuty({ id, duty, summaryDigest })` → `ATTEMPT_DUTY_REVIEW_CLOSED` (E6 only). Administrative actions: `OBSERVE_OUTCOME`, `CREATE_ATTEMPT_DUTY`, `ASSIGN_ATTEMPT_DUTY`, `CLOSE_ATTEMPT_DUTY` on the intent id. `inspectAttemptHistory(events)` is the replay-only report (`{ scope, executionCapability: false, head, attempts: [...] }`).

# Remote-report dispatch hooks and resumption

*Last reviewed: 14 October 2026.*

Reference for the [API guide](../API.md) §2. It covers one narrow problem. An operation can be admitted durably, which means IronTrellis has written down that it may happen. Then the process can stop before it calls the outside service, through a crash, a restart or a host that is still waiting for evidence. After that, two mistakes are possible. One is never calling the service, even though the admission said it could be called. The other is calling it twice. The hooks below let a trusted host wait before the call and, after a restart, try an admitted call that never started. They never allow a second attempt. These facts were checked against the engine source (`packages/core/src/execution.ts`, `coordinators.ts`) on the date above.

## `openLocalExecution` with dispatch hooks

`openLocalExecution(options, adapter, mode, dispatchHooks?)` takes an optional fourth argument of type `LocalExecutionDispatchHooks`. The hooks are accepted only with mode `"REMOTE_REPORT"`. With any other mode, or with a member of the wrong type, opening the handle fails.

| Member | Contract |
|---|---|
| `beforeInvoke(context)` | Async. Runs after the admission is durable and outside the history writer lock, so stops and power-reducing writes can still land while it waits. It must answer `{ status: "READY" }` before the adapter is called. Any other answer, or a thrown error, leaves the operation undispatched. It cannot confer authority and cannot call the adapter. |
| `noDispatchStart(operationId)` | Synchronous. Must return exactly `true` only when the host has proved that no attempt has started (no attempt-start record exists). Any other value is not proof of absence, and neither is a thrown error. |
| `resumeUndispatched?` | Optional boolean, on by default when hooks are supplied. `false` keeps the original reconciliation-only behavior for admitted operations. |

`context` is `{ operationId, intentId, admissionEventId, admissionHead, submissionIdentity: { idempotencyKey, submissionFingerprint }, resumed }`. `resumed` is `true` when the call is a resumption after a restart.

**Results.** A handle opened with hooks can return `{ status: "NOT_DISPATCHED", operationId, dispatchPerformed: false, reason }`. The `reason` is the one `beforeInvoke` gave, or `ACCESS_NOT_CURRENT` when it failed or gave no usable answer, or a resumption refusal (below). A resumed call that does reach the adapter returns `EXECUTION_RESULT` with `resumed: true`. If `noDispatchStart` throws for an admitted operation, the result is `RECONCILIATION_ONLY` with an `OUTCOME_UNKNOWN` outcome, never a new call. A handle opened without hooks keeps its original return type, which has no `NOT_DISPATCHED` member, and its reconciliation-only behavior.

**Exactly once.** If an admitted operation's attempt-start record exists, it is never invoked again, including after a restart. If no attempt-start record exists, the operation has not been dispatched, whatever waiting records exist. A later `run` of the same operation may then dispatch it once, after it passes the host's checks. Exactly-once comes from the exclusive creation of that attempt-start record, not from the process staying alive.

**What it does not record.** A delayed or undispatched call is an application report. It adds no Core refusal event and no spool entry. A resumed dispatch records its normal receipt and effect only after the actual call.

## `DurableAdmissionCoordinator.resumeInvocation`

`resumeInvocation({ intentId, admissionEventId, admissionHead, submissionIdentity, noDispatchStart })` rebuilds the right to try an existing admission, process-locally. It works under the history writer lock and in this order:

1. The adapter profile must be unchanged.
2. The request must be plain own data with exactly these five fields.
3. The admission must exist, with the same event id and the same head (hash, position and time).
4. The current history must still contain that admission head (otherwise `HISTORY_DIVERGED`).
5. The intent must still be open: no consumption, outcome, terminal record or effect, and no canceled obligation (otherwise `INTENT_NOT_OPEN`).
6. The submission identity is recomputed from the history and must match the caller's.
7. `noDispatchStart()` must return exactly `true` (otherwise `DISPATCH_STARTED`).

It answers `{ status: "RESUMABLE", capability }` or `{ status: "NOT_RESUMABLE", reason }`, where the reason is `ADMISSION_MISMATCH`, `HISTORY_DIVERGED`, `INTENT_NOT_OPEN`, `ADAPTER_PROFILE_CHANGED`, `DISPATCH_STARTED` or `UNAVAILABLE`. It appends nothing, submits nothing and does not expose a way to build a capability. `admit`, `invoke` and `reconcile` are unchanged. The returned capability still goes through `invoke` and all of its admission checks, and it can be used once.

## Checkpoint policy advisory

`checkpointPolicyListings(epochs)` (root import) is a pure helper. For each owner-key epoch it lists an explicit `byType.STATE_CHECKPOINT` threshold that is larger than the number of distinct non-`AGENT` credentials in that epoch: `{ fromPosition, policy, checkpointThreshold, nonAgentCredentials }`. Credentials are counted once across all key ids that share them, using the existing owner-key class rules. Such a policy is still valid, and replay does not change. The listing warns that losing that committee could block automatic checkpoints.

`irontrellis verify` lists these findings after it verifies, read against the same verified head. If the history moved between the two reads, or the listing cannot be read, the JSON reports `checkpointPolicies: { status: "UNAVAILABLE", reason }`. The verification verdict is unchanged. Owner-write JSON reports the current listing. The text output of `owner rotate-key` and `owner commit-next-key` shows it too.

## Packages built on these hooks

These packages have their own documentation. The facts below are the boundary they share with Core.

- **MCP gateway live anchoring.** `createGateway` accepts optional `anchoring` host configuration, which requires `recordCalls: true`. Exactly-once jobs support narrow resumption. Per-call mode gives each call its own operation and has no same-job resumption. CLI and config-file setup do not enable this profile. Only a `HEAD_POSITIONS` resume horizon is implemented. A stop after an attempt has started can yield `OUTCOME_UNKNOWN` with zero calls, and that never makes a retry safe. The tree contains no qualified finality-report producer and sets no live default. Synthetic reports and structural codecs are not consensus evidence, and the diagnostic `verifyAnchor` answers `UNVERIFIED` with `report: null`, which cannot release a wait. Same-owner file permissions are not a sandbox against hostile code running as that owner. Details: [LIVE-ANCHORING](../../packages/mcp-gateway/docs/LIVE-ANCHORING.md).
- **Anchor outbox** (`@ramex-labs/irontrellis-anchor-outbox`). It reuses the gateway's durable private-file primitives. Its runtime dependencies are Core, the gateway and exactly `viem@2.55.19`. The attempt identity has eight closed fields and a numeric nonce. Its `unsignedTxDigest` covers the whole canonical unsigned legacy transaction, fees included, while the anchor statement's own digest stays independent of fees. A fee change is a new attempt identity, reached only through an explicit clearance and a fresh claim, never automatically. No fee replacement is implemented. The installed-package smoke test contacts no chain and uses no real key. Details: [anchor outbox README](../../packages/anchor-outbox/README.md).

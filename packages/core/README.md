# @ramex-labs/irontrellis

**Agents change. The structure holds.**

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. This package is its engine and local host API: it writes that record as a signed, replayable history and reads it back.

## Why a record of authority

An AI agent acts on authority that changes while it runs: grants are made and revoked, sessions end, agents are replaced. Later someone asks whether one action was allowed at that moment, and on whose authority. Logs record what a system says it did, but rarely the authority behind it. An IronTrellis history records the authority itself, as signed, hash-chained events that are replayed to recompute every answer.

## 60-second quickstart

```sh
npm install @ramex-labs/irontrellis@next   # Node ≥ 22.18, zero runtime dependencies
```

```js
import { createLocalOwner, createLocalDomain } from "@ramex-labs/irontrellis/local";

const owner = await createLocalOwner({
  historyFile: "./history.jsonl",        // creates history.jsonl, history.jsonl.owner-key.json and the committed next key history.jsonl.owner-next-key.json (0600; move it offline)
  domain: createLocalDomain(),           // a fresh format-2 namespace
  owner: "operations", controller: "operator",
  now: Date.now,                         // the trusted host clock
});
await owner.createAgent({ id: "bea" });
await owner.grant({ id: "collect", to: "bea", actions: ["read", "collect"], resources: ["incident:42"], expiresAt: Date.now() + 12 * 3_600_000 });

const ask = { actor: "bea", action: "read", resource: "incident:42" };
console.log(owner.authorize(ask).decision);                                    // ALLOW
console.log(owner.why(ask).answer.authorization.proof.controllingAuthorityIds); // [ 'collect' ]
await owner.revoke("collect");
const denied = owner.authorize(ask);
console.log(denied.decision, denied.evidence.code);                            // DENY REVOKED
const report = owner.verify();
console.log(report.ok, report.pinnedHeadStatus, report.controlSignatures);     // true MATCHES VERIFIED
```

| Printed | What it shows |
| --- | --- |
| `ALLOW` | bea may read `incident:42`: the recorded grant `collect` allows it |
| `[ 'collect' ]` | WHY: the grant that controls that decision |
| `DENY REVOKED` | after `revoke`, the same question is refused, and the code says why |
| `true MATCHES VERIFIED` | `verify`: no check failed, the pin matches the head, and the control signatures are valid |

Every write appends one owner-signed event to `history.jsonl` and pins the head; every question reads the captured history and executes nothing. `ALLOW` is an answer about the record, not a capability.

## What it is

| Part | What it is |
| --- | --- |
| **A history** | An append-only JSONL file of hash-chained events (`docs/HISTORY-FORMAT.md`). This package writes format 2 (`irontrellis-event/2`): every control event is signed with an owner key, the pinned head is attested, a state root commits to what the history establishes, and the history can bind remote witnesses and anchor its heads in an anchor log. Format-1 (`irontrellis-event/1`) and legacy Continuity (`continuity-event/0.2`) histories open read only; `migrateHistory` moves them to format 2, except the sources `docs/MIGRATION.md` lists as refused (a format-1 history that rotated its owner keys or bound witnesses, for example). |
| **An engine** | Replay, the authorization decision procedure with proofs, the WHY / RESPONSIBLE / SURVIVES queries, intent admission, receipts, administrative (duty) events and the exactly-once coordinators, all pure functions over plain data. On legacy histories it reproduces the Continuity 0.2.2 reference to the byte (53,984 differential authorization comparisons). The conformance vectors pin it: the Continuity suite and the format-1 suite, which an independent Python implementation also passes, and the format-2 suites (`docs/CONFORMANCE.md`). |
| **A local API** | An owner handle for control writes, runtime handles for session-signed operations, duties and receipts, observations for the questions, capacity, verification, anchoring and migration. |

**Format 2 as released.** Publishing 1.0.0-rc.2 releases format 2. A history it writes keeps its verdicts: later versions read it exactly as 1.0.0-rc.2 does, or refuse it; rule fixes after 1.0.0-rc.2 come as a new format. Format 2 as released means challenge profile `g3`, the default. The `frozen-r2.3` profile (`IRONTRELLIS_CHALLENGE_PROFILE=frozen-r2.3`, or `setChallengeProfile`) only verifies the frozen conformance vectors.

## Export map

| import | contents |
|---|---|
| `@ramex-labs/irontrellis` | everything below plus the engine: `replay`, `authorizeState`, `authorizePortable`, `whyState`, `responsibleState`, `survivesState` (and the `*Portable` forms), `proposeIntentAdmission`, `createReceipt`, `verifyReceipt`, `produceAdministrativeEvent` and their `*State` forms over an already replayed state (`proposeIntentAdmissionState`, `createReceiptState`, `verifyReceiptState`, `produceAdministrativeEventState`, …), `DurableAdmissionCoordinator`, `DurableReceiptCoordinator`, `admittedSubmissionIdentity`, `forkReplayState`, `withProspectiveEvent`, canonical form and hashing (`canonicalEncode`, `hashCanonical`, `HistoryHasher`, `jsonStringifyWithBigints`), the signature suites (`suiteFor`, `generateKeyPair`, `signHashWith`), event validation and the control challenge, `createOwnerKeyFile`, `loadOwnerKeyFile`, `signControlEvent`, `attestHead`, `verifyHeadAttestation`, owner key rotation and pre-rotation (`ownerKeysAt`, `verifyHeadAttestationAt`, `verifyRotationEvent`, `ownerKeyEventTransition`, `ownerKeyDigest`; `LocalOwner#rotateOwnerKey`, `prepareOwnerKeyRotation`, `commitOwnerKeyRotation`, `commitNextKey`, `ownerKeyStatus`), `localAnchorLog`, `rekorAnchor` (experimental), `anchorHead`, `anchorsPathFor`, the remote witness client and bindings (`remoteWitness`, `boundWitnessesOf`, `boundPolicyOf`, `verifyWitnessReceipt`; docs/WITNESS.md), `HISTORY_FILE_LIMITS`, and every constant and type |
| `@ramex-labs/irontrellis/local` | `createLocalOwner`, `openLocalOwner`, `createLocalDomain`, `createLocalAttemptOwner`, `createLocalReviewOwner`, `openLocalRuntime`, `openLocalSimulation`, `openLocalExecution`, `createSimulatedAdapter`, `commitTerms`, `openLocalEvidenceTool`, `selectEvidence`, `openLocalAttemptRecorder`, `inspectAttemptHistory`, `observeHistory`, `observeState`, `captureHistory`, `replayHistory`, `capturePolicy`, `evaluatePolicy`, `capacityOf`, `assertCapacityTransition`, `migrateHistory`, `verifyHistory`, `IronTrellisError` (`ContinuityError` alias) |
| `@ramex-labs/irontrellis/store` | `openHistoryStore`, `createHistoryStore`, `HISTORY_FILE_LIMITS`, `HistoryStore` (including `verify()` and `repin()`), `StoreOptions` (`acceptRollback`, `allowUnpinned`, `inspect`, `reuseExistingKey`, `lockTimeoutMs`, …), `PinnedHead`, `HeadAttestation` |
| `@ramex-labs/irontrellis/attempts` | `openLocalAttemptRecorder`, `inspectAttemptHistory` |
| `@ramex-labs/irontrellis/internal-format1` | not public, no semver promise, test tooling only: the legacy and format-1 writers (`createFormat1TestOwner`, `openFormat1TestOwner`, `openHistoryStoreInternal`, `createHistoryStoreInternal`, `format1TestOptions`, and the mark `FORMAT1_TEST_TOOLING` they set). The public API writes format 2 only |
| `@ramex-labs/irontrellis/custody` | owner-key custody (docs/CUSTODY.md): key references (`keyReference`, `parseKeyReference`, `referenceSigner`, `publicKeySigner`, `OWNER_KEY_REF_VERSION`, …), the signer-backend registry (`registerSignerBackend`, `signerBackend`, `signerBackendKinds`), the built-in `ssh-agent`, `command` and `vault-transit` signers, and the OpenSSH key helpers (`parseSshPublicKey`, `sshPublicKeyLine`, `openSshPrivateKey`); also exported from the root |
| other subpaths | `/transparency`: the remote witness's wire formats; `/adapter`: the trusted integration-host interface; `/platform`: platform file helpers; `/duties`, `/evidence`, `/policy`, `/runtime`, `/simulation`: one handle family each, also re-exported by `/local` (docs/API.md) |

All write methods are `async`; all queries are synchronous; amounts are `bigint`; results are frozen. Coming from `@ramex-labs/continuity`: rename the import and `await` the writes (`docs/MIGRATION.md`).

## Read-only use

```js
import { openHistoryStore, verifyHistory } from "@ramex-labs/irontrellis";
const state = openHistoryStore("./history.jsonl").state();   // any format, no key needed
const report = verifyHistory("./history.jsonl");             // chain, control signatures, pinned head and its attestation, anchors, anchor logs
report.ok;                                                   // true only when report.failures is empty
```

`verifyHistory` reads `<history>.anchors` when it exists and any extra anchor logs you pass (`{ anchorLogs: [localAnchorLog(path)] }`), and reports pin and anchor-log problems in `failures` instead of throwing. Opening a history, by contrast, refuses it when its pin or anchor log cannot vouch for it:

| Opening a history refuses | Code (`detail.reason`) |
| --- | --- |
| a pin the file does not contain | `ROLLBACK_DETECTED` (`BEHIND_PIN`) |
| a malformed pin | `ROLLBACK_DETECTED` (`PIN_MALFORMED`) |
| a missing pin beside a format-1 or format-2 history with events after its genesis | `ROLLBACK_DETECTED` (`PIN_MISSING`) |
| a pin without a valid owner attestation of a prefix of the file | `ROLLBACK_DETECTED` (`PIN_UNATTESTED`, `PIN_ATTESTATION_INVALID`, `PIN_ATTESTED_NOT_PREFIX`) |
| a file that `<history>.anchors` holds a later head of | `ROLLBACK_DETECTED` (`ANCHOR_LOG_ROLLBACK`) |
| an unreadable `<history>.anchors` | `ANCHOR_LOG_UNREADABLE` |

Still run `verifyHistory` after a restore and on a schedule, with an anchor log kept elsewhere or a remote witness (`docs/OPERATOR.md` §3): a rollback to a head the owner once attested is caught only by evidence of a later head that the restorer could not rewrite (`docs/SECURITY.md`, freshness and rollback; `docs/WITNESS.md`).

## Performance

Writes and decisions work on the cached state and never replay the history; the execution path (`run`, `recordReceipt`, `obligate`) does too. Opening a history replays it once; Ed25519 verification runs on worker threads (`IRONTRELLIS_VERIFY_THREADS`).

The format-2 engine was measured in October 2026 on a 2-vCPU virtual machine with one 10,000-event history (docs/BENCHMARKS.md):

| Path | Measured |
| --- | --- |
| a signed control write, with fsync | about 4.1 ms |
| a full replay | about 0.56 ms per event |
| an export view of the last 1,000 events | about 45 ms |
| a hook check from a snapshot | about 0.9 to 1.2 s, which misses its budget |

Later engine changes were not re-measured. With a KMS `signer` or a key held by an ssh-agent or a command signer (docs/CUSTODY.md), every write waits for its pin attestation; `await owner.flush()` before the process exits reports a failure. Measured figures and method: `docs/BENCHMARKS.md`; scale, memory and limits: `docs/PERFORMANCE.md`.

## Limits

- **Session-signed writes wait for the owner.** Runtime, simulation and duty handles sign with a session key, and so do the coding-agent hook and the MCP gateway when they record refusals and effects. Such events get no owner attestation and no witness statement until the next owner write or checkpoint covers them. Meanwhile `verify` notes `PIN_ATTESTED_EARLIER`, and `UNWITNESSED_TAIL` when it asks remote witnesses.
- **No public-chain anchors are verified.** `verifyHistory` checks that every anchored head the history records is a prefix of it, and compares the history with the anchor logs it reads. It does not verify anchors on a public chain (known issues 54, 56 and 71 in `docs/records/KNOWN-ISSUES-r2.5.md`); the separate anchoring tools used for the public-chain demonstration records report `TRUSTED_NODE` only, never consensus-verified.
- **A file vouches only for itself.** `verifyHistory` takes the history id and the first owner keys from the file it checks, so a substitute history signed with other keys verifies just as cleanly; it has no option to compare them with published values yet. Open a format-2 history with the history id the owner published (`openHistoryStore(path, { historyId })` refuses any other with `HISTORY_IDENTITY_MISMATCH`) and compare `ownerKeysAt(state, 0)` with the published owner keys. The `irontrellis` command's `verify --expect-history-id` and `--expect-owner-key` do both.

## Documentation

| Document | What it covers |
| --- | --- |
| `docs/PRINCIPLES.md` | what a decision means |
| `docs/GLOSSARY.md` | the terms |
| `docs/API.md` | every export, shapes and error codes |
| `docs/HISTORY-FORMAT.md` | the file format and signatures, for implementers |
| `docs/ARCHITECTURE.md` | how the parts fit |
| `docs/SECURITY.md` | what is and is not established |
| `docs/OPERATOR.md` | backups, verification, keys, incidents |
| `docs/CONFORMANCE.md` | the conformance suites |
| `docs/MIGRATION.md` | moving from Continuity and older formats |

The command-line tool is the `irontrellis` package; hooks for coding agents are `@ramex-labs/irontrellis-hooks`.

Apache-2.0.

*Last reviewed: 24 October 2026. This page is revisited at each release.*

# IronTrellis remote tools

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. `@ramex-labs/irontrellis-remote-tools` 1.0.0-rc.2 supplies the implementation behind the five-subpath `@ramex-labs/irontrellis-remote` SDK: the cooperative destination, the client that talks to it, the executor that runs admitted work, and recovery.

This port uses the format-2 engine and Core's adapter storage interface, and needs Node.js 22.18 or later. It performs synthetic local effects; service reports never prove an outside outcome.

## What a trusted application builds

| Part | Factory | What it fixes |
| --- | --- | --- |
| Tool registry | `createToolRegistry` | The service, the account and the tool contracts (`REFERENCE_TOOLS` is a sample set) |
| Destination | `createCooperativeDestination` | A loopback service bound to an independently configured format-2 `domain` and `historyId` (the genesis record hash) |
| Client | `createCooperativeClient` | The destination's loopback address and pinned Ed25519 keys: the coordinator's private key and the destination's public key |
| Executor | `createCooperativeExecutor` | A fixed runtime session, role and tenure |
| Recovery | `createCooperativeRecovery` | Status lookup and cancellation (expose cancellation only to the application's operator) |

The package also exports `inspectDestinationLock` and `recoverDestinationLock` for operators, and `createProtectedEvidenceDestination` with `readProtectedEvidence`: a destination whose tools close and restore a reviewer's access to a fixed evidence bundle, and the reviewer's reader. The other subpaths in `package.json` (`./client`, `./destination`, `./durable-store`, `./executor`, `./recovery`, `./validation`, `./wire` and `./protected-evidence`) are internal modules without type declarations.

Keep all configuration, signer callbacks, operator recovery, checkpoint publication, and history paths outside model control. Agent tools receive only the application-selected business fields.

## A call, end to end

| Step | Where | What happens |
| --- | --- | --- |
| 1 | Agent | Calls a tool with business fields only, such as a ticket's title. |
| 2 | Executor | Records the admission in the local history, then `checkpointHistory(store)` transfers the history's format-2 export view. |
| 3 | Destination | Accepts the transfer only if it verifies in full and extends the history it accepted before. |
| 4 | Destination | Checks the operation against that history, prepares it, then commits it once: the synthetic effect and its deduplication record share one durable write. Every result it returns is signed. |
| 5 | Executor | Returns the execution result with the last service report, `externalOutcome: "NOT_PROVEN"` and the revocation boundary `DESTINATION_ACKNOWLEDGED_CHECKPOINT`. |

## Which heads the destination accepts

Every `checkpointHistory(store)` transfers a format-2 export view, and the destination accepts only verified full history transfers. Its `headAuthenticationPolicy` decides how the head of the history must be authenticated:

| | `REQUIRE_OWNER` (the default) | `COORDINATOR_AUTHENTICATED` (explicit) |
| --- | --- | --- |
| Accepts | A head Core authenticates as `HEAD_ATTESTATION`, `STATE_CHECKPOINT` or `GENESIS` | A fully verified runtime tail received in a request signed by the pinned coordinator |
| Claims | An owner-authenticated head | No owner-attested head |

Runtime writes normally leave the new head unattested and unwitnessed until the next owner write; the earlier attestation still covers only the earlier head. Under `REQUIRE_OWNER` the application must obtain a new owner checkpoint or attestation before publishing such a tail; until then the destination refuses it (`CHECKPOINT_CONFLICT`). The executor transfers the history right after recording its own admission, so under `REQUIRE_OWNER` the destination accepts that transfer only when the admission's head is owner-attested; otherwise nothing is prepared, the run ends `OUTCOME_UNKNOWN`, and its result's `diagnostic` says that the destination refused the checkpoint before anything was dispatched. Two setups work: give the executor the owner key as its `signer` (which puts that key in the executor's process), or set the destination to `COORDINATOR_AUTHENTICATED`, as this package's tests do.

Both policies enforce the independent history identity and domain, native event signatures and replay, clock monotonicity, and the prior head's record hash. The chosen policy is persisted in the destination identity and cannot change on restart.

## What the destination keeps

The destination persists a reference to the verified transfer and one durable snapshot holding effects, deduplication records and cancellation tombstones. Only `irontrellis-cooperative-destination/1` state with a pinned format-2 history is accepted.

| Rule | What it means |
| --- | --- |
| A checkpoint acknowledged by the destination fences queued work prepared against an older head. | Committing work prepared before it is refused (`CHECKPOINT_CHANGED`). |
| Local revocation only becomes that destination fence after the destination acknowledges the new checkpoint. | Until then, the destination cannot know of the revocation. |
| Trusted local clocks are also checked before committing. | A time earlier than one already accepted is refused (`CLOCK_INVALID`). |

## When the outcome is uncertain

A transport loss returns an unknown outcome; it never authorizes a new operation ID or automatic redelivery.

| Function | What it does | What it never does |
| --- | --- | --- |
| `createCooperativeRecovery`, `lookup` | Asks the destination for the operation's status | Prepare or dispatch |
| `createCooperativeRecovery`, `cancel` | Cancels the operation; one already applied answers `TOO_LATE` | Prepare or dispatch |
| `inspectDestinationLock`, `recoverDestinationLock` | Let an operator inspect and recover the exact stale destination lock, on the same host, only after the OS confirms its owning process is absent | Take over a lock because of its age |

Call `executor.close()`, `recovery.close()`, and `await destination.close()` to release resources.

## Not in this port

Inline `checkpoint(events)`, segmented bindings, old history profiles, and destination migration are absent.

## LangChain

`./langchain` exports `createIronTrellisTool` and `createIronTrellisTools`, and requires the optional peers `@langchain/core` 1.2.12 and `zod` 4.6.5. Each tool's schema holds only the business fields the application selected; the application fixes the operation ID and business key.

## Frozen protocol strings

Some strings inside signed or hashed bytes keep the old name's spelling. They are hash and signature domain separators, not accepted aliases:

| Strings | Used in |
| --- | --- |
| `continuity-cooperative-request/1`, `continuity-cooperative-response/1`, `continuity-cooperative-request-signature/1`, `continuity-cooperative-response-signature/1` | The signed request and response envelopes and their signatures |
| `continuity-protected-evidence/1` | The protected-evidence identity |
| `continuity-destination-identity/1`, `continuity-destination-snapshot/1`, `continuity-destination-lock/1` | The durable checksum and lock envelopes |
| `continuity-tool-contract/1`, `continuity-tool-terms/1` | The tool contract and terms identifiers |

The tool contract and terms identifiers use explicit SHA-256. This intentionally differs from the original Keccak-256 digest and does not claim old digest compatibility. The canonical encoding is unchanged: `test/hash-quantity.test.mjs` checks it against vectors from the original code and computes both digests over the same bytes.

## Limits

| Topic | Limit |
| --- | --- |
| Rollback | The store has no authenticated rollback witness: hashes detect corruption, but restoring an entire old destination directory is outside its guarantee. |
| Effects | The destination performs synthetic local effects. A service report never proves an outside outcome. |
| Capacity | A destination accepts at most 256 operations in its lifetime (`CAPACITY_EXHAUSTED`); a registry holds 1 to 32 tools of at most 16 fields each; the client waits 2,000 ms per request by default (20 to 10,000). |
| PHL, Proof of Human Lineage | This package's tests use the default owner policy, under which owner keys are classed as declared (`DECLARED`). Core ships the PHL `ATTESTED` policy, but no additional adapter-level PHL coverage is established here. |

## Check it yourself

In the repository, run `pnpm install` and `pnpm -r build`, then `npm test` in `packages/remote-tools`. Test fixtures use real Core owner/runtime histories and synthetic keys. The test history export directory can be selected with `IRONTRELLIS_TEST_HISTORY_DIR`, so that an independent history checker can re-check those histories; `test/verify-install.py` runs such a checker over them when given its path with `--checker`.

The test commands above check this package as it ships. They do not test your deployment, and the limits stated above still apply.

## License

Apache-2.0. The package carries the repository NOTICE, with required third-party attribution retained below it; see [LICENSING.md](LICENSING.md) and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The optional peers keep their own licenses.

*Last reviewed: 24 October 2026. This page is revisited at each release.*

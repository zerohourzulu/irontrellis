# IronTrellis managed-agents adapter

IronTrellis (formerly Continuity) keeps a checkable record of who may act for whom, and which duties survive when an AI agent is replaced. This package, `@ramex-labs/irontrellis-managed-agents` 1.0.0-rc.2.1, runs in your backend, where an agent's tool calls arrive: from a hosted ("managed") agent platform, or from the OpenAI Agents SDK or LangGraph through the [agent shims](../agent-shims/README.md). It checks each call against the agent's authority in a format-2 history, admits it in that history before its handler runs, never re-enters the handler for it automatically, and later records what the provider reports happened.

It is a trusted backend adapter over the actual format-2 Core. Your authenticated host fixes the tenant, host, **full workflow**, session and actor; the Core history, domain, controller, session and signer; the mappings and the downstream handlers. Never derive these from model tool arguments.

```sh
npm install @ramex-labs/irontrellis-managed-agents@next
```

## Why it exists

| Situation | Risk | What the adapter does |
| --- | --- | --- |
| The grant is revoked while the call waits for finality | The handler runs on authority that has ended | Checks authority at admission, and again under the writer lock just before the handler |
| The process crashes after the handler ran | A retry repeats the effect | Never re-enters the handler for an admitted call; a retry only looks up status |
| The provider reports a call your backend never saw | The gap stays invisible | Records the provider's events as signed observations |

## One call, start to finish

Agent `bea` asks to call the tool `write` on `notes`:

1. `decide(call)` returns Core's answer from the captured history (`observeState`): ALLOW, DENY or INDETERMINATE. A runtime session or role tenure that is no longer current gives DENY; an unmapped tool or invalid mapping evidence gives the package's own INDETERMINATE. It writes nothing, and its answer is advisory: no execution permit.
2. `record(call)` repeats the native authorization and durably admits the exact, explicit intent id before reaching any handler.
3. The adapter yields at once, so Core's writer lock is free while your `awaitFinality` waits for your finality evidence.
4. Under the writer lock again, it freshly checks host, session, control, authority, the original admission and your fence, persists a `DISPATCHED` marker in its recovery journal, checks again, and synchronously enters the fixed `write` handler under that same lock. The handler's promise is awaited outside the lock.
5. It records the receipt and returns `CORE_RESULT`. Like every result, it carries `externalOutcome: "NOT_PROVEN"`: the history shows what was admitted and acknowledged, not what happened in the world.
6. Later, `reconcile(page)` records what the provider's event stream reports, as `RECONCILIATION_OBSERVED` observations (event type 42).

`governed(options)` returns `decide`, `record`, `reconcile` and `close`. `reconcile` needs an explicit reconciler session and cursor journal (the `reconciliation` option); without them it fails with `RECONCILIATION_NOT_CONFIGURED`. `createManagedReconciler` exposes the same native observation path on its own.

## Configure `governed(options)`

| Option | What you supply |
| --- | --- |
| `local` | Core's execution options: history file, domain, owner, controller, clock `now`, runtime `session`, `signHash` |
| `route` | `{ tenantId, host, workflowId, sessionId, actorId }`, from your authenticated host |
| `mappings` | Per tool: `version`, `action`, `role`, `tenure`, `destination`; a synchronous `map(args)` giving `{ resource, amount?, counterparty? }`; `execute(args, context)`; optional `status(idempotencyKey)` |
| `journalPath`, `initializeJournal` | The recovery journal. Set `initializeJournal: true` only for deliberate new state |
| `assertCurrent()` | Your live host guard |
| `awaitFinality({ idempotencyKey, admissionHead })` | Resolves `FINALIZED` (repeating the key and the admitted head's hash, with the downstream `fencingToken`) or `PENDING` |
| `assertFence(context)` | Checks the fencing token before the handler is entered |
| `reconciliation` | Optional: the reconciler's own `local`, `journalPath`, `initializeJournal`, `match`, `repeatedCursorPolicy`, `afterObservation` |

The history must be format 2, created by Core's `createLocalAttemptOwner` (its attempt-record adapter policy), or `governed` refuses (`FORMAT_2_REQUIRED`, `REMOTE_REPORT_PROFILE_REQUIRED`). Every call is captured before its first await with Core's bounded data capture, which refuses proxies, accessors, symbols, cycles, sparse arrays and executable shapes. `assertCurrent` and `assertFence` must synchronously return `undefined`: a native Promise's rejection is observed, but async or thenable guards are refused.

A call is identified by tenant, host, workflow, session and call id, and bound to its arguments, mapping version, destination and mapped operation: `record` with a reused id and changed content throws `CALL_CONFLICT` (`decide` answers INDETERMINATE).

## Results of `record`

| `status` | Meaning | Handler entered? |
| --- | --- | --- |
| `CORE_RESULT` | Admitted, acknowledged, receipt recorded | Once; a repeat of the call returns `CORE_RESULT` again without entering it |
| `DENIED` | Core refused (`NOT_AUTHORIZED`, `POLICY_REFUSED`); Core's refusal-record metadata is kept when present | No |
| `INDETERMINATE` | Nothing admitted, for example an unmapped tool | No |
| `UNCERTAIN` | An admission may exist and the outcome is open | Perhaps |

`core` and `receipt` are Core's own result types. `DENIED`, `INDETERMINATE` and `UNCERTAIN` keep the native result and, where available, the error's `code`, `detail` and `mayHaveCommitted`. A failed receipt is explicit (`receiptError`) and never treated as recorded.

## The effect boundary

`awaitFinality` and `assertFence` are **trusted integration contracts**, not a built-in chain or committee consensus. Your host must validate its finality evidence, its current leader lease, and the actual fencing and idempotency of the cooperating downstream service.

| What happens | Handler | Result |
| --- | --- | --- |
| Finality `PENDING`, an outage, or a fence failure | Not entered | `UNCERTAIN`; a retry stays uncertain (no resume permit for an admitted attempt) |
| Revocation while the effect is pending | Already entered | Success withheld; the effect is not undone |
| Retry, restart or journal rollback after admission | Never re-entered | Status lookup only |

Your `status` must look up the original idempotency key and must never dispatch.

## The recovery journal

| | |
| --- | --- |
| What it is | Unsigned operational metadata (call phases, stream cursors), not a canonical findings ledger |
| Where | A private directory that must already exist, reached by its real path, owner-only and owned by the process's user |
| Capacity | 256 call slots, 256 stream cursor slots, 4 MiB; a full journal is refused before the prior file is replaced |
| Writes | Bounded strict JSON, exclusive local locks, atomic rename, file and directory fsync |
| Refused | Symbolic links, non-regular files, duplicate keys, malformed state, excess bytes, unsafe POSIX permissions |
| Stale lock | A `<journal>.lock` or `<journal>.page` left after a process died needs operator inspection and removal; it is never taken over automatically |

Do not erase or reinitialize a cursor journal to resume an existing stream. The journal does not authenticate a rollback of the whole trusted directory, nor protect against its owner or the OS administrator.

## Reconciling what the provider reports

Your host supplies an already authenticated, ordered provider page: `{ tenantId, host, workflowId, sessionId, after, nextCursor, providerDeclaredComplete, events }`. The fixed route determines the stream; the events cannot select a reconciler, tenant, workflow or session. Each event keeps its `sourceEventIndex` and gets one result:

| Result | When |
| --- | --- |
| `ACCEPTED` | Recorded as a new observation |
| `DUPLICATE` | Its digest is already accepted for the same stream and event reference, by any reconciler |
| `BLOCKED` | Recording failed or Core refused it |
| `UNREPRESENTABLE` | No observed actor (`data.actorId`); the raw evidence is still retained |

- `data.actorId` is the **observed actor**, not the signing reconciler. `action`, `resource`, `observedAt` and `amount` are included only when supplied. Core decides missing-field lists, match status, duplicates, equivocation and signatures.
- A changed digest is accepted as an equivocation that refers to the earliest observation; a repeat of either version is `DUPLICATE`.
- An optional, trusted `match(event)` maps an event to an earlier admission (`{ intentId }`) or refusal (`{ refusalId }`); the payload cannot choose its match.
- The digest is the SHA-256 of Core's UTF-8 canonical encoding of `{ version: "managed-host-event/1", event }`. Those exact bytes are retained durably before recording, opaque and missing-actor events included, at `<journal>.sources/<hex digest>.canonical.json`: canonical captured envelopes, not byte-for-byte HTTP originals; 128 KiB per file, 4,096 distinct digests, reused only if byte-identical, no silent garbage collection.
- A malformed page, including a missing or invalid event id or type, is refused whole, before any append.

Only a page whose events are all `ACCEPTED` or `DUPLICATE` advances the cursor, after the durable checkpoint; a blocked page keeps its prior token. A crash between the append and the cursor update retries through `DUPLICATE`. The guard runs again after the cursor fsync: if it fails, the acknowledgment is withheld although the durable cursor may have changed. That is write and output uncertainty, not a rollback: inspect the retained state before choosing the next token. Empty advancing pages are accepted; a repeated token is refused unless `repeatedCursorPolicy: "ALLOW_EMPTY_STABLE"` and the page is empty. `providerDeclaredComplete` stays the provider's claim, and `coverage` is always `SUPPLIED_HOST_EVENTS_ONLY`.

| Bound | Limit |
| --- | --- |
| A captured call or page | 64 KiB, 4,096 nodes, depth 16 |
| A page | 1,000 events |

## Always ask

`resolveAlwaysAsk(options, event)` is an advisory, provider-mediated veto for a route whose host is `claude-managed-agents`. Bind the authenticated provider session through the fixed route and your live host guard. It accepts only an actual `agent.tool_use` or `agent.mcp_tool_use` event with `evaluated_permission: "ask"`, for a selected tool; route fields the event carries must match.

Configure a pinned effective-configuration digest, the selected tools, and `assertAlwaysAsk(config, selectedTools)`: a synchronous validator, written against the provider's actual effective-policy schema, that verifies every selected tool is `always_ask`. A matching configuration hash alone does not establish that. Configuration, native authority and host binding are rechecked across awaits. It returns a `user.tool_confirmation` object, with `allow: true` only for ALLOW; it does not send it or bypass the provider.

## What the tests show, and what they do not

| The local synthetic tests show | They do not show |
| --- | --- |
| Exclusion ordering and fail-closed behavior | A public chain, a distributed lease or an external business outcome |
| No effect is redispatched after the tested journal rollback | Full anti-rollback storage |
| Observations hold what the supplied pages said | That the provider supplied every event |

**Not owner-attested.** Writing native observations needs no owner privilege or owner head attestation. With `local` as listed above (a runtime session and its `signHash`, no owner signer), everything the adapter writes stays unattested by the owner, and unseen by any witness, until the owner's next write.

## Removed and changed

- Removed on purpose: the old `run` alias, `SignedLedger`, the ledger verification and entry exports, and the ledger-backed helper signatures. Legacy signed ledgers are archive-only. There is no automatic importer: a migration needs reviewed source actors, the source serialization and keys, the retained original signed bytes and manifest, then new native observations at the current head.
- New `/2` identities bind the workflow explicitly (`irontrellis-managed-call/2`, `irontrellis-adapter-route/2`, `irontrellis-managed-stream/2`, `irontrellis-reconciliation-cursor/2`). The frozen `managed-terms/1` stays Keccak-256; `managed-host-event/1` stays SHA-256.
- Core ships the attestation policy for PHL, Proof of Human Lineage (`humanFloor: "ATTESTED"`). This adapter's retained checks establish no additional PHL policy coverage.

## Check it yourself

From a checkout of the repository:

```sh
pnpm install
pnpm -r build
pnpm --filter @ramex-labs/irontrellis-managed-agents test
```

`test/verify-install.py` packs this package, the agent shims and unchanged Core, installs a clean offline consumer, runs the real-engine and framework tests and a strict check of the declarations, and checks every test history with a separate spec-only history checker (not part of this repository). Its paths select the local, pinned toolchain and the checker:

```sh
python3 packages/managed-agents/test/verify-install.py --node <node> --pnpm <pnpm> --output <dir> --store-dir <pnpm store> --tsc <typescript/bin/tsc> --type-roots <dir> --checker <checker>
```

These commands check this package as it ships. They do not test your deployment, and the limits stated above still apply.

Apache-2.0. The package carries the repository NOTICE, with any required attribution appended.

*Last reviewed: 24 October 2026. This page is revisited at each release.*

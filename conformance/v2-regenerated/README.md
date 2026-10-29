# Regenerated format-2 vectors (engine-derived)

IronTrellis (formerly Continuity) writes its histories in format 2. This suite tests format 2 across the whole engine: the topics of the format-1 suite, re-expressed in format 2, and what format 2 adds, from state records and budgets to export, read-only sources, observations and the session time horizon.

`generate.mjs` is the port of `conformance/v1/generate.mjs` to format 2. Like v1, its expected results are **this engine's own answers** (`packages/core/dist`), projected exactly as `conformance/adapters/node.mjs` answers; they are not an oracle derived from the specification. The suites derived from the specification's own generator are `conformance/v2` (frozen, the record of the earlier challenges) and `conformance/v2-g3` (the same suite, regenerated under profile `g3`). The format-2 specification names this suite, with `v2-g3`, as part of format 2's definition (Core specification §19). A future Python implementation of format 2 must pass both kinds of suite.

Every history is signed under the session-challenge profile `g3`, the engine's default (approved on 11 October 2026); the generator refuses to run under another profile.

## Running and regenerating

```
pnpm --filter @ramex-labs/irontrellis build
node conformance/run.mjs --suite v2-regenerated --adapter conformance/adapters/node.mjs
node conformance/v2-regenerated/generate.mjs            # write vectors.json, MANIFEST.json, glossary.json, histories/
node conformance/v2-regenerated/generate.mjs --check    # exit 1 when a fresh generation differs
```

The generation is deterministic. It uses:

- the published seeds of `conformance/v2/TEST-KEYS.md` (owner `owner:1` 0x…1001, next key `owner:2` 0x…1102, `key:spender`, `key:gateway`, `acme:1`, `stranger:1`) and the further seeds listed in `MANIFEST.json` `keys`;
- the domain of `conformance/v2`, counter ids, scripted clocks and the fixed migration id `0x4d…4d`;
- for the migration twins, the parameters of `packages/core/test/format2-migrate.test.mjs` (owner key seed `0x7e…7e`, no next key, clock 5000), so their pinned heads and roots are that test's `PINNED` values.

Pin files carried by `writer-open` vectors have `pinnedAt` set to the pinned head's time. (The store stamps its wall clock there; it is unsigned bookkeeping.)

## Checking the pinned roots yourself

`MANIFEST.json` `pinnedPositions` lists, for each history, every position whose state root is pinned. `node scripts/pin-roots.mjs --out <dir>` (a directory outside the repository) writes the pinned roots of this suite and of `v2-g3`, with the full record set at each pinned position, so that a reviewer can recompute each state root from its records. An independent checker, written from the specification alone and kept outside this repository, re-derives these roots, except those of the session-time-horizon histories, which it predates; its evidence is advisory.

## Layout and protocol additions

Loader and request shapes are as in `conformance/v2/README.md`: a vector names `history: {ref, eventCount}` or carries `events`. This suite adds the following, all implemented by the node adapter and the runner:

| Addition | Request | Compared result |
| --- | --- | --- |
| replay `input.testCapacityLimits` | `{op:"replay", …, testCapacityLimits: {maxStateRecords, reservedStateRecords}}`: the test-only lowered hard limits of `capacity.ts` (`setCapacityLimitsForTests`), applied for that request only | As replay |
| kind `export-verify` (verifier level) | `{op:"verify-export", view}`: the export-view verifier of Core specification §15, over a view as carried | `{ok, code, missingPositions, from:{position, stateRoot, verified, authenticated}, to:{…}, eventCount}` |
| kind `writer-open` (evaluator level) | `{op:"open-for-write", lines, pin?, marker?, ownerKey?}`: the store files (`.jsonl`, `.head`, `.migrated`) are written to a scratch directory, and an owner write is attempted | `{written, code, reason}` (Core specification §16.1: `FORMAT_READ_ONLY`, with its reason) |
| kind `authority-evaluation` (evaluator level) | `{op:"evaluate-authority", input}`: the supplied-scope raw path ([legacy semantics, part 2](../../docs/legacy-semantics/02-authorization.md) §7.1; `evaluateAuthorityPath`), with the input carried as JSON (the 0.2 transport, its `$continuity.bigint` markers decoded by the engine's capture) | As `authorize` |
| SURVIVES on a format-2 history | Unchanged request | The adapter answers through the state API ([`observeHistory`](../../docs/reference/api-observations-signing.md)). The portable `continuity-query-envelope/0.2` accepts format-2 histories too, and gives the same answers |

`glossary.json` fixes the difference between two hashes of the genesis: `genesisEventHash` is `eventHash(e₀)`, while `historyId`, the genesis hash, is `recordHash(0)`. The vector `export/v2r/a70-glossary-genesis-hashes` pins both values.

## Topics

`MANIFEST.json` gives the counts by topic (`counts.byTopic`) and every vector's purpose.

| Topic | What it covers |
| --- | --- |
| genesis-and-control-signatures, owner-keys, anchors-and-witness-bindings, authorization, survives, attestation | The format-1 topics, re-expressed in format 2 (`handover-v2`, `handover-anchored-v2`, `authority-v2`, `rotation-v2`, `pre-rotation-v2`, `witness-bound-v2`); attestations are `/2`, with a state root and a projection head |
| migration | The legacy handover migrated to format 2 (prefix end 25) and the format-1 `handover-v1` migrated to format 2 (prefix end 21), heads and roots pinned; incomplete and truncated prefixes; a session without expiry in a migrated prefix (the omitted expiry survives the round trip, an explicit `null` is refused, its first use after the prefix is refused, and a fresh session is admitted) |
| state-records | `rich-v2`: every state-record kind of Core specification §7.2 except `shadow` (which is in the migration twins), with the root pinned where each kind first appears |
| lifecycle-authorization | Types 14 to 16; consumptions, outcomes and receipts naming an unknown intent (a valid signature gives `TRANSITION_INVALID`, a bad signature `RECORD_AUTHORIZATION_INVALID`, a wrong signer `TRANSITION_INVALID`); two faults at once (a fence with a bad signature gives `SESSION_FENCED`; a credential mismatch with a fence, and a missing session, give `RECORD_AUTHORIZATION_INVALID`; a wrapper fence with a bad counterparty signature gives `COUNTERPARTY_SIGNATURE_INVALID`; a type-16 inherited or nested mismatch gives `EVENT_DATA_INVALID`); and the fence on a refusal |
| duty-policy | Activation, disposition, review and contest, with the duty view of Core specification §13.3 at each step; schema refusals; a second activation and a replayed finding |
| budgets | The saturated rollover; `BUDGET_SET_TOO_LARGE` (17 matching budgets) and the 257th budget; a `roleIds` budget across a handover; Amount negatives; and a budget declared with `amountCap: null`, which clears bit 2 of its projection row (the projection head is pinned and checked against its `"0"` twin) |
| effects, counterparties, checkpoints, eip191-sessions | `EFFECT_LIMIT`; a counterparty re-registration that keeps the chain; checkpoints every N events (`everyEvents`); EIP-191 sessions |
| capacity | The control-event reserve at a lowered cap (a non-control ◇ event that reaches the reserve threshold is admitted, one above it is `CAPACITY_RESERVED`; a control ◆ event is admitted up to the cap, `CAPACITY_EXCEEDED` above it), a declared `maxStateRecords`, and `CAPACITY_CONTROL_ONLY` with the duty quota |
| export | Views with `fromRecords` and the dependency closure; round trips (ok, `EXPORT_DEPENDENCIES_MISSING`, `INVALID_INPUT` for unsorted, null and unknown fields, from 0 with and without records, inside a migrated prefix); the genesis-hash glossary |
| read-only | `FORMAT_READ_ONLY` for a legacy history, a format-1 history and fenced sources; the format-2 target is writable |
| observation | Type 42, `RECONCILIATION_OBSERVED`, over `observation-v2` (a reconciler matching an admission and a refusal, an unmatched event, an equivocation, a second equivocation by another reconciler, a second stream; root pinned) and `observation-cap-v2` (the same setup at `maxEvents`). Duplicates (also after an equivocation, and by another reconciler); the match, head and reconciler bindings; forged and unsigned authorizations; a fenced session; the schema (unsupplied, `match.position`, 128 and 129 code points); capacity; type 42 in a migrated prefix and in a format-1 history; and one export round trip. These are engine-derived; the specification's own observation group is a separate suite |
| session-time-horizon | Rule T3 of Core specification §6.5.6: a session-signed event may run at most `sessionTimeHorizonMs` past the owner's latest time. At the bound and one millisecond past it, for a refusal and for an admission; after a checkpoint moves the owner's time, and after a power-reducing event written at the head's time, which doesn't; a fenced session, where T3 is checked before the fence; values near 2^53 − 1, including one where the owner's time plus the horizon would pass 2^53 − 1; and migrated histories, whose prefix is exempt but whose first event after the prefix is not. No vector yet covers an obligation or duty record past the bound ([known issue 52](../../docs/records/KNOWN-ISSUES-r2.5.md)) |

These later additions carry their inputs in the vector, not in a saved history, so `MANIFEST.json` pins no position for them:

- **Authorization decisions** (`authorization/v2r`): a proof too large for the output limit, and the fallback root that wins once that winner is revoked; a request Amount over the maximum; `AMOUNT_OVERFLOW` decided per candidate, so that another root wins when one would overflow, also when the winner's usage is already at the maximum.
- **The raw path**, as `authority-evaluation` vectors: which check comes first when two fail; and the overflow checks of candidate evaluation on supplied usage ([legacy semantics, part 2](../../docs/legacy-semantics/02-authorization.md) §4.2, restated for format 2 in Core specification §8.1.1): `deny-count-overflow-single-root` and `allow-second-root-when-first-count-would-overflow` (a count of 2^53 − 1 under a grant capped by `maxCumulativeAmount` only), `deny-amount-overflow-raw-count-capped-grant` (usage at the maximum under a grant capped by `maxTransactions` only), and the supplied-scope twins `deny-amount-overflow-single-root-supplied-scope` and `allow-second-root-when-first-would-overflow-supplied-scope`, which use a `maxTransactions`-only grant because the raw path carries usage only for capped grants. Before the change that added these overflow checks, every one of those five answered ALLOW.
- **Migration**: a migrated session without expiry, used after the prefix as an attester (`TRANSITION_INVALID` at the attester-eligibility step of Core specification §13.2) and as the outer session. The findings are signed against an in-memory copy of the state in which the prefix session has an expiry, so they are validly signed and refused only by replay.
- **Public keys in upper-case hex**: `replay/v2r/rejects-session-public-key-uppercase-hex` (type 8) and `replay/v2r/rejects-owner-key-uppercase-hex` (type 26). A public key not written in lower-case hex is `EVENT_DATA_INVALID` at the data-grammar check (C4 in Core specification Appendix A), and each has a lower-case twin that the generator requires to replay.
- **A budget with `amountCap: null`**: `replay/v2r/projection-null-amount-cap-clears-bit2`, in budgets above.

The two count-overflow cases could not be built over events, because no accepted format-2 history reaches the count; they are built on the raw path instead, as the `authority-evaluation` vectors above.

## Not covered here

The eligibility refusals of Core specification §13 that need a validly signed but ineligible finding (a fifth disposition, a third contest, COMPLETED after a contest, and a delegated, capped, wrong-resource or expired activation grant) are not vectors: the engine refuses them before signing, so the core package's duty tests cover them (`packages/core/test/duty-differential.test.mjs`, `packages/core/test/format2-duty.test.mjs`). Witness bindings that carry a REGISTERED receipt of a format-2 genesis are not covered either. See [known issue 17](../../docs/records/KNOWN-ISSUES-r2.5.md).

*Last reviewed: 24 October 2026. This page is revisited at each release.*
